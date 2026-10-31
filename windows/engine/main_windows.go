package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "EvgeniumNetworkEngine"

var version = "0.2.0"

type Rank struct {
	ID     string  `json:"id"`
	Label  string  `json:"label"`
	Mbps   float64 `json:"download_mbps"`
	RTT    int64   `json:"rtt_ms"`
	Losses int     `json:"losses"`
	Good   bool    `json:"good"`
	Error  string  `json:"error,omitempty"`
}
type Status struct {
	Version   string `json:"version"`
	State     string `json:"state"`
	Message   string `json:"message"`
	Route     string `json:"route"`
	Protected bool   `json:"protected"`
	Updated   int64  `json:"updated"`
	Restarts  int    `json:"restarts"`
	Ranking   []Rank `json:"ranking"`
}

func dataDir(sid string) string {
	return filepath.Join(os.Getenv("ProgramData"), "EvgeniumNetwork", sid)
}
func readConfig(sid string) (Config, error) {
	var c Config
	b, e := os.ReadFile(filepath.Join(dataDir(sid), "engine.json"))
	if e != nil {
		return c, e
	}
	if len(b) > 128*1024 {
		return c, errors.New("config_too_large")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	if c.Owner != sid {
		return c, errors.New("wrong_owner")
	}
	return c, validateConfig(c)
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(path+".tmp", b, 0600); e != nil {
		return e
	}
	return os.Rename(path+".tmp", path)
}
func writeStatus(sid string, st Status) {
	st.Version = version
	st.Updated = time.Now().Unix()
	_ = writeJSON(filepath.Join(dataDir(sid), "status.json"), st)
}
func socksClient(port int, timeout time.Duration) *http.Client {
	proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}, Timeout: timeout}
}
func request(port int, addr string, limit int64) ([]byte, error) {
	client := socksClient(port, 7*time.Second)
	defer client.CloseIdleConnections()
	resp, e := client.Get(addr)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http_%d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("response_too_large")
	}
	return b, e
}

// Two independent HTTPS checks avoid treating one external API outage as a
// broken VPN. Both must still report the exact expected Estonia exit.
func confirmedExit(port int, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := socksClient(port, timeout)
	defer client.CloseIdleConnections()
	for _, address := range []string{"https://api.ipify.org", "https://www.cloudflare.com/cdn-cgi/trace"} {
		req, _ := http.NewRequestWithContext(ctx, "GET", address, nil)
		r, e := client.Do(req)
		if e != nil {
			continue
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, 2048))
		r.Body.Close()
		if e != nil || r.StatusCode != 200 {
			continue
		}
		if strings.TrimSpace(string(b)) == "38.180.164.67" {
			return true
		}
		for _, line := range strings.Split(string(b), "\n") {
			if line == "ip=38.180.164.67" {
				return true
			}
		}
	}
	return false
}
func healthy(id string) bool { return confirmedExit(routePort(id), 7*time.Second) }
func probe(t Transport) Rank {
	r := Rank{ID: t.ID, Label: t.Label}
	start := time.Now()
	quick := func(address string, limit int64) ([]byte, error) {
		client := socksClient(routePort(t.ID), 2500*time.Millisecond)
		defer client.CloseIdleConnections()
		response, err := client.Get(address)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return nil, errors.New("http")
		}
		return io.ReadAll(io.LimitReader(response.Body, limit))
	}
	timeout := 4 * time.Second
	if t.Network != "" {
		timeout = 6 * time.Second
	}
	if !confirmedExit(routePort(t.ID), timeout) {
		r.Error = "Выход в Эстонии не подтверждён"
		return r
	}
	r.RTT = time.Since(start).Milliseconds()
	start = time.Now()
	b, e := quick("https://speed.cloudflare.com/__down?bytes=262144", 262144)
	if e == nil && len(b) == 262144 {
		r.Mbps = float64(len(b)) * 8 / time.Since(start).Seconds() / 1e6
	}
	r.Good = true
	return r
}

var currentBridge *packetBridge
var bridgeWork sync.Mutex

func probeAll(previous []Rank) []Rank {
	result := make([]Rank, 0, len(transports))
	old := ""
	if currentBridge != nil {
		old = currentBridge.currentRoute()
		defer currentBridge.route(old)
	}
	for _, t := range transports {
		if currentBridge != nil {
			_ = currentBridge.route(t.ID)
		}
		r := probe(t)
		for _, p := range previous {
			if p.ID == r.ID {
				r.Losses = p.Losses
			}
		}
		result = append(result, r)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Good != result[j].Good {
			return result[i].Good
		}
		return result[i].Mbps > result[j].Mbps
	})
	return result
}
func choose(c Config, ranks []Rank) string {
	if c.Policy.Route != "" && c.Policy.Route != "auto" {
		return c.Policy.Route
	}
	for _, r := range ranks {
		if r.Losses < 3 && r.Good {
			return r.ID
		}
	}
	return ""
}

func following(c Config, ranks []Rank, current string) string {
	if c.Policy.Route != "" && c.Policy.Route != "auto" {
		return c.Policy.Route
	}
	position := -1
	for i, r := range ranks {
		if r.ID == current {
			position = i
		}
	}
	for step := 1; step < len(ranks); step++ {
		r := ranks[(position+step)%len(ranks)]
		if r.Good && r.Losses < 3 {
			return r.ID
		}
	}
	return ""
}

type coreProcess struct {
	cmd  *exec.Cmd
	done chan error
	log  *rotatingLog
	job  windows.Handle
}

func startCore(c Config, route string, probeOnly bool) (*coreProcess, error) {
	exe, e := os.Executable()
	if e != nil {
		return nil, e
	}
	path := filepath.Join(dataDir(c.Owner), "core.json")
	b, e := marshalCore(c, route, probeOnly)
	if e != nil {
		return nil, e
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		return nil, e
	}
	logPath := filepath.Join(dataDir(c.Owner), "engine.log")
	f, e := openLog(logPath, 512*1024)
	if e != nil {
		return nil, e
	}
	cmd := exec.Command(filepath.Join(filepath.Dir(exe), "xray.exe"), "run", "-config", path)
	cmd.Dir = filepath.Dir(exe)
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_SUSPENDED | 0x08000000}
	if e = cmd.Start(); e != nil {
		f.Close()
		return nil, e
	}
	job, e := containChild(cmd.Process.Pid)
	if e != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		f.Close()
		return nil, e
	}
	p := &coreProcess{cmd: cmd, done: make(chan error, 1), log: f, job: job}
	go func() { e := cmd.Wait(); f.Close(); p.done <- e }()
	return p, nil
}
func (p *coreProcess) stop() {
	if p != nil {
		if p.job != 0 {
			windows.CloseHandle(p.job)
			p.job = 0
		}
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
		}
	}
}

func (p *coreProcess) dead() bool {
	if p == nil {
		return true
	}
	select {
	case e := <-p.done:
		p.done <- e
		return true
	default:
		return false
	}
}
func containChild(pid int) (windows.Handle, error) {
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return 0, e
	}
	bad := func(e error) (windows.Handle, error) { windows.CloseHandle(job); return 0, e }
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		return bad(e)
	}
	process, e := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if e != nil {
		return bad(e)
	}
	defer windows.CloseHandle(process)
	if e = windows.AssignProcessToJobObject(job, process); e != nil {
		return bad(e)
	}
	snapshot, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if e != nil {
		return bad(e)
	}
	defer windows.CloseHandle(snapshot)
	var thread windows.ThreadEntry32
	thread.Size = uint32(unsafe.Sizeof(thread))
	for e = windows.Thread32First(snapshot, &thread); e == nil; e = windows.Thread32Next(snapshot, &thread) {
		if thread.OwnerProcessID != uint32(pid) {
			continue
		}
		h, e := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, thread.ThreadID)
		if e != nil {
			return bad(e)
		}
		_, e = windows.ResumeThread(h)
		windows.CloseHandle(h)
		if e != nil {
			return bad(e)
		}
		return job, nil
	}
	return bad(errors.New("child_thread_not_found"))
}

type engineService struct{ sid string }

func (e *engineService) Execute(_ []string, requests <-chan svc.ChangeRequest, updates chan<- svc.Status) (bool, uint32) {
	updates <- svc.Status{State: svc.StartPending}
	c, err := readConfig(e.sid)
	if err != nil {
		writeStatus(e.sid, Status{State: "error", Message: "Настройки VPN повреждены. Нажмите «Включить» для восстановления."})
		return false, 1
	}
	for i, v := range c.LAN {
		p, _ := netip.ParsePrefix(v)
		c.LAN[i] = p.Masked().String()
	}
	sort.Strings(c.LAN)
	st := Status{State: "connecting", Message: "Включаю защиту сети…"}
	var old Status
	if b, x := os.ReadFile(filepath.Join(dataDir(e.sid), "status.json")); x == nil {
		_ = json.Unmarshal(b, &old)
		if !c.ResetRating {
			st.Ranking = old.Ranking
		}
	}
	if err = updateGuard(c, 0); err != nil {
		st.State = "error"
		st.Message = "Не удалось включить защиту Windows: " + err.Error()
		writeStatus(e.sid, st)
		return false, 2
	}
	st.Protected = true
	writeStatus(e.sid, st)
	currentBridge, err = newPacketBridge()
	if err != nil {
		st.State = "error"
		st.Message = "Не удалось запустить локальный транспорт. Повторю после перезапуска службы."
		writeStatus(e.sid, st)
		return false, 3
	}
	defer currentBridge.close()
	server, err := diagnosticServer(e.sid)
	if err != nil {
		return false, 4
	}
	defer server.Close()
	updates <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	var core *coreProcess
	defer func() { core.stop() }()
	needRank := len(st.Ranking) == 0
	desired := choose(c, st.Ranking)
	failures := 0
	lastReset := time.Now()
	lastNetworkCheck := time.Now()
	initialApps := routingApplications(c.Policy.Applications)
	sort.Strings(initialApps)
	lastApplications := strings.Join(initialApps, "\n")
	tick := func() time.Duration {
		if !bridgeWork.TryLock() {
			return 2 * time.Second
		}
		defer bridgeWork.Unlock()

		if core != nil && time.Since(lastNetworkCheck) > 30*time.Second {
			lastNetworkCheck = time.Now()
			changed := false
			if lan, x := physicalLAN(); x == nil && strings.Join(lan, ",") != strings.Join(c.LAN, ",") {
				c.LAN = lan
				changed = true
			}
			apps := routingApplications(c.Policy.Applications)
			sort.Strings(apps)
			signature := strings.Join(apps, "\n")
			if lastApplications != "" && signature != lastApplications {
				changed = true
			}
			lastApplications = signature
			if changed {
				core.stop()
				core = nil
				currentBridge.resetAllCarriers()
			}
		}
		if desired == "" {
			desired = transports[0].ID
			needRank = true
		}
		if core == nil {
			st.State = "connecting"
			st.Message = "Подключаю HSVDS → Эстония…"
			st.Route = desired
			writeStatus(e.sid, st)
			if err = updateGuard(c, 0); err == nil {
				_ = currentBridge.route(desired)
				core, err = startCore(c, "vpn", false)
			}
			if err != nil {
				st.Message = "Не удалось запустить ядро. Повторяю автоматически."
				writeStatus(e.sid, st)
				core = nil
				return 5 * time.Second
			}
			var luid uint64
			for i := 0; i < 30; i++ {
				if luid, err = tunnelLUID(); err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if err != nil {
				core.stop()
				core = nil
				currentBridge.resetAllCarriers()
				return 3 * time.Second
			}
			if err = updateGuard(c, luid); err != nil {
				core.stop()
				core = nil
				currentBridge.resetAllCarriers()
				st.Message = "Восстанавливаю защиту сетевого адаптера: " + err.Error()
				writeStatus(e.sid, st)
				return 3 * time.Second
			}
		}
		if needRank {
			st.Message = "Быстро проверяю доступные маршруты…"
			writeStatus(e.sid, st)
			st.Ranking = probeAll(st.Ranking)
			needRank = false
			c.ResetRating = false
			best := choose(c, st.Ranking)
			if best != "" {
				desired = best
			}
			_ = currentBridge.route(desired)
		}
		st.Route = desired
		if healthy(desired) {
			failures = 0
			st.State = "connected"
			st.Message = "Подключено через Эстонию. IP: 38.180.164.67."
			for i := range st.Ranking {
				if st.Ranking[i].ID == desired {
					st.Ranking[i].Good = true
				}
			}
		} else {
			failures++
			st.State = "recovering"
			st.Message = "Связь потеряна. Восстанавливаю автоматически; трафик защищён."
			if core.dead() {
				core.stop()
				core = nil
				currentBridge.resetAllCarriers()
				st.Restarts++
				return 2 * time.Second
			}
			if failures >= 2 {
				failures = 0
				for i := range st.Ranking {
					if st.Ranking[i].ID == desired {
						st.Ranking[i].Losses++
					}
				}
				next := following(c, st.Ranking, desired)
				if next != "" {
					desired = next
					_ = currentBridge.route(desired)
				} else if time.Since(lastReset) > 45*time.Second {
					for i := range st.Ranking {
						st.Ranking[i].Losses = 0
					}
					needRank = true
					lastReset = time.Now()
				}
				// Recreate a stale WG/SOCKS session under the persistent guard.
				// Selecting a different carrier alone can retain a dead association.
				core.stop()
				core = nil
				currentBridge.resetAllCarriers()
				st.State = "recovering"
				st.Message = "Пересоздаю соединение через резервный маршрут…"
				writeStatus(e.sid, st)
				return 100 * time.Millisecond
			}
		}
		writeStatus(e.sid, st)
		return 5 * time.Second
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case change := <-requests:
			switch change.Cmd {
			case svc.Interrogate:
				updates <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			case svc.Stop, svc.Shutdown:
				updates <- svc.Status{State: svc.StopPending}
				st.State = "protected"
				st.Message = "VPN остановлен. Защита сохранена до команды «Отключить»."
				writeStatus(e.sid, st)
				return false, 0
			case svc.Cmd(128):
				if next, x := readConfig(e.sid); x == nil {
					c = next
					needRank = c.ResetRating || len(st.Ranking) == 0
					if c.ResetRating {
						st.Ranking = nil
					}
					desired = choose(c, st.Ranking)
					st.State = "connecting"
					st.Message = "Применяю настройки и восстанавливаю соединение…"
					writeStatus(e.sid, st)
					core.stop()
					core = nil
					currentBridge.resetAllCarriers()
					timer.Reset(0)
				}
			}
		case <-timer.C:
			timer.Reset(tick())
		}
	}
}
func diagnosticServer(sid string) (*http.Server, error) {
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return nil, e
	}
	token := base64.RawURLEncoding.EncodeToString(key)
	if e := os.WriteFile(filepath.Join(dataDir(sid), "control.key"), []byte(token), 0600); e != nil {
		return nil, e
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:18559")
	if e != nil {
		return nil, e
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if r.Method != "POST" || r.URL.Path != "/diagnose" || r.URL.RawQuery != "" || r.Host != "127.0.0.1:18559" || r.Header.Get("Origin") != "" || subtle.ConstantTimeCompare([]byte(auth), []byte(token)) != 1 || r.ContentLength > 0 {
			http.Error(w, "denied", 403)
			return
		}
		deadline := time.Now().Add(30 * time.Second)
		for !bridgeWork.TryLock() {
			if time.Now().After(deadline) {
				http.Error(w, "busy", 409)
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
		defer bridgeWork.Unlock()
		old := currentBridge.currentRoute()
		defer currentBridge.route(old)
		routes := probeAll(nil)
		transfers := []TransferProbe{}
		packets := map[string][]PacketProbe{}
		for _, route := range routes {
			if !route.Good {
				continue
			}
			_ = currentBridge.route(route.ID)
			transfers = append(transfers, uploadProbe(route.ID))
			packets[route.ID] = udpPackets(routePort(route.ID))
		}
		_ = currentBridge.route(old)
		services := serviceProbes(routePort(old))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"routes": routes, "transfers": transfers, "packets": packets, "services": services})
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 180 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go server.Serve(listener)
	return server, nil
}
func managedService(m *mgr.Mgr) (*mgr.Service, error) {
	s, e := m.OpenService(serviceName)
	if e != nil {
		return nil, e
	}
	conf, e := s.Config()
	if e != nil {
		s.Close()
		return nil, e
	}
	exe, _ := os.Executable()
	if !strings.HasPrefix(strings.ToLower(conf.BinaryPathName), strings.ToLower("\""+exe+"\" service S-1-5-21-")) {
		s.Close()
		return nil, errors.New("service_ownership_mismatch")
	}
	return s, nil
}
func stopService(s *mgr.Service) error {
	status, e := s.Query()
	if e != nil {
		return e
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, e = s.Control(svc.Stop); e != nil {
		return e
	}
	for i := 0; i < 250; i++ {
		time.Sleep(100 * time.Millisecond)
		st, e := s.Query()
		if e != nil {
			return e
		}
		if st.State == svc.Stopped {
			return nil
		}
	}
	return errors.New("service_stop_timeout")
}
func control(command, sid string) error {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := managedService(m)
	if e != nil && !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return e
	}
	if command == "install" {
		if !sidPattern.MatchString(sid) {
			return errors.New("invalid_owner")
		}
		if _, e = readConfig(sid); e != nil {
			return e
		}
		if s == nil {
			exe, _ := os.Executable()
			s, e = m.CreateService(serviceName, exe, mgr.Config{DisplayName: "Evgenium Network VPN", Description: "Evgenium VPN and persistent traffic protection", StartType: mgr.StartAutomatic}, "service", sid)
			if e != nil {
				return e
			}
			_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 3 * time.Second}, {Type: mgr.ServiceRestart, Delay: 10 * time.Second}}, 60)
		}
		defer s.Close()
		cfg, e := s.Config()
		if e != nil {
			return e
		}
		if !strings.HasSuffix(cfg.BinaryPathName, " "+sid) {
			return errors.New("VPN уже используется другой учётной записью Windows.")
		}
		state, e := s.Query()
		if e != nil {
			return e
		}
		if state.State == svc.Running {
			_, e = s.Control(svc.Cmd(128))
			return e
		}
		return s.Start()
	}
	if s != nil {
		defer s.Close()
		token, e := windows.GetCurrentProcessToken().GetTokenUser()
		if e != nil {
			return e
		}
		conf, e := s.Config()
		if e != nil {
			return e
		}
		if command != "uninstall-all" && !strings.HasSuffix(conf.BinaryPathName, " "+token.User.Sid.String()) {
			return errors.New("VPN запущен другой учётной записью Windows.")
		}
	}
	switch command {
	case "remove", "uninstall-all":
		if s != nil {
			if e = stopService(s); e != nil {
				return e
			}
			if e = s.Delete(); e != nil {
				return e
			}
		}
		if e = removeGuard(); e != nil {
			return e
		}
		if command == "uninstall-all" {
			// Wintun refuses to remove a package used by another application's
			// adapters. Never force-remove or enumerate foreign adapters.
			exe, _ := os.Executable()
			dll := windows.NewLazyDLL(filepath.Join(filepath.Dir(exe), "wintun.dll"))
			proc := dll.NewProc("WintunDeleteDriver")
			if proc.Find() == nil {
				_, _, _ = proc.Call()
			}
		}
		return nil
	case "upgrade-stop":
		if s != nil {
			return stopService(s)
		}
		return nil
	case "upgrade-start":
		if s != nil {
			st, e := s.Query()
			if e != nil {
				return e
			}
			if st.State != svc.Running {
				return s.Start()
			}
		}
		return nil
	case "reload":
		if s == nil {
			return errors.New("VPN не запущен")
		}
		_, e = s.Control(svc.Cmd(128))
		return e
	}
	return errors.New("unknown_operation")
}
func run() error {
	args := os.Args[1:]
	if len(args) == 0 {
		return errors.New("internal_engine")
	}
	switch args[0] {
	case "keygen":
		k, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"private_key": base64.StdEncoding.EncodeToString(k.Bytes()), "public_key": base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())})
	case "pubkey":
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 128))
		if e != nil {
			return e
		}
		raw, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if e != nil {
			return e
		}
		key, e := ecdh.X25519().NewPrivateKey(raw)
		if e != nil {
			return e
		}
		fmt.Println(base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()))
		return nil
	case "validate", "render":
		var c Config
		if e := json.NewDecoder(io.LimitReader(os.Stdin, 128*1024)).Decode(&c); e != nil {
			return e
		}
		if args[0] == "render" {
			b, e := marshalCore(c, "vpn", false)
			if e != nil {
				return e
			}
			_, e = os.Stdout.Write(b)
			return e
		}
		return validateConfig(c)
	case "validate-exception":
		var value struct {
			Category string `json:"category"`
			Value    string `json:"value"`
		}
		if err := json.NewDecoder(io.LimitReader(os.Stdin, 4096)).Decode(&value); err != nil {
			return err
		}
		return validateException(value.Category, value.Value)
	case "normalize":
		if len(args) != 3 {
			return errors.New("arguments")
		}
		return validateException(args[1], args[2])
	case "service":
		if len(args) != 2 || !sidPattern.MatchString(args[1]) {
			return errors.New("invalid_owner")
		}
		return svc.Run(serviceName, &engineService{sid: args[1]})
	case "install":
		if len(args) != 2 {
			return errors.New("invalid_owner")
		}
		return control(args[0], args[1])
	case "remove", "uninstall-all", "upgrade-stop", "upgrade-start", "reload":
		return control(args[0], "")
	case "diagnose":
		if len(args) != 2 || !sidPattern.MatchString(args[1]) {
			return errors.New("invalid_owner")
		}
		token, e := os.ReadFile(filepath.Join(dataDir(args[1]), "control.key"))
		if e != nil {
			return e
		}
		request, _ := http.NewRequest("POST", "http://127.0.0.1:18559/diagnose", nil)
		request.Header.Set("Authorization", "Bearer "+string(token))
		client := &http.Client{Timeout: 180 * time.Second, Transport: &http.Transport{Proxy: nil}}
		response, e := client.Do(request)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return fmt.Errorf("diagnostic_http_%d", response.StatusCode)
		}
		_, e = io.Copy(os.Stdout, io.LimitReader(response.Body, 128*1024))
		return e
	case "routes":
		return json.NewEncoder(os.Stdout).Encode(transports)
	case "selftest":
		fmt.Println("Evgenium engine " + version)
		return nil
	}
	return errors.New("unknown_operation")
}
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctx
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
