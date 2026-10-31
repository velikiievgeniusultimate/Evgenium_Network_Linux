package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

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
func healthy(id string) bool {
	b, e := request(routePort(id), "https://api.ipify.org", 128)
	return e == nil && strings.TrimSpace(string(b)) == "38.180.164.67"
}
func probe(t Transport) Rank {
	r := Rank{ID: t.ID, Label: t.Label}
	start := time.Now()
	if !healthy(t.ID) {
		r.Error = "Выход в Эстонии не подтверждён"
		return r
	}
	r.RTT = time.Since(start).Milliseconds()
	start = time.Now()
	b, e := request(routePort(t.ID), "https://speed.cloudflare.com/__down?bytes=262144", 262144)
	if e == nil && len(b) == 262144 {
		r.Mbps = float64(len(b)) * 8 / time.Since(start).Seconds() / 1e6
	}
	r.Good = true
	return r
}
func probeAll(previous []Rank) []Rank {
	result := make([]Rank, len(transports))
	var group sync.WaitGroup
	for i, t := range transports {
		group.Add(1)
		go func(i int, t Transport) {
			defer group.Done()
			result[i] = probe(t)
			for _, p := range previous {
				if p.ID == t.ID {
					result[i].Losses = p.Losses
				}
			}
		}(i, t)
	}
	group.Wait()
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Good != result[j].Good {
			return result[i].Good
		}
		return result[i].Mbps > result[j].Mbps
	})
	return result
}
func choose(c Config, ranks []Rank) string {
	for _, r := range ranks {
		if r.Losses >= 3 {
			continue
		}
		if c.Policy.Route != "" && c.Policy.Route != "auto" && r.ID != c.Policy.Route {
			continue
		}
		if r.Good {
			return r.ID
		}
	}
	return ""
}

type coreProcess struct {
	cmd  *exec.Cmd
	done chan error
	log  *os.File
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
	if st, e := os.Stat(logPath); e == nil && st.Size() > 1024*1024 {
		_ = os.Remove(logPath + ".1")
		_ = os.Rename(logPath, logPath+".1")
	}
	f, e := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	cmd := exec.Command(filepath.Join(filepath.Dir(exe), "xray.exe"), "run", "-config", path)
	cmd.Dir = filepath.Dir(exe)
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if e = cmd.Start(); e != nil {
		f.Close()
		return nil, e
	}
	p := &coreProcess{cmd: cmd, done: make(chan error, 1), log: f}
	go func() { p.done <- cmd.Wait(); f.Close() }()
	return p, nil
}
func (p *coreProcess) stop() {
	if p != nil {
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
		}
	}
}

type engineService struct{ sid string }

func (e *engineService) Execute(_ []string, requests <-chan svc.ChangeRequest, updates chan<- svc.Status) (bool, uint32) {
	updates <- svc.Status{State: svc.StartPending}
	c, err := readConfig(e.sid)
	if err != nil {
		writeStatus(e.sid, Status{State: "error", Message: "Настройки VPN повреждены. Нажмите «Восстановить»."})
		return false, 1
	}
	st := Status{State: "connecting", Message: "Включаю защиту сети…"}
	var old Status
	if b, err := os.ReadFile(filepath.Join(dataDir(e.sid), "status.json")); err == nil {
		_ = json.Unmarshal(b, &old)
		if !c.ResetRating {
			st.Ranking = old.Ranking
		}
	}
	if err = updateGuard(c, 0); err != nil {
		st.State = "error"
		st.Message = "Не удалось включить защиту Windows."
		writeStatus(e.sid, st)
		return false, 2
	}
	st.Protected = true
	writeStatus(e.sid, st)
	updates <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	var core *coreProcess
	defer func() { core.stop() }()
	interval := time.NewTimer(0)
	defer interval.Stop()
	needRank := len(st.Ranking) == 0
	desired := ""
	failures := 0
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
					if needRank {
						st.Ranking = nil
					}
					desired = ""
					core.stop()
					core = nil
					interval.Reset(0)
				}
			}
		case <-interval.C:
			if core == nil {
				if desired == "" {
					desired = choose(c, st.Ranking)
				}
				if desired == "" {
					desired = transports[0].ID
					needRank = true
				}
				st.State = "connecting"
				st.Message = "Подключаю HSVDS → Эстония…"
				st.Route = desired
				writeStatus(e.sid, st)
				if err = updateGuard(c, 0); err == nil {
					core, err = startCore(c, desired, false)
				}
				if err != nil {
					st.Message = "Не удалось запустить сетевое ядро. Повторяю автоматически."
					writeStatus(e.sid, st)
					core = nil
					interval.Reset(5 * time.Second)
					continue
				}
				var luid uint64
				for i := 0; i < 30; i++ {
					if luid, err = tunnelLUID(); err == nil {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				if err != nil || updateGuard(c, luid) != nil {
					core.stop()
					core = nil
					st.Message = "Сетевой адаптер ещё не готов. Восстанавливаю автоматически."
					writeStatus(e.sid, st)
					interval.Reset(3 * time.Second)
					continue
				}
				time.Sleep(300 * time.Millisecond)
				if needRank {
					st.Message = "Быстро проверяю доступные маршруты…"
					writeStatus(e.sid, st)
					st.Ranking = probeAll(st.Ranking)
					needRank = false
					c.ResetRating = false
					_ = writeJSON(filepath.Join(dataDir(c.Owner), "engine.json"), c)
					best := choose(c, st.Ranking)
					if best != "" && best != desired {
						core.stop()
						core = nil
						desired = best
						interval.Reset(0)
						continue
					}
				}
			}
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
				if failures >= 2 {
					failures = 0
					for i := range st.Ranking {
						if st.Ranking[i].ID == desired {
							st.Ranking[i].Losses++
							st.Ranking[i].Good = false
						}
					}
					next := choose(c, st.Ranking)
					core.stop()
					core = nil
					st.Restarts++
					if next != "" {
						desired = next
					} else {
						desired = ""
						needRank = true
					}
				}
			}
			writeStatus(e.sid, st)
			interval.Reset(5 * time.Second)
		}
	}
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
		return removeGuard()
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
	case "validate":
		var c Config
		if e := json.NewDecoder(io.LimitReader(os.Stdin, 128*1024)).Decode(&c); e != nil {
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
		var st Status
		b, err := os.ReadFile(filepath.Join(dataDir(args[1]), "status.json"))
		if err != nil {
			return err
		}
		if err = json.Unmarshal(b, &st); err != nil {
			return err
		}
		routes := probeAll(st.Ranking)
		transfers := []TransferProbe{}
		packets := map[string][]PacketProbe{}
		for _, r := range routes {
			if !r.Good {
				continue
			}
			transfers = append(transfers, uploadProbe(r.ID))
			packets[r.ID] = udpPackets(routePort(r.ID))
		}
		services := []ServiceProbe{}
		if st.Route != "" {
			services = serviceProbes(routePort(st.Route))
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"routes": routes, "transfers": transfers, "packets": packets, "services": services})
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
