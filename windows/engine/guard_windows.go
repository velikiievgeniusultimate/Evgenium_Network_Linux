package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

var provider = wf.ProviderID(windows.GUID{Data1: 0x1ed82050, Data2: 0x74e7, Data3: 0x42ac, Data4: [8]byte{0x91, 0x64, 0x45, 0x56, 0x47, 0x57, 0x49, 0x4e}})
var policyLayer = wf.SublayerID(windows.GUID{Data1: 0x1ed82051, Data2: 0x74e7, Data3: 0x42ac, Data4: [8]byte{0x91, 0x64, 0x45, 0x56, 0x47, 0x57, 0x49, 0x4e}})
var barrierLayer = wf.SublayerID(windows.GUID{Data1: 0x1ed82052, Data2: 0x74e7, Data3: 0x42ac, Data4: [8]byte{0x91, 0x64, 0x45, 0x56, 0x47, 0x57, 0x49, 0x4e}})

func ruleID(name string) wf.RuleID {
	b := sha256.Sum256([]byte("EvgeniumNetwork/" + name))
	return *(*wf.RuleID)(unsafe.Pointer(&b[0]))
}
func addRule(s *wf.Session, sub wf.SublayerID, name string, layer wf.LayerID, weight uint64, action wf.Action, conditions ...*wf.Match) error {
	return s.AddRule(&wf.Rule{ID: ruleID(sub.String() + "/" + layer.String() + "/" + name), Name: "Evgenium Network: " + name, Layer: layer, Sublayer: sub, Provider: provider, Weight: weight, Action: action, Persistent: true, Conditions: conditions})
}
func removeRules(s *wf.Session, sub wf.SublayerID) error {
	rules, e := s.Rules()
	if e != nil {
		return e
	}
	for _, r := range rules {
		if r.Provider == provider && r.Sublayer == sub {
			if e := s.DeleteRule(r.ID); e != nil {
				return e
			}
		}
	}
	return nil
}
func ensureObjects(s *wf.Session) error {
	providers, e := s.Providers()
	if e != nil {
		return e
	}
	found := false
	for _, p := range providers {
		found = found || p.ID == provider
	}
	if !found {
		if e = s.AddProvider(&wf.Provider{ID: provider, Name: "Evgenium Network", Persistent: true}); e != nil {
			return e
		}
	}
	layers, e := s.Sublayers()
	if e != nil {
		return e
	}
	for _, id := range []wf.SublayerID{policyLayer, barrierLayer} {
		found = false
		for _, v := range layers {
			found = found || v.ID == id
		}
		if !found {
			if e = s.AddSublayer(&wf.Sublayer{ID: id, Name: "Evgenium Network protection", Provider: provider, Weight: 0xffff, Persistent: true}); e != nil {
				return e
			}
		}
	}
	return nil
}
func appPaths(names []string) []string {
	found := map[string]bool{}
	wanted := map[string]bool{}
	for _, s := range names {
		if filepath.IsAbs(s) {
			if _, e := os.Stat(s); e == nil {
				found[s] = true
			}
		} else {
			wanted[strings.ToLower(s)] = true
		}
	}
	snapshot, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e == nil {
		defer windows.CloseHandle(snapshot)
		var entry windows.ProcessEntry32
		entry.Size = uint32(unsafe.Sizeof(entry))
		for e = windows.Process32First(snapshot, &entry); e == nil; e = windows.Process32Next(snapshot, &entry) {
			if !wanted[strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))] {
				continue
			}
			h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
			if e != nil {
				continue
			}
			buf := make([]uint16, 32768)
			size := uint32(len(buf))
			if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) == nil {
				found[windows.UTF16ToString(buf[:size])] = true
			}
			windows.CloseHandle(h)
		}
	}
	ret := []string{}
	for p := range found {
		ret = append(ret, p)
	}
	return ret
}
func fillGuard(s *wf.Session, sub wf.SublayerID, c Config, luid uint64) error {
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	core := filepath.Join(filepath.Dir(exe), "xray.exe")
	app, e := wf.AppID(core)
	if e != nil {
		return e
	}
	for _, layer := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6} {
		if e = addRule(s, sub, "block-physical", layer, 1, wf.ActionBlock); e != nil {
			return e
		}
		if e = addRule(s, sub, "engine", layer, 1000, wf.ActionPermit, &wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: app}); e != nil {
			return e
		}
		if e = addRule(s, sub, "loopback", layer, 990, wf.ActionPermit, &wf.Match{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: uint32(wf.ConditionFlagIsLoopback)}); e != nil {
			return e
		}
		if luid != 0 {
			if e = addRule(s, sub, "tunnel", layer, 980, wf.ActionPermit, &wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: luid}); e != nil {
				return e
			}
		}
		for i, p := range appPaths(c.Policy.Applications) {
			id, e := wf.AppID(p)
			if e != nil {
				continue
			}
			if e = addRule(s, sub, fmt.Sprintf("application-%d", i), layer, 900, wf.ActionPermit, &wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: id}); e != nil {
				return e
			}
		}
		for i, text := range c.Policy.Ports {
			m := portPattern.FindStringSubmatch(text)
			if m == nil || m[3] == "out" {
				continue
			}
			var port uint16
			fmt.Sscan(m[2], &port)
			conditions := []*wf.Match{{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: port}}
			if m[1] != "both" {
				proto := uint8(6)
				if m[1] == "udp" {
					proto = 17
				}
				conditions = append(conditions, &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: proto})
			}
			if e = addRule(s, sub, fmt.Sprintf("server-port-%d", i), layer, 900, wf.ActionPermit, conditions...); e != nil {
				return e
			}
		}
		if layer == wf.LayerALEAuthConnectV4 {
			for _, port := range []uint16{67, 68} {
				if e = addRule(s, sub, fmt.Sprintf("dhcp-%d", port), layer, 950, wf.ActionPermit, &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: uint8(17)}, &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: port}); e != nil {
					return e
				}
			}
			nets := []string{}
			for _, v := range c.Policy.Networks {
				if p, e := netip.ParsePrefix(v); e == nil {
					nets = append(nets, p.Masked().String())
				} else if ip, e := netip.ParseAddr(v); e == nil {
					nets = append(nets, ip.String()+"/32")
				}
			}
			if c.Policy.base("networks:lan") {
				nets = append(nets, c.LAN...)
			}
			if c.Policy.base("networks:linklocal") {
				nets = append(nets, "169.254.0.0/16")
			}
			for i, text := range nets {
				p, e := netip.ParsePrefix(text)
				if e != nil || !p.Addr().Is4() {
					continue
				}
				if p.Overlaps(netip.MustParsePrefix("10.78.0.0/24")) || p.Overlaps(netip.MustParsePrefix("198.18.254.0/30")) {
					continue
				}
				if e = addRule(s, sub, fmt.Sprintf("network-%d", i), layer, 900, wf.ActionPermit, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: p}); e != nil {
					return e
				}
			}
			for i, text := range c.Policy.DNS {
				ip, e := netip.ParseAddr(text)
				if e != nil {
					continue
				}
				if e = addRule(s, sub, fmt.Sprintf("dns-%d", i), layer, 910, wf.ActionPermit, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: ip}, &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(53)}); e != nil {
					return e
				}
			}
			if c.Policy.base("ports:discovery") {
				for _, port := range []uint16{1900, 5353, 5355} {
					if e = addRule(s, sub, fmt.Sprintf("discovery-%d", port), layer, 900, wf.ActionPermit, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("224.0.0.0/4")}, &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: port}, &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: uint8(17)}); e != nil {
						return e
					}
				}
			}
		}
		// Lower-priority catchall within our own sublayer. Other security software's
		// block rules are never overridden by these soft permits.
	}
	return nil
}
func updateGuard(c Config, luid uint64) error {
	s, e := wf.New(&wf.Options{Name: "Evgenium Network protection"})
	if e != nil {
		return e
	}
	defer s.Close()
	if e = ensureObjects(s); e != nil {
		return e
	}
	// A retained barrier makes replacement fail closed, including process death.
	// Never delete the previous policy until the barrier is fully installed.
	existing, e := s.Rules()
	if e != nil {
		return e
	}
	barrier := false
	for _, r := range existing {
		if r.Provider == provider && r.Sublayer == barrierLayer {
			barrier = true
		}
	}
	if !barrier {
		if e = fillGuard(s, barrierLayer, c, 0); e != nil {
			return e
		}
	}
	if e = removeRules(s, policyLayer); e != nil {
		return e
	}
	if e = fillGuard(s, policyLayer, c, luid); e != nil {
		return e
	}
	return removeRules(s, barrierLayer)
}
func removeGuard() error {
	s, e := wf.New(&wf.Options{Name: "Evgenium Network disconnect"})
	if e != nil {
		return e
	}
	defer s.Close()
	for _, sub := range []wf.SublayerID{barrierLayer, policyLayer} {
		if e = removeRules(s, sub); e != nil {
			return e
		}
		e = s.DeleteSublayer(sub)
		if e != nil && !errors.Is(e, windows.Errno(0x80320007)) {
			return e
		}
	}
	e = s.DeleteProvider(provider)
	if errors.Is(e, windows.Errno(0x80320005)) {
		return nil
	}
	return e
}
func tunnelLUID() (uint64, error) {
	alias, e := windows.UTF16PtrFromString("EvgeniumTunnel")
	if e != nil {
		return 0, e
	}
	var luid uint64
	r, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceAliasToLuid").Call(uintptr(unsafe.Pointer(alias)), uintptr(unsafe.Pointer(&luid)))
	if r != 0 {
		return 0, windows.Errno(r)
	}
	return luid, nil
}
