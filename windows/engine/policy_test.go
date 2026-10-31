package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func fixture() Config {
	return Config{Schema: 1, Owner: "S-1-5-21-1-2-3-1001", PrivateKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", Profile: Profile{Schema: 1, PublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", Endpoint: "195.209.211.163:51820", Address: "10.78.0.2/32", MTU: 1280}, Policy: Policy{Route: "auto"}, LAN: []string{"192.168.0.0/24"}}
}
func TestRejectInjectedPolicy(t *testing.T) {
	for cat, values := range map[string][]string{"applications": {"cmd.exe\nanything", "../bad", "evil.exe;calc"}, "networks": {"https://site.com/x", "0.0.0.0/0", "10.78.0.2", "198.18.254.0/24", "bad..com"}, "ports": {"tcp:0:out", "udp:53:both", "tcp:65536:out", "udp:12:weird"}, "dns": {"127.0.0.1", "0.0.0.0", "1.1.1.1;calc"}} {
		for _, v := range values {
			if validateException(cat, v) == nil {
				t.Errorf("accepted %s %q", cat, v)
			}
		}
	}
}
func TestPolicyAndDNSIsolation(t *testing.T) {
	c := fixture()
	c.Policy.Applications = []string{`C:\Apps\client.exe`}
	c.Policy.Networks = []string{"example.com", "=exact.example.com", "203.0.113.9"}
	c.Policy.Ports = []string{"tcp:443:out", "udp:25565:in"}
	c.Policy.DNS = []string{"192.168.0.1"}
	b, e := marshalCore(c, "ru-wg", false)
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	if !strings.Contains(s, "autoSystemRoutingTable") || strings.Contains(s, "Waydroid") {
		t.Fatal("wrong platform")
	}
	var v map[string]any
	json.Unmarshal(b, &v)
	rules := v["routing"].(map[string]any)["rules"].([]any)
	dnsAt, appAt := -1, -1
	for i, r := range rules {
		rule := r.(map[string]any)
		if rule["outboundTag"] == "dns-out" {
			dnsAt = i
		}
		if _, ok := rule["process"]; ok {
			appAt = i
		}
	}
	if dnsAt < 0 || appAt <= dnsAt {
		t.Fatal("application can bypass DNS isolation")
	}
	last := rules[len(rules)-1].(map[string]any)
	if last["outboundTag"] != "ru-wg" {
		t.Fatal("unmatched traffic can bypass VPN")
	}
}
func TestBaseToggles(t *testing.T) {
	c := fixture()
	c.Policy.Disabled = []string{"networks:lan", "networks:linklocal", "ports:discovery"}
	b, e := marshalCore(c, "ru-wg", false)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"192.168.0.0/24", "169.254.0.0/16", "5353"} {
		if strings.Contains(string(b), s) {
			t.Fatal("disabled base survives", s)
		}
	}
}
func TestKeyAndServerValidation(t *testing.T) {
	for _, bad := range []string{"evil:51820", "195.209.211.163:22"} {
		c := fixture()
		c.Profile.Endpoint = bad
		if validateConfig(c) == nil {
			t.Fatal("wrong server accepted")
		}
	}
	c := fixture()
	c.PrivateKey = strings.Repeat("A", 43) + "="
	if validateConfig(c) == nil {
		t.Fatal("zero key")
	}
}
