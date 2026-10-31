package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type Policy struct {
	Applications []string `json:"applications"`
	Networks     []string `json:"networks"`
	Ports        []string `json:"ports"`
	DNS          []string `json:"dns"`
	Disabled     []string `json:"disabled_base"`
	Route        string   `json:"route"`
}
type Profile struct {
	Schema    int    `json:"schema"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"`
	Address   string `json:"address"`
	MTU       int    `json:"mtu"`
}
type Config struct {
	Schema      int      `json:"schema"`
	Owner       string   `json:"owner"`
	PrivateKey  string   `json:"private_key"`
	Profile     Profile  `json:"profile"`
	Policy      Policy   `json:"policy"`
	LAN         []string `json:"lan"`
	ResetRating bool     `json:"reset_rating"`
}
type Transport struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Port      int    `json:"port"`
	Network   string `json:"network"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
	UUID      string `json:"uuid"`
}

// Added transports only encapsulate authenticated WireGuard packets. They never
// provide unrestricted server-side egress or replace per-device authentication.
var transports = []Transport{
	{ID: "ru-wg", Label: "HSVDS → Эстония · UDP"},
	{ID: "ru-tcp", Label: "HSVDS → Эстония · Reality TCP", Network: "raw", Port: 24580, PublicKey: "sBLhmMMiyFypa_ZD847la1nxurq5XvdOrOMqGaFfEyk", ShortID: "ca7df665eb918089", UUID: "df22abb5-c348-48d6-9b74-5991919367c2"},
	{ID: "ru-xhttp", Label: "HSVDS → Эстония · Reality XHTTP", Network: "xhttp", Port: 24581, PublicKey: "sBLhmMMiyFypa_ZD847la1nxurq5XvdOrOMqGaFfEyk", ShortID: "ca7df665eb918089", UUID: "df22abb5-c348-48d6-9b74-5991919367c2"},
}
var sidPattern = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$`)
var portPattern = regexp.MustCompile(`^(tcp|udp|both):([0-9]{1,5}):(out|in|both)$`)
var processPattern = regexp.MustCompile(`^[^<>"|?*\x00-\x1f]+$`)
var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

func validKey(s string) bool {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != 32 {
		return false
	}
	var any byte
	for _, v := range b {
		any |= v
	}
	return any != 0 && base64.StdEncoding.EncodeToString(b) == s
}
func (p Policy) base(id string) bool {
	for _, s := range p.Disabled {
		if s == id {
			return false
		}
	}
	return true
}
func validateConfig(c Config) error {
	if c.Schema != 1 || !sidPattern.MatchString(c.Owner) || !validKey(c.PrivateKey) || !validKey(c.Profile.PublicKey) || c.Profile.Schema != 1 || c.Profile.Endpoint != "195.209.211.163:51820" || c.Profile.MTU != 1280 {
		return errors.New("invalid_engine_profile")
	}
	ip, e := netip.ParsePrefix(c.Profile.Address)
	if e != nil || ip.Bits() != 32 || !netip.MustParsePrefix("10.78.0.0/24").Contains(ip.Addr()) {
		return errors.New("invalid_device_address")
	}
	for cat, values := range map[string][]string{"applications": c.Policy.Applications, "networks": c.Policy.Networks, "ports": c.Policy.Ports, "dns": c.Policy.DNS} {
		if len(values) > 256 {
			return errors.New("too_many_exceptions")
		}
		for _, s := range values {
			if e := validateException(cat, s); e != nil {
				return e
			}
		}
	}
	for _, s := range c.LAN {
		p, e := netip.ParsePrefix(s)
		if e != nil || !p.Addr().Is4() {
			return errors.New("invalid_lan")
		}
	}
	if c.Policy.Route != "" && c.Policy.Route != "auto" {
		found := false
		for _, t := range transports {
			found = found || t.ID == c.Policy.Route
		}
		if !found {
			return errors.New("unknown_route")
		}
	}
	return nil
}
func validateException(cat, s string) error {
	if len(s) == 0 || len(s) > 512 || strings.IndexFunc(s, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return errors.New("invalid_exception")
	}
	switch cat {
	case "applications":
		if !processPattern.MatchString(s) || !strings.HasSuffix(strings.ToLower(s), ".exe") {
			return errors.New("Укажите имя .exe или полный путь к приложению.")
		}
	case "networks":
		if !strings.Contains(s, "/") {
			if ip, e := netip.ParseAddr(s); e == nil {
				if !ip.Is4() {
					return errors.New("Требуется IPv4-адрес.")
				}
				return validateException(cat, ip.String()+"/32")
			}
		}
		if p, e := netip.ParsePrefix(s); e == nil {
			if !p.Addr().Is4() {
				return errors.New("Требуется IPv4-подсеть.")
			}
			for _, reserved := range []string{"10.78.0.0/24", "198.18.254.0/30"} {
				if p.Overlaps(netip.MustParsePrefix(reserved)) {
					return errors.New("Подсеть пересекается со служебной сетью VPN.")
				}
			}
			return nil
		}
		domain := strings.TrimPrefix(s, "=")
		if !domainPattern.MatchString(domain) || len(domain) > 253 || strings.Contains(domain, "..") || !strings.Contains(domain, ".") {
			return errors.New("Укажите домен без https:// и пути.")
		}
	case "ports":
		m := portPattern.FindStringSubmatch(s)
		if m == nil {
			return errors.New("Формат: tcp:443:out, udp:25565:in или both:25565:both.")
		}
		n, _ := strconv.Atoi(m[2])
		if n < 1 || n > 65535 || n == 53 {
			return errors.New("Порт должен быть 1–65535; DNS задаётся отдельно.")
		}
	case "dns":
		ip, e := netip.ParseAddr(s)
		if e != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			return errors.New("Укажите адрес внешнего или домашнего DNS-сервера.")
		}
	default:
		return errors.New("unknown_category")
	}
	return nil
}

type obj = map[string]any

func coreConfig(c Config, selected string, probeOnly bool) (map[string]any, error) {
	if e := validateConfig(c); e != nil {
		return nil, e
	}
	inbounds := []any{}
	outbounds := []any{}
	rules := []any{}
	for i, t := range transports {
		check := "check-" + t.ID
		inbounds = append(inbounds, obj{"tag": check, "listen": "127.0.0.1", "port": 18554 + i, "protocol": "socks", "settings": obj{"auth": "noauth", "udp": true}})
		rules = append(rules, obj{"type": "field", "inboundTag": []string{check}, "outboundTag": "vpn"})
		if t.Network != "" {
			inbound := "carrier-in-" + t.ID
			inbounds = append(inbounds, obj{"tag": inbound, "listen": "127.0.0.1", "port": 18570 + i, "protocol": "socks", "settings": obj{"auth": "noauth", "udp": true}})
			rules = append(rules, obj{"type": "field", "inboundTag": []string{inbound}, "outboundTag": "carrier-" + t.ID})
			stream := obj{"network": t.Network, "security": "reality", "realitySettings": obj{"serverName": "www.yandex.ru", "fingerprint": "chrome", "password": t.PublicKey, "shortId": t.ShortID}}
			if t.Network == "xhttp" {
				stream["xhttpSettings"] = obj{"path": "/evgenium-wg", "mode": "auto"}
			}
			outbounds = append(outbounds, obj{"tag": "carrier-" + t.ID, "protocol": "vless", "settings": obj{"vnext": []any{obj{"address": "195.209.211.163", "port": t.Port, "users": []any{obj{"id": t.UUID, "encryption": "none"}}}}}, "streamSettings": stream})
		}
	}
	outbounds = append(outbounds, obj{"tag": "vpn", "protocol": "wireguard", "settings": obj{"secretKey": c.PrivateKey, "address": []string{c.Profile.Address}, "mtu": 1280, "noKernelTun": true, "peers": []any{obj{"endpoint": c.Profile.Endpoint, "publicKey": c.Profile.PublicKey, "allowedIPs": []string{"0.0.0.0/0", "::/0"}, "keepAlive": 25}}}, "streamSettings": obj{"sockopt": obj{"dialerProxy": "wg-bridge"}}}, obj{"tag": "wg-bridge", "protocol": "socks", "settings": obj{"servers": []any{obj{"address": "127.0.0.1", "port": 18560}}}, "streamSettings": obj{"sockopt": obj{"interface": loopbackName()}}})
	selected = "vpn"
	outbounds = append(outbounds, obj{"tag": "direct", "protocol": "freedom", "settings": obj{"domainStrategy": "UseIPv4"}}, obj{"tag": "dns-out", "protocol": "dns"}, obj{"tag": "block", "protocol": "blackhole"})
	if !probeOnly {
		inbounds = append(inbounds, obj{"tag": "tun", "protocol": "tun", "settings": obj{"name": "EvgeniumTunnel", "mtu": 1280, "gateway": []string{"198.18.254.1/30", "fd78:6576:ff::1/126"}, "dns": []string{"198.18.254.2"}, "autoSystemRoutingTable": []string{"0.0.0.0/0", "::/0"}, "autoOutboundsInterface": "auto"}, "sniffing": obj{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}})
	}
	// Resolver requests use VPN even when an application has a direct exception.
	rules = append(rules, obj{"type": "field", "inboundTag": []string{"dns-engine"}, "outboundTag": selected})
	if len(c.Policy.DNS) > 0 {
		rules = append(rules, obj{"type": "field", "ip": c.Policy.DNS, "port": "53", "outboundTag": "direct"})
	}
	rules = append(rules, obj{"type": "field", "port": "53", "outboundTag": "dns-out"})
	if len(c.Policy.Applications) > 0 {
		rules = append(rules, obj{"type": "field", "process": c.Policy.Applications, "inboundTag": []string{"tun"}, "outboundTag": "direct"})
	}
	networks := []string{}
	domains := []string{}
	for _, s := range c.Policy.Networks {
		if p, e := netip.ParsePrefix(s); e == nil {
			networks = append(networks, p.Masked().String())
		} else if ip, e := netip.ParseAddr(s); e == nil {
			networks = append(networks, ip.String()+"/32")
		} else {
			prefix := "domain:"
			if strings.HasPrefix(s, "=") {
				prefix = "full:"
				s = s[1:]
			}
			domains = append(domains, prefix+s)
		}
	}
	if c.Policy.base("networks:lan") {
		for _, s := range c.LAN {
			p, _ := netip.ParsePrefix(s)
			if !p.Overlaps(netip.MustParsePrefix("10.78.0.0/24")) && !p.Overlaps(netip.MustParsePrefix("198.18.254.0/30")) {
				networks = append(networks, s)
			}
		}
	}
	if c.Policy.base("networks:linklocal") {
		networks = append(networks, "169.254.0.0/16")
	}
	if len(networks) > 0 {
		rules = append(rules, obj{"type": "field", "ip": networks, "inboundTag": []string{"tun"}, "outboundTag": "direct"})
	}
	if len(domains) > 0 {
		rules = append(rules, obj{"type": "field", "domain": domains, "inboundTag": []string{"tun"}, "outboundTag": "direct"})
	}
	for _, s := range c.Policy.Ports {
		m := portPattern.FindStringSubmatch(s)
		net := "tcp,udp"
		if m[1] != "both" {
			net = m[1]
		}
		if m[3] != "in" {
			rules = append(rules, obj{"type": "field", "network": net, "port": m[2], "outboundTag": "direct"})
		}
		if m[3] != "out" {
			rules = append(rules, obj{"type": "field", "network": net, "sourcePort": m[2], "outboundTag": "direct"})
		}
	}
	if c.Policy.base("ports:discovery") {
		rules = append(rules, obj{"type": "field", "network": "udp", "port": "5353,5355,1900", "ip": []string{"224.0.0.0/4", "255.255.255.255/32"}, "outboundTag": "direct"})
	}
	rules = append(rules, obj{"type": "field", "inboundTag": []string{"tun"}, "outboundTag": selected})
	return obj{"log": obj{"loglevel": "warning", "access": "none"}, "inbounds": inbounds, "outbounds": outbounds, "dns": obj{"servers": []string{"1.1.1.1", "9.9.9.9"}, "queryStrategy": "UseIPv4", "tag": "dns-engine"}, "routing": obj{"domainStrategy": "AsIs", "rules": rules}}, nil
}
func marshalCore(c Config, route string, probe bool) ([]byte, error) {
	v, e := coreConfig(c, route, probe)
	if e != nil {
		return nil, e
	}
	return json.MarshalIndent(v, "", "  ")
}
func routePort(id string) int {
	for i, t := range transports {
		if t.ID == id {
			return 18554 + i
		}
	}
	return 0
}
func exceptionDescription(cat, value string) string {
	if e := validateException(cat, value); e != nil {
		return e.Error()
	}
	return fmt.Sprintf("%s: %s", cat, value)
}
