package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// One authenticated WG session survives carrier changes. All carriers return
// packets to the same local UDP association; no parallel WG identities can race.
type carrier struct {
	tcp    net.Conn
	udp    *net.UDPConn
	remote *net.UDPAddr
	direct bool
}
type packetBridge struct {
	mu          sync.Mutex
	listener    net.Listener
	udp         *net.UDPConn
	direct      *net.UDPConn
	peers       map[string]*carrier
	current     string
	client      *net.UDPAddr
	association net.Conn
	closed      bool
}

// Query the original default routes, explicitly excluding our TUN. A best-route
// lookup after activation would select the TUN again and recursively eat WG.
func physicalIndex() (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := `$ErrorActionPreference='Stop'; $r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.InterfaceAlias -ne 'EvgeniumTunnel' -and $_.State -eq 'Alive'} | Sort-Object @{Expression={$_.RouteMetric+$_.InterfaceMetric}} | Select-Object -First 1; if(!$r){exit 2}; [Console]::Write($r.InterfaceIndex)`
	cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, e := cmd.Output()
	if e != nil {
		return 0, fmt.Errorf("physical_route: %w", e)
	}
	index, e := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32)
	if e != nil || index == 0 {
		return 0, errors.New("physical_route_missing")
	}
	return uint32(index), nil
}
func nativeUDP() (*net.UDPConn, error) {
	index, e := physicalIndex()
	if e != nil {
		return nil, e
	}
	d := net.Dialer{Timeout: 3 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
		var result error
		e := raw.Control(func(fd uintptr) {
			result = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(bits.ReverseBytes32(index)))
		})
		if e != nil {
			return e
		}
		return result
	}}
	conn, e := d.Dial("udp4", "195.209.211.163:51820")
	if e != nil {
		return nil, e
	}
	return conn.(*net.UDPConn), nil
}
func newPacketBridge() (*packetBridge, error) {
	listener, e := net.Listen("tcp4", "127.0.0.1:18560")
	if e != nil {
		return nil, e
	}
	udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18560})
	if e != nil {
		listener.Close()
		return nil, e
	}
	b := &packetBridge{listener: listener, udp: udp, peers: map[string]*carrier{}, current: "ru-wg"}
	go b.accept()
	go b.receive()
	return b, nil
}
func (b *packetBridge) accept() {
	for {
		conn, e := b.listener.Accept()
		if e != nil {
			return
		}
		go b.associate(conn)
	}
}
func (b *packetBridge) associate(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	header := make([]byte, 2)
	if _, e := io.ReadFull(conn, header); e != nil || header[0] != 5 || header[1] < 1 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, e := io.ReadFull(conn, methods); e != nil {
		return
	}
	allowed := false
	for _, m := range methods {
		allowed = allowed || m == 0
	}
	if !allowed {
		return
	}
	conn.Write([]byte{5, 0})
	request := make([]byte, 4)
	if _, e := io.ReadFull(conn, request); e != nil || request[0] != 5 || request[1] != 3 {
		return
	}
	n := 4
	if request[3] == 4 {
		n = 16
	} else if request[3] != 1 {
		return
	}
	address := make([]byte, n+2)
	if _, e := io.ReadFull(conn, address); e != nil {
		return
	}
	// Publish the association before acknowledging it. The client can send its
	// first WG handshake on another CPU as soon as it receives the reply.
	b.mu.Lock()
	old := b.association
	b.association = conn
	b.client = nil
	b.mu.Unlock()
	if old != nil {
		old.Close()
	}
	conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0x48, 0x80})
	conn.SetDeadline(time.Time{})
	io.Copy(io.Discard, conn)
	b.mu.Lock()
	if b.association == conn {
		b.association = nil
		b.client = nil
	}
	b.mu.Unlock()
}
func (b *packetBridge) route(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errors.New("bridge_closed")
	}
	known := false
	for _, t := range transports {
		known = known || t.ID == id
	}
	if !known {
		return errors.New("unknown_carrier")
	}
	b.current = id
	return nil
}
func (b *packetBridge) currentRoute() string { b.mu.Lock(); defer b.mu.Unlock(); return b.current }
func (b *packetBridge) getCarrier(id string) (*carrier, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, net.ErrClosed
	}
	if c := b.peers[id]; c != nil {
		return c, nil
	}
	var c *carrier
	var e error
	if id == "ru-wg" {
		udp, err := nativeUDP()
		e = err
		if e == nil {
			c = &carrier{udp: udp, direct: true}
		}
	} else {
		index := -1
		for i, t := range transports {
			if t.ID == id {
				index = i
			}
		}
		if index < 0 {
			return nil, errors.New("unknown_carrier")
		}
		tcp, udp, remote, err := udpRelay(18570 + index)
		e = err
		if e == nil {
			c = &carrier{tcp: tcp, udp: udp, remote: remote}
		}
	}
	if e != nil {
		return nil, e
	}
	b.peers[id] = c
	go b.responses(id, c)
	return c, nil
}
func (b *packetBridge) receive() {
	buffer := make([]byte, 8192)
	for {
		n, peer, e := b.udp.ReadFromUDP(buffer)
		if e != nil {
			return
		}
		if n < 10 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 || buffer[3] != 1 || string(buffer[4:8]) != string([]byte{195, 209, 211, 163}) || binary.BigEndian.Uint16(buffer[8:10]) != 51820 || n-10 > 4096 {
			continue
		}
		b.mu.Lock()
		if b.association == nil {
			b.mu.Unlock()
			continue
		}
		b.client = peer
		id := b.current
		b.mu.Unlock()
		c, e := b.getCarrier(id)
		if e != nil {
			continue
		}
		if c.direct {
			_, e = c.udp.Write(buffer[10:n])
		} else {
			packet := append([]byte{0, 0, 0, 1, 127, 0, 0, 1, 0xca, 0x6c}, buffer[10:n]...)
			_, e = c.udp.WriteToUDP(packet, c.remote)
		}
		if e != nil {
			b.drop(id, c)
		}
	}
}
func (b *packetBridge) responses(id string, c *carrier) {
	buffer := make([]byte, 8192)
	for {
		n, e := c.udp.Read(buffer)
		if e != nil {
			b.drop(id, c)
			return
		}
		payload := buffer[:n]
		if !c.direct {
			if n < 10 || buffer[2] != 0 {
				continue
			}
			offset := 10
			if buffer[3] == 4 {
				offset = 22
			}
			if n < offset {
				continue
			}
			payload = buffer[offset:n]
		}
		if len(payload) > 4096 {
			continue
		}
		b.mu.Lock()
		peer := b.client
		closed := b.closed
		b.mu.Unlock()
		if peer != nil && !closed {
			packet := append([]byte{0, 0, 0, 1, 195, 209, 211, 163, 0xca, 0x6c}, payload...)
			b.udp.WriteToUDP(packet, peer)
		}
	}
}
func (b *packetBridge) drop(id string, c *carrier) {
	b.mu.Lock()
	if b.peers[id] == c {
		delete(b.peers, id)
		c.udp.Close()
		if c.tcp != nil {
			c.tcp.Close()
		}
	}
	b.mu.Unlock()
}
func (b *packetBridge) close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	for _, c := range b.peers {
		c.udp.Close()
		if c.tcp != nil {
			c.tcp.Close()
		}
	}
	if b.association != nil {
		b.association.Close()
	}
	b.mu.Unlock()
	b.listener.Close()
	b.udp.Close()
}
func (b *packetBridge) resetCarrier(id string) {
	b.mu.Lock()
	c := b.peers[id]
	b.mu.Unlock()
	if c != nil {
		b.drop(id, c)
	}
}
func loopbackName() string {
	interfaces, _ := net.Interfaces()
	for _, inf := range interfaces {
		if inf.Flags&net.FlagLoopback != 0 {
			return inf.Name
		}
	}
	return "Loopback Pseudo-Interface 1"
}

var _ = fmt.Sprint
var _ = os.ErrNotExist

func physicalLAN() ([]string, error) {
	index, e := physicalIndex()
	if e != nil {
		return nil, e
	}
	inf, e := net.InterfaceByIndex(int(index))
	if e != nil {
		return nil, e
	}
	addresses, e := inf.Addrs()
	if e != nil {
		return nil, e
	}
	result := []string{}
	for _, a := range addresses {
		p, e := netip.ParsePrefix(a.String())
		if e != nil || !p.Addr().Is4() || p.Bits() == 0 || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
			continue
		}
		if p.Overlaps(netip.MustParsePrefix("10.78.0.0/24")) || p.Overlaps(netip.MustParsePrefix("198.18.254.0/30")) {
			continue
		}
		result = append(result, p.Masked().String())
	}
	sort.Strings(result)
	return result, nil
}

func (b *packetBridge) resetAllCarriers() {
	b.mu.Lock()
	old := b.peers
	b.peers = map[string]*carrier{}
	b.mu.Unlock()
	for _, c := range old {
		c.udp.Close()
		if c.tcp != nil {
			c.tcp.Close()
		}
	}
}
