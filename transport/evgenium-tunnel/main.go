// EvgeniumTunnel carries bounded datagrams over mutually authenticated TLS 1.3.
// It changes no routes or firewall rules. The UDP destination is local configuration,
// never a network-controlled address. Linux only; experimental wire protocol v1.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const magic = "EVGT\x00\x01\x00\x00"
const maxPayload = 4096
const headerSize = 11

var errFrame = errors.New("invalid_frame")

const dataFrame byte = 1
const pingFrame byte = 2
const pongFrame byte = 3

type counters struct{ rx, tx, rxBytes, txBytes, queueDrop, staleDrop, kernelDrop, invalid, ioErrors, gaps, udpError, reconnect, active, rtt atomic.Uint64 }

var stats counters

func snapshot() map[string]uint64 {
	return map[string]uint64{"utc_ms": uint64(time.Now().UnixMilli()), "udp_received": stats.rx.Load(), "udp_delivered": stats.tx.Load(), "received_bytes": stats.rxBytes.Load(), "delivered_bytes": stats.txBytes.Load(), "queue_drops": stats.queueDrop.Load(), "stale_drops": stats.staleDrop.Load(), "kernel_drops": stats.kernelDrop.Load(), "invalid_frames": stats.invalid.Load(), "stream_read_errors": stats.ioErrors.Load(), "sequence_gaps": stats.gaps.Load(), "udp_errors": stats.udpError.Load(), "reconnects": stats.reconnect.Load(), "active": stats.active.Load(), "rtt_us": stats.rtt.Load()}
}

type packet struct {
	kind byte
	seq  uint64
	data []byte
	at   time.Time
}

func encode(w io.Writer, p packet) error {
	if err := valid(p.kind, len(p.data)); err != nil {
		return err
	}
	var h [headerSize]byte
	h[0] = p.kind
	binary.BigEndian.PutUint16(h[1:3], uint16(len(p.data)))
	binary.BigEndian.PutUint64(h[3:], p.seq)
	if n, err := w.Write(h[:]); err != nil {
		return err
	} else if n != len(h) {
		return io.ErrShortWrite
	}
	n, err := w.Write(p.data)
	if err == nil && n != len(p.data) {
		return io.ErrShortWrite
	}
	return err
}
func valid(kind byte, n int) error {
	if kind == dataFrame && n > 0 && n <= maxPayload {
		return nil
	}
	if (kind == pingFrame || kind == pongFrame) && n == 8 {
		return nil
	}
	return errFrame
}
func decode(r io.Reader) (packet, error) {
	var h [headerSize]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return packet{}, e
	}
	n := int(binary.BigEndian.Uint16(h[1:3]))
	if e := valid(h[0], n); e != nil {
		return packet{}, e
	}
	p := packet{kind: h[0], seq: binary.BigEndian.Uint64(h[3:]), data: make([]byte, n)}
	_, e := io.ReadFull(r, p.data)
	return p, e
}

type options struct {
	mode, listen, udpListen, udpPeer, server, serverName, ca, cert, key, peerName, crl string
	queue, buffer, maxSessions                                                         int
	maxAge                                                                             time.Duration
	pace                                                                               float64
}

func socketBuffer(c *net.UDPConn, n int) error {
	if err := c.SetReadBuffer(n); err != nil {
		return err
	}
	if err := c.SetWriteBuffer(n); err != nil {
		return err
	}
	raw, e := c.SyscallConn()
	if e != nil {
		return e
	}
	var actual int
	var optionErr error
	e = raw.Control(func(fd uintptr) {
		// These options affect only this process's socket, not global sysctls.
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, n)
		optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RXQ_OVFL, 1)
		actual, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	})
	if e != nil {
		return e
	}
	if optionErr != nil {
		return optionErr
	}
	log.Printf("udp_buffer requested=%d actual=%d", n, actual)
	return nil
}
func udp(o options, server bool) (*net.UDPConn, error) {
	peer, e := net.ResolveUDPAddr("udp4", o.udpPeer)
	if e != nil {
		return nil, e
	}
	if !localPeer(peer.IP) {
		return nil, errors.New("udp_peer_must_be_local")
	}
	var local *net.UDPAddr
	if !server {
		local, e = net.ResolveUDPAddr("udp4", o.udpListen)
		if e != nil {
			return nil, e
		}
		if !local.IP.IsLoopback() {
			return nil, errors.New("udp_listener_must_be_loopback")
		}
	}
	c, e := net.DialUDP("udp4", local, peer)
	if e != nil {
		return nil, e
	}
	if e = socketBuffer(c, o.buffer); e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}
func receiveUDP(ctx context.Context, c *net.UDPConn, q chan<- packet) error {
	var seq uint64
	var lastDrop uint32
	buf := make([]byte, maxPayload+1)
	oob := make([]byte, 128)
	for {
		n, on, flags, _, e := c.ReadMsgUDP(buf, oob)
		if e != nil {
			return e
		}
		messages, _ := syscall.ParseSocketControlMessage(oob[:on])
		for _, m := range messages {
			if m.Header.Level == syscall.SOL_SOCKET && m.Header.Type == syscall.SO_RXQ_OVFL && len(m.Data) >= 4 {
				v := binary.NativeEndian.Uint32(m.Data)
				stats.kernelDrop.Add(uint64(v - lastDrop))
				lastDrop = v
			}
		}
		if flags&syscall.MSG_TRUNC != 0 || n > maxPayload || n == 0 {
			stats.invalid.Add(1)
			continue
		}
		seq++
		stats.rx.Add(1)
		stats.rxBytes.Add(uint64(n))
		p := packet{kind: dataFrame, seq: seq, data: append([]byte(nil), buf[:n]...), at: time.Now()}
		select {
		case q <- p:
		case <-ctx.Done():
			return ctx.Err()
		default:
			stats.queueDrop.Add(1)
		}
	}
}
func writeFrames(ctx context.Context, c net.Conn, q <-chan packet, control <-chan packet, o options) error {
	w := bufio.NewWriterSize(c, 64*1024)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	send := func(p packet) error {
		if p.kind == dataFrame && time.Since(p.at) > o.maxAge {
			stats.staleDrop.Add(1)
			return nil
		}
		return encode(w, p)
	}
	for {
		var p packet
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p = <-control:
		case p = <-q:
		case now := <-tick.C:
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], uint64(now.UnixNano()))
			p = packet{kind: pingFrame, data: b[:]}
		}
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if e := send(p); e != nil {
			return e
		}
		// Flush immediately for sparse traffic, batch at most 32 already queued frames.
	batch:
		for i := 1; i < 32; i++ {
			select {
			case p = <-control:
				if e := send(p); e != nil {
					return e
				}
			case p = <-q:
				if e := send(p); e != nil {
					return e
				}
			default:
				break batch
			}
		}
		if e := w.Flush(); e != nil {
			return e
		}
	}
}
func readFrames(ctx context.Context, c net.Conn, u *net.UDPConn, control chan<- packet, o options) error {
	r := bufio.NewReaderSize(c, 64*1024)
	var last uint64
	next := time.Now()
	for {
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
		p, e := decode(r)
		if e != nil {
			if errors.Is(e, errFrame) {
				stats.invalid.Add(1)
			} else {
				stats.ioErrors.Add(1)
			}
			return e
		}
		switch p.kind {
		case pingFrame:
			select {
			case control <- packet{kind: pongFrame, data: p.data}:
			default:
			}
		case pongFrame:
			sent := int64(binary.BigEndian.Uint64(p.data))
			delta := time.Now().UnixNano() - sent
			if delta >= 0 && delta < int64(20*time.Second) {
				stats.rtt.Store(uint64(delta / 1000))
			}
		case dataFrame:
			if p.seq <= last {
				stats.invalid.Add(1)
				return errors.New("sequence_replay")
			}
			if p.seq > last+1 {
				stats.gaps.Add(p.seq - last - 1)
			}
			last = p.seq
			if o.pace > 0 {
				now := time.Now()
				if next.Before(now) {
					next = now
				}
				delay := time.Until(next)
				if delay > 0 {
					timer := time.NewTimer(delay)
					select {
					case <-ctx.Done():
						timer.Stop()
						return ctx.Err()
					case <-timer.C:
					}
				}
				next = next.Add(time.Duration(float64(len(p.data)) * 8e3 / o.pace))
			}
			if _, e = u.Write(p.data); e != nil {
				stats.udpError.Add(1)
				return e
			}
			stats.tx.Add(1)
			stats.txBytes.Add(uint64(len(p.data)))
		}
	}
}
func session(c *tls.Conn, u *net.UDPConn, o options) error {
	defer c.Close()
	defer u.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	if e := c.HandshakeContext(ctx); e != nil {
		return errors.New("tls_authentication_failed")
	}
	if o.mode == "server" && o.crl != "" {
		release, ok := reserveDevice(c.ConnectionState().PeerCertificates[0].Raw)
		if !ok {
			return errors.New("device_session_limit")
		}
		defer release()
	}
	if c.ConnectionState().NegotiatedProtocol != "evgenium/1" {
		return errors.New("protocol_negotiation_failed")
	}
	if _, e := io.WriteString(c, magic); e != nil {
		return e
	}
	b := make([]byte, len(magic))
	if _, e := io.ReadFull(c, b); e != nil {
		return e
	}
	if string(b) != magic {
		return errors.New("protocol_version_failed")
	}
	_ = c.SetDeadline(time.Time{})
	stats.active.Add(1)
	defer stats.active.Add(^uint64(0))
	q := make(chan packet, o.queue)
	control := make(chan packet, 8)
	done := make(chan error, 3)
	var wg sync.WaitGroup
	for _, f := range []func() error{func() error { return receiveUDP(ctx, u, q) }, func() error { return writeFrames(ctx, c, q, control, o) }, func() error { return readFrames(ctx, c, u, control, o) }} {
		wg.Add(1)
		go func(fn func() error) { defer wg.Done(); done <- fn() }(f)
	}
	e := <-done
	cancel()
	c.Close()
	u.Close()
	wg.Wait()
	return e
}
func tlsConfig(o options) (*tls.Config, error) {
	pair, e := tls.LoadX509KeyPair(o.cert, o.key)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(o.ca)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid_ca")
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, NextProtos: []string{"evgenium/1"}, SessionTicketsDisabled: true}
	if o.mode == "server" {
		c.ClientCAs = roots
		c.ClientAuth = tls.RequireAndVerifyClientCert
		c.VerifyConnection = func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 {
				return errors.New("unauthorized_peer")
			}
			if o.crl != "" {
				return verifyDevice(s, o.crl, time.Now())
			}
			if s.PeerCertificates[0].Subject.CommonName != o.peerName {
				return errors.New("unauthorized_peer")
			}
			return nil
		}
	} else {
		c.RootCAs = roots
		c.ServerName = o.serverName
	}
	return c, nil
}
func main() {
	var o options
	flag.StringVar(&o.mode, "mode", "", "server or client")
	flag.StringVar(&o.listen, "listen", "0.0.0.0:24577", "TLS listener")
	flag.StringVar(&o.server, "server", "", "TLS endpoint")
	flag.StringVar(&o.serverName, "server-name", "", "verified TLS identity")
	flag.StringVar(&o.udpListen, "udp-listen", "127.0.0.1:24559", "local UDP socket")
	flag.StringVar(&o.udpPeer, "udp-peer", "127.0.0.1:24547", "fixed UDP peer")
	flag.StringVar(&o.ca, "ca", "", "CA PEM")
	flag.StringVar(&o.cert, "cert", "", "certificate PEM")
	flag.StringVar(&o.key, "key", "", "private key PEM")
	flag.StringVar(&o.crl, "crl", "", "signed device CRL: enables device identity policy instead of a single peer CN")
	flag.StringVar(&o.peerName, "peer-name", "evgenium-ru-lab", "allowed client certificate CN")
	flag.IntVar(&o.queue, "queue", 1024, "bounded UDP queue, packets")
	flag.IntVar(&o.buffer, "udp-buffer", 4*1024*1024, "socket buffer bytes")
	flag.IntVar(&o.maxSessions, "max-sessions", 8, "maximum concurrent server sessions including handshakes")
	flag.DurationVar(&o.maxAge, "max-age", 500*time.Millisecond, "discard obsolete queued datagrams")
	flag.Float64Var(&o.pace, "pace-mbps", 0, "optional local UDP delivery pacing (0 disables)")
	flag.Parse()
	if (o.mode != "server" && o.mode != "client") || o.queue < 1 || o.queue > 4096 || o.buffer < 4096 || o.buffer > 8*1024*1024 || o.maxSessions < 1 || o.maxSessions > 32 || o.maxAge < time.Millisecond || o.maxAge > 5*time.Second || math.IsNaN(o.pace) || math.IsInf(o.pace, 0) || o.pace < 0 || o.pace > 10000 {
		log.Fatal("invalid_options")
	}
	cfg, e := tlsConfig(o)
	if e != nil {
		log.Fatal("credential_configuration_failed")
	}
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		requests := make(chan os.Signal, 1)
		signal.Notify(requests, syscall.SIGUSR1)
		for {
			select {
			case <-tick.C:
			case <-requests:
			}
			b, _ := json.Marshal(snapshot())
			log.Printf("metrics %s", b)
		}
	}()

	if o.mode == "client" {
		for {
			u, e := udp(o, false)
			if e != nil {
				log.Printf("udp_open_failed %v", e)
				time.Sleep(3 * time.Second)
				continue
			}
			c, e := tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second, KeepAlive: 15 * time.Second}, "tcp4", o.server, cfg)
			if e == nil {
				e = session(c, u, o)
			} else {
				u.Close()
			}
			stats.reconnect.Add(1)
			log.Printf("connection_ended %v", e)
			time.Sleep(time.Second)
		}
	} else {
		l, e := tls.Listen("tcp4", o.listen, cfg)
		if e != nil {
			log.Fatal(e)
		}
		defer l.Close()
		slots := make(chan struct{}, o.maxSessions)
		for {
			c, e := l.Accept()
			if e != nil {
				log.Fatal(e)
			}
			select {
			case slots <- struct{}{}:
				go func(c net.Conn) {
					defer func() { <-slots }()
					u, e := udp(o, true)
					if e != nil {
						c.Close()
						return
					}
					e = session(c.(*tls.Conn), u, o)
					if e != nil {
						log.Printf("session_ended %v", e)
					}
				}(c)
			default:
				c.Close()
			}
		}
	}
}
