// SPDX-License-Identifier: GPL-2.0-or-later
// TCP passthrough: TLS and device authentication terminate only at the fixed backend.
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type limits struct {
	mu                    sync.Mutex
	ips                   map[string]int
	total, maximum, perIP int
}

func (l *limits) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maximum || l.ips[ip] >= l.perIP {
		return false
	}
	l.total++
	l.ips[ip]++
	return true
}
func (l *limits) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	l.ips[ip]--
	if l.ips[ip] == 0 {
		delete(l.ips, ip)
	}
}

// Each successful read renews the idle deadline for both directions. Heartbeats
// keep a healthy idle VPN alive; there is no maximum connection lifetime.
type activityReader struct {
	net.Conn
	other net.Conn
	idle  time.Duration
}

func (r activityReader) Read(p []byte) (int, error) {
	n, e := r.Conn.Read(p)
	if n > 0 {
		deadline := time.Now().Add(r.idle)
		r.Conn.SetDeadline(deadline)
		r.other.SetDeadline(deadline)
	}
	return n, e
}
func bridge(ctx context.Context, a, b net.Conn, idle time.Duration) {
	defer a.Close()
	defer b.Close()
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	deadline := time.Now().Add(idle)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		io.CopyBuffer(dst, activityReader{src, dst, idle}, make([]byte, 64*1024))
		a.Close()
		b.Close()
	}
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
}

// backendSelector only chooses before any client bytes are forwarded. A failed
// connection is never replayed onto another backend: TLS remains end-to-end.
// Cooldown avoids making every new client wait for a known-dead primary.
type backendSelector struct {
	mu                sync.Mutex
	primary, fallback string
	cooldown          time.Duration
	retryAt           time.Time
	probing           bool
	dial              func(context.Context, string, string) (net.Conn, error)
	now               func() time.Time
}

func (s *backendSelector) connect(ctx context.Context) (net.Conn, error) {
	s.mu.Lock()
	tryPrimary := s.fallback == "" || (!s.now().Before(s.retryAt) && !s.probing)
	recoveryProbe := tryPrimary && !s.retryAt.IsZero() && s.fallback != ""
	if recoveryProbe {
		s.probing = true
	}
	s.mu.Unlock()
	if tryPrimary {
		c, err := s.dial(ctx, "tcp4", s.primary)
		s.mu.Lock()
		if recoveryProbe {
			s.probing = false
		}
		if err == nil {
			s.retryAt = time.Time{}
		} else if ctx.Err() == nil {
			s.retryAt = s.now().Add(s.cooldown)
		}
		s.mu.Unlock()
		if err == nil || s.fallback == "" || ctx.Err() != nil {
			return c, err
		}
	}
	return s.dial(ctx, "tcp4", s.fallback)
}

func serve(ctx context.Context, listener net.Listener, backend string, maximum, perIP int, idle time.Duration, congestion string) error {
	return serveWithFallback(ctx, listener, backend, "", time.Minute, maximum, perIP, idle, congestion)
}
func serveWithFallback(ctx context.Context, listener net.Listener, backend, fallback string, cooldown time.Duration, maximum, perIP int, idle time.Duration, congestion string) error {
	lim := limits{ips: make(map[string]int), maximum: maximum, perIP: perIP}
	var wg sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	defer wg.Wait()
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}
	if congestion != "" {
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			return raw.Control(func(fd uintptr) {
				if e := syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, congestion); e != nil {
					log.Print("requested congestion control unavailable; using system default")
				}
			})
		}
	}
	selector := backendSelector{primary: backend, fallback: fallback, cooldown: cooldown, dial: dialer.DialContext, now: time.Now}
	for {
		c, e := listener.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		host, _, e := net.SplitHostPort(c.RemoteAddr().String())
		if e != nil || !lim.acquire(host) {
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer lim.release(host)
			defer c.Close()
			if tcp, ok := c.(*net.TCPConn); ok {
				tcp.SetKeepAlive(true)
				tcp.SetKeepAlivePeriod(15 * time.Second)
				tcp.SetNoDelay(true)
			}
			remote, e := selector.connect(ctx)
			if e != nil {
				log.Print("backend unavailable")
				return
			}
			bridge(ctx, c, remote, idle)
		}()
	}
}
func main() {
	listen := flag.String("listen", "0.0.0.0:24579", "TCP listener")
	backend := flag.String("backend", "38.180.164.67:24578", "fixed authenticated TLS backend")
	fallback := flag.String("fallback-backend", "", "optional fixed TLS passthrough backend, used only when primary connect fails")
	cooldown := flag.Duration("primary-retry", time.Minute, "retry failed primary after this cooldown")
	maximum := flag.Int("max-connections", 128, "global connection limit")
	perIP := flag.Int("max-per-ip", 32, "connection limit per public IP (including CGNAT)")
	idle := flag.Duration("idle-timeout", 60*time.Second, "close when neither direction carries data")
	cc := flag.String("backend-congestion", "bbr", "per-socket congestion control; empty uses system default")
	flag.Parse()
	if *maximum < 1 || *perIP < 1 || *idle < time.Second || *cooldown < time.Second {
		log.Fatal("invalid limits")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	listener, e := net.Listen("tcp4", *listen)
	if e != nil {
		log.Fatal(e)
	}
	defer listener.Close()
	log.Print("fixed-backend TLS passthrough ready")
	if e = serveWithFallback(ctx, listener, *backend, *fallback, *cooldown, *maximum, *perIP, *idle, *cc); e != nil {
		log.Fatal(e)
	}
}
