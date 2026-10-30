package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestLimits(t *testing.T) {
	l := limits{ips: map[string]int{}, maximum: 2, perIP: 1}
	if !l.acquire("a") || l.acquire("a") || !l.acquire("b") || l.acquire("c") {
		t.Fatal("limits")
	}
	l.release("a")
	if !l.acquire("c") || len(l.ips) != 2 {
		t.Fatal("release")
	}
}
func TestBridgeDuplexAndCancellation(t *testing.T) {
	a, x := net.Pipe()
	b, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { bridge(ctx, a, b, time.Second); close(done) }()
	x.SetDeadline(time.Now().Add(time.Second))
	y.SetDeadline(time.Now().Add(time.Second))
	go x.Write([]byte("hello"))
	p := make([]byte, 5)
	if _, e := io.ReadFull(y, p); e != nil || string(p) != "hello" {
		t.Fatal(e)
	}
	go y.Write([]byte("world"))
	if _, e := io.ReadFull(x, p); e != nil || string(p) != "world" {
		t.Fatal(e)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel leaked")
	}
}
func TestIdleExpiry(t *testing.T) {
	a, x := net.Pipe()
	b, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	done := make(chan struct{})
	go func() { bridge(context.Background(), a, b, 30*time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle leaked")
	}
}
func TestActivityRenewsLifetime(t *testing.T) {
	a, x := net.Pipe()
	b, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bridge(ctx, a, b, 200*time.Millisecond)
	for i := 0; i < 8; i++ {
		go x.Write([]byte("x"))
		p := make([]byte, 1)
		y.SetReadDeadline(time.Now().Add(time.Second))
		if _, e := io.ReadFull(y, p); e != nil {
			t.Fatal(e)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func TestServeBackendFailureAndShutdown(t *testing.T) {
	dead, _ := net.Listen("tcp4", "127.0.0.1:0")
	target := dead.Addr().String()
	dead.Close()
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, l, target, 2, 1, time.Second, "") }()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	if n, e := c.Read(make([]byte, 1)); n != 0 || e == nil {
		t.Fatal("backend failure not closed")
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("serve leaked")
	}
}

func TestFallbackCooldownAndPrimaryRecovery(t *testing.T) {
	now := time.Unix(1000, 0)
	primaryAlive := false
	var calls []string
	selector := backendSelector{primary: "primary", fallback: "fallback", cooldown: time.Minute, now: func() time.Time { return now }}
	selector.dial = func(_ context.Context, _, target string) (net.Conn, error) {
		calls = append(calls, target)
		if target == "primary" && !primaryAlive {
			return nil, io.EOF
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	connect := func() {
		t.Helper()
		c, e := selector.connect(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		c.Close()
	}
	connect()
	connect()
	if len(calls) != 3 || calls[0] != "primary" || calls[1] != "fallback" || calls[2] != "fallback" {
		t.Fatalf("failed primary not cached: %v", calls)
	}
	primaryAlive = true
	now = now.Add(time.Minute)
	connect()
	connect()
	if len(calls) != 5 || calls[3] != "primary" || calls[4] != "primary" {
		t.Fatalf("primary did not recover: %v", calls)
	}
}

func TestHealthyPrimaryDoesNotDialFallback(t *testing.T) {
	var calls []string
	selector := backendSelector{primary: "primary", fallback: "fallback", cooldown: time.Minute, now: time.Now}
	selector.dial = func(_ context.Context, _, target string) (net.Conn, error) {
		calls = append(calls, target)
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	c, e := selector.connect(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if len(calls) != 1 || calls[0] != "primary" {
		t.Fatalf("unexpected fallback: %v", calls)
	}
}

func TestCanceledPrimaryDoesNotDialFallbackOrPoisonHealth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	selector := backendSelector{primary: "primary", fallback: "fallback", cooldown: time.Minute, now: time.Now}
	selector.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		calls++
		cancel()
		return nil, context.Canceled
	}
	if c, e := selector.connect(ctx); c != nil || e != context.Canceled {
		t.Fatalf("unexpected result %v %v", c, e)
	}
	if calls != 1 || !selector.retryAt.IsZero() {
		t.Fatal("cancellation treated as failed primary")
	}
}

func TestRecoveryProbeDoesNotStallOtherClients(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	now := time.Unix(2000, 0)
	selector := backendSelector{primary: "primary", fallback: "fallback", cooldown: time.Minute, now: func() time.Time { return now }, retryAt: now.Add(-time.Second)}
	selector.dial = func(_ context.Context, _, target string) (net.Conn, error) {
		if target == "primary" {
			close(started)
			<-release
			return nil, io.EOF
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	done := make(chan struct{})
	go func() {
		c, _ := selector.connect(context.Background())
		if c != nil {
			c.Close()
		}
		close(done)
	}()
	<-started
	second := make(chan struct{})
	go func() {
		c, _ := selector.connect(context.Background())
		if c != nil {
			c.Close()
		}
		close(second)
	}()
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("client stalled behind primary recovery probe")
	}
	close(release)
	<-done
}

func TestNoFallbackReplayAfterPrimaryHasReceivedBytes(t *testing.T) {
	primary, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer primary.Close()
	fallback, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer fallback.Close()
	front, _ := net.Listen("tcp4", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveWithFallback(ctx, front, primary.Addr().String(), fallback.Addr().String(), time.Minute, 2, 1, time.Second, "")
	}()
	received := make(chan string, 1)
	go func() {
		c, e := primary.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 5)
		_, e = io.ReadFull(c, b)
		if e == nil {
			received <- string(b)
		}
	}()
	c, e := net.Dial("tcp4", front.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("hello"))
	select {
	case data := <-received:
		if data != "hello" {
			t.Fatal(data)
		}
	case <-time.After(time.Second):
		t.Fatal("primary did not receive data")
	}
	if n, e := c.Read(make([]byte, 1)); n != 0 || e == nil {
		t.Fatal("closed primary did not close client")
	}
	fallback.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	if conn, e := fallback.Accept(); e == nil {
		conn.Close()
		t.Fatal("replayed established TLS stream to fallback")
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
