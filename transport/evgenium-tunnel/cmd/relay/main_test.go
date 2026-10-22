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
