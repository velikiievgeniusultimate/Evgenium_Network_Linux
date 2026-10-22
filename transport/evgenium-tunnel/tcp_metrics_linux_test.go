package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPInfoTracksRealSocketAndStops(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var peer net.Conn
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("accept timeout")
	}
	defer peer.Close()
	if _, err = conn.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(peer, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	if _, err = tcpInfo(conn.(*net.TCPConn)); err != nil {
		t.Fatal(err)
	}
	before := tcpMetrics.samples.Load()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { watchTCP(ctx, conn); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP sampler did not stop")
	}
	if tcpMetrics.samples.Load() < before+2 {
		t.Fatal("missing initial/final samples")
	}
	conn.Close()
	if _, err = tcpInfo(conn.(*net.TCPConn)); err == nil {
		t.Fatal("closed socket reported usable metrics")
	}
}
