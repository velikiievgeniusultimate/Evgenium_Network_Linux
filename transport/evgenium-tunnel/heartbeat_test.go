package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestHeartbeatRejectsUnsolicitedAndOldPong(t *testing.T) {
	h := heartbeat{interval: time.Second, timeout: 3 * time.Second}
	now := time.Now()
	p, _ := h.probe(now)
	if h.ack([]byte("bad data"), now) {
		t.Fatal("unmatched accepted")
	}
	if !h.expired(now.Add(3 * time.Second)) {
		t.Fatal("missing pong ignored")
	}
	if !h.ack(p.data, now.Add(time.Second)) {
		t.Fatal("matching pong rejected")
	}
	if h.expired(now.Add(time.Hour)) {
		t.Fatal("ack did not clear")
	}
	q, _ := h.probe(now.Add(3 * time.Second))
	if h.ack(p.data, now.Add(4*time.Second)) {
		t.Fatal("old pong accepted")
	}
	if !h.ack(q.data, now.Add(4*time.Second)) {
		t.Fatal("new pong rejected")
	}
}
func TestPendingProbeDeadlineCannotBePostponed(t *testing.T) {
	h := heartbeat{interval: time.Second, timeout: 3 * time.Second}
	now := time.Now()
	h.probe(now)
	for i := 1; i < 10; i++ {
		if _, ok := h.probe(now.Add(time.Duration(i) * time.Second)); ok {
			t.Fatal("replaced pending probe")
		}
	}
	if !h.expired(now.Add(4 * time.Second)) {
		t.Fatal("deadline moved")
	}
}
func TestHeartbeatWatchCancels(t *testing.T) {
	h := heartbeat{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h.watch(ctx) != context.Canceled {
		t.Fatal("watch ignored cancel")
	}
}
func TestProbeNotStarvedByContinuousData(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	q := make(chan packet, 64)
	for i := 0; i < 64; i++ {
		q <- packet{kind: dataFrame, seq: uint64(i + 1), data: []byte("load"), at: time.Now()}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &heartbeat{interval: time.Second, timeout: 3 * time.Second}
	done := make(chan error, 1)
	go func() { done <- writeFrames(ctx, a, q, make(chan packet), options{heartbeat: h, maxAge: time.Minute}) }()
	b.SetReadDeadline(time.Now().Add(time.Second))
	p, e := decode(b)
	if e != nil || p.kind != pingFrame {
		t.Fatal("probe starved", p.kind, e)
	}
	cancel()
	a.Close()
	<-done
}
