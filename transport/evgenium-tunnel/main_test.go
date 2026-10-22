package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestFrames(t *testing.T) {
	for _, n := range []int{1, 16, 1280, 4096} {
		want := packet{kind: dataFrame, seq: 42, data: bytes.Repeat([]byte{173}, n)}
		var b bytes.Buffer
		if e := encode(&b, want); e != nil {
			t.Fatal(e)
		}
		got, e := decode(&b)
		if e != nil || got.seq != want.seq || !bytes.Equal(got.data, want.data) {
			t.Fatal("integrity", e)
		}
	}
}
func TestRejectBeforeAllocation(t *testing.T) {
	for _, v := range []struct {
		k byte
		n uint16
	}{{0, 1}, {1, 0}, {1, 65535}, {2, 4096}, {3, 0}} {
		var h [11]byte
		h[0] = v.k
		binary.BigEndian.PutUint16(h[1:3], v.n)
		if _, e := decode(bytes.NewReader(h[:])); e == nil {
			t.Fatal(v)
		}
	}
}
func TestTruncation(t *testing.T) {
	var b bytes.Buffer
	_ = encode(&b, packet{kind: dataFrame, seq: 1, data: []byte("payload")})
	for i := 0; i < b.Len(); i++ {
		if _, e := decode(bytes.NewReader(b.Bytes()[:i])); e == nil {
			t.Fatal(i)
		}
	}
}
func TestQueueBoundAndKernelReceiver(t *testing.T) {
	server, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	sender, e := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	q := make(chan packet, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	before := stats.queueDrop.Load()
	go func() { done <- receiveUDP(ctx, server, q) }()
	for i := 0; i < 100; i++ {
		_, _ = sender.Write([]byte("test"))
	}
	deadline := time.Now().Add(time.Second)
	for stats.queueDrop.Load() == before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stats.queueDrop.Load() == before || len(q) != 1 {
		t.Fatal("unbounded or unmeasured queue")
	}
	cancel()
	server.Close()
	<-done
}
func TestStaleQueueIsNotReplayed(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	q := make(chan packet, 2)
	q <- packet{kind: dataFrame, seq: 1, data: []byte("stale"), at: time.Now().Add(-time.Second)}
	q <- packet{kind: dataFrame, seq: 2, data: []byte("fresh"), at: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- writeFrames(ctx, a, q, make(chan packet), options{maxAge: time.Second / 2}) }()
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	p, e := decode(b)
	if e != nil || string(p.data) != "fresh" {
		t.Fatal(p, e)
	}
	cancel()
	a.Close()
	<-done
}
func TestReplayRejected(t *testing.T) {
	u, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan error, 1)
	go func() { done <- readFrames(context.Background(), a, u, make(chan packet, 1), options{}) }()
	_ = encode(b, packet{kind: dataFrame, seq: 0, data: []byte("replay")})
	if e := <-done; e == nil || e.Error() != "sequence_replay" {
		t.Fatal(e)
	}
}
func FuzzFrames(f *testing.F) {
	f.Add([]byte{1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 42})
	f.Add([]byte{1, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := decode(bytes.NewReader(b))
		if e == nil {
			var out bytes.Buffer
			if e = encode(&out, p); e != nil {
				t.Fatal(e)
			}
			if len(out.Bytes()) > headerSize+maxPayload {
				t.Fatal("oversized")
			}
		}
	})
}

var _ io.Reader = (*bytes.Reader)(nil)

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestShortWrite(t *testing.T) {
	if e := encode(shortWriter{}, packet{kind: dataFrame, seq: 1, data: []byte("x")}); e != io.ErrShortWrite {
		t.Fatal(e)
	}
}

// Coalescing changes write boundaries, never datagram boundaries or order.
func TestBatchLimitsPreserveFrames(t *testing.T) {
	for _, batch := range []int{1, 10, 32} {
		a, b := net.Pipe()
		q := make(chan packet, 65)
		for i := 1; i <= 65; i++ {
			q <- packet{kind: dataFrame, seq: uint64(i), data: bytes.Repeat([]byte{byte(i)}, 1200), at: time.Now()}
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- writeFrames(ctx, a, q, make(chan packet), options{batch: batch, maxAge: 5 * time.Second})
		}()
		_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
		for i := 1; i <= 65; i++ {
			p, e := decode(b)
			if e != nil || p.seq != uint64(i) || !bytes.Equal(p.data, bytes.Repeat([]byte{byte(i)}, 1200)) {
				t.Fatalf("batch=%d frame=%d error=%v", batch, i, e)
			}
		}
		cancel()
		a.Close()
		b.Close()
		<-done
	}
}
