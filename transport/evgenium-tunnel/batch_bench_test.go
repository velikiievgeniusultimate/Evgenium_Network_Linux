// SPDX-License-Identifier: GPL-2.0-or-later
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// Opt-in engineering benchmark: actual mTLS over loopback, never an Internet
// speed estimate. Run with EVG_LOCAL_BATCH_BENCH=1 and GOMAXPROCS=1, pinning the
// test process to one CPU. Deliberately old FIFO entries exercise max-age=0.
func TestLocalTLSBatchBenchmark(t *testing.T) {
	if os.Getenv("EVG_LOCAL_BATCH_BENCH") != "1" {
		t.Skip("opt-in loopback benchmark")
	}
	for repeat := 0; repeat < 2; repeat++ {
		for _, batch := range []int{1, 10, 32} {
			t.Run(fmt.Sprintf("repeat%d_batch%d", repeat, batch), func(t *testing.T) {
				s, c := credentials(t)
				sc, e := tlsConfig(s)
				if e != nil {
					t.Fatal(e)
				}
				cc, e := tlsConfig(c)
				if e != nil {
					t.Fatal(e)
				}
				ln, e := tls.Listen("tcp4", "127.0.0.1:0", sc)
				if e != nil {
					t.Fatal(e)
				}
				defer ln.Close()
				accepted := make(chan net.Conn, 1)
				go func() {
					p, e := ln.Accept()
					if e == nil {
						p.SetDeadline(time.Now().Add(20 * time.Second))
						p.(*tls.Conn).Handshake()
						accepted <- p
					}
				}()
				client, e := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp4", ln.Addr().String(), cc)
				if e != nil {
					t.Fatal(e)
				}
				defer client.Close()
				server := <-accepted
				defer server.Close()
				server.SetDeadline(time.Now().Add(20 * time.Second))
				if e := server.(*tls.Conn).Handshake(); e != nil {
					t.Fatal(e)
				}
				const count = 3500
				const payloadSize = 1200
				payload := bytes.Repeat([]byte{0xa7}, payloadSize)
				q := make(chan packet, count)
				for i := 1; i <= count; i++ {
					q <- packet{kind: dataFrame, seq: uint64(i), data: payload, at: time.Now().Add(-2 * time.Second)}
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				hb := &heartbeat{interval: 20 * time.Millisecond, timeout: 5 * time.Second}
				done := make(chan error, 1)
				pongDone := make(chan struct{})
				go func() {
					defer close(pongDone)
					for {
						p, e := decode(client)
						if e != nil {
							return
						}
						if p.kind == pongFrame {
							hb.ack(p.data, time.Now())
						}
					}
				}()
				stale := stats.staleDrop.Load()
				flushes := stats.flushes.Load()
				var before, after syscall.Rusage
				syscall.Getrusage(syscall.RUSAGE_SELF, &before)
				start := time.Now()
				go func() {
					done <- writeFrames(ctx, client, q, make(chan packet), options{batch: batch, maxAge: 0, heartbeat: hb})
				}()
				reader := bufio.NewReaderSize(server, 64*1024)
				n := 0
				pings := 0
				for n < count {
					p, e := decode(reader)
					if e != nil {
						t.Fatal(e)
					}
					if p.kind == pingFrame {
						pings++
						if e := encode(server, packet{kind: pongFrame, data: p.data}); e != nil {
							t.Fatal(e)
						}
						continue
					}
					n++
					if p.seq != uint64(n) || !bytes.Equal(p.data, payload) {
						t.Fatalf("corruption at %d", n)
					}
				}
				elapsed := time.Since(start)
				syscall.Getrusage(syscall.RUSAGE_SELF, &after)
				// Batch=32 must not wait for 31 companions after the bulk queue drains.
				sparseStart := time.Now()
				q <- packet{kind: dataFrame, seq: count + 1, data: payload, at: time.Now()}
				for {
					p, e := decode(reader)
					if e != nil {
						t.Fatal(e)
					}
					if p.kind == pingFrame {
						pings++
						encode(server, packet{kind: pongFrame, data: p.data})
						continue
					}
					if p.seq != count+1 {
						t.Fatal("sparse frame wrong")
					}
					break
				}
				sparse := time.Since(sparseStart)
				cancel()
				client.Close()
				server.Close()
				<-done
				<-pongDone
				if stats.staleDrop.Load() != stale {
					t.Fatal("live FIFO dropped")
				}
				if pings == 0 {
					t.Fatal("heartbeat starved")
				}
				if sparse > time.Second {
					t.Fatal("sparse packet delayed")
				}
				micros := func(v syscall.Timeval) float64 { return float64(v.Sec)*1e6 + float64(v.Usec) }
				cpu := (micros(after.Utime) + micros(after.Stime) - micros(before.Utime) - micros(before.Stime)) / 1e6
				row := map[string]any{"local_loopback_only": true, "batch": batch, "repeat": repeat, "payload_bytes": count * payloadSize, "seconds": elapsed.Seconds(), "mbps": float64(count*payloadSize*8) / elapsed.Seconds() / 1e6, "cpu_seconds_both_ends": cpu, "cpu_ms_per_MiB": cpu * 1000 / (float64(count*payloadSize) / 1048576), "tls_flushes": stats.flushes.Load() - flushes, "pings": pings, "stale_drops": stats.staleDrop.Load() - stale, "sparse_us": sparse.Microseconds(), "integrity": true}
				b, _ := json.Marshal(row)
				t.Log(string(b))
			})
		}
	}
}

// A sparse control/data stream must flush immediately even when the configured
// batch cap exceeds the available packet count. Old entries remain valid.
func TestBatchSparseAgedFIFO(t *testing.T) {
	for _, batch := range []int{1, 10, 32} {
		t.Run(fmt.Sprint(batch), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			q := make(chan packet, 1)
			done := make(chan error, 1)
			go func() { done <- writeFrames(ctx, a, q, make(chan packet), options{batch: batch, maxAge: 0}) }()
			defer func() { cancel(); a.Close(); <-done }()
			for i := 1; i <= 3; i++ {
				q <- packet{kind: dataFrame, seq: uint64(i), data: []byte{byte(i)}, at: time.Now().Add(-2 * time.Second)}
				b.SetReadDeadline(time.Now().Add(time.Second))
				p, e := decode(b)
				if e != nil || p.seq != uint64(i) || !bytes.Equal(p.data, []byte{byte(i)}) {
					t.Fatalf("sparse FIFO seq=%d err=%v", i, e)
				}
			}
		})
	}
}
