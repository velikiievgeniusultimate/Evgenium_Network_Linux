package main

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// A matching pong proves progress in BOTH directions. Data and unsolicited pongs
// cannot keep a half-broken connection alive. Deadlines use monotonic time.
type heartbeat struct {
	mu                sync.Mutex
	interval, timeout time.Duration
	next, sent        time.Time
	nonce             uint64
}

func (h *heartbeat) probe(now time.Time) (packet, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.sent.IsZero() || now.Before(h.next) {
		return packet{}, false
	}
	h.nonce = uint64(now.UnixNano())
	h.sent = now
	h.next = now.Add(h.interval)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, h.nonce)
	return packet{kind: pingFrame, data: b}, true
}
func (h *heartbeat) ack(data []byte, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(data) != 8 || h.sent.IsZero() || binary.BigEndian.Uint64(data) != h.nonce {
		return false
	}
	h.sent = time.Time{}
	h.next = now.Add(h.interval)
	return true
}
func (h *heartbeat) expired(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.sent.IsZero() && now.Sub(h.sent) >= h.timeout
}
func (h *heartbeat) watch(ctx context.Context) error {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-t.C:
			if h.expired(now) {
				stats.heartbeatTimeouts.Add(1)
				return errors.New("heartbeat_roundtrip_timeout")
			}
		}
	}
}
