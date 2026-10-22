package main

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Linux TCP_INFO describes the outer TLS connection, not the inner VPN stream.
// No addresses or payload are collected. Samples are best effort, never fatal.
var tcpMetrics struct{ samples, errors, retrans, maxRTT, maxUnacked atomic.Uint64 }

func tcpInfo(c *net.TCPConn) (syscall.TCPInfo, error) {
	var info syscall.TCPInfo
	raw, err := c.SyscallConn()
	if err != nil {
		return info, err
	}
	var callErr error
	err = raw.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(info))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP,
			syscall.TCP_INFO, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			callErr = errno
		}
	})
	if err != nil {
		return info, err
	}
	return info, callErr
}

func watchTCP(ctx context.Context, c net.Conn) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	var previous uint32
	sample := func() {
		info, err := tcpInfo(tcp)
		if err != nil {
			tcpMetrics.errors.Add(1)
			return
		}
		tcpMetrics.samples.Add(1)
		// Counter is per connection. Modular subtraction also handles uint32 wrap.
		tcpMetrics.retrans.Add(uint64(info.Total_retrans - previous))
		previous = info.Total_retrans
		maximum(&tcpMetrics.maxRTT, uint64(info.Rtt))
		maximum(&tcpMetrics.maxUnacked, uint64(info.Unacked))
	}
	sample()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			sample()
			return
		case <-ticker.C:
			sample()
		}
	}
}
