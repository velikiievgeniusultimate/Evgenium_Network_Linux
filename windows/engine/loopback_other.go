//go:build !windows

package main

import "net"

func loopbackName() string {
	all, _ := net.Interfaces()
	for _, n := range all {
		if n.Flags&net.FlagLoopback != 0 {
			return n.Name
		}
	}
	return "lo"
}
