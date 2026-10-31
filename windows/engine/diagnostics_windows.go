package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type PacketProbe struct {
	Size     int    `json:"size"`
	Sent     int    `json:"sent"`
	Received int    `json:"received"`
	RTT      int64  `json:"rtt_us"`
	Elapsed  int64  `json:"elapsed_ms"`
	Error    string `json:"error,omitempty"`
}
type ServiceProbe struct {
	Service string `json:"service"`
	OK      bool   `json:"ok"`
	HTTP    int    `json:"http_status"`
	Millis  int64  `json:"elapsed_ms"`
}
type TransferProbe struct {
	Route     string  `json:"route"`
	Direction string  `json:"direction"`
	Bytes     int     `json:"bytes"`
	Millis    int64   `json:"elapsed_ms"`
	Mbps      float64 `json:"mbps"`
	OK        bool    `json:"ok"`
}

func udpRelay(port int) (net.Conn, *net.UDPConn, *net.UDPAddr, error) {
	tcp, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if e != nil {
		return nil, nil, nil, e
	}
	bad := func(e error) (net.Conn, *net.UDPConn, *net.UDPAddr, error) { tcp.Close(); return nil, nil, nil, e }
	tcp.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = tcp.Write([]byte{5, 1, 0}); e != nil {
		return bad(e)
	}
	var reply [2]byte
	if _, e = io.ReadFull(tcp, reply[:]); e != nil || reply != [2]byte{5, 0} {
		return bad(fmt.Errorf("socks_auth"))
	}
	if _, e = tcp.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
		return bad(e)
	}
	var h [4]byte
	if _, e = io.ReadFull(tcp, h[:]); e != nil || h[1] != 0 {
		return bad(fmt.Errorf("socks_udp"))
	}
	n := 4
	if h[3] == 4 {
		n = 16
	} else if h[3] != 1 {
		return bad(fmt.Errorf("socks_address"))
	}
	buf := make([]byte, n+2)
	if _, e = io.ReadFull(tcp, buf); e != nil {
		return bad(e)
	}
	tcp.SetDeadline(time.Time{})
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(binary.BigEndian.Uint16(buf[n:]))}
	udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		return bad(e)
	}
	return tcp, udp, remote, nil
}
func udpPackets(port int) []PacketProbe {
	tcp, udp, remote, e := udpRelay(port)
	if e != nil {
		return []PacketProbe{{Error: "udp_associate_unavailable"}}
	}
	defer tcp.Close()
	defer udp.Close()
	result := []PacketProbe{}
	for _, size := range []int{64, 256, 512, 1024, 1200, 1400} {
		r := PacketProbe{Size: size, Sent: 10}
		start := time.Now()
		var sum int64
		sent := map[string]time.Time{}
		for i := 0; i < 10; i++ {
			payload := make([]byte, size)
			rand.Read(payload)
			copy(payload, []byte("EVGDIAG1"))
			payload[8] = byte(i)
			key := string(payload)
			sent[key] = time.Now()
			packet := append([]byte{0, 0, 0, 1, 10, 78, 0, 1, 0x60, 0x0c}, payload...)
			if _, e = udp.WriteToUDP(packet, remote); e != nil {
				r.Error = "send_error"
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		deadline := time.Now().Add(1200 * time.Millisecond)
		buf := make([]byte, 8192)
		for r.Received < r.Sent {
			udp.SetReadDeadline(deadline)
			n, _, err := udp.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if n < 10 {
				continue
			}
			offset := 10
			if buf[3] == 4 {
				offset = 22
			}
			if n <= offset {
				continue
			}
			payload := string(buf[offset:n])
			if at, ok := sent[payload]; ok {
				r.Received++
				sum += time.Since(at).Microseconds()
				delete(sent, payload)
			}
		}
		if r.Received > 0 {
			r.RTT = sum / int64(r.Received)
		} else {
			r.Error = "no_udp_response"
		}
		r.Elapsed = time.Since(start).Milliseconds()
		result = append(result, r)
		if r.Received == 0 && size == 64 {
			break
		}
	}
	return result
}
func serviceProbes(port int) []ServiceProbe {
	targets := [][2]string{{"dns_https", "https://www.cloudflare.com/cdn-cgi/trace"}, {"discord_api", "https://discord.com/api/v10/gateway"}, {"discord_cdn", "https://cdn.discordapp.com/"}, {"vk", "https://vk.com/"}, {"github", "https://github.com/"}}
	result := []ServiceProbe{}
	for _, target := range targets {
		start := time.Now()
		client := socksClient(port, 6*time.Second)
		req, _ := http.NewRequest("GET", target[1], nil)
		req.Header.Set("Range", "bytes=0-1023")
		response, e := client.Do(req)
		r := ServiceProbe{Service: target[0], Millis: time.Since(start).Milliseconds()}
		if e == nil {
			r.HTTP = response.StatusCode
			r.OK = response.StatusCode < 500
			io.Copy(io.Discard, io.LimitReader(response.Body, 2048))
			response.Body.Close()
		}
		client.CloseIdleConnections()
		result = append(result, r)
	}
	return result
}
func uploadProbe(id string) TransferProbe {
	port := routePort(id)
	r := TransferProbe{Route: id, Direction: "upload", Bytes: 262144}
	data := make([]byte, r.Bytes)
	rand.Read(data)
	client := socksClient(port, 10*time.Second)
	defer client.CloseIdleConnections()
	start := time.Now()
	response, e := client.Post("https://speed.cloudflare.com/__up", "application/octet-stream", bytes.NewReader(data))
	r.Millis = time.Since(start).Milliseconds()
	if e == nil {
		r.OK = response.StatusCode >= 200 && response.StatusCode < 300
		io.Copy(io.Discard, io.LimitReader(response.Body, 2048))
		response.Body.Close()
	}
	if r.OK {
		r.Mbps = float64(r.Bytes) * 8 / time.Since(start).Seconds() / 1e6
	}
	return r
}
func sanitizedError(e error) string {
	if e == nil {
		return ""
	}
	if strings.Contains(e.Error(), "timeout") {
		return "timeout"
	}
	return "network"
}
