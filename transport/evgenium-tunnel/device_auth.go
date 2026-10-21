package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"sync"
	"time"
)

// Only an address assigned inside our namespace may be the configured UDP peer.
// This permits a fixed local IKE socket after output DNAT without an arbitrary proxy.
func localPeer(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		n, ok := address.(*net.IPNet)
		if ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

var deviceName = regexp.MustCompile(`^device-[a-f0-9]{24}$`)
var errDevice = errors.New("device_certificate_revoked_or_unverified")

// Called only after the standard library verifies the client chain and EKU.
// Read the atomically replaced CRL on every new handshake; stale/missing/invalid
// CRLs fail closed. The ingress supervisor closes sessions on CRL changes.
func verifyDevice(s tls.ConnectionState, path string, now time.Time) error {
	if len(s.PeerCertificates) == 0 || !deviceName.MatchString(s.PeerCertificates[0].Subject.CommonName) {
		return errDevice
	}
	f, err := os.Open(path)
	if err != nil {
		return errDevice
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 2*1024*1024+1))
	if err != nil || len(raw) > 2*1024*1024 {
		return errDevice
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "X509 CRL" || len(rest) > 2 {
		return errDevice
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil || now.Before(crl.ThisUpdate) || !now.Before(crl.NextUpdate) {
		return errDevice
	}
	signed := false
	for _, chain := range s.VerifiedChains {
		if len(chain) > 1 && crl.CheckSignatureFrom(chain[1]) == nil {
			signed = true
			break
		}
	}
	if !signed {
		return errDevice
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(s.PeerCertificates[0].SerialNumber) == 0 {
			return errDevice
		}
	}
	return nil
}

var deviceSessions = struct {
	sync.Mutex
	count map[[32]byte]int
}{count: make(map[[32]byte]int)}

func reserveDevice(raw []byte) (func(), bool) {
	id := sha256.Sum256(raw)
	deviceSessions.Lock()
	defer deviceSessions.Unlock()
	if deviceSessions.count[id] >= 2 {
		return nil, false
	}
	deviceSessions.count[id]++
	return func() {
		deviceSessions.Lock()
		defer deviceSessions.Unlock()
		deviceSessions.count[id]--
		if deviceSessions.count[id] == 0 {
			delete(deviceSessions.count, id)
		}
	}, true
}
