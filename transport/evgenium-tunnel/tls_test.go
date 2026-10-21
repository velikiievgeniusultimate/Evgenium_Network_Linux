package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func credentials(t *testing.T) (options, options) {
	t.Helper()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	write := func(name, typ string, data []byte) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: data}), 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	caPath := write("ca", "CERTIFICATE", der)
	makePair := func(name string, server bool) options {
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		c := &x509.Certificate{SerialNumber: big.NewInt(int64(len(name) + 2)), Subject: pkix.Name{CommonName: name}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			c.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		}
		cert, e := x509.CreateCertificate(rand.Reader, c, ca, p, key)
		if e != nil {
			t.Fatal(e)
		}
		pk, _ := x509.MarshalPKCS8PrivateKey(k)
		return options{ca: caPath, cert: write(name+".crt", "CERTIFICATE", cert), key: write(name+".key", "PRIVATE KEY", pk), peerName: "allowed-client", serverName: "127.0.0.1"}
	}
	s, c := makePair("server", true), makePair("allowed-client", false)
	s.mode = "server"
	c.mode = "client"
	return s, c
}
func TestMutualTLS(t *testing.T) {
	s, c := credentials(t)
	for _, name := range []string{"valid", "wrong-client-name", "no-client-certificate", "wrong-server-name"} {
		t.Run(name, func(t *testing.T) {
			sc, e := tlsConfig(s)
			if e != nil {
				t.Fatal(e)
			}
			cc, e := tlsConfig(c)
			if e != nil {
				t.Fatal(e)
			}
			switch name {
			case "wrong-client-name":
				bad := s
				bad.peerName = "another-client"
				sc, e = tlsConfig(bad)
				if e != nil {
					t.Fatal(e)
				}
			case "no-client-certificate":
				cc.Certificates = nil
			case "wrong-server-name":
				cc.ServerName = "other.example"
			}
			l, e := tls.Listen("tcp4", "127.0.0.1:0", sc)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			done := make(chan error, 1)
			go func() {
				conn, e := l.Accept()
				if e == nil {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(time.Second))
					e = conn.(*tls.Conn).Handshake()
				}
				done <- e
			}()
			conn, ce := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp4", l.Addr().String(), cc)
			if conn != nil {
				defer conn.Close()
			}
			se := <-done
			if name == "valid" {
				if ce != nil || se != nil {
					t.Fatal(ce, se)
				}
				if conn.ConnectionState().Version != tls.VersionTLS13 {
					t.Fatal("old TLS")
				}
			} else if ce == nil && se == nil {
				t.Fatal("unauthenticated connection accepted")
			}
		})
	}
}
