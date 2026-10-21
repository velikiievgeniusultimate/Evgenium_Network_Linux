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

func TestDeviceRevocationPolicy(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	client := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "device-0123456789abcdef01234567"}}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{client}, VerifiedChains: [][]*x509.Certificate{{client, ca}}}
	path := filepath.Join(t.TempDir(), "devices.pem")
	write := func(revoked, expired, foreign bool) {
		crl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
		if revoked {
			crl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: client.SerialNumber, RevocationTime: now.Add(-time.Minute)}}
		}
		if expired {
			crl.NextUpdate = now.Add(-time.Second)
		}
		signer := key
		if foreign {
			_, signer, _ = ed25519.GenerateKey(rand.Reader)
		}
		data, e := x509.CreateRevocationList(rand.Reader, crl, ca, signer)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: data}), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(false, false, false)
	if err := verifyDevice(state, path, now); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name                      string
		revoked, expired, foreign bool
	}{{"revoked", true, false, false}, {"expired", false, true, false}, {"foreign", false, false, true}} {
		t.Run(c.name, func(t *testing.T) {
			write(c.revoked, c.expired, c.foreign)
			if verifyDevice(state, path, now) == nil {
				t.Fatal("accepted")
			}
		})
	}
	write(false, false, false)
	if verifyDevice(state, path, now.Add(-2*time.Hour)) == nil {
		t.Fatal("future CRL accepted")
	}
	client.Subject.CommonName = "server"
	if verifyDevice(state, path, now) == nil {
		t.Fatal("non-device accepted")
	}
	client.Subject.CommonName = "device-0123456789abcdef01234567"
	state.VerifiedChains = nil
	if verifyDevice(state, path, now) == nil {
		t.Fatal("unverified chain accepted")
	}
	os.Remove(path)
	if verifyDevice(state, path, now) == nil {
		t.Fatal("missing CRL accepted")
	}
}
func TestFixedPeerIsLocal(t *testing.T) {
	if !localPeer(net.ParseIP("127.0.0.1")) {
		t.Fatal("loopback refused")
	}
	if localPeer(net.ParseIP("192.0.2.10")) {
		t.Fatal("remote destination accepted")
	}
}

func TestPerDeviceSessionBound(t *testing.T) {
	a, ok := reserveDevice([]byte("certificate"))
	if !ok {
		t.Fatal("first")
	}
	b, ok := reserveDevice([]byte("certificate"))
	if !ok {
		t.Fatal("second")
	}
	if _, ok = reserveDevice([]byte("certificate")); ok {
		t.Fatal("unbounded")
	}
	a()
	b()
	c, ok := reserveDevice([]byte("certificate"))
	if !ok {
		t.Fatal("slot leaked")
	}
	c()
}
