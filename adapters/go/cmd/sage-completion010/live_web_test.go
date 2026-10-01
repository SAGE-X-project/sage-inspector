package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveWebSourceConfiguration(t *testing.T) {
	dir := t.TempDir()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "inspector"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, err := x509.CreateCertificate(rand.Reader, client, ca, clientKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	base := liveWebConfig{Origin: "https://agent.example", AdminHost: "admin.example.com",
		RootDER:       base64.RawURLEncoding.EncodeToString(rootDER),
		InspectorCert: certPath, InspectorKey: keyPath,
		Agents: map[string]liveWebAgent{
			completionAlice: {Public: "127.0.0.1:9001", Admin: "127.0.0.1:9002"},
			completionBob:   {Public: "127.0.0.1:9003", Admin: "127.0.0.1:9004"},
		}}
	for _, tc := range []struct {
		name   string
		change func(*liveWebConfig)
		accept bool
	}{
		{"configured-loopback-source", func(*liveWebConfig) {}, true},
		{"untrusted-origin", func(c *liveWebConfig) { c.Origin = "https://other.example" }, false},
		{"remote-destination", func(c *liveWebConfig) {
			c.Agents[completionAlice] = liveWebAgent{Public: "192.0.2.1:9001", Admin: "127.0.0.1:9002"}
		}, false},
		{"missing-participant", func(c *liveWebConfig) { delete(c.Agents, completionBob) }, false},
		{"wrong-participant", func(c *liveWebConfig) {
			delete(c.Agents, completionBob)
			c.Agents["did:sage:web:agent.example:other"] = liveWebAgent{Public: "127.0.0.1:9003", Admin: "127.0.0.1:9004"}
		}, false},
		{"invalid-root", func(c *liveWebConfig) { c.RootDER = "AA" }, false},
		{"relative-client-key", func(c *liveWebConfig) { c.InspectorKey = "client.key" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.Agents = make(map[string]liveWebAgent, len(base.Agents))
			for k, v := range base.Agents {
				cfg.Agents[k] = v
			}
			tc.change(&cfg)
			value, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "source.json")
			if err := os.WriteFile(path, value, 0600); err != nil {
				t.Fatal(err)
			}
			_, err = openLiveWebSource(path)
			if (err == nil) != tc.accept {
				t.Fatalf("accept=%v error=%v", tc.accept, err)
			}
		})
	}
}
