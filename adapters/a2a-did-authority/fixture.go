// Package main observes only public, owned fixtures; no deployment authority.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"sync"
	"time"

	sagedid "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/sage/pkg/agent/hpke"
	"github.com/sage-x-project/sage/pkg/agent/registry010"
)

const callerDID = "did:sage:web:inspection.example:caller"
const serverDID = "did:sage:web:inspection.example:service"
const epoch int64 = 1700000000

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
func signingKey(who string) ed25519.PrivateKey {
	seed := byte(17)
	if who == serverDID {
		seed = 23
	}
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}
func kemKey() *ecdh.PrivateKey {
	return must(ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{29}, 32)))
}

type recordView struct {
	DID        string `json:"did"`
	Controller string `json:"controller"`
	Version    string `json:"version"`
	SigningHex string `json:"signing_hex"`
	KEMHex     string `json:"kem_hex"`
	Service    string `json:"service"`
	Time       int64  `json:"time"`
}
type fixture struct {
	mu                  sync.Mutex
	mono, unix          int64
	target              string
	unavailable         bool
	reads, observations int
	records             []recordView
}

func (f *fixture) Now() (registry010.Stamp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return registry010.Stamp{MonoMS: f.mono, Unix: f.unix}, nil
}
func (f *fixture) expire() { f.mu.Lock(); defer f.mu.Unlock(); f.mono += 6000; f.unix += 6 }
func (f *fixture) fail()   { f.mu.Lock(); defer f.mu.Unlock(); f.unavailable = true }
func (f *fixture) record(ctx context.Context, identity string, reading bool) (sagedid.Record, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if reading {
		f.reads++
	} else {
		f.observations++
	}
	if ctx == nil || ctx.Err() != nil || f.unavailable || (identity != callerDID && identity != serverDID) {
		return sagedid.Record{}, 0, errors.New("owned fixture unavailable")
	}
	d := must(did.Parse(identity))
	pub := signingKey(identity).Public().(ed25519.PublicKey)
	keys := []sagedid.Key{}
	kem := ""
	if identity == serverDID {
		raw := kemKey().PublicKey().Bytes()
		keys = append(keys, sagedid.Key{Name: "kem", Alg: sagedid.AlgX25519, State: sagedid.KeyAccepted, Material: raw})
		kem = hex.EncodeToString(raw)
	}
	// Registry snapshots require strictly increasing key names: kem before sign.
	keys = append(keys, sagedid.Key{Name: "sign", Alg: sagedid.AlgEd25519, State: sagedid.KeyAccepted, Material: append([]byte(nil), pub...)})
	issued := epoch
	r := sagedid.Record{DID: d, Controller: "inspector-owned-operator", State: sagedid.StateActive, Version: "17", Keys: keys, Services: []sagedid.Service{{Name: "a2a", Type: "A2AInterface", URI: f.target}}, Observation: sagedid.Observation{Issued: &issued, Source: "inspector-did-authority", Time: f.unix}}
	f.records = append(f.records, recordView{identity, r.Controller, r.Version, hex.EncodeToString(pub), kem, f.target, f.unix})
	return r, f.mono, nil
}
func (f *fixture) Observe(ctx context.Context, d did.DID) (sagedid.Record, error) {
	r, _, e := f.record(ctx, d.String(), false)
	return r, e
}
func (f *fixture) Read(ctx context.Context, identity string) (registry010.Snapshot, error) {
	r, mono, e := f.record(ctx, identity, true)
	if e != nil {
		return registry010.Snapshot{}, e
	}
	keys := []registry010.Key{}
	for _, k := range r.Keys {
		keys = append(keys, registry010.Key{Name: k.Name, Alg: k.Alg, State: string(k.State), Material: hex.EncodeToString(k.Material)})
	}
	// The record digest binds immutable authority data, not a new observation time.
	raw := must(json.Marshal(map[string]any{"id": identity, "controller": r.Controller, "state": r.State, "version": r.Version, "keys": keys, "services": r.Services}))
	digest := sha256.Sum256(raw)
	return registry010.Snapshot{Source: "inspector-did-authority", Registry: "web:inspection.example", Network: "owned-fixture", DID: identity, Version: r.Version, State: string(r.State), Digest: hex.EncodeToString(digest[:]), Ready: true, Validated: true, Finalized: true, AcquiredMS: mono, Keys: keys}, nil
}

type replay struct {
	mu              sync.Mutex
	denied          map[string]bool
	setup, accepted int
}

func (s *replay) reserve(v hpke.Replay010, setup bool, validate func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := v.Sender + "|" + v.Recipient + "|"
	keys := []string{prefix + "id|" + v.ID, prefix + "nonce|" + v.Nonce}
	if setup && v.Context != "" {
		keys = append(keys, v.Sender+"|context|"+v.Context)
	}
	for _, key := range keys {
		if s.denied[key] {
			return errors.New("owned fixture duplicate")
		}
	}
	for _, key := range keys {
		s.denied[key] = true
	}
	if setup {
		s.setup++
	}
	if validate != nil {
		if e := validate(); e != nil {
			return e
		}
		s.accepted++
	}
	return nil
}
func (s *replay) Reserve(v hpke.Replay010) error { return s.reserve(v, true, nil) }
func (s *replay) ReserveRecord(v hpke.Replay010, validate func() error) error {
	return s.reserve(v, false, validate)
}
func (s *replay) counts() (int, int) { s.mu.Lock(); defer s.mu.Unlock(); return s.setup, s.accepted }
func complete(ctx context.Context, directory string, f *fixture, httpSetup bool) (*hpke.AuthenticatedCompletion010, *hpke.AuthenticatedCompletion010, *replay, *replay, func()) {
	journals := []*registry010.Journal{}
	endpoints := []*hpke.CompletionEndpoint010{}
	stores := []*replay{}
	var left, right *hpke.AuthenticatedCompletion010
	cleanup := func() {
		if left != nil {
			left.Close()
		}
		if right != nil {
			right.Close()
		}
		for _, ep := range endpoints {
			ep.Close()
		}
		for _, j := range journals {
			_ = j.Close()
		}
	}
	ready := false
	defer func() {
		if !ready {
			cleanup()
		}
	}()
	for n, identity := range []string{callerDID, serverDID} {
		journal := must(registry010.OpenJournal(filepath.Join(directory, []string{"caller", "server"}[n]), true))
		journals = append(journals, journal)
		gate := must(registry010.NewGate(registry010.Config{Source: "inspector-did-authority", Registry: "web:inspection.example", Network: "owned-fixture"}, f, f, journal))
		store := &replay{denied: map[string]bool{}}
		stores = append(stores, store)
		var kem []byte
		if identity == serverDID {
			kem = kemKey().Bytes()
		}
		ep := must(hpke.NewCompletionEndpoint010(identity, identity+"#sign", signingKey(identity).Seed(), kem, gate, f, store))
		endpoints = append(endpoints, ep)
	}
	a, b := endpoints[0], endpoints[1]
	if httpSetup {
		if a.BindHTTP(f.target) != nil || b.BindHTTP(f.target) != nil {
			panic("owned fixture HTTP setup")
		}
		pending, hello, e := a.StartHTTP(ctx, serverDID, serverDID+"#sign", 300)
		if e != nil {
			panic(e)
		}
		response, reply, e := b.RespondHTTP(ctx, hello, 300)
		if e != nil {
			panic(e)
		}
		right = response
		left = must(pending.CompleteHTTP(ctx, reply))
	} else {
		pending, hello, e := a.Start(ctx, serverDID, serverDID+"#sign", 300)
		if e != nil {
			panic(e)
		}
		response, reply, e := b.Respond(ctx, hello, 300)
		if e != nil {
			panic(e)
		}
		right = response
		left = must(pending.Complete(ctx, reply))
	}
	ready = true
	return left, right, stores[0], stores[1], cleanup
}
func certificate() (tls.Certificate, *x509.CertPool) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32))
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned inspection fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der := must(x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key))
	parsed := must(x509.ParseCertificate(der))
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, roots
}
