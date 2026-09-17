// Synthetic local test dependencies; never a network service or production resolver.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/sage-x-project/sage/pkg/agent/crypto/jcs"
	"github.com/sage-x-project/sage/pkg/agent/hpke"
	"github.com/sage-x-project/sage/pkg/agent/registry010"
	"strings"
)

func canon010(v any) []byte { b, _ := jcs.Marshal(v); return b }

const completionRegistry = "web:agent.example"
const completionAlice = "did:sage:web:agent.example:alice"
const completionBob = "did:sage:web:agent.example:bob"

type completionControl struct {
	records   int
	expiry    int64
	mono, utc int64
	mode      string
}

func (c *completionControl) Now() (registry010.Stamp, error) {
	if c.mode == "clock-error" {
		return registry010.Stamp{}, errors.New("clock")
	}
	return registry010.Stamp{MonoMS: c.mono, Unix: c.utc}, nil
}
func (c *completionControl) Read(_ context.Context, did string) (registry010.Snapshot, error) {
	if c.mode == "source-error" {
		return registry010.Snapshot{}, errors.New("source")
	}
	seed := byte(1)
	if did == completionBob {
		seed = 2
	}
	key := registry010.Key{Name: "signing-1", Alg: "ed25519", Material: hex.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public().(ed25519.PublicKey)), State: "accepted"}
	keys := []registry010.Key{}
	if did == completionBob {
		p, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{3}, 32))
		kem := registry010.Key{Name: "kem-1", Alg: "x25519", Material: hex.EncodeToString(p.PublicKey().Bytes()), State: "accepted"}
		if c.mode == "revoke-kem" {
			kem.State = "revoked"
		}
		keys = append(keys, kem)
	}
	if (c.mode == "revoke-init" && did == completionAlice) || (c.mode == "revoke-resp" && did == completionBob) {
		key.State = "revoked"
	}
	if c.mode == "changed-material" && did == completionBob {
		key.Material = hex.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32)).Public().(ed25519.PublicKey))
	}
	keys = append(keys, key)
	version := "2"
	if strings.HasPrefix(c.mode, "revoke") || c.mode == "changed-material" || c.mode == "unrelated" {
		version = "3"
	}
	if c.mode == "unrelated" {
		extra := key
		extra.Name = "z-extra"
		extra.Material = hex.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32)).Public().(ed25519.PublicKey))
		keys = append(keys, extra)
	}
	if c.expiry != 0 {
		for i := range keys {
			expiry := c.expiry
			keys[i].Expires = &expiry
		}
	}
	h := sha256.Sum256(canon010(keys))
	return registry010.Snapshot{Source: "fixture-authority", Registry: completionRegistry, Network: "local", DID: did, Version: version, State: "active", Digest: hex.EncodeToString(h[:]), Ready: true, Validated: true, Finalized: true, AcquiredMS: c.mono, Keys: keys}, nil
}

type completionReplay struct {
	c    *completionControl
	seen map[string]bool
}

func (r *completionReplay) Reserve(v hpke.Replay010) error {
	if r.c.mode == "store-error" {
		return errors.New("store")
	}
	prefix := v.Sender + "|" + v.Recipient
	ids := []string{prefix + "|id|" + v.ID, prefix + "|nonce|" + v.Nonce}
	if v.Context != "" {
		ids = append(ids, v.Sender+"|ctx|"+v.Context)
	}
	for _, id := range ids {
		if r.seen[id] {
			return errors.New("duplicate")
		}
	}
	for _, id := range ids {
		r.seen[id] = true
	}
	if r.c.mode == "utc-delay" {
		r.c.utc++
		r.c.mono += 1000
	}
	if r.c.mode == "store-delay" {
		r.c.mono += 5001
	}
	return nil
}

// Bounded synthetic transaction store; not a durable deployment implementation.
func (r *completionReplay) ReserveRecord(v hpke.Replay010, validate func() error) error {
	if r.c.mode == "store-error" {
		return errors.New("store")
	}
	prefix := v.Sender + "|" + v.Recipient
	ids := []string{prefix + "|id|" + v.ID, prefix + "|nonce|" + v.Nonce}
	if r.c.mode == "transport-id" {
		r.seen[ids[0]] = true
	}
	if r.c.mode == "transport-nonce" {
		r.seen[ids[1]] = true
	}
	for _, id := range ids {
		if r.seen[id] {
			return errors.New("duplicate")
		}
	}
	if r.c.mode == "utc-delay" {
		r.c.utc++
		r.c.mono += 1000
	}
	if r.c.mode == "store-delay" {
		r.c.mono += 5001
	}
	if err := validate(); err != nil {
		return err
	}
	for _, id := range ids {
		r.seen[id] = true
	}
	r.c.records++
	return nil
}
