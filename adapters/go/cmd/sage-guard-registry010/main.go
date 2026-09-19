// Fixture-only registry binding probe. No network, external tools or host hooks.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	g "github.com/sage-x-project/sage/pkg/agent/guard010"
	r "github.com/sage-x-project/sage/pkg/agent/registry010"
	"io"
	"os"
	"strings"
)

type registryControl struct {
	snap            r.Snapshot
	mono, delay     int64
	reads           int
	fail, clockFail bool
}

func (c *registryControl) Now() (r.Stamp, error) {
	if c.clockFail {
		return r.Stamp{}, errors.New("clock")
	}
	return r.Stamp{MonoMS: c.mono, Unix: 1700000000}, nil
}
func (c *registryControl) Read(context.Context, string) (r.Snapshot, error) {
	c.reads++
	if c.fail {
		return r.Snapshot{}, errors.New("source")
	}
	s := c.snap
	s.AcquiredMS = c.mono
	return s, nil
}
func (c *registryControl) Advance(r.Scope, uint64, string, bool) error { c.mono += c.delay; return nil }

type sink struct {
	c               *registryControl
	mode            string
	checks, effects int
	arguments       string
}

func (s *sink) Check(context.Context, string, string) error {
	s.checks++
	if s.checks == 2 {
		switch s.mode {
		case "revoked":
			s.c.snap.Keys[0].State = "revoked"
		case "unready":
			s.c.snap.Ready = false
		case "source":
			s.c.fail = true
		case "clock":
			s.c.clockFail = true
		case "stale":
			s.c.delay = 5001
		case "boundary":
			s.c.delay = 5000
		case "rollback":
			s.c.mono = 0
		}
	}
	return nil
}
func (s *sink) Commit(_ context.Context, i *g.Invocation) error {
	s.effects++
	s.arguments = string(i.Arguments())
	return nil
}
func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 1048577))
	if e != nil || len(raw) > 1048576 {
		os.Exit(2)
	}
	var q struct {
		Mode  string       `json:"mode"`
		Input guardFixture `json:"input"`
	}
	if json.Unmarshal(raw, &q) != nil {
		os.Exit(2)
	}
	switch q.Mode {
	case "valid", "boundary", "revoked", "unready", "source", "clock", "stale", "rollback":
	default:
		os.Exit(2)
	}
	f := q.Input
	env, _ := hex.DecodeString(f.s("envelope_hex"))
	var envelope struct {
		Intent struct{ Issuer, Keyid string }
	}
	if json.Unmarshal(env, &envelope) != nil {
		os.Exit(2)
	}
	issuer, kid := envelope.Intent.Issuer, envelope.Intent.Keyid
	i := strings.LastIndex(issuer, ":")
	if i < 9 {
		os.Exit(2)
	}
	registry := issuer[9:i]
	parts := strings.Split(kid, "#")
	if len(parts) != 2 {
		os.Exit(2)
	}
	c := &registryControl{mono: 100, snap: r.Snapshot{Source: "fixture", Registry: registry, Network: "fixture", DID: issuer, Version: "1", State: "active", Digest: strings.Repeat("a", 64), Ready: true, Validated: true, Finalized: true, Keys: []r.Key{{Name: parts[1], Alg: "ed25519", Material: f.s("public_key_hex"), State: "accepted"}}}}
	gate, e := r.NewGate(r.Config{Source: "fixture", Registry: registry, Network: "fixture"}, c, c, c)
	if e != nil {
		os.Exit(2)
	}
	a, e := g.NewRegistryAuthority(gate, issuer, kid)
	if e != nil {
		os.Exit(2)
	}
	sink := &sink{c: c, mode: q.Mode}
	dispatch, e := g.OpenDispatchGate(os.Args[1], true, f.s("expected_recipient"), a, f, sink)
	if e != nil {
		os.Exit(2)
	}
	receipt, err := dispatch.Dispatch(context.Background(), env)
	if dispatch.Close() != nil {
		os.Exit(2)
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": err == nil, "committed": receipt != nil && receipt.Committed(), "effects": sink.effects, "arguments": sink.arguments, "reads": c.reads}) != nil {
		os.Exit(2)
	}
}
