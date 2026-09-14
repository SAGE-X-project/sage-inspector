package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sage-x-project/sage/pkg/agent/session"
)

// This is the legacy core record API projection, not a tuple/registry verifier.
func sessionObserve(op string, raw json.RawMessage) (string, map[string]any, error) {
	out := map[string]any{}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", nil, err
	}
	field := func(name string) (string, error) {
		var s *string
		if err := json.Unmarshal(fields[name], &s); err != nil || s == nil {
			return "", fmt.Errorf("invalid %s", name)
		}
		return *s, nil
	}
	gethex := func(name string) ([]byte, error) {
		s, e := field(name)
		if e != nil {
			return nil, e
		}
		return hex.DecodeString(s)
	}
	seed, e := gethex("seed_hex")
	if e != nil {
		return "", nil, e
	}
	th, e := gethex("th_hex")
	if e != nil {
		return "", nil, e
	}
	if len(seed) != 32 || len(th) != 32 {
		return "", nil, fmt.Errorf("invalid trusted key control")
	}
	sid, e := field("sid")
	if e != nil {
		return "", nil, e
	}
	direction, e := field("direction")
	if e != nil {
		return "", nil, e
	}
	if direction != "c2s" && direction != "s2c" {
		return "", nil, fmt.Errorf("invalid direction")
	}
	caller, e := gethex("caller_aad_hex")
	if e != nil {
		return "", nil, e
	}
	if len(caller) > 4034 {
		return "", nil, fmt.Errorf("fixture AAD exceeds transport bound")
	}
	role := direction == "c2s"
	if op == "sage.session.record.open" {
		role = !role
	}
	cfg := session.Config{MaxAge: time.Hour, IdleTimeout: 10 * time.Minute, MaxMessages: 1000, RekeyInterval: 256}
	core, e := session.NewSecureSessionFromExporterWithRole(sid, seed, role, cfg)
	if e != nil {
		return "", nil, e
	}
	defer func() { _ = core.Close() }()
	if op == "sage.session.record.open" {
		wire, e := gethex("record_hex")
		if e != nil {
			return "", nil, e
		}
		plain, e := core.DecryptWithAADInbound(wire, caller)
		if e != nil {
			return "REJECT", out, nil
		}
		out["plaintext_hex"] = hex.EncodeToString(plain)
	} else {
		var b struct {
			Byte   *int `json:"byte"`
			Length *int `json:"length"`
		}
		if e := json.Unmarshal(fields["plaintext"], &b); e != nil || b.Byte == nil || b.Length == nil || *b.Byte < 0 || *b.Byte > 255 || *b.Length < 0 || *b.Length > 8*1024*1024-35 {
			return "", nil, fmt.Errorf("invalid plaintext recipe")
		}
		plain := []byte(strings.Repeat(string([]byte{byte(*b.Byte)}), *b.Length))
		wire, e := core.EncryptWithAADOutbound(plain, caller)
		if e != nil {
			return "REJECT", out, nil
		}
		sum := sha256.Sum256(wire)
		out["record_sha256"] = hex.EncodeToString(sum[:])
		out["record_bytes"] = len(wire)
	}
	return "ACCEPT", out, nil
}
