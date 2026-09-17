package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sage-x-project/sage/pkg/agent/session"
)

// The core owns record cryptography; this adapter does not verify envelopes or registry state.
func record010Observe(op string, raw json.RawMessage) (string, map[string]any, error) {
	out := map[string]any{}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", nil, err
	}
	allowed := map[string]bool{"seed_hex": true, "th_hex": true, "direction": true, "caller_aad_hex": true}
	if op == "sage.session.record010.open" {
		allowed["record_hex"] = true
	} else {
		allowed["plaintext"] = true
	}
	for key := range fields {
		if !allowed[key] {
			return "", nil, fmt.Errorf("unexpected record control: %s", key)
		}
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
	if op == "sage.session.record010.open" {
		role = !role
	}
	core, e := session.NewRecordSession010(seed, th, role)
	if e != nil {
		return "", nil, e
	}
	defer core.Close()
	if op == "sage.session.record010.open" {
		wire, e := gethex("record_hex")
		if e != nil {
			return "", nil, e
		}
		plain, e := core.Open(wire, caller)
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
		wire, e := core.Seal(plain, caller)
		if e != nil {
			return "REJECT", out, nil
		}
		sum := sha256.Sum256(wire)
		out["record_sha256"] = hex.EncodeToString(sum[:])
		out["record_bytes"] = len(wire)
		if op == "sage.session.record010.export" {
			out["record_hex"] = hex.EncodeToString(wire)
			out["session_id"] = core.ID()
		}
	}
	return "ACCEPT", out, nil
}
