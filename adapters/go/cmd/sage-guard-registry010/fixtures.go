package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"github.com/sage-x-project/sage/pkg/agent/guard010"
)

// Fixture controls emulate trusted host services only. They are not a wire
// authorization format, registry implementation, or production policy engine.
type guardFixture map[string]json.RawMessage

func (f guardFixture) s(k string) string { var s string; _ = json.Unmarshal(f[k], &s); return s }
func (f guardFixture) yes(k string) bool { var b bool; _ = json.Unmarshal(f[k], &b); return b }
func (f guardFixture) Now(context.Context) (int64, error) {
	var n int64
	if !f.yes("clock_trusted") || json.Unmarshal(f["now"], &n) != nil {
		return 0, guard010.ErrInvalid
	}
	return n, nil
}
func (f guardFixture) ActiveKey(_ context.Context, issuer, kid string) (ed25519.PublicKey, error) {
	if !f.yes("active_key") {
		return nil, guard010.ErrInvalid
	}
	if expected := f.s("expected_issuer"); expected != "" && issuer != expected {
		return nil, guard010.ErrInvalid
	}
	b, e := hex.DecodeString(f.s("public_key_hex"))
	return ed25519.PublicKey(b), e
}
func (f guardFixture) Bindings(_ context.Context, issuer, requestID string) (string, []byte, []byte, error) {
	if issuer != f.s("expected_issuer") {
		return "", nil, nil, guard010.ErrInvalid
	}
	return f.s("original_digest"), f["approved_policy"], f["approved_manifest"], nil
}
func (f guardFixture) Authorize(_ context.Context, issuer, tool string, args []byte) error {
	var schema struct {
		Tool       string
		Required   []string
		Properties map[string]string
	}
	var a map[string]any
	if !f.yes("policy_allow") || json.Unmarshal(f["tool_schema"], &schema) != nil || schema.Tool != tool || json.Unmarshal(args, &a) != nil {
		return guard010.ErrInvalid
	}
	for _, k := range schema.Required {
		if _, ok := a[k]; !ok {
			return guard010.ErrInvalid
		}
	}
	for k, v := range a {
		if schema.Properties[k] != "string" {
			return guard010.ErrInvalid
		}
		if _, ok := v.(string); !ok {
			return guard010.ErrInvalid
		}
	}
	return nil
}
