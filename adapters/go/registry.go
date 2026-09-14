package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/sage-x-project/sage/pkg/agent/did"
)

// Existing DID/PoP entry points: no replacement registry policy in the adapter.
func registryObserve(op string, raw json.RawMessage) (string, map[string]any, error) {
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return "", nil, e
	}
	field := func(n string) (string, error) {
		var s *string
		if e := json.Unmarshal(fields[n], &s); e != nil || s == nil {
			return "", fmt.Errorf("invalid %s", n)
		}
		return *s, nil
	}
	id, e := field("did")
	if e != nil {
		return "", nil, e
	}
	if op == "sage.did.validate" {
		e = did.ValidateDID(id)
	} else {
		alg, err := field("alg")
		if err != nil {
			return "", nil, err
		}
		if alg != "ed25519" {
			return "UNSUPPORTED", map[string]any{}, nil
		}
		if _, err := field("name"); err != nil {
			return "", nil, err
		}
		p, err := field("public_key_hex")
		if err != nil {
			return "", nil, err
		}
		pub, err := hex.DecodeString(p)
		if err != nil {
			return "", nil, err
		}
		s, err := field("signature_hex")
		if err != nil {
			return "", nil, err
		}
		sig, err := hex.DecodeString(s)
		if err != nil {
			return "", nil, err
		}
		e = did.VerifyKeyProofOfPossession(did.AgentDID(id), &did.AgentKey{Type: did.KeyTypeEd25519, KeyData: pub, Signature: sig})
	}
	if e != nil {
		return "REJECT", map[string]any{}, nil
	}
	return "ACCEPT", map[string]any{"valid": true}, nil
}
