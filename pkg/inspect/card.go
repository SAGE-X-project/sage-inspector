package inspect

import (
	"fmt"

	"github.com/sage-x-project/sage/pkg/agent/did"
)

// CardReport explains an A2A agent card with proof.
type CardReport struct {
	DID       string   `json:"did"`
	Keys      []string `json:"keys"`
	ProofType string   `json:"proof_type,omitempty"`
	Method    string   `json:"verification_method,omitempty"`
	Checks    []Check  `json:"checks"`
	Verified  bool     `json:"verified"`
}

// InspectCard parses, validates and verifies the proof of an agent card.
func InspectCard(raw []byte) *CardReport {
	r := &CardReport{}
	card, err := did.ParseA2AAgentCardWithProof(raw)
	if err != nil {
		r.Checks = append(r.Checks, Check{Name: "parse", Status: "fail", Detail: err.Error()})
		return r
	}
	r.DID = card.ID
	for _, k := range card.PublicKeys {
		r.Keys = append(r.Keys, fmt.Sprintf("%s (%s)", k.ID, k.Type))
	}
	r.Checks = append(r.Checks, Check{Name: "parse", Status: "pass", Detail: fmt.Sprintf("%d keys, %d services", len(card.PublicKeys), len(card.Endpoints))})
	if err := did.ValidateA2ACardWithProof(card); err != nil {
		r.Checks = append(r.Checks, Check{Name: "validate", Status: "fail", Detail: err.Error()})
	} else {
		r.Checks = append(r.Checks, Check{Name: "validate", Status: "pass"})
	}
	if card.Proof == nil {
		r.Checks = append(r.Checks, Check{Name: "proof", Status: "fail", Detail: "no proof member"})
		return r
	}
	r.ProofType, r.Method = card.Proof.Type, card.Proof.VerificationMethod
	ok, err := did.VerifyA2ACardProof(card)
	switch {
	case err != nil:
		r.Checks = append(r.Checks, Check{Name: "proof", Status: "fail", Detail: err.Error()})
	case !ok:
		r.Checks = append(r.Checks, Check{Name: "proof", Status: "fail", Detail: "signature does not verify"})
	default:
		r.Verified = true
		r.Checks = append(r.Checks, Check{Name: "proof", Status: "pass", Detail: "JCS canonical form without proof verifies with " + card.Proof.VerificationMethod})
	}
	return r
}
