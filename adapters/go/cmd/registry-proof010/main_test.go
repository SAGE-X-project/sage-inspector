package main

import "testing"

func TestEvaluateBoundaries(t *testing.T) {
	base := request{CaseID: "signing", RegistryID: "web:agents.example.com", AgentID: "billing-bot", Name: "sign-1", Alg: "ed25519", PublicKeyHex: "01"}
	if got := evaluate(base); got.Verdict != "ACCEPT" || got.CaseID != "signing" || got.ChallengeHex == "" {
		t.Fatalf("valid challenge: %+v", got)
	}
	base.AgentID = "agént"
	if got := evaluate(base); got.Verdict != "REJECT" || got.ChallengeHex != "" {
		t.Fatalf("non-ASCII input: %+v", got)
	}
	base.AgentID = "billing-bot"
	base.PublicKeyHex = "0G"
	if got := evaluate(base); got.Verdict != "REJECT" {
		t.Fatalf("invalid hex: %+v", got)
	}
}
