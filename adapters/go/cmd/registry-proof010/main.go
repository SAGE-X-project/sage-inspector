package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	"github.com/sage-x-project/sage/pkg/agent/registry010"
)

type request struct {
	CaseID       string `json:"case_id"`
	RegistryID   string `json:"registry_id"`
	AgentID      string `json:"agent_id"`
	Name         string `json:"name"`
	Alg          string `json:"alg"`
	PublicKeyHex string `json:"public_key_hex"`
}

type response struct {
	CaseID          string `json:"case_id"`
	Verdict         string `json:"verdict"`
	ChallengeHex    string `json:"challenge_hex,omitempty"`
	ChallengeSHA256 string `json:"challenge_sha256,omitempty"`
}

func evaluate(q request) response {
	r := response{CaseID: q.CaseID, Verdict: "REJECT"}
	key, err := hex.DecodeString(q.PublicKeyHex)
	if err != nil || hex.EncodeToString(key) != q.PublicKeyHex {
		return r
	}
	challenge, err := registry010.PoPChallenge010(q.RegistryID, q.AgentID, q.Name, q.Alg, key)
	if err != nil {
		return r
	}
	digest := sha256.Sum256(challenge)
	r.Verdict = "ACCEPT"
	r.ChallengeHex = hex.EncodeToString(challenge)
	r.ChallengeSHA256 = hex.EncodeToString(digest[:])
	return r
}

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil || len(raw) > 4096 {
		os.Exit(2)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var q request
	if decoder.Decode(&q) != nil || decoder.Decode(new(any)) != io.EOF {
		os.Exit(2)
	}
	if json.NewEncoder(os.Stdout).Encode(evaluate(q)) != nil {
		os.Exit(2)
	}
}
