package conformance

import (
	"encoding/json"
	"os"
	"testing"
)

func TestHTTPBoundaryExpansionMatchesIndependentWireHashes(t *testing.T) {
	f, err := os.Open("../../vectors/0.10.0/http-boundaries.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	suite, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../docs/evidence/http-boundary-proofs.json")
	if err != nil {
		t.Fatal(err)
	}
	var proofs map[string]struct {
		Request  string `json:"request_sha256"`
		Response string `json:"response_sha256"`
	}
	if err := json.Unmarshal(data, &proofs); err != nil {
		t.Fatal(err)
	}
	for _, c := range suite.Cases {
		t.Run(c.ID, func(t *testing.T) {
			message, err := DecodeHTTPBoundaryInput(c.Input)
			if err != nil {
				t.Fatal(err)
			}
			if Digest(message.Request) != proofs[c.ID].Request || Digest(message.Response) != proofs[c.ID].Response {
				t.Fatal("expanded bytes differ from independently signed fixture")
			}
		})
	}
}

func TestHTTPBoundaryInvalidControlsAreErrors(t *testing.T) {
	data, err := os.ReadFile("../../vectors/0.10.0/http-boundaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var suite Suite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []map[string]any{
		{"now_unix": nil}, {"now_unix": -1}, {"now_unix": 0.5}, {"clock_trusted": nil},
		{"request_hex": "zz"}, {"request_padding": -1}, {"request_padding": 16777218},
		{"request_padding": 2}, {"trusted_keys": map[string]string{}},
		{"body_repeat": 2}, {"expected_target": "http://agent.example/"}, {"unknown_control": true},
	} {
		var input map[string]any
		if err := json.Unmarshal(suite.Cases[0].Input, &input); err != nil {
			t.Fatal(err)
		}
		for k, v := range mutation {
			input[k] = v
		}
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeHTTPBoundaryInput(raw); err == nil {
			t.Fatalf("invalid harness controls accepted: %v", mutation)
		}
	}
}
