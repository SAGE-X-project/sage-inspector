package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictDIDObservation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		verdict string
	}{
		{"canonical", "did:sage:web:example.com:agent", "ACCEPT"},
		{"legacy alias", "did:sage:ETH:0xabc", "REJECT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := map[string]any{
				"schema_version": 1, "protocol_version": "0.10.0",
				"profile": "primitive-foundation", "case_id": "one",
				"operation": "sage.did010.parse", "input": map[string]string{"did": tc.input},
			}
			data, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := run(strings.NewReader(string(data)), &output); err != nil {
				t.Fatal(err)
			}
			var response struct {
				Verdict string `json:"verdict"`
			}
			if err := json.Unmarshal(output.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Verdict != tc.verdict {
				t.Fatalf("verdict = %q, want %q", response.Verdict, tc.verdict)
			}
		})
	}
}
