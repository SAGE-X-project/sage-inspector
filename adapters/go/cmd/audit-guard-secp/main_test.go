package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestAudit(t *testing.T) {
	raw, e := os.ReadFile("../../../../vectors/0.10.0/guard-canonical-signatures.json")
	if e != nil {
		t.Fatal(e)
	}
	n, e := audit(raw)
	if e != nil || n != 4 {
		t.Fatalf("%d %v", n, e)
	}
	for _, field := range []string{"message_hex", "signature_hex"} {
		var x map[string]any
		json.Unmarshal(raw, &x)
		for _, item := range x["cases"].([]any) {
			c := item.(map[string]any)
			a := c["audit"].(map[string]any)
			if a["algorithm"] == "secp256k1" {
				a[field] = "00"
				break
			}
		}
		bad, _ := json.Marshal(x)
		if _, e = audit(bad); e == nil {
			t.Fatal("accepted changed " + field)
		}
	}
}
