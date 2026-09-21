package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

func TestAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../../vectors/0.10.0/guard-canonical-signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	if count, err := audit(raw); err != nil || count != 4 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	for _, mode := range []string{"message", "signature", "high-s", "recovery-bit", "invalid-v"} {
		t.Run(mode, func(t *testing.T) {
			var suite map[string]any
			if err := json.Unmarshal(raw, &suite); err != nil {
				t.Fatal(err)
			}
			for _, item := range suite["cases"].([]any) {
				c := item.(map[string]any)
				a := c["audit"].(map[string]any)
				if a["algorithm"] != "secp256k1" {
					continue
				}
				if mode == "message" {
					a["message_hex"] = "00"
					break
				}
				if mode == "signature" {
					a["signature_hex"] = "00"
					break
				}
				in := c["input"].(map[string]any)
				encoded, _ := hex.DecodeString(in["envelope_hex"].(string))
				var env map[string]any
				if err := json.Unmarshal(encoded, &env); err != nil {
					t.Fatal(err)
				}
				sig, _ := base64.RawURLEncoding.DecodeString(env["proof"].(string))
				switch mode {
				case "high-s":
					n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
					n.Sub(n, new(big.Int).SetBytes(sig[32:64])).FillBytes(sig[32:64])
					sig[64] ^= 1
				case "recovery-bit":
					sig[64] ^= 1
				case "invalid-v":
					sig[64] = 2
				}
				env["proof"] = base64.RawURLEncoding.EncodeToString(sig)
				encoded, _ = json.Marshal(env)
				in["envelope_hex"] = hex.EncodeToString(encoded)
				a["signature_hex"] = hex.EncodeToString(sig)
				break
			}
			changed, _ := json.Marshal(suite)
			if _, err := audit(changed); err == nil {
				t.Fatal("accepted invalid fixture")
			}
		})
	}
}
