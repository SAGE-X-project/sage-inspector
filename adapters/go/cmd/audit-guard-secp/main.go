// Audit public secp256k1 fixtures independently of SAGE verification code.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
	"math/big"
	"os"
)

func audit(raw []byte) (int, error) {
	var suite struct {
		Cases []struct {
			ID        string                     `json:"id"`
			Operation string                     `json:"operation"`
			Input     map[string]json.RawMessage `json:"input"`
			Audit     struct {
				Algorithm string `json:"algorithm"`
				Message   string `json:"message_hex"`
				Signature string `json:"signature_hex"`
				Valid     bool   `json:"cryptographically_valid"`
			} `json:"audit"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		return 0, err
	}
	n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	half := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	count := 0
	for _, c := range suite.Cases {
		if c.Audit.Algorithm != "secp256k1" {
			continue
		}
		var envelopeHex, publicHex string
		if e := json.Unmarshal(c.Input["envelope_hex"], &envelopeHex); e != nil {
			return 0, e
		}
		if e := json.Unmarshal(c.Input["public_key_hex"], &publicHex); e != nil {
			return 0, e
		}
		envelope, e := hex.DecodeString(envelopeHex)
		if e != nil {
			return 0, e
		}
		public, e := hex.DecodeString(publicHex)
		if e != nil {
			return 0, e
		}
		var env map[string]json.RawMessage
		if e = json.Unmarshal(envelope, &env); e != nil {
			return 0, e
		}
		role, domain := "intent", "sage-execution-intent|0.10.0"
		if c.Operation == "sage.guard.result.verify" {
			role, domain = "result", "sage-tool-result|0.10.0"
		} else if c.Operation != "sage.guard.intent.verify" {
			return 0, fmt.Errorf("operation")
		}
		var object any
		decoder := json.NewDecoder(bytes.NewReader(env[role]))
		decoder.UseNumber()
		if e = decoder.Decode(&object); e != nil {
			return 0, e
		}
		// Fixtures use ASCII keys/values and safe integers: sorted Go JSON equals JCS here.
		canonical, e := json.Marshal(object)
		if e != nil {
			return 0, e
		}
		message := append([]byte(domain+"\x00"), canonical...)
		var proof string
		if e = json.Unmarshal(env["proof"], &proof); e != nil {
			return 0, e
		}
		sig, e := base64.RawURLEncoding.DecodeString(proof)
		if e != nil {
			return 0, e
		}
		if len(sig) != 65 || len(public) != 65 || public[0] != 4 || hex.EncodeToString(message) != c.Audit.Message || hex.EncodeToString(sig) != c.Audit.Signature || !c.Audit.Valid {
			return 0, fmt.Errorf("fixture correlation: %s", c.ID)
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:64])
		if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(half) > 0 || sig[64] > 1 {
			return 0, fmt.Errorf("noncanonical signature")
		}
		h := sha3.NewLegacyKeccak256()
		h.Write(message)
		digest := h.Sum(nil)
		key, _, e := ecdsa.RecoverCompact(append([]byte{27 + sig[64]}, sig[:64]...), digest)
		if e != nil || !bytes.Equal(key.SerializeUncompressed(), public) {
			return 0, fmt.Errorf("recovered key mismatch")
		}
		var scalarR, scalarS secp.ModNScalar
		scalarR.SetByteSlice(sig[:32])
		scalarS.SetByteSlice(sig[32:64])
		if !ecdsa.NewSignature(&scalarR, &scalarS).Verify(digest, key) {
			return 0, fmt.Errorf("ECDSA verification")
		}
		count++
	}
	if count != 4 {
		return 0, fmt.Errorf("expected four secp256k1 cases")
	}
	return count, nil
}
func main() {
	if len(os.Args) != 2 {
		panic("fixture path required")
	}
	raw, e := os.ReadFile(os.Args[1])
	if e == nil {
		var count int
		count, e = audit(raw)
		if e == nil {
			fmt.Printf("{\"secp_cases\":%d,\"low_s\":true,\"recovery\":true}\n", count)
		}
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
