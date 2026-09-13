// Thin adapter: the core alone decides document acceptance.
package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/sage-x-project/sage/pkg/agent/crypto/jcs"
	"github.com/sage-x-project/sage/pkg/agent/crypto/keys"
)

func run(r io.Reader, w io.Writer) error {
	var q struct {
		Schema    int             `json:"schema_version"`
		Version   string          `json:"protocol_version"`
		Profile   string          `json:"profile"`
		Case      string          `json:"case_id"`
		Operation string          `json:"operation"`
		Input     json.RawMessage `json:"input"`
	}
	d := json.NewDecoder(io.LimitReader(r, (4<<20)+1))
	d.DisallowUnknownFields()
	if e := d.Decode(&q); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing input")
	}
	if q.Schema != 1 || q.Version != "0.10.0" || q.Profile != "primitive-foundation" || q.Case == "" {
		return fmt.Errorf("invalid request")
	}
	verdict := "UNSUPPORTED"
	output := map[string]any{}
	if q.Operation == "json.syntax" || q.Operation == "jcs.canonicalize" {
		var in struct {
			Document string `json:"document_hex"`
		}
		if e := json.Unmarshal(q.Input, &in); e != nil {
			return e
		}
		b, e := hex.DecodeString(in.Document)
		if e != nil {
			return e
		}
		canonical, e := jcs.Canonicalize(b)
		verdict = "REJECT"
		if e == nil {
			verdict = "ACCEPT"
			if q.Operation == "json.syntax" {
				output["valid"] = true
			} else {
				output["canonical_hex"] = hex.EncodeToString(canonical)
			}
		}
	}
	if q.Operation == "signature.verify" {
		var in struct {
			Algorithm string `json:"algorithm"`
			Public    string `json:"public_key_hex"`
			Message   string `json:"message_hex"`
			Signature string `json:"signature_hex"`
		}
		if e := json.Unmarshal(q.Input, &in); e != nil {
			return e
		}
		pub, e := hex.DecodeString(in.Public)
		if e != nil {
			return e
		}
		msg, e := hex.DecodeString(in.Message)
		if e != nil {
			return e
		}
		sig, e := hex.DecodeString(in.Signature)
		if e != nil {
			return e
		}
		var key crypto.PublicKey
		switch in.Algorithm {
		case "ed25519":
			key = ed25519.PublicKey(pub)
		case "ecdsa-p256-sha256", "sage-secp256k1-keccak256":
			// The core API takes coordinates, not arbitrary SEC1 wire encodings.
			// Unsupported wire encodings must not be pre-rejected on the core's behalf.
			if len(pub) == 65 && pub[0] == 4 {
				curve := elliptic.P256()
				if in.Algorithm == "sage-secp256k1-keccak256" {
					curve = keys.Secp256k1Curve()
				}
				key, e = keys.ParseECDSAPublicKey(curve, pub[1:33], pub[33:])
			}
		}
		if e != nil {
			verdict = "REJECT"
		} else if key != nil {
			verdict = "REJECT"
			if keys.VerifySignature(key, msg, sig) == nil {
				verdict = "ACCEPT"
				output["valid"] = true
			}
		}
	}

	return json.NewEncoder(w).Encode(map[string]any{"schema_version": 1, "case_id": q.Case, "verdict": verdict, "output": output})
}
func main() {
	if e := run(os.Stdin, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
}
