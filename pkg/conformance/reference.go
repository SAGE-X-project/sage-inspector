package conformance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Reference exercises only foundation primitives. It is not a SAGE peer and
// does not certify Ed25519 subgroup rules, JCS canonicalization or Execution Guard.
type Reference struct{}

func (Reference) Observe(ctx context.Context, q Request) (Observation, error) {
	if e := ctx.Err(); e != nil {
		return Observation{}, e
	}
	o := Observation{SchemaVersion: 1, CaseID: q.CaseID, Verdict: "REJECT", Output: json.RawMessage(`{}`)}
	accept := func(v any) (Observation, error) { o.Verdict = "ACCEPT"; o.Output, _ = json.Marshal(v); return o, nil }
	switch q.Operation {
	case "sha256":
		var in struct {
			DataHex string `json:"data_hex"`
		}
		if decode(q.Input, &in) != nil {
			return o, nil
		}
		b, e := hexBytes(in.DataHex)
		if e != nil {
			return o, nil
		}
		return accept(map[string]string{"sha256_hex": Digest(b)})
	case "hkdf-sha256":
		var in struct {
			IKM    string `json:"ikm_hex"`
			Salt   string `json:"salt_hex"`
			Info   string `json:"info_hex"`
			Length int    `json:"length"`
		}
		if decode(q.Input, &in) != nil || in.Length < 0 || in.Length > 255*32 {
			return o, nil
		}
		ikm, e1 := hexBytes(in.IKM)
		salt, e2 := hexBytes(in.Salt)
		info, e3 := hexBytes(in.Info)
		if e1 != nil || e2 != nil || e3 != nil {
			return o, nil
		}
		mac := hmac.New(sha256.New, salt)
		mac.Write(ikm)
		prk := mac.Sum(nil)
		out := []byte{}
		var last []byte
		for i := 1; len(out) < in.Length; i++ {
			if e := ctx.Err(); e != nil {
				return Observation{}, e
			}
			mac = hmac.New(sha256.New, prk)
			mac.Write(last)
			mac.Write(info)
			mac.Write([]byte{byte(i)})
			last = mac.Sum(nil)
			out = append(out, last...)
		}
		return accept(map[string]string{"prk_hex": hex.EncodeToString(prk), "okm_hex": hex.EncodeToString(out[:in.Length])})
	case "base64url-raw.decode":
		var in struct {
			Encoded string `json:"encoded"`
		}
		if decode(q.Input, &in) != nil {
			return o, nil
		}
		b, e := base64.RawURLEncoding.Strict().DecodeString(in.Encoded)
		if e != nil || base64.RawURLEncoding.EncodeToString(b) != in.Encoded {
			return o, nil
		}
		return accept(map[string]string{"data_hex": hex.EncodeToString(b)})
	case "json.syntax":
		var in struct {
			DocumentHex string `json:"document_hex"`
		}
		if decode(q.Input, &in) != nil {
			return o, nil
		}
		b, e := hexBytes(in.DocumentHex)
		if e != nil {
			return o, nil
		}
		if _, e = strictJSON(b); e != nil {
			return o, nil
		}
		return accept(map[string]bool{"valid": true})
	default:
		o.Verdict = "UNSUPPORTED"
		return o, nil
	}
}
func hexBytes(s string) ([]byte, error) {
	if s != strings.ToLower(s) {
		return nil, fmt.Errorf("hex must be lowercase")
	}
	return hex.DecodeString(s)
}
