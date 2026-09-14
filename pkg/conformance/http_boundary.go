package conformance

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// HTTPBoundaryInput contains trusted harness controls, not protocol policy.
// DecodeHTTPBoundaryInput validates the controls and expands compact wire recipes.
// It intentionally does not parse or reject malformed HTTP under test.
type HTTPBoundaryInput struct {
	RequestHex        string            `json:"request_hex"`
	ResponseHex       string            `json:"response_hex"`
	PublicKeyHex      string            `json:"public_key_hex"`
	BodyRepeat        int               `json:"body_repeat"`
	NowUnix           *int64            `json:"now_unix"`
	ClockTrusted      *bool             `json:"clock_trusted"`
	ExpectedTarget    string            `json:"expected_target"`
	ExpectedRecipient string            `json:"expected_recipient"`
	TrustedKeys       map[string]string `json:"trusted_keys"`
	RequestPadding    int               `json:"request_padding,omitempty"`
	ResponsePadding   int               `json:"response_padding,omitempty"`
}

// HTTPBoundaryMessage is ready for a subject's bounded raw-message API.
// Verification and the decision to accept belong exclusively to that subject.
type HTTPBoundaryMessage struct {
	Controls HTTPBoundaryInput
	Request  []byte
	Response []byte
}

func DecodeHTTPBoundaryInput(raw json.RawMessage) (*HTTPBoundaryMessage, error) {
	var in HTTPBoundaryInput
	value, err := strictJSON(raw)
	if err != nil {
		return nil, err
	}
	members, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("HTTP controls must be an object")
	}
	for _, name := range []string{"request_hex", "response_hex", "public_key_hex", "body_repeat", "now_unix", "clock_trusted", "expected_target", "expected_recipient", "trusted_keys"} {
		if _, ok := members[name]; !ok {
			return nil, fmt.Errorf("missing HTTP control %s", name)
		}
	}
	for name, value := range members {
		if value == nil {
			return nil, fmt.Errorf("null HTTP control %s", name)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		return nil, err
	}
	if in.BodyRepeat != 1 || in.NowUnix == nil || *in.NowUnix < 0 || *in.NowUnix > 9007199254740991 || in.ClockTrusted == nil {
		return nil, fmt.Errorf("missing or invalid HTTP clock/recipe controls")
	}
	u, err := url.Parse(in.ExpectedTarget)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || len(in.ExpectedTarget) > 8192 {
		return nil, fmt.Errorf("invalid expected HTTP target")
	}
	if !strings.HasPrefix(in.ExpectedRecipient, "did:") || len(in.ExpectedRecipient) > 2048 || len(in.TrustedKeys) < 1 || len(in.TrustedKeys) > 32 {
		return nil, fmt.Errorf("invalid recipient/key controls")
	}
	if key, err := hex.DecodeString(in.PublicKeyHex); err != nil || len(key) != 32 {
		return nil, fmt.Errorf("invalid fixture public key")
	}
	for kid, value := range in.TrustedKeys {
		key, err := hex.DecodeString(value)
		if !strings.HasPrefix(kid, "did:") || !strings.Contains(kid, "#") || strings.HasSuffix(kid, "#") || len(kid) > 4096 || err != nil || len(key) != 32 {
			return nil, fmt.Errorf("invalid trusted key observation")
		}
	}
	request, err := expandHTTPPadding(in.RequestHex, in.RequestPadding)
	if err != nil {
		return nil, err
	}
	response, err := expandHTTPPadding(in.ResponseHex, in.ResponsePadding)
	if err != nil {
		return nil, err
	}
	return &HTTPBoundaryMessage{Controls: in, Request: request, Response: response}, nil
}

func expandHTTPPadding(encoded string, padding int) ([]byte, error) {
	const maxExpanded = (17 << 20) + 32768
	if padding < 0 || padding > (16<<20)+1 {
		return nil, fmt.Errorf("invalid HTTP padding control")
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if padding == 0 {
		return raw, nil
	}
	if len(raw) == 0 || raw[len(raw)-1] != ' ' || !bytes.Contains(raw, []byte("\r\n\r\n")) || len(raw)-1+padding > maxExpanded {
		return nil, fmt.Errorf("invalid HTTP padding recipe")
	}
	return append(raw[:len(raw)-1], bytes.Repeat([]byte{' '}, padding)...), nil
}
