package inspect

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/sage-x-project/sage/pkg/agent/core/rfc9421"
)

// Check is one named observation about a message.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass, fail, info, skip
	Detail string `json:"detail,omitempty"`
}

// MessageReport explains a signed HTTP request or response.
type MessageReport struct {
	Kind           string                                   `json:"kind"` // request or response
	Label          string                                   `json:"label,omitempty"`
	KeyID          string                                   `json:"keyid,omitempty"`
	DID            string                                   `json:"did,omitempty"`
	Algorithm      string                                   `json:"alg,omitempty"`
	Created        int64                                    `json:"created,omitempty"`
	Expires        int64                                    `json:"expires,omitempty"`
	Nonce          string                                   `json:"nonce,omitempty"`
	Components     []string                                 `json:"components,omitempty"`
	SignatureBase  string                                   `json:"signature_base,omitempty"`
	Signatures     map[string]*rfc9421.SignatureInputParams `json:"-"`
	Checks         []Check                                  `json:"checks"`
	Verified       bool                                     `json:"verified"`
	AllSignatures  []string                                 `json:"all_signatures,omitempty"`
	ContentDigest  string                                   `json:"content_digest,omitempty"`
	ExpectedDigest string                                   `json:"expected_digest,omitempty"`
}

func (r *MessageReport) add(name, status, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
}

// MessageOptions control verification.
type MessageOptions struct {
	// PublicKey verifies the signature; nil only explains the message.
	PublicKey crypto.PublicKey
	// Request is the request a response is bound to (responses only).
	Request *http.Request
	// Label selects the signature; empty picks the first label.
	Label string
	// Now overrides the clock for the timing checks.
	Now func() time.Time
	// IgnoreAge skips the created/expires checks (for archived messages).
	IgnoreAge bool
}

// ParsePublicKey accepts a hex key: 32 bytes Ed25519, 33/65 bytes
// secp256k1, or 65 bytes P-256 when prefixed with "p256:".
func ParsePublicKey(spec string) (crypto.PublicKey, error) {
	spec = strings.TrimSpace(spec)
	p256 := strings.HasPrefix(spec, "p256:")
	spec = strings.TrimPrefix(strings.TrimPrefix(spec, "p256:"), "0x")
	raw, err := hex.DecodeString(spec)
	if err != nil {
		return nil, err
	}
	switch {
	case len(raw) == ed25519.PublicKeySize && !p256:
		return ed25519.PublicKey(raw), nil
	case len(raw) == 33:
		return ethcrypto.DecompressPubkey(raw)
	case len(raw) == 65 && !p256:
		return ethcrypto.UnmarshalPubkey(raw)
	case len(raw) == 65 && p256:
		return parseP256(raw)
	}
	return nil, fmt.Errorf("unsupported key length %d", len(raw))
}

// ReadRequest parses a raw HTTP/1.x request (as captured on the wire).
func ReadRequest(raw []byte) (*http.Request, error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	// http.ReadRequest leaves URL relative; RFC 9421 needs the absolute target.
	if req.URL.Host == "" {
		req.URL.Host = req.Host
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}
	}
	return req, nil
}

// ReadResponse parses a raw HTTP/1.x response.
func ReadResponse(raw []byte, req *http.Request) (*http.Response, error) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// InspectRequest explains and optionally verifies a signed request.
func InspectRequest(req *http.Request, o MessageOptions) *MessageReport {
	r := &MessageReport{Kind: "request"}
	body := drain(&req.Body)
	params := r.parseSignature(req.Header, o.Label)
	if params == nil {
		return r
	}
	base, err := rfc9421.NewCanonicalizer().BuildSignatureBase(req, r.Label, params)
	if err != nil {
		r.add("signature-base", "fail", err.Error())
	} else {
		r.SignatureBase = base
		r.add("signature-base", "info", "reconstructed")
	}
	r.checkDigest(req.Header, body)
	r.checkTiming(params, o)
	r.checkKeyID(params, req.Header.Get("X-SAGE-DID"))
	if o.PublicKey == nil {
		r.add("verify", "skip", "no public key given")
		return r
	}
	opts := rfc9421.StrictHTTPVerificationOptions()
	opts.SignatureName = r.Label
	opts.DisableReplayCheck = true
	opts.ExpectedDID = r.DID
	if o.IgnoreAge {
		opts.MaxAge = 0
		opts.MaxClockSkew = 100 * 365 * 24 * time.Hour
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	if err := rfc9421.NewHTTPVerifierWithReplayGuard(nil).VerifyRequest(req, o.PublicKey, opts); err != nil {
		r.add("verify", "fail", err.Error())
	} else {
		r.Verified = true
		r.add("verify", "pass", "strict request verification (replay check disabled)")
	}
	return r
}

// InspectResponse explains and optionally verifies a signed response.
func InspectResponse(resp *http.Response, o MessageOptions) *MessageReport {
	r := &MessageReport{Kind: "response"}
	body := drain(&resp.Body)
	params := r.parseSignature(resp.Header, o.Label)
	if params == nil {
		return r
	}
	req := o.Request
	if req == nil {
		req = resp.Request
	}
	if req == nil {
		r.add("request-binding", "fail", "no request given; ;req components cannot be rebuilt")
		return r
	}
	base, err := rfc9421.NewCanonicalizer().BuildResponseSignatureBase(resp, req, r.Label, params)
	if err != nil {
		r.add("signature-base", "fail", err.Error())
	} else {
		r.SignatureBase = base
		r.add("signature-base", "info", "reconstructed")
	}
	bound := false
	for _, c := range params.CoveredComponents {
		if strings.Contains(c, ";req") {
			bound = true
		}
	}
	if bound {
		r.add("request-binding", "pass", "covers ;req components")
	} else {
		r.add("request-binding", "fail", "no ;req component; response is not bound to its request")
	}
	r.checkDigest(resp.Header, body)
	r.checkTiming(params, o)
	r.checkKeyID(params, "")
	if o.PublicKey == nil {
		r.add("verify", "skip", "no public key given")
		return r
	}
	opts := rfc9421.StrictHTTPResponseVerificationOptions()
	opts.SignatureName = r.Label
	opts.DisableReplayCheck = true
	opts.ExpectedDID = r.DID
	if o.IgnoreAge {
		opts.MaxAge = 0
		opts.MaxClockSkew = 100 * 365 * 24 * time.Hour
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if req.Body != nil {
		req.Body = io.NopCloser(bytes.NewReader(drain(&req.Body)))
	}
	if err := rfc9421.NewHTTPVerifierWithReplayGuard(nil).VerifyResponse(resp, req, o.PublicKey, opts); err != nil {
		r.add("verify", "fail", err.Error())
	} else {
		r.Verified = true
		r.add("verify", "pass", "strict response verification")
	}
	return r
}

func (r *MessageReport) parseSignature(h http.Header, label string) *rfc9421.SignatureInputParams {
	inputs, err := rfc9421.ParseSignatureInput(h.Get("Signature-Input"))
	if err != nil || len(inputs) == 0 {
		detail := "missing"
		if err != nil {
			detail = err.Error()
		}
		r.add("signature-input", "fail", detail)
		return nil
	}
	for l := range inputs {
		r.AllSignatures = append(r.AllSignatures, l)
	}
	if label == "" {
		for l := range inputs {
			if label == "" || l < label {
				label = l
			}
		}
	}
	params, ok := inputs[label]
	if !ok {
		r.add("signature-input", "fail", fmt.Sprintf("label %q not present", label))
		return nil
	}
	r.Label, r.KeyID, r.Algorithm, r.Created, r.Expires, r.Nonce = label, params.KeyID, params.Algorithm, params.Created, params.Expires, params.Nonce
	r.Components = params.CoveredComponents
	r.Signatures = inputs
	r.add("signature-input", "pass", fmt.Sprintf("label %s, %d components", label, len(params.CoveredComponents)))
	if h.Get("Signature") == "" {
		r.add("signature", "fail", "missing")
		return nil
	}
	r.add("signature", "pass", "present")
	return params
}

func (r *MessageReport) checkDigest(h http.Header, data []byte) {
	got := h.Get("Content-Digest")
	r.ContentDigest = got
	if len(data) == 0 {
		if got == "" {
			r.add("content-digest", "info", "no body, no digest")
			return
		}
	}
	want := rfc9421.ComputeContentDigest(data)
	r.ExpectedDigest = want
	switch {
	case got == "":
		r.add("content-digest", "fail", "body present but no Content-Digest")
	case strings.Contains(got, want):
		r.add("content-digest", "pass", "sha-256 matches the body")
	default:
		r.add("content-digest", "fail", "sha-256 does not match the body")
	}
}

func (r *MessageReport) checkTiming(p *rfc9421.SignatureInputParams, o MessageOptions) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if p.Created == 0 {
		r.add("created", "fail", "missing")
	} else {
		age := now().Unix() - p.Created
		status := "pass"
		if !o.IgnoreAge && (age > 300 || age < -300) {
			status = "fail"
		}
		r.add("created", status, fmt.Sprintf("%s (%ds ago)", time.Unix(p.Created, 0).UTC().Format(time.RFC3339), age))
	}
	if p.Nonce == "" {
		r.add("nonce", "fail", "missing; replay protection impossible")
	} else {
		r.add("nonce", "pass", p.Nonce)
	}
}

func (r *MessageReport) checkKeyID(p *rfc9421.SignatureInputParams, headerDID string) {
	r.DID = rfc9421.KeyIDDID(p.KeyID)
	switch {
	case p.KeyID == "":
		r.add("keyid", "fail", "missing")
	case !strings.HasPrefix(r.DID, "did:"):
		r.add("keyid", "fail", "keyid is not a DID: "+p.KeyID)
	case headerDID != "" && headerDID != r.DID:
		r.add("keyid", "fail", "X-SAGE-DID "+headerDID+" differs from keyid DID "+r.DID)
	default:
		r.add("keyid", "pass", r.DID)
	}
}

// drain reads the whole body, leaves a fresh reader in its place and
// returns the bytes so several checks can consume the same body.
func drain(body *io.ReadCloser) []byte {
	if *body == nil || *body == http.NoBody {
		return nil
	}
	data, _ := io.ReadAll(*body)
	_ = (*body).Close()
	*body = io.NopCloser(bytes.NewReader(data))
	return data
}
