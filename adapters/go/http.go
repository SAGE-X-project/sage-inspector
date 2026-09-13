package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	core "github.com/sage-x-project/sage/pkg/agent/core/rfc9421"
)

type httpInput struct {
	Request   string `json:"request_hex"`
	Response  string `json:"response_hex"`
	PublicKey string `json:"public_key_hex"`
	Repeat    int    `json:"body_repeat"`
}

var requestCoverage = []string{"@method", "@target-uri", "@authority", "content-type", "content-digest", "x-sage-did", "x-sage-version"}
var responseCoverage = []string{"@status", `"@method";req`, `"@target-uri";req`, `"@authority";req`, `"content-digest";req`, `"signature";req`, `"x-sage-version";req`, "content-type", "content-digest", "x-sage-did", "x-sage-version"}

func httpObserve(op string, input json.RawMessage) (string, map[string]any, error) {
	out := map[string]any{}
	// No injected clock or complete SAGE boundary API exists in this core revision.
	if op == "sage.http.verify" {
		return "UNSUPPORTED", out, nil
	}
	var in httpInput
	if e := json.Unmarshal(input, &in); e != nil {
		return "", nil, e
	}
	raw, e := hex.DecodeString(in.Request)
	if e != nil {
		return "", nil, e
	}
	response, e := hex.DecodeString(in.Response)
	if e != nil {
		return "", nil, e
	}
	if in.Repeat < 1 || in.Repeat > (16<<20)+1 {
		return "", nil, fmt.Errorf("invalid repeat control")
	}
	if in.Repeat > 1 {
		at := bytes.Index(raw, []byte("\r\n\r\n"))
		if at < 0 || len(raw[at+4:]) != 1 {
			return "", nil, fmt.Errorf("repeat needs one body byte")
		}
		raw = append(raw[:at+4], bytes.Repeat(raw[at+4:], in.Repeat)...)
	}
	var req *http.Request
	if len(raw) > 0 {
		req, e = http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if e != nil {
			return "REJECT", out, nil
		}
		defer func() { _ = req.Body.Close() }()
	}
	var resp *http.Response
	if len(response) > 0 {
		resp, e = http.ReadResponse(bufio.NewReader(bytes.NewReader(response)), req)
		if e != nil {
			return "REJECT", out, nil
		}
		defer func() { _ = resp.Body.Close() }()
	}
	if req == nil && resp == nil {
		return "", nil, fmt.Errorf("missing message")
	}
	header := http.Header{}
	if resp != nil {
		header = resp.Header
	} else {
		header = req.Header
	}
	var value string
	switch op {
	case "rfc9421.base":
		var params map[string]*core.SignatureInputParams
		params, e = core.ParseSignatureInput(header.Get("Signature-Input"))
		if e == nil && params["sig1"] == nil {
			e = fmt.Errorf("missing sig1")
		}
		if e == nil {
			if resp != nil {
				value, e = core.NewCanonicalizer().BuildResponseSignatureBase(resp, req, "sig1", params["sig1"])
			} else {
				value, e = core.NewCanonicalizer().BuildSignatureBase(req, "sig1", params["sig1"])
			}
		}
		if e == nil {
			out["base_hex"] = hex.EncodeToString([]byte(value))
		}
	case "sage.content-digest":
		validator := core.NewBodyIntegrityValidator()
		if resp != nil {
			e = validator.ValidateResponseContentDigest(resp, []string{"content-digest"})
		} else {
			e = validator.ValidateContentDigest(req, []string{"content-digest"})
		}
		if e == nil {
			out["valid"] = true
		}
	case "rfc9421.archived.verify":
		var pk []byte
		pk, e = hex.DecodeString(in.PublicKey)
		if e != nil {
			return "", nil, e
		}
		verifier := core.NewHTTPVerifier()
		defer verifier.Close()
		opts := core.StrictHTTPVerificationOptions()
		opts.SignatureName = "sig1"
		opts.MaxAge = 0
		opts.RequiredComponents = requestCoverage
		opts.ExpectedAuthorities = []string{"agent.example"}
		if resp != nil {
			opts = core.StrictHTTPResponseVerificationOptions()
			opts.SignatureName = "sig1"
			opts.MaxAge = 0
			opts.RequiredComponents = responseCoverage
			e = verifier.VerifyResponse(resp, req, ed25519.PublicKey(pk), opts)
		} else {
			e = verifier.VerifyRequest(req, ed25519.PublicKey(pk), opts)
		}
		if e == nil {
			out["valid"] = true
		}
	default:
		return "UNSUPPORTED", out, nil
	}
	if e != nil {
		return "REJECT", map[string]any{}, nil
	}
	return "ACCEPT", out, nil
}
