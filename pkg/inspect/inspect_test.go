package inspect

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/sage/pkg/agent/core/rfc9421"
	"github.com/sage-x-project/sage/pkg/agent/did"
	"github.com/sage-x-project/sage/pkg/vectors"
)

const testDID = "did:sage:ethereum:0x1111111111111111111111111111111111111111"

func TestRunVectorsAgainstFreshGeneration(t *testing.T) {
	dir := t.TempDir()
	if err := vectors.Generate(dir); err != nil {
		t.Fatal(err)
	}
	rep, err := RunVectors(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Passed != 26 {
		t.Fatalf("passed %d failed %d: %+v", rep.Passed, rep.Failed, rep.Results)
	}
	if _, err := RunVectors(t.TempDir()); err != nil {
		t.Fatalf("missing files should be reported, not returned: %v", err)
	}
	rep, _ = RunVectors(t.TempDir())
	if rep.OK() || rep.Failed != 26 {
		t.Fatalf("empty dir: passed %d failed %d", rep.Passed, rep.Failed)
	}
}

func signedRequest(t *testing.T, priv ed25519.PrivateKey) (*http.Request, []byte) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`
	req, _ := http.NewRequest(http.MethodPost, "https://agent-b.example/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Digest", rfc9421.ComputeContentDigest([]byte(body)))
	req.Header.Set("X-SAGE-DID", testDID)
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	params := &rfc9421.SignatureInputParams{
		CoveredComponents: []string{`"@method"`, `"@target-uri"`, `"@authority"`, `"content-type"`, `"content-digest"`, `"x-sage-did"`, `"date"`},
		KeyID:             testDID + "#key-1", Algorithm: "ed25519", Created: time.Now().Unix(), Nonce: "n-1",
	}
	if err := rfc9421.NewHTTPVerifier().SignRequest(req, "sig1", params, priv); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	req.Body = io.NopCloser(strings.NewReader(body))
	if err := req.Write(&buf); err != nil {
		t.Fatal(err)
	}
	req.Body = io.NopCloser(strings.NewReader(body))
	return req, buf.Bytes()
}

func TestInspectRequestRoundTripThroughRawBytes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, raw := signedRequest(t, priv)
	req, err := ReadRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	rep := InspectRequest(req, MessageOptions{PublicKey: pub})
	if !rep.Verified || rep.DID != testDID || rep.KeyID != testDID+"#key-1" {
		t.Fatalf("not verified: %+v", rep.Checks)
	}
	if !strings.Contains(rep.SignatureBase, `"@signature-params"`) {
		t.Fatalf("signature base missing: %q", rep.SignatureBase)
	}
	// Explain-only and wrong key.
	rep = InspectRequest(mustReq(t, raw), MessageOptions{})
	if rep.Verified {
		t.Fatal("verified without a key")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	rep = InspectRequest(mustReq(t, raw), MessageOptions{PublicKey: other})
	if rep.Verified {
		t.Fatal("verified with the wrong key")
	}
	// Tampered body: digest check fails.
	tampered := bytes.Replace(raw, []byte(`"id":1`), []byte(`"id":2`), 1)
	rep = InspectRequest(mustReq(t, tampered), MessageOptions{PublicKey: pub})
	if rep.Verified || !hasCheck(rep.Checks, "content-digest", "fail") {
		t.Fatalf("tampered body not detected: %+v", rep.Checks)
	}
}

func TestInspectResponseBinding(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	req, rawReq := signedRequest(t, priv)
	srv := httptest.NewServer((&rfc9421.ResponseSigner{PrivateKey: priv, KeyID: testDID + "#key-1", Algorithm: "ed25519"}).Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	})))
	defer srv.Close()
	out, _ := http.NewRequest(req.Method, srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	out.Header = req.Header.Clone()
	resp, err := http.DefaultClient.Do(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	if err := resp.Write(&buf); err != nil {
		t.Fatal(err)
	}
	parsedReq := mustReq(t, rawReq)
	// The server signed @target-uri of the request it saw (the httptest URL).
	parsedReq.URL, parsedReq.Host = out.URL, out.Host
	parsed, err := ReadResponse(buf.Bytes(), parsedReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parsed.Body.Close() }()
	rep := InspectResponse(parsed, MessageOptions{PublicKey: pub, Request: parsedReq})
	if !rep.Verified || !hasCheck(rep.Checks, "request-binding", "pass") {
		t.Fatalf("response not verified: %+v", rep.Checks)
	}
}

func TestInspectCard(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	meta := &did.AgentMetadataV4{DID: testDID, Name: "a", Endpoint: "https://a.example", IsActive: true, CreatedAt: now, UpdatedAt: now,
		Keys: []did.AgentKey{{Type: did.KeyTypeEd25519, KeyData: pub, Verified: true, CreatedAt: now}}}
	card, err := did.GenerateA2ACardWithProof(meta, priv, did.KeyTypeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := jsonMarshal(card)
	rep := InspectCard(raw)
	if !rep.Verified || rep.DID != testDID {
		t.Fatalf("card not verified: %+v", rep.Checks)
	}
	bad := bytes.Replace(raw, []byte(`"name":"a"`), []byte(`"name":"b"`), 1)
	if rep := InspectCard(bad); rep.Verified {
		t.Fatal("tampered card verified")
	}
	if rep := InspectCard([]byte("{")); len(rep.Checks) == 0 || rep.Checks[0].Status != "fail" {
		t.Fatal("garbage accepted")
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParsePublicKey("0x" + hex.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey("zz"); err == nil {
		t.Fatal("bad hex accepted")
	}
}

func mustReq(t *testing.T, raw []byte) *http.Request {
	t.Helper()
	req, err := ReadRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func hasCheck(checks []Check, name, status string) bool {
	for _, c := range checks {
		if c.Name == name && c.Status == status {
			return true
		}
	}
	return false
}
