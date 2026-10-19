package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
)

type suite struct {
	Cases []struct {
		ID        string `json:"id"`
		Execution string `json:"execution"`
		Input     input  `json:"input"`
		Expected  struct {
			SourceCalls int `json:"source_calls"`
			Responses   []struct {
				Status      int    `json:"status"`
				ContentType string `json:"content_type"`
				SageCode    string `json:"sage_code"`
				ProblemType string `json:"problem_type"`
			} `json:"responses"`
		} `json:"expected"`
	} `json:"cases"`
}

func contracts(t *testing.T) suite {
	t.Helper()
	raw, e := os.ReadFile("../../vectors/0.10.0/did-profile-observations.json")
	if e != nil {
		t.Fatal(e)
	}
	var s suite
	if e = json.Unmarshal(raw, &s); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestNativeContracts(t *testing.T) {
	count := 0
	for _, c := range contracts(t).Cases {
		if c.Execution != "native" {
			continue
		}
		count++
		t.Run(c.ID, func(t *testing.T) {
			saved := http.DefaultTransport
			out, e := observe(c.Input)
			if e != nil {
				t.Fatal(e)
			}
			if http.DefaultTransport != saved {
				t.Fatal("default transport not restored")
			}
			if out.SourceCalls != c.Expected.SourceCalls || out.NetworkAttempts != 0 || len(out.Responses) != len(c.Expected.Responses) {
				t.Fatalf("counts: %+v", out)
			}
			for i, row := range out.Responses {
				want := c.Expected.Responses[i]
				if row.Status != want.Status || row.ContentType != want.ContentType || row.ProblemType != want.ProblemType {
					t.Fatalf("response header: %+v", row)
				}
				if row.SageCode != want.SageCode {
					t.Fatalf("sage code: %+v", row)
				}
				raw, err := hex.DecodeString(row.BodyHex)
				if err != nil {
					t.Fatal(err)
				}
				if len(raw) > 0 {
					var obj map[string]any
					if err = json.Unmarshal(raw, &obj); err != nil {
						t.Fatal(err)
					}
					if c.ID == "didp-05-unsupported-accept" {
						if obj["sageCode"] != "representation.unsupported" {
							t.Fatal("missing required representation error code")
						}
					}
					if c.ID == "didp-02-json-envelope" {
						md := obj["didDocumentMetadata"].(map[string]any)
						if value, ok := md["deactivated"].(bool); !ok || value {
							t.Fatal("missing explicit active boolean")
						}
					}
				}
			}
		})
	}
	if count != 25 {
		t.Fatal(count)
	}
}
func TestInputAndOutputFailures(t *testing.T) {
	for _, raw := range []string{"", "{", `{"unknown":true}`, `{} {}`, `{"keys":[{"unknown":true}]}`} {
		if _, e := readInput(strings.NewReader(raw)); e == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	if e := run(strings.NewReader("{"), io.Discard); e == nil {
		t.Fatal("bad JSON accepted")
	}
	if e := run(strings.NewReader(`{}`), io.Discard); e == nil {
		t.Fatal("missing interface accepted")
	}
	c := contracts(t).Cases[0].Input
	for _, accepts := range [][]string{nil, {"a", "b", "c"}} {
		bad := c
		bad.Accepts = accepts
		if _, e := observe(bad); e == nil {
			t.Fatal("unbounded accepts")
		}
	}
	bad := c
	bad.DID = "bad"
	if _, e := observe(bad); e == nil {
		t.Fatal("invalid DID parse")
	}
	bad = c
	bad.Keys = append([]keyInput(nil), c.Keys...)
	bad.Keys[0].Material = "zz"
	if _, e := observe(bad); e == nil {
		t.Fatal("bad key encoding")
	}
	raw, _ := json.Marshal(c)
	var buf bytes.Buffer
	if e := run(bytes.NewReader(raw), &buf); e != nil {
		t.Fatal(e)
	}
	if e := run(bytes.NewReader(raw), badWriter{}); e == nil {
		t.Fatal("writer failure lost")
	}
}

type badWriter struct{}

func (badWriter) Write([]byte) (int, error) { return 0, errors.New("fixture write failure") }
func TestProducerFailureAndDeniedNetwork(t *testing.T) {
	p := fixtureProducer{fail: true, inner: producer.New()}
	if _, _, e := p.Produce(&document.Document{}, representation.ProduceOptions{Version: spec.V11}); e == nil {
		t.Fatal("fallback")
	}
	var n atomic.Int64
	d := denyNetwork{&n}
	if _, e := d.RoundTrip(&http.Request{URL: nil}); e == nil || n.Load() != 1 {
		t.Fatal("default network not denied")
	}
}
func TestMainSuccess(t *testing.T) {
	in, e := os.CreateTemp(t.TempDir(), "input")
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	out, e := os.CreateTemp(t.TempDir(), "output")
	if e != nil {
		t.Fatal(e)
	}
	defer out.Close()
	raw, _ := json.Marshal(contracts(t).Cases[0].Input)
	if _, e = in.Write(raw); e != nil {
		t.Fatal(e)
	}
	if _, e = in.Seek(0, 0); e != nil {
		t.Fatal(e)
	}
	savedIn, savedOut := os.Stdin, os.Stdout
	defer func() { os.Stdin = savedIn; os.Stdout = savedOut }()
	os.Stdin = in
	os.Stdout = out
	main()
	if _, e = out.Seek(0, 0); e != nil {
		t.Fatal(e)
	}
	var got output
	if e = json.NewDecoder(out).Decode(&got); e != nil || got.SourceCalls != 1 {
		t.Fatalf("main output: %v", e)
	}
}

func TestAbsentSourceAndInputBounds(t *testing.T) {
	c := contracts(t).Cases[0].Input
	c.DID = "did:sage:web:registry.example:absent"
	out, e := observe(c)
	if e != nil || out.SourceCalls != 1 || out.Responses[0].SageCode != "record.not-found" {
		t.Fatalf("missing record: %v %+v", e, out)
	}
	if _, e := readInput(strings.NewReader(strings.Repeat(" ", 65537))); e == nil {
		t.Fatal("oversized input accepted")
	}
	if _, e := readInput(badReader{}); e == nil {
		t.Fatal("read failure lost")
	}
}

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, errors.New("fixture read failure") }
