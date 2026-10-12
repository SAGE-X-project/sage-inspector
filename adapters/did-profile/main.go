// This observer exercises library APIs against an explicit fixture Source.
// It neither validates registry proofs nor grants message key authority.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	sage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
)

type keyInput struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Material  string `json:"material_hex"`
	State     string `json:"state"`
}
type input struct {
	Interface   string     `json:"interface"`
	DID         string     `json:"did"`
	Accepts     []string   `json:"accepts"`
	State       string     `json:"state"`
	Keys        []keyInput `json:"keys"`
	SourceError string     `json:"source_error"`
	FailDID11   bool       `json:"fail_did11"`
}
type output struct {
	SourceCalls     int        `json:"source_calls"`
	NetworkAttempts int64      `json:"network_attempts"`
	Responses       []response `json:"responses"`
}
type response struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	BodyHex     string `json:"body_hex"`
	SageCode    string `json:"sage_code"`
	ProblemType string `json:"problem_type"`
}
type fixtureSource struct {
	record sage.Record
	code   sage.Code
	calls  atomic.Int64
}

func (s *fixtureSource) Observe(_ context.Context, d did.DID) (sage.Record, error) {
	s.calls.Add(1)
	if s.code != "" {
		return sage.Record{}, sage.NewError(s.code, "")
	}
	if d != s.record.DID {
		return sage.Record{}, sage.NewError(sage.CodeRecordNotFound, "")
	}
	return s.record, nil
}

type fixtureProducer struct {
	fail  bool
	inner representation.Producer
}

func (p fixtureProducer) Produce(d *document.Document, o representation.ProduceOptions) ([]byte, string, error) {
	if p.fail && o.Version.String() == "1.1" {
		return nil, "", errors.New("fixture projection unavailable")
	}
	return p.inner.Produce(d, o)
}

type denyNetwork struct{ attempts *atomic.Int64 }

func (d denyNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	d.attempts.Add(1)
	return nil, errors.New("fixture forbids default HTTP transport")
}

func readInput(r io.Reader) (input, error) {
	var in input
	raw, err := io.ReadAll(io.LimitReader(r, 65537))
	if err != nil {
		return in, err
	}
	if len(raw) > 65536 {
		return in, errors.New("oversized fixture input")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return in, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return in, errors.New("trailing input")
	}
	return in, nil
}

func source(in input) (*fixtureSource, error) {
	// The requested DID may deliberately be malformed; the fixture record is fixed.
	d, err := did.Parse("did:sage:web:registry.example:agent-1")
	if err != nil {
		return nil, err
	}
	issued := int64(1799999000)
	r := sage.Record{DID: d, Controller: "controller-1", State: sage.State(in.State), Version: "7",
		Services:    []sage.Service{{Name: "a2a", Type: "A2AInterface", URI: "https://agent.example/a2a"}},
		Observation: sage.Observation{Issued: &issued, Source: "fixture-web-registry", Time: 1800000000}}
	for _, k := range in.Keys {
		raw, e := hex.DecodeString(k.Material)
		if e != nil {
			return nil, e
		}
		r.Keys = append(r.Keys, sage.Key{Name: k.Name, Alg: k.Algorithm, Material: raw, State: sage.KeyState(k.State)})
	}
	return &fixtureSource{record: r, code: sage.Code(in.SourceError)}, nil
}
func observe(in input) (output, error) {
	out := output{Responses: []response{}}
	if (in.Interface != "sage-api" && in.Interface != "did-resolution-tls") || len(in.Accepts) < 1 || len(in.Accepts) > 2 {
		return out, errors.New("unsupported bounded interface")
	}
	src, err := source(in)
	if err != nil {
		return out, err
	}
	p := fixtureProducer{fail: in.FailDID11, inner: producer.New()}
	var attempts atomic.Int64
	savedTransport, savedClient := http.DefaultTransport, http.DefaultClient
	http.DefaultTransport = denyNetwork{&attempts}
	http.DefaultClient = &http.Client{Transport: http.DefaultTransport, Timeout: time.Second}
	defer func() { http.DefaultTransport = savedTransport; http.DefaultClient = savedClient }()
	if in.Interface == "sage-api" {
		d, e := did.Parse(in.DID)
		if e != nil {
			return out, e
		}
		for _, accept := range in.Accepts {
			res := sage.Respond(context.Background(), src, sage.Request{DID: d, Accept: accept}, p)
			row := response{Status: 200, ContentType: res.ContentType, BodyHex: hex.EncodeToString(res.Body)}
			if res.Problem != nil {
				row.Status = res.Problem.Problem().Status
				row.SageCode = string(res.Problem.Code)
				row.ProblemType = res.Problem.Problem().Type
			}
			out.Responses = append(out.Responses, row)
		}
	} else {
		resolver, e := sage.NewResolver(src, consumer.New(), p)
		if e != nil {
			return out, e
		}
		server := httptest.NewUnstartedServer(sage.NewHandler(resolver, "/1.0/identifiers"))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
		server.StartTLS()
		defer server.Close()
		client := server.Client()
		client.Timeout = 5 * time.Second
		for _, accept := range in.Accepts {
			req, e := http.NewRequest(http.MethodGet, server.URL+"/1.0/identifiers/"+url.PathEscape(in.DID), nil)
			if e != nil {
				return out, e
			}
			req.Header.Set("Accept", accept)
			res, e := client.Do(req)
			if e != nil {
				return out, e
			}
			raw, e := io.ReadAll(io.LimitReader(res.Body, 262145))
			res.Body.Close()
			if e != nil {
				return out, e
			}
			if len(raw) > 262144 {
				return out, errors.New("oversized handler output")
			}
			// Decode only diagnostic strings. The independent observer checks the complete raw JSON.
			var obj map[string]any
			if e = json.Unmarshal(raw, &obj); e != nil {
				return out, e
			}
			row := response{Status: res.StatusCode, ContentType: res.Header.Get("Content-Type"), BodyHex: hex.EncodeToString(raw)}
			row.SageCode, _ = obj["sageCode"].(string)
			row.ProblemType, _ = obj["type"].(string)
			out.Responses = append(out.Responses, row)
		}
	}
	out.SourceCalls = int(src.calls.Load())
	out.NetworkAttempts = attempts.Load()
	return out, nil
}
func run(r io.Reader, w io.Writer) error {
	in, e := readInput(r)
	if e != nil {
		return e
	}
	out, e := observe(in)
	if e != nil {
		return e
	}
	return json.NewEncoder(w).Encode(out)
}
func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "DID observer:", err)
		os.Exit(1)
	}
}
