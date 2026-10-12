package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sage-x-project/sage-adk/core/a2abinding"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPolicyContractsDirectAndTLS(t *testing.T) {
	raw, e := os.ReadFile("../../vectors/0.10.0/a2a-call-observations.json")
	if e != nil {
		t.Fatal(e)
	}
	var suite struct {
		Cases []struct {
			ID, Execution string
			Input         fixtureInput
			Expected      map[string]output
		}
	}
	if e = json.Unmarshal(raw, &suite); e != nil {
		t.Fatal(e)
	}
	if len(suite.Cases) != 23 {
		t.Fatal("incomplete contract set")
	}
	for _, c := range suite.Cases {
		if c.Execution == "unsupported" {
			continue
		}
		for _, mode := range []string{"direct", "tls"} {
			t.Run(c.ID+"/"+mode, func(t *testing.T) {
				got, e := observe(c.Input, mode)
				if e != nil {
					t.Fatal(e)
				}
				a, _ := json.Marshal(got)
				b, _ := json.Marshal(c.Expected[mode])
				if !bytes.Equal(a, b) {
					t.Fatalf("got %s want %s", a, b)
				}
			})
		}
	}
}
func TestInputBoundaries(t *testing.T) {
	for _, raw := range []string{"", "{}", "null", "{} {}", `{"mode":"direct","fixture":{"unknown":true}}`} {
		var out, err bytes.Buffer
		if run(bytes.NewBufferString(raw), &out, &err) == 0 || out.Len() != 0 || err.String() != "invalid fixture\n" {
			t.Fatal(raw, out.String(), err.String())
		}
	}
	var out, err bytes.Buffer
	if run(bytes.NewReader(bytes.Repeat([]byte(" "), 1048577)), &out, &err) == 0 {
		t.Fatal("oversized fixture")
	}
}

func validInput(t *testing.T) fixtureInput {
	t.Helper()
	raw, e := os.ReadFile("../../vectors/0.10.0/a2a-call-observations.json")
	if e != nil {
		t.Fatal(e)
	}
	var suite struct {
		Cases []struct {
			Execution string
			Input     fixtureInput
		}
	}
	if e = json.Unmarshal(raw, &suite); e != nil {
		t.Fatal(e)
	}
	for _, c := range suite.Cases {
		if c.Execution == "policy" {
			return c.Input
		}
	}
	t.Fatal("policy input missing")
	return fixtureInput{}
}
func TestValidFramingAndInvalidFixtureConfiguration(t *testing.T) {
	in := validInput(t)
	raw, _ := json.Marshal(request{Mode: "direct", Fixture: in})
	var out, stderr bytes.Buffer
	if run(bytes.NewReader(raw), &out, &stderr) != 0 || !json.Valid(out.Bytes()) || stderr.Len() != 0 {
		t.Fatal("valid framed input")
	}
	for _, mode := range []string{"unknown", ""} {
		if _, e := observe(in, mode); e == nil {
			t.Fatal("invalid mode accepted")
		}
	}
	bad := in
	bad.API = "unknown"
	if _, e := observe(bad, "direct"); e == nil {
		t.Fatal("invalid API accepted")
	}
	for _, key := range []string{"xx", "00"} {
		bad = in
		bad.KeyHex = key
		if _, e := observe(bad, "direct"); e == nil {
			t.Fatal("bad public key accepted")
		}
	}
	for _, card := range []string{"{", "{}", `{"signatures":[0]}`} {
		bad = in
		bad.ClientCardInvalid = true
		bad.Card = card
		if _, e := observe(bad, "direct"); e == nil {
			t.Fatal("invalid client fixture")
		}
	}
}
func TestDeniedFinalCheckNeverPublishesTheHTTPBody(t *testing.T) {
	for _, mode := range []string{"direct", "tls"} {
		t.Run(mode, func(t *testing.T) {
			var published atomic.Int32
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { published.Add(1) }))
			defer ts.Close()
			o := &observer{out: emptyOutput(), mode: mode, tls: ts}
			_, e := o.exchange(context.Background(), frame{Scope: "fixture-policy-only"}, func(context.Context) error { return errors.New("fixture gate denied") })
			if e == nil || published.Load() != 0 || o.out.FinalChecks != 1 {
				t.Fatal("denied gate published", e, published.Load(), o.out.FinalChecks)
			}
		})
	}
}
func TestFixtureInfrastructureFailuresAreNotPolicyRejections(t *testing.T) {
	for _, mode := range []string{"status", "bound", "json", "missing", "status-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "status" {
					w.WriteHeader(500)
					return
				}
				if mode == "bound" {
					fmt.Fprint(w, strings.Repeat("x", 16385))
					return
				}
				if mode == "missing" {
					w.WriteHeader(403)
					fmt.Fprint(w, "{}")
					return
				}
				if mode == "status-mismatch" {
					w.WriteHeader(403)
					fmt.Fprint(w, `{"Sender":"fixture","Payload":"YQ==","Error":""}`)
					return
				}
				fmt.Fprint(w, "{")
			}))
			defer ts.Close()
			o := &observer{out: emptyOutput(), mode: "tls", tls: ts}
			if _, e := o.exchange(context.Background(), frame{Scope: "fixture-policy-only"}, nil); e == nil {
				t.Fatal("infrastructure failure masked")
			}
		})
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ts.Close()
	o := &observer{out: emptyOutput(), mode: "tls", tls: ts}
	if _, e := o.owner(context.Background(), a2abinding.ProtectedCall{}, func(context.Context) error { return nil }); e == nil || o.failure == nil {
		t.Fatal("failed TLS mislabeled as policy rejection")
	}
}
func TestFixtureFrameIsLocalAndClosed(t *testing.T) {
	o := &observer{out: emptyOutput()}
	for _, raw := range []string{`{}`, `{"Scope":"foreign"}`, `{"Unknown":true}`} {
		r := httptest.NewRequest("POST", "https://fixture.invalid/policy", strings.NewReader(raw))
		w := httptest.NewRecorder()
		o.serve(w, r)
		if w.Code != 400 {
			t.Fatal("bad fixture frame accepted")
		}
	}
	w := httptest.NewRecorder()
	o.serve(w, httptest.NewRequest("GET", "https://fixture.invalid/policy", nil))
	if w.Code != 400 {
		t.Fatal("method accepted")
	}
	if o.out.Dispatches != 0 || len(o.out.Payloads) != 0 {
		t.Fatal("invalid frame reached ADK")
	}
}

func TestReplyFramePresenceTypesAndStatus(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", "{}", `{"Sender":"a","Payload":"YQ=="}`, `{"Sender":null,"Payload":"YQ==","Error":""}`, `{"Sender":"a","Payload":"YQ==","Error":null}`, `{"Sender":"a","Payload":"YQ==","Error":"","Extra":true}`, `{"Sender":"a","Payload":"YQ==","Error":"","Sender":"a"}`, `{"Sender":"a","Payload":1,"Error":""}`, `{"Sender":"a","Payload":"!","Error":""}`, `{"Sender":"a","Payload":"YQ==","Error":""} {}`, `{"Sender":"a",`, `{"Sender"}`} {
		if _, e := parseReply([]byte(raw), 200); e == nil {
			t.Fatal("bad reply accepted", raw)
		}
	}
	for _, status := range []int{403, 500} {
		if _, e := parseReply([]byte(`{"Sender":"a","Payload":"YQ==","Error":""}`), status); e == nil {
			t.Fatal("status mismatch")
		}
	}
	if _, e := parseReply([]byte(`{"Sender":"a","Payload":"YQ==","Error":""}`), 200); e != nil {
		t.Fatal(e)
	}
	if _, e := parseReply([]byte(`{"Sender":"","Payload":null,"Error":"authentication failed"}`), 403); e != nil {
		t.Fatal(e)
	}
	if _, e := parseReply([]byte(`{"Sender":"","Payload":"","Error":"authentication failed"}`), 403); e == nil {
		t.Fatal("non-null payload on refusal")
	}
}
