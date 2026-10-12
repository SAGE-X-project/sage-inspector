// The adapter observes only a card verifier against a public fixture Source.
// It is not a Registry Source or a protected transport implementation.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sage-x-project/did-go/advanced/sage"
	didgo "github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/sage-adk/core/a2abinding"
	"github.com/sage-x-project/sage/pkg/agent/registry010"
)

type input struct {
	Card         string      `json:"card"`
	ExpectedPeer string      `json:"expected_peer"`
	Record       recordInput `json:"record"`
}
type recordInput struct {
	DID          string   `json:"did"`
	Controller   string   `json:"controller"`
	State        string   `json:"state"`
	Version      string   `json:"version"`
	KeyName      string   `json:"key_name"`
	KeyAlg       string   `json:"key_alg"`
	KeyState     string   `json:"key_state"`
	KeyHex       string   `json:"key_hex"`
	ServiceURLs  []string `json:"service_urls"`
	ServiceTypes []string `json:"service_types,omitempty"`
}
type output struct {
	Accepted   bool     `json:"accepted"`
	Error      string   `json:"error"`
	DID        string   `json:"did"`
	Version    string   `json:"version"`
	Interfaces []string `json:"interfaces"`
}
type fixtureSource struct{ record sage.Record }

func (s fixtureSource) Observe(context.Context, didgo.DID) (sage.Record, error) { return s.record, nil }

type fixtureClock struct{}

func (fixtureClock) Now() (registry010.Stamp, error) {
	return registry010.Stamp{MonoMS: 100, Unix: 101}, nil
}

func observe(in input) (output, error) {
	out := output{Interfaces: []string{}}
	d, e := didgo.Parse(in.Record.DID)
	if e != nil {
		return out, e
	}
	material, e := hex.DecodeString(in.Record.KeyHex)
	if e != nil {
		return out, e
	}
	issued := int64(100)
	r := sage.Record{DID: d, Controller: in.Record.Controller, State: sage.State(in.Record.State), Version: in.Record.Version,
		Keys:        []sage.Key{{Name: in.Record.KeyName, Alg: in.Record.KeyAlg, Material: material, State: sage.KeyState(in.Record.KeyState)}},
		Observation: sage.Observation{Issued: &issued, Source: "inspector-public-fixture", Time: 101}}
	if len(in.Record.ServiceTypes) > 0 && len(in.Record.ServiceTypes) != len(in.Record.ServiceURLs) {
		return out, errors.New("service type count")
	}
	for i, u := range in.Record.ServiceURLs {
		kind := "A2AInterface"
		if len(in.Record.ServiceTypes) > 0 {
			kind = in.Record.ServiceTypes[i]
		}
		r.Services = append(r.Services, sage.Service{Name: fmt.Sprintf("a2a%d", i), Type: kind, URI: u})
	}
	v, e := a2abinding.NewVerifier(a2abinding.VerifierConfig{Source: fixtureSource{r}, Clock: fixtureClock{}, ExpectedPeer: in.ExpectedPeer})
	if e != nil {
		return out, e
	}
	card, e := v.Verify(context.Background(), []byte(in.Card))
	if e != nil {
		out.Error = e.Error()
		return out, nil
	}
	out.Accepted = true
	out.DID = card.DID()
	out.Version = card.RecordVersion()
	for _, iface := range card.Interfaces() {
		out.Interfaces = append(out.Interfaces, iface.URL)
	}
	return out, nil
}

func run(stdin io.Reader, stdout, stderr io.Writer) int {
	raw, e := io.ReadAll(io.LimitReader(stdin, 1048577))
	var in input
	if e == nil && len(raw) <= 1048576 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		e = dec.Decode(&in)
		if e == nil {
			var trailing any
			if dec.Decode(&trailing) != io.EOF {
				e = errors.New("trailing input")
			}
		}
	} else {
		e = errors.New("bounded input")
	}
	if e == nil {
		var out output
		out, e = observe(in)
		if e == nil {
			e = json.NewEncoder(stdout).Encode(out)
		}
	}
	if e != nil {
		fmt.Fprintln(stderr, "invalid fixture")
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Stdin, os.Stdout, os.Stderr)) }
