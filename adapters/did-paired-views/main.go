// This bounded observer uses explicit public fixture records. It is not an
// authoritative Registry provider or protected-message authorization endpoint.
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
	"strconv"

	sage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
)

const fixtureDID = "did:sage:web:registry.example:agent-1"

type input struct {
	Scenario string `json:"scenario"`
}
type view struct {
	BodyHex     string `json:"body_hex"`
	ContentType string `json:"content_type"`
	MetadataHex string `json:"metadata_hex"`
}
type pair struct {
	Core10 *view  `json:"core10"`
	DID11  *view  `json:"did11"`
	Code   string `json:"code"`
}
type output struct {
	SourceCalls   int    `json:"source_calls"`
	ProducerCalls int    `json:"producer_calls"`
	Results       []pair `json:"results"`
}
type fixtureSource struct {
	scenario string
	calls    int
}

func (s *fixtureSource) Observe(_ context.Context, target did.DID) (sage.Record, error) {
	s.calls++
	if s.scenario == "source-stale" {
		return sage.Record{}, sage.NewError(sage.CodeRecordStale, "fixture unavailable")
	}
	if target.String() != fixtureDID || s.calls > 2 || (s.scenario != "changing" && s.calls > 1) {
		return sage.Record{}, sage.NewError(sage.CodeRecordInvalid, "unexpected observation")
	}
	issued := int64(1800000000 + s.calls - 1)
	r := sage.Record{DID: target, Controller: "controller-1", State: sage.StateActive, Version: strconv.Itoa(6 + s.calls),
		Keys: []sage.Key{
			{Name: "agree", Alg: sage.AlgX25519, Material: append([]byte{9}, make([]byte, 31)...), State: sage.KeyAccepted},
			{Name: "sign", Alg: sage.AlgEd25519, Material: []byte{0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a}, State: sage.KeyAccepted},
		},
		Services:    []sage.Service{{Name: "a2a", Type: "A2AInterface", URI: "https://agent.example/a2a"}},
		Observation: sage.Observation{Issued: &issued, Source: "fixture-web-registry", Time: issued + 1}}
	if s.calls == 2 {
		// One update-services mutation: controller and every lifetime key remain.
		r.Services[0].URI = "https://next.example/a2a"
	}
	switch s.scenario {
	case "created":
		r.State = sage.StateCreated
	case "deactivated":
		r.State = sage.StateDeactivated
	case "unusable":
		r.Keys[0].State = sage.KeyRevoked
		expires := issued + 1
		r.Keys[1].Expires = &expires
	}
	return r, nil
}

type fixtureProducer struct {
	scenario string
	calls    int
	buffer   []byte
}

func (p *fixtureProducer) Produce(d *document.Document, o representation.ProduceOptions) ([]byte, string, error) {
	p.calls++
	if p.scenario == "second-error" && p.calls == 2 {
		return []byte("discarded partial bytes"), "", errors.New("fixture projection unavailable")
	}
	data, mt, err := producer.New().Produce(d, o)
	if p.scenario == "scratch" {
		p.buffer = append(p.buffer[:0], data...)
		return p.buffer, mt, err
	}
	return data, mt, err
}

func encodeView(v sage.ProjectionView) (*view, error) {
	md, err := json.Marshal(v.Metadata)
	if err != nil {
		return nil, err
	}
	return &view{BodyHex: hex.EncodeToString(v.Data), ContentType: v.ContentType, MetadataHex: hex.EncodeToString(md)}, nil
}

func observe(in input) (output, error) {
	out := output{Results: []pair{}}
	switch in.Scenario {
	case "changing", "created", "deactivated", "unusable", "second-error", "source-stale", "invalid-id", "scratch":
	default:
		return out, errors.New("unsupported paired observation scenario")
	}
	src := &fixtureSource{scenario: in.Scenario}
	p := &fixtureProducer{scenario: in.Scenario, buffer: make([]byte, 0, 262144)}
	target := fixtureDID
	if in.Scenario == "invalid-id" {
		target = "did:example:unrelated"
	}
	d, err := did.Parse(target)
	if err != nil {
		return out, err
	}
	calls := 1
	if in.Scenario == "changing" {
		calls = 2
	}
	for range calls {
		actual, problem := sage.ObserveViews(context.Background(), src, d, p)
		row := pair{}
		if problem != nil {
			row.Code = string(problem.Code)
		}
		// Preserve any pair even with an error so a partial return cannot hide.
		if actual != nil {
			if in.Scenario == "scratch" && len(p.buffer) > 0 {
				p.buffer[0] = 'x' // Ordinary producer storage reuse after returning.
			}
			row.Core10, err = encodeView(actual.Core10)
			if err != nil {
				return out, err
			}
			if in.Scenario == "scratch" {
				if metadata, ok := actual.Core10.Metadata.Extra["sage"].(map[string]any); ok {
					metadata["controller"] = "caller-owned"
				}
				if len(actual.Core10.Data) > 0 {
					actual.Core10.Data[0] = 'y'
				}
			}
			row.DID11, err = encodeView(actual.DID11)
			if err != nil {
				return out, err
			}
		}
		out.Results = append(out.Results, row)
	}
	out.SourceCalls, out.ProducerCalls = src.calls, p.calls
	return out, nil
}

func run(r io.Reader, w io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(r, 2049))
	if err != nil {
		return err
	}
	if len(raw) > 2048 {
		return errors.New("oversized paired observation input")
	}
	var in input
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing paired observation input")
	}
	out, err := observe(in)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(out)
}
func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Paired DID observer:", err)
		os.Exit(1)
	}
}
