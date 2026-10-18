package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	sage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
)

func TestPairedNativeScenarios(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/0.10.0/did-paired-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			ID       string
			Input    json.RawMessage
			Expected any
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 8 {
		t.Fatal("missing authored scenarios")
	}
	for _, c := range fixture.Cases {
		t.Run(c.ID, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(bytes.NewReader(c.Input), &output); err != nil {
				t.Fatal(err)
			}
			var actual map[string]any
			if err := json.Unmarshal(output.Bytes(), &actual); err != nil {
				t.Fatal(err)
			}
			for _, rawRow := range actual["results"].([]any) {
				row := rawRow.(map[string]any)
				for _, projection := range []string{"core10", "did11"} {
					if row[projection] == nil {
						continue
					}
					view := row[projection].(map[string]any)
					for encoded, decoded := range map[string]string{"body_hex": "body", "metadata_hex": "metadata"} {
						raw, err := hex.DecodeString(view[encoded].(string))
						if err != nil {
							t.Fatal(err)
						}
						var value any
						if err := json.Unmarshal(raw, &value); err != nil {
							t.Fatal(err)
						}
						view[decoded] = value
						delete(view, encoded)
					}
				}
			}
			if !reflect.DeepEqual(actual, c.Expected) {
				t.Fatalf("actual %#v, expected %#v", actual, c.Expected)
			}
		})
	}
}

func TestPairedInputRefusals(t *testing.T) {
	for _, raw := range []string{"", "{}", "null", `{"scenario":3}`, `{"scenario":"unknown"}`, `{"scenario":"created","extra":1}`, `{"scenario":"created"} {}`, `{"scenario":"created"} trailing`, strings.Repeat(" ", 2049)} {
		var output bytes.Buffer
		if err := run(strings.NewReader(raw), &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid input admitted", raw)
		}
	}
}

type failedIO struct{}

func (failedIO) Read([]byte) (int, error)  { return 0, errors.New("fixture read unavailable") }
func (failedIO) Write([]byte) (int, error) { return 0, errors.New("fixture write unavailable") }

func TestPairedIOAndMetadataFailures(t *testing.T) {
	var output bytes.Buffer
	if run(failedIO{}, &output) == nil || run(strings.NewReader(`{"scenario":"created"}`), failedIO{}) == nil {
		t.Fatal("IO failure hidden")
	}
	v := sage.ProjectionView{Metadata: document.Metadata{Extra: map[string]any{"bad": make(chan int)}}}
	if _, err := encodeView(v); err == nil {
		t.Fatal("invalid metadata encoded")
	}
}

func TestPairedSourceLimitsAndHistory(t *testing.T) {
	d, err := did.Parse(fixtureDID)
	if err != nil {
		t.Fatal(err)
	}
	source := &fixtureSource{scenario: "changing"}
	first, err := source.Observe(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.Observe(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if first.Controller != second.Controller || !reflect.DeepEqual(first.Keys, second.Keys) || first.Version != "7" || second.Version != "8" || first.Services[0].URI == second.Services[0].URI {
		t.Fatal("service-only mutation changed key/controller history")
	}
	if _, err := source.Observe(context.Background(), d); err == nil {
		t.Fatal("unexpected third observation")
	}
	other, err := did.Parse("did:sage:web:registry.example:other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&fixtureSource{scenario: "created"}).Observe(context.Background(), other); err == nil {
		t.Fatal("different identifier admitted")
	}
	single := &fixtureSource{scenario: "created"}
	if _, err := single.Observe(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if _, err := single.Observe(context.Background(), d); err == nil {
		t.Fatal("single call fixture silently reread")
	}
}
