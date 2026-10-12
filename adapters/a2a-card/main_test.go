package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestIndependentCardFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/0.10.0/a2a-card-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var suite struct {
		Cases []struct {
			ID       string
			Input    input
			Expected output
		}
	}
	if err = json.Unmarshal(raw, &suite); err != nil {
		t.Fatal(err)
	}
	if len(suite.Cases) != 41 {
		t.Fatal("fixture count")
	}
	for _, c := range suite.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got, e := observe(c.Input)
			if e != nil {
				t.Fatal(e)
			}
			actual, _ := json.Marshal(got)
			expected, _ := json.Marshal(c.Expected)
			if !bytes.Equal(actual, expected) {
				t.Fatalf("actual %s expected %s", actual, expected)
			}
		})
	}
}

func TestBoundedAdapterErrors(t *testing.T) {
	for _, raw := range []string{"", "{}", "null", "{} {}", `{"card":"x","unknown":true}`, `{"record":{"did":"not-a-did"}}`} {
		var stdout, stderr bytes.Buffer
		if run(bytes.NewBufferString(raw), &stdout, &stderr) == 0 || stdout.Len() != 0 || stderr.String() != "invalid fixture\n" {
			t.Fatal(raw, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if run(bytes.NewReader(bytes.Repeat([]byte(" "), 1048577)), &stdout, &stderr) == 0 {
		t.Fatal("oversize")
	}
	raw, err := os.ReadFile("../../vectors/0.10.0/a2a-card-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct{ Cases []struct{ Input input } }
	json.Unmarshal(raw, &s)
	b, _ := json.Marshal(s.Cases[0].Input)
	stdout.Reset()
	stderr.Reset()
	if run(bytes.NewReader(b), &stdout, &stderr) != 0 || !json.Valid(stdout.Bytes()) || stderr.Len() != 0 {
		t.Fatal("valid framed input")
	}
	bad := s.Cases[0].Input
	bad.Record.KeyHex = "xx"
	if _, e := observe(bad); e == nil {
		t.Fatal("bad key encoding")
	}
	bad = s.Cases[0].Input
	bad.ExpectedPeer = "not-a-did"
	if _, e := observe(bad); e == nil {
		t.Fatal("invalid expected peer")
	}
}

func TestCardSizeHasOtherwiseValidControl(t *testing.T) {
	raw, e := os.ReadFile("../../vectors/0.10.0/a2a-card-observations.json")
	if e != nil {
		t.Fatal(e)
	}
	var s struct {
		Cases []struct {
			ID    string
			Input input
		}
	}
	if e = json.Unmarshal(raw, &s); e != nil {
		t.Fatal(e)
	}
	for _, c := range s.Cases {
		if c.ID == "a2ab-04-oversized" {
			if len(c.Input.Card) != 262145 {
				t.Fatal("oversize boundary")
			}
			in := c.Input
			in.Card = in.Card[:262144]
			out, e := observe(in)
			if e != nil || !out.Accepted {
				t.Fatal("valid control failed", e, out)
			}
			out, e = observe(c.Input)
			if e != nil || out.Accepted {
				t.Fatal("oversized accepted", e, out)
			}
			return
		}
	}
	t.Fatal("size case missing")
}

func TestExactRegistryServiceType(t *testing.T) {
	raw, e := os.ReadFile("../../vectors/0.10.0/a2a-service-type-observations.json")
	if e != nil {
		t.Fatal(e)
	}
	var suite struct {
		Cases []struct {
			ID       string
			Input    input
			Expected output
		}
	}
	if e = json.Unmarshal(raw, &suite); e != nil {
		t.Fatal(e)
	}
	if len(suite.Cases) != 2 {
		t.Fatal("TABLE fixture count")
	}
	for _, c := range suite.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got, e := observe(c.Input)
			if e != nil {
				t.Fatal(e)
			}
			actual, _ := json.Marshal(got)
			want, _ := json.Marshal(c.Expected)
			if !bytes.Equal(actual, want) {
				t.Fatalf("actual %s expected %s", actual, want)
			}
		})
	}
	for _, kind := range []string{"A2AINTERFACE", "A2AInterface ", "", "OtherType"} {
		in := suite.Cases[0].Input
		in.Record.ServiceTypes = []string{kind}
		got, e := observe(in)
		if e != nil || got.Accepted {
			t.Fatalf("type %q accepted: %v %+v", kind, e, got)
		}
	}
	in := suite.Cases[0].Input
	in.Record.ServiceTypes = []string{"A2AInterface", "a2ainterface"}
	if _, e = observe(in); e == nil {
		t.Fatal("mismatched type count")
	}
}
