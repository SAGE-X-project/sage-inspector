package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) *Suite {
	t.Helper()
	f, e := os.Open("../../vectors/0.10.0/foundation.json")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	s, e := Load(f)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func options() Options {
	return Options{Subject: Subject{Name: "test", Revision: "fixture", Kind: "reference"}, RunnerVersion: "test", Timeout: time.Second}
}
func TestFrozenKnownAnswers(t *testing.T) {
	s := fixture(t)
	r, e := Run(context.Background(), s, Reference{}, options())
	if e != nil {
		t.Fatal(e)
	}
	if r.ExitCode() != 0 || r.Counts["PASS"] != 26 {
		b, _ := json.Marshal(r)
		t.Fatal(string(b))
	}
}
func TestLoaderRejectsAmbiguity(t *testing.T) {
	s := fixture(t)
	b, _ := json.Marshal(s)
	raw := string(b)
	cases := map[string]string{
		"duplicate":         strings.Replace(raw, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		"escaped-duplicate": strings.Replace(raw, `"schema_version":1`, `"schema_version":1,"\u0073chema_version":1`, 1),
		"case-fold":         strings.Replace(raw, `"schema_version"`, `"SCHEMA_VERSION"`, 1),
		"wrong-version":     strings.Replace(raw, `"0.10.0"`, `"1.0.0-draft.1"`, 1),
		"missing":           strings.Replace(raw, `"schema_version":1,`, "", 1),
		"null":              strings.Replace(raw, `"schema_version":1`, `"schema_version":null`, 1),
		"unknown":           strings.Replace(raw, `"schema_version":1`, `"schema_version":1,"surprise":true`, 1),
		"trailing":          raw + `{}`, "oversized": strings.Repeat(" ", MaxJSONBytes+1),
	}
	for n, b := range cases {
		t.Run(n, func(t *testing.T) {
			if _, e := Load(strings.NewReader(b)); e == nil {
				t.Fatal("accepted invalid suite")
			}
		})
	}
	for _, mutate := range []func(*Suite){func(s *Suite) { s.Cases = nil }, func(s *Suite) { s.Cases[1].ID = s.Cases[0].ID }, func(s *Suite) { s.Cases[0].SourceIDs = []string{"missing"} }, func(s *Suite) { s.Cases[0].Expected.Verdict = "UNSUPPORTED" }, func(s *Suite) { s.Cases[0].Expected.Output = nil }} {
		s := fixture(t)
		mutate(s)
		if s.Validate() == nil {
			t.Fatal("accepted invalid metadata")
		}
	}
}
func TestStrictJSONCorners(t *testing.T) {
	for _, b := range []string{`"\\ud800"`, `"\ud800\udc00"`, `{"quote":"\"","x":"\\"}`, `[1,{"x":true}]`, `1e-400`} {
		if _, e := strictJSON([]byte(b)); e != nil {
			t.Fatalf("valid %s: %v", b, e)
		}
	}
	for _, b := range []string{`"\udc00"`, `"\ud800x"`, `"\ud800\ud800"`, `1e999`, `-1e-999`, `{"a":1,"\u0061":2}`, strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)} {
		if _, e := strictJSON([]byte(b)); e == nil {
			t.Fatalf("invalid %s", b)
		}
	}
}

type observeFunc func(context.Context, Request) (Observation, error)

func (f observeFunc) Observe(c context.Context, q Request) (Observation, error) { return f(c, q) }
func TestVerdictsCannotHideMissingEvidence(t *testing.T) {
	s := fixture(t)
	o := options()
	o.Select = []string{s.Cases[0].ID}
	r, e := Run(context.Background(), s, Reference{}, o)
	if e != nil || r.ExitCode() != 3 || r.Counts["NOT_RUN"] != 25 {
		t.Fatalf("subset: %+v %v", r, e)
	}
	o.Select = []string{"typo"}
	if _, e = Run(context.Background(), s, Reference{}, o); e == nil {
		t.Fatal("unknown selection")
	}
	s = fixture(t)
	s = subset(t, s, 3, 4) // expected REJECT: a crash is never this expected rejection.
	tests := []struct {
		name   string
		fn     observeFunc
		status string
	}{
		{"error", func(context.Context, Request) (Observation, error) { return Observation{}, errors.New("failed") }, "FAIL"},
		{"unsupported", func(_ context.Context, q Request) (Observation, error) {
			return Observation{1, q.CaseID, "UNSUPPORTED", json.RawMessage(`{}`)}, nil
		}, "UNSUPPORTED"},
		{"wrong-correlation", func(_ context.Context, q Request) (Observation, error) {
			return Observation{1, "other", "REJECT", json.RawMessage(`{}`)}, nil
		}, "FAIL"},
		{"invalid-output", func(_ context.Context, q Request) (Observation, error) {
			return Observation{1, q.CaseID, "REJECT", json.RawMessage(`null`)}, nil
		}, "FAIL"},
		{"timeout", func(c context.Context, q Request) (Observation, error) {
			<-c.Done()
			return Observation{1, q.CaseID, "REJECT", json.RawMessage(`{}`)}, nil
		}, "FAIL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := options()
			o.Timeout = 10 * time.Millisecond
			r, e := Run(context.Background(), s, tc.fn, o)
			if e != nil || r.Results[0].Status != tc.status || r.ExitCode() == 0 {
				t.Fatalf("%+v %v", r, e)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, e = Run(ctx, s, Reference{}, options())
	if e != nil || r.Counts["NOT_RUN"] != 1 || r.ExitCode() != 3 {
		t.Fatal("cancelled run passed")
	}
}

// Child-process fixture: only active when explicitly invoked with a helper arg.
func TestAdapterHelper(t *testing.T) {
	mode := ""
	for _, a := range os.Args {
		if strings.HasPrefix(a, "helper=") {
			mode = strings.TrimPrefix(a, "helper=")
		}
	}
	if mode == "" {
		return
	}
	var q Request
	if json.NewDecoder(os.Stdin).Decode(&q) != nil {
		os.Exit(8)
	}
	switch mode {
	case "exit":
		os.Exit(7)
	case "timeout":
		time.Sleep(2 * time.Second)
	case "oversized":
		fmt.Print(strings.Repeat("x", MaxJSONBytes+1))
		os.Exit(0)
	case "malformed":
		fmt.Print(`{"schema_version":1,"schema_version":1}`)
		os.Exit(0)
	case "leak-check":
		if bytes.Contains(q.Input, []byte("expected")) {
			os.Exit(9)
		}
	}
	o, _ := (Reference{}).Observe(context.Background(), q)
	if mode == "wrong-case" {
		o.CaseID = "wrong"
	}
	json.NewEncoder(os.Stdout).Encode(o)
	os.Exit(0)
}
func TestExternalAdapterFailures(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	s := fixture(t)
	s = subset(t, s, 0, 1)
	for _, mode := range []string{"leak-check", "exit", "timeout", "oversized", "malformed", "wrong-case"} {
		t.Run(mode, func(t *testing.T) {
			a, e := NewProcess(exe, []string{"-test.run=^TestAdapterHelper$", "--", "helper=" + mode})
			if e != nil {
				t.Fatal(e)
			}
			o := options()
			o.Timeout = 2 * time.Second
			if mode == "timeout" {
				o.Timeout = 100 * time.Millisecond
			}
			r, e := Run(context.Background(), s, a, o)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "leak-check" {
				if r.ExitCode() != 0 {
					t.Fatalf("%+v", r.Results)
				}
			} else if r.Results[0].Status != "FAIL" {
				t.Fatalf("%+v", r.Results)
			}
		})
	}
}
func TestExpectedNeverSentToAdapter(t *testing.T) {
	s := fixture(t)
	s = subset(t, s, 0, 1)
	a := observeFunc(func(ctx context.Context, q Request) (Observation, error) {
		b, _ := json.Marshal(q)
		if bytes.Contains(b, []byte("expected")) || bytes.Contains(b, []byte("prk_hex")) {
			t.Fatal("expected output disclosed to adapter")
		}
		return Reference{}.Observe(ctx, q)
	})
	r, e := Run(context.Background(), s, a, options())
	if e != nil || r.ExitCode() != 0 {
		t.Fatal(e)
	}
}

func subset(t *testing.T, s *Suite, start, end int) *Suite {
	t.Helper()
	s.Cases = s.Cases[start:end]
	b, _ := json.Marshal(s)
	out, e := Load(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestLoadedSuiteIsImmutable(t *testing.T) {
	s := fixture(t)
	s.Cases[0].Expected.Output = json.RawMessage(`{}`)
	if _, e := Run(context.Background(), s, Reference{}, options()); e == nil {
		t.Fatal("mutated suite retained original digest")
	}
}
