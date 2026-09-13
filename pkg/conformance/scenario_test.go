package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestScenarioChild(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "scenario-child" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	scanner := bufio.NewScanner(os.Stdin)
	count := uint64(0)
	for scanner.Scan() {
		if bytes.Contains(scanner.Bytes(), []byte("expected")) {
			os.Exit(9)
		}
		var q StepRequest
		if json.Unmarshal(scanner.Bytes(), &q) != nil {
			os.Exit(8)
		}
		if mode == "timeout" {
			time.Sleep(time.Second)
			continue
		}
		count++
		o := StepObservation{2, q.CaseID, q.StepID, "ACCEPT", json.RawMessage(`{}`), map[string]uint64{"dispatch": count}}
		switch mode {
		case "wrong-id":
			o.StepID = "wrong"
		case "unsupported":
			o.Verdict = "UNSUPPORTED"
		case "effect":
			o.Effects["dispatch"] = 99
		case "malformed":
			_, _ = os.Stdout.WriteString("{\n")
			os.Exit(0)
		}
		if err := json.NewEncoder(os.Stdout).Encode(o); err != nil {
			os.Exit(1)
		}
		if mode == "exit" {
			os.Exit(1)
		}
	}
	if mode == "trailing" {
		_, _ = os.Stdout.WriteString("extra\n")
	}
	os.Exit(0)
}
func scenarioFixture(t *testing.T) *Scenario {
	t.Helper()
	s := `{"schema_version":2,"protocol_version":"0.10.0","profile":"stateful-scenario","id":"counter","sources":[{"id":"manual","kind":"spec-derived","uri":"inspector:test","reference":"Harness counter only, not SAGE"}],"steps":[{"id":"one","operation":"dispatch","input":{},"timeout_ms":150,"expected":{"verdict":"ACCEPT","output":{}},"effects":{"dispatch":1}},{"id":"two","operation":"dispatch","input":{},"timeout_ms":150,"expected":{"verdict":"ACCEPT","output":{}},"effects":{"dispatch":2}}]}`
	got, e := LoadScenario(strings.NewReader(s))
	if e != nil {
		t.Fatal(e)
	}
	return got
}
func TestScenarioProcess(t *testing.T) {
	for _, mode := range []string{"ok", "wrong-id", "unsupported", "effect", "malformed", "timeout", "exit", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			p, e := NewProcess(os.Args[0], []string{"-test.run=TestScenarioChild", "scenario-child", mode})
			if e != nil {
				t.Fatal(e)
			}
			start := time.Now()
			r, e := RunScenario(context.Background(), scenarioFixture(t), p, Subject{Name: "harness", Revision: "test"})
			if e != nil {
				t.Fatal(e)
			}
			want := "FAIL"
			if mode == "ok" {
				want = "PASS"
			}
			if mode == "unsupported" {
				want = "INCOMPLETE"
			}
			if r.Status != want {
				t.Fatalf("%s: %+v", want, r)
			}
			if mode == "ok" && r.Steps[1].Actual.Effects["dispatch"] != 2 {
				t.Fatal("state lost")
			}
			if mode == "timeout" && (r.Steps[1].Status != "NOT_RUN" || time.Since(start) > 2*time.Second) {
				t.Fatal("timeout did not stop scenario")
			}
		})
	}
}
func TestScenarioFrozenAndInvalid(t *testing.T) {
	s := scenarioFixture(t)
	p, _ := NewProcess(os.Args[0], nil)
	s.Steps[0].Expected.Verdict = "REJECT"
	if _, e := RunScenario(context.Background(), s, p, Subject{Name: "x", Revision: "y"}); e == nil {
		t.Fatal("mutation accepted")
	}
	raw := string(scenarioFixture(t).raw)
	for _, bad := range []string{strings.Replace(raw, `"schema_version":2`, `"schema_version":1`, 1), strings.Replace(raw, `"timeout_ms":150`, `"timeout_ms":0`, 1), strings.Replace(raw, `"id":"two"`, `"id":"one"`, 1), strings.Replace(raw, `"input":{}`, `"input":{},"extra":true`, 1)} {
		if _, e := LoadScenario(strings.NewReader(bad)); e == nil {
			t.Fatal("invalid fixture accepted")
		}
	}
}
