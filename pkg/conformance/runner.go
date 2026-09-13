package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"time"
)

type Request struct {
	SchemaVersion   int             `json:"schema_version"`
	ProtocolVersion string          `json:"protocol_version"`
	Profile         string          `json:"profile"`
	CaseID          string          `json:"case_id"`
	Operation       string          `json:"operation"`
	Input           json.RawMessage `json:"input"`
}
type Observation struct {
	SchemaVersion int             `json:"schema_version"`
	CaseID        string          `json:"case_id"`
	Verdict       string          `json:"verdict"`
	Output        json.RawMessage `json:"output"`
}
type Adapter interface {
	Observe(context.Context, Request) (Observation, error)
}
type Subject struct {
	Name             string `json:"name"`
	Revision         string `json:"revision"`
	Kind             string `json:"kind"`
	ExecutableSHA256 string `json:"executable_sha256,omitempty"`
}
type Result struct {
	CaseID        string       `json:"case_id"`
	Operation     string       `json:"operation"`
	RuleIDs       []string     `json:"rule_ids"`
	SourceIDs     []string     `json:"source_ids"`
	Derivation    string       `json:"derivation"`
	InputSHA256   string       `json:"input_sha256"`
	RequestSHA256 string       `json:"adapter_request_sha256"`
	Expected      Expected     `json:"expected"`
	Actual        *Observation `json:"actual,omitempty"`
	Status        string       `json:"status"`
	Reason        string       `json:"reason,omitempty"`
	DurationMS    int64        `json:"duration_ms"`
}
type Report struct {
	SchemaVersion   int            `json:"schema_version"`
	ProtocolVersion string         `json:"protocol_version"`
	Profile         string         `json:"profile"`
	SuiteID         string         `json:"suite_id"`
	SuiteSHA256     string         `json:"suite_sha256"`
	RunnerVersion   string         `json:"runner_version"`
	Environment     string         `json:"environment"`
	Created         string         `json:"created"`
	Subject         Subject        `json:"subject"`
	Sources         []Source       `json:"sources"`
	Scope           string         `json:"scope"`
	Status          string         `json:"status"`
	Counts          map[string]int `json:"counts"`
	Results         []Result       `json:"results"`
}
type Options struct {
	Subject       Subject
	RunnerVersion string
	Timeout       time.Duration
	Select        []string
}

func Run(ctx context.Context, s *Suite, a Adapter, o Options) (*Report, error) {
	if s == nil || len(s.raw) == 0 {
		return nil, fmt.Errorf("suite must originate from Load")
	}
	original, e := Load(bytes.NewReader(s.raw))
	if e != nil {
		return nil, e
	}
	currentBytes, e := json.Marshal(s)
	if e != nil {
		return nil, e
	}
	originalBytes, _ := json.Marshal(original)
	if !bytes.Equal(currentBytes, originalBytes) || s.Digest != original.Digest {
		return nil, fmt.Errorf("suite mutated after loading")
	}
	s = original // detach this run from caller-owned slices and provenance.
	if e := s.Validate(); e != nil {
		return nil, e
	}
	if a == nil || o.Timeout <= 0 || o.Timeout > time.Minute || o.Subject.Name == "" || o.Subject.Revision == "" || (o.Subject.Kind != "reference" && o.Subject.Kind != "external") {
		return nil, fmt.Errorf("invalid adapter/options")
	}
	known := map[string]bool{}
	for _, c := range s.Cases {
		known[c.ID] = true
	}
	selected := map[string]bool{}
	for _, id := range o.Select {
		if !known[id] || selected[id] {
			return nil, fmt.Errorf("unknown/duplicate selected case %q", id)
		}
		selected[id] = true
	}
	r := &Report{SchemaVersion: 1, ProtocolVersion: s.ProtocolVersion, Profile: s.Profile, SuiteID: s.ID, SuiteSHA256: s.Digest, RunnerVersion: o.RunnerVersion, Environment: runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH, Created: time.Now().UTC().Format(time.RFC3339Nano), Subject: o.Subject, Sources: s.Sources, Scope: "Only listed primitive cases; no full SAGE, state-machine, registry or Execution Guard certification.", Counts: map[string]int{"PASS": 0, "FAIL": 0, "UNSUPPORTED": 0, "NOT_RUN": 0}}
	for _, c := range s.Cases {
		q := Request{1, s.ProtocolVersion, s.Profile, c.ID, c.Operation, c.Input}
		qb, _ := json.Marshal(q)
		item := Result{CaseID: c.ID, Operation: c.Operation, RuleIDs: c.RuleIDs, SourceIDs: c.SourceIDs, Derivation: c.Derivation, InputSHA256: Digest(c.Input), RequestSHA256: Digest(qb), Expected: c.Expected, Status: "NOT_RUN"}
		if len(selected) > 0 && !selected[c.ID] {
			item.Reason = "not selected"
		} else if ctx.Err() != nil {
			item.Reason = "run cancelled"
		} else {
			start := time.Now()
			cc, cancel := context.WithTimeout(ctx, o.Timeout)
			obs, e := a.Observe(cc, q)
			timedOut := cc.Err() != nil
			cancel()
			item.DurationMS = time.Since(start).Milliseconds()
			item.Status = "FAIL"
			if timedOut {
				item.Reason = "adapter deadline/cancellation"
			} else if e != nil {
				item.Reason = "adapter error: " + e.Error()
			} else if e = validObservation(obs, c.ID); e != nil {
				item.Reason = "invalid adapter response: " + e.Error()
			} else {
				item.Actual = &obs
				if obs.Verdict == "UNSUPPORTED" {
					item.Status = "UNSUPPORTED"
					item.Reason = "adapter does not support this operation"
				} else if obs.Verdict != c.Expected.Verdict {
					item.Reason = "verdict mismatch"
				} else {
					want, _ := strictJSON(c.Expected.Output)
					got, _ := strictJSON(obs.Output)
					if reflect.DeepEqual(want, got) {
						item.Status = "PASS"
					} else {
						item.Reason = "output mismatch"
					}
				}
			}
		}
		r.Counts[item.Status]++
		r.Results = append(r.Results, item)
	}
	r.Status = "PASS"
	if r.Counts["FAIL"] > 0 {
		r.Status = "FAIL"
	} else if r.Counts["NOT_RUN"] > 0 || r.Counts["UNSUPPORTED"] > 0 {
		r.Status = "INCOMPLETE"
	}
	return r, nil
}
func validObservation(o Observation, id string) error {
	if o.SchemaVersion != 1 || o.CaseID != id || (o.Verdict != "ACCEPT" && o.Verdict != "REJECT" && o.Verdict != "UNSUPPORTED") || !object(o.Output) {
		return fmt.Errorf("schema, correlation, verdict or output invalid")
	}
	v, _ := strictJSON(o.Output)
	if o.Verdict != "ACCEPT" && len(v.(map[string]any)) != 0 {
		return fmt.Errorf("nonaccept output must be empty")
	}
	return nil
}
func (r *Report) ExitCode() int {
	if r.Status == "PASS" {
		return 0
	}
	if r.Status == "INCOMPLETE" {
		return 3
	}
	return 1
}
