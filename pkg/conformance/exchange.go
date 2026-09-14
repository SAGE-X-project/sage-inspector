package conformance

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"
)

// ExchangeReport records live producer bytes and consumer observations. Passing
// this legacy API projection does not establish a 0.10.0 handshake or replay policy.
type ExchangeReport struct {
	SchemaVersion   int              `json:"schema_version"`
	ProtocolVersion string           `json:"protocol_version"`
	Environment     string           `json:"environment"`
	Created         string           `json:"created"`
	Scope           string           `json:"scope"`
	Subjects        []Subject        `json:"subjects"`
	Status          string           `json:"status"`
	Conformance     string           `json:"conformance"`
	Counts          map[string]int   `json:"counts"`
	Exchanges       []ExchangeResult `json:"exchanges"`
}
type ExchangeResult struct {
	ID         string         `json:"id"`
	Sender     string         `json:"sender"`
	Receiver   string         `json:"receiver"`
	Direction  string         `json:"direction"`
	Production ExchangeStep   `json:"production"`
	Checks     []ExchangeStep `json:"checks"`
}
type ExchangeStep struct {
	ID              string       `json:"id"`
	Request         Request      `json:"request"`
	RequestSHA256   string       `json:"request_sha256"`
	Actual          *Observation `json:"actual,omitempty"`
	ExpectedVerdict string       `json:"expected_verdict"`
	Status          string       `json:"status"`
	Reason          string       `json:"reason,omitempty"`
	PositiveControl string       `json:"positive_control,omitempty"`
}

func exchangeStep(ctx context.Context, adapter Adapter, id, operation string, input map[string]any, expected string) ExchangeStep {
	raw, _ := json.Marshal(input)
	q := Request{1, ProtocolVersion, "primitive-foundation", id, operation, raw}
	request, _ := json.Marshal(q)
	s := ExchangeStep{ID: id, Request: q, RequestSHA256: Digest(request), ExpectedVerdict: expected, Status: "FAIL"}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	o, err := adapter.Observe(bounded, q)
	if err != nil {
		s.Reason = err.Error()
		return s
	}
	if err = validObservation(o, id); err != nil {
		s.Reason = err.Error()
		return s
	}
	s.Actual = &o
	if o.Verdict == "UNSUPPORTED" {
		s.Status = "UNSUPPORTED"
		return s
	}
	if o.Verdict != expected {
		s.Reason = "verdict differs from expected exchange behavior"
		return s
	}
	s.Status = "PASS"
	return s
}

// RunExchange uses two operator-supplied adapters. Names and binary hashes are
// provenance, not independent implementation attestation; review the source lock.
func RunExchange(ctx context.Context, subjects []Subject, adapters []Adapter) (*ExchangeReport, error) {
	if len(subjects) != 2 || len(adapters) != 2 {
		return nil, fmt.Errorf("two subjects required")
	}
	for _, s := range subjects {
		if s.Kind != "external" || s.Name == "" || len(s.Revision) != 40 || len(s.ExecutableSHA256) != 64 {
			return nil, fmt.Errorf("incomplete external subject identity")
		}
	}
	if subjects[0].Name == subjects[1].Name || subjects[0].ExecutableSHA256 == subjects[1].ExecutableSHA256 {
		return nil, fmt.Errorf("distinct subject identities required")
	}
	report := &ExchangeReport{SchemaVersion: 1, ProtocolVersion: ProtocolVersion, Environment: runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH, Created: time.Now().UTC().Format(time.RFC3339Nano), Subjects: subjects, Status: "PASS", Conformance: "NOT_ESTABLISHED", Counts: map[string]int{"PASS": 0, "FAIL": 0, "UNSUPPORTED": 0, "NOT_RUN": 0}, Scope: "Live legacy session API exchange only; fixed public test seed bypasses handshake. Fresh receiver per check: no replay, lifecycle, HTTP/WS, host isolation or full 0.10.0 claim. Negative checks require a passing positive control to isolate a defense."}
	for sender := 0; sender < 2; sender++ {
		for _, direction := range []string{"c2s", "s2c"} {
			receiver := 1 - sender
			id := subjects[sender].Name + "-to-" + subjects[receiver].Name + "-" + direction
			controls := map[string]any{"seed_hex": strings.Repeat("01", 32), "th_hex": strings.Repeat("02", 32), "sid": "inspector-live-exchange", "direction": direction, "caller_aad_hex": "736167652d696e73706563746f72", "plaintext": map[string]int{"byte": 97, "length": 32}}
			x := ExchangeResult{ID: id, Sender: subjects[sender].Name, Receiver: subjects[receiver].Name, Direction: direction}
			x.Production = exchangeStep(ctx, adapters[sender], id+"-produce", "sage.session.record.export", controls, "ACCEPT")
			var exported struct {
				Record string `json:"record_hex"`
				SHA256 string `json:"record_sha256"`
				Bytes  int    `json:"record_bytes"`
			}
			var wire []byte
			if x.Production.Status == "PASS" {
				err := decode(x.Production.Actual.Output, &exported)
				wire, _ = hex.DecodeString(exported.Record)
				if err != nil || len(wire) == 0 || len(wire) > 4096 || len(wire) != exported.Bytes || Digest(wire) != exported.SHA256 || hex.EncodeToString(wire) != exported.Record {
					x.Production.Status = "FAIL"
					x.Production.Reason = "invalid exported record bytes or hash"
				}
			}
			positive := "NOT_RUN"
			for _, mutation := range []string{"valid", "ciphertext", "aad", "seed", "direction", "sid", "transcript"} {
				expected := "REJECT"
				if mutation == "valid" {
					expected = "ACCEPT"
				}
				step := ExchangeStep{ID: id + "-" + mutation, ExpectedVerdict: expected, Status: "NOT_RUN", Reason: "producer did not emit a valid record"}
				if x.Production.Status == "PASS" {
					input := map[string]any{}
					for k, v := range controls {
						if k != "plaintext" {
							input[k] = v
						}
					}
					input["record_hex"] = exported.Record
					switch mutation {
					case "ciphertext":
						modified := append([]byte(nil), wire...)
						modified[len(modified)-1] ^= 1
						input["record_hex"] = hex.EncodeToString(modified)
					case "aad":
						input["caller_aad_hex"] = "00"
					case "seed":
						input["seed_hex"] = strings.Repeat("03", 32)
					case "direction":
						if direction == "c2s" {
							input["direction"] = "s2c"
						} else {
							input["direction"] = "c2s"
						}
					case "sid":
						input["sid"] = "different-session"
					case "transcript":
						input["th_hex"] = strings.Repeat("04", 32)
					}
					operation := "sage.session.record.open"
					if mutation == "transcript" {
						operation = "sage.session.record.open.bound"
					}
					step = exchangeStep(ctx, adapters[receiver], step.ID, operation, input, expected)
					if mutation == "valid" && step.Status == "PASS" {
						var plain struct {
							Plaintext string `json:"plaintext_hex"`
						}
						if decode(step.Actual.Output, &plain) != nil || plain.Plaintext != strings.Repeat("61", 32) {
							step.Status = "FAIL"
							step.Reason = "plaintext differs from sender input"
						}
					}
				}
				if mutation == "valid" {
					positive = step.Status
				} else {
					step.PositiveControl = positive
				}
				x.Checks = append(x.Checks, step)
			}
			report.Counts[x.Production.Status]++
			for _, s := range x.Checks {
				report.Counts[s.Status]++
			}
			report.Exchanges = append(report.Exchanges, x)
		}
	}
	if report.Counts["FAIL"] > 0 {
		report.Status = "FAIL"
	} else if report.Counts["UNSUPPORTED"] > 0 || report.Counts["NOT_RUN"] > 0 {
		report.Status = "INCOMPLETE"
	}
	return report, nil
}
