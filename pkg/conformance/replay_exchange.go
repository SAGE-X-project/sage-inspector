package conformance

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"time"
)

type ReplayTrial struct {
	ID                 string       `json:"id"`
	Sender             string       `json:"sender"`
	Receiver           string       `json:"receiver"`
	Direction          string       `json:"direction"`
	Production         ExchangeStep `json:"production"`
	Reception          ExchangeStep `json:"reception"`
	FreshRecordControl ExchangeStep `json:"fresh_record_control"`
	Expected           []Expected   `json:"expected_actions"`
	ActionStatuses     []string     `json:"action_statuses"`
}
type ReplayReport struct {
	SchemaVersion   int            `json:"schema_version"`
	ProtocolVersion string         `json:"protocol_version"`
	Environment     string         `json:"environment"`
	Created         string         `json:"created"`
	Subjects        []Subject      `json:"subjects"`
	Scope           string         `json:"scope"`
	Status          string         `json:"status"`
	Conformance     string         `json:"conformance"`
	ActionCounts    map[string]int `json:"action_counts"`
	Trials          []ReplayTrial  `json:"trials"`
}

// RunReplayExchange sends five real producer records to one persistent receiver
// per trial. The adapter invokes the core for every action, including duplicates.
func RunReplayExchange(ctx context.Context, subjects []Subject, adapters []Adapter) (*ReplayReport, error) {
	if len(subjects) != 2 || len(adapters) != 2 {
		return nil, fmt.Errorf("two subjects required")
	}
	for _, s := range subjects {
		if s.Kind != "external" || len(s.Revision) != 40 || len(s.ExecutableSHA256) != 64 || s.Name == "" {
			return nil, fmt.Errorf("incomplete external subject identity")
		}
	}
	if subjects[0].Name == subjects[1].Name || subjects[0].ExecutableSHA256 == subjects[1].ExecutableSHA256 {
		return nil, fmt.Errorf("distinct subjects required")
	}
	report := &ReplayReport{SchemaVersion: 1, ProtocolVersion: ProtocolVersion, Environment: runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH, Created: time.Now().UTC().Format(time.RFC3339Nano), Subjects: subjects, Status: "PASS", Conformance: "NOT_ESTABLISHED", ActionCounts: map[string]int{"PASS": 0, "FAIL": 0, "UNSUPPORTED": 0, "NOT_RUN": 0}, Scope: "Live legacy core replay and explicit close only. One persistent receiver per action batch; separate fresh receiver for close positive control. No Inspector replay filtering. Fixed public seed bypasses handshake; no expiry, crash recovery, simultaneous race, full 0.10.0 or host certification."}
	for sender := 0; sender < 2; sender++ {
		for _, direction := range []string{"c2s", "s2c"} {
			receiver := 1 - sender
			id := subjects[sender].Name + "-to-" + subjects[receiver].Name + "-" + direction
			controls := map[string]any{"seed_hex": strings.Repeat("01", 32), "sid": "inspector-replay-exchange", "direction": direction, "caller_aad_hex": "73616765", "messages_hex": []string{"61", "62", "63", "64", "65"}}
			trial := ReplayTrial{ID: id, Sender: subjects[sender].Name, Receiver: subjects[receiver].Name, Direction: direction}
			for _, plain := range []string{"61", "reject", "reject", "62", "64", "63", "reject", "close", "reject"} {
				e := Expected{Verdict: "REJECT", Output: json.RawMessage(`{}`)}
				if plain != "reject" {
					e.Verdict = "ACCEPT"
					if plain != "close" {
						e.Output, _ = json.Marshal(map[string]string{"plaintext_hex": plain})
					}
				}
				trial.Expected = append(trial.Expected, e)
				trial.ActionStatuses = append(trial.ActionStatuses, "NOT_RUN")
			}
			trial.Production = exchangeStep(ctx, adapters[sender], id+"-produce-sequence", "legacy.session.export-sequence", controls, "ACCEPT")
			trial.Reception = ExchangeStep{ID: id + "-receive-sequence", ExpectedVerdict: "ACCEPT", Status: "NOT_RUN", Reason: "producer did not provide five valid records"}
			trial.FreshRecordControl = ExchangeStep{ID: id + "-fresh-record-control", ExpectedVerdict: "ACCEPT", Status: "NOT_RUN", Reason: "producer did not provide five valid records"}
			var exported struct {
				Records []string `json:"records_hex"`
			}
			if trial.Production.Status == "PASS" {
				valid := decode(trial.Production.Actual.Output, &exported) == nil && len(exported.Records) == 5
				seen := map[string]bool{}
				for _, r := range exported.Records {
					b, e := hex.DecodeString(r)
					if e != nil || len(b) == 0 || len(b) > 2048 || seen[r] || hex.EncodeToString(b) != r {
						valid = false
					}
					seen[r] = true
				}
				if !valid {
					trial.Production.Status = "FAIL"
					trial.Production.Reason = "invalid producer record sequence"
				}
			}
			if trial.Production.Status == "PASS" {
				corrupted, _ := hex.DecodeString(exported.Records[1])
				corrupted[len(corrupted)-1] ^= 1
				actions := []map[string]string{}
				for _, n := range []int{0, 0, -1, 1, 3, 2, 3, -2, 4} {
					if n == -2 {
						actions = append(actions, map[string]string{"kind": "close"})
						continue
					}
					record := hex.EncodeToString(corrupted)
					if n >= 0 {
						record = exported.Records[n]
					}
					actions = append(actions, map[string]string{"kind": "open", "record_hex": record})
				}
				input := map[string]any{}
				for k, v := range controls {
					if k != "messages_hex" {
						input[k] = v
					}
				}
				input["actions"] = []map[string]string{{"kind": "open", "record_hex": exported.Records[4]}}
				trial.FreshRecordControl = exchangeStep(ctx, adapters[receiver], trial.FreshRecordControl.ID, "legacy.session.receive-sequence", input, "ACCEPT")
				if trial.FreshRecordControl.Status == "PASS" {
					var control struct {
						Results []Expected `json:"results"`
					}
					if decode(trial.FreshRecordControl.Actual.Output, &control) != nil || len(control.Results) != 1 || control.Results[0].Verdict != "ACCEPT" {
						trial.FreshRecordControl.Status = "FAIL"
						trial.FreshRecordControl.Reason = "fresh record control failed"
					} else {
						got, _ := strictJSON(control.Results[0].Output)
						want, _ := strictJSON(json.RawMessage(`{"plaintext_hex":"65"}`))
						if !reflect.DeepEqual(got, want) {
							trial.FreshRecordControl.Status = "FAIL"
							trial.FreshRecordControl.Reason = "fresh record control plaintext mismatch"
						}
					}
				}
				input["actions"] = actions
				trial.Reception = exchangeStep(ctx, adapters[receiver], trial.Reception.ID, "legacy.session.receive-sequence", input, "ACCEPT")
				if trial.Reception.Status == "PASS" {
					var received struct {
						Results []Expected `json:"results"`
					}
					if decode(trial.Reception.Actual.Output, &received) != nil || len(received.Results) != len(trial.Expected) {
						trial.Reception.Status = "FAIL"
						trial.Reception.Reason = "incomplete receiver actions"
					} else {
						for i, actual := range received.Results {
							trial.ActionStatuses[i] = "FAIL"
							want, _ := strictJSON(trial.Expected[i].Output)
							got, e := strictJSON(actual.Output)
							if e == nil && actual.Verdict == trial.Expected[i].Verdict && reflect.DeepEqual(want, got) {
								trial.ActionStatuses[i] = "PASS"
							} else {
								trial.Reception.Status = "FAIL"
								trial.Reception.Reason = "receiver action differs from expected replay/close behavior"
							}
						}
					}
				}
			}
			if trial.Production.Status == "FAIL" || trial.Reception.Status == "FAIL" || trial.FreshRecordControl.Status == "FAIL" {
				report.Status = "FAIL"
			} else if report.Status != "FAIL" && (trial.Production.Status != "PASS" || trial.Reception.Status != "PASS" || trial.FreshRecordControl.Status != "PASS") {
				report.Status = "INCOMPLETE"
			}
			for _, status := range trial.ActionStatuses {
				report.ActionCounts[status]++
			}
			report.Trials = append(report.Trials, trial)
		}
	}
	return report, nil
}
