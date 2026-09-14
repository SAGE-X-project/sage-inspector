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

type ConcurrentRound struct {
	ID            string       `json:"id"`
	Reception     ExchangeStep `json:"reception"`
	CheckStatuses []string     `json:"check_statuses"`
	Overlap       []bool       `json:"call_interval_overlap"`
}
type ConcurrentBatch struct {
	ID         string            `json:"id"`
	Sender     string            `json:"sender"`
	Receiver   string            `json:"receiver"`
	Direction  string            `json:"direction"`
	Production ExchangeStep      `json:"production"`
	Rounds     []ConcurrentRound `json:"rounds"`
}
type ConcurrentReport struct {
	SchemaVersion   int               `json:"schema_version"`
	ProtocolVersion string            `json:"protocol_version"`
	Created         string            `json:"created"`
	Environment     string            `json:"environment"`
	Subjects        []Subject         `json:"subjects"`
	Scope           string            `json:"scope"`
	Status          string            `json:"status"`
	Conformance     string            `json:"conformance"`
	Counts          map[string]int    `json:"check_counts"`
	ObservedWorkers int               `json:"observed_workers"`
	Batches         []ConcurrentBatch `json:"batches"`
}
type parallelWorker struct {
	Index    int             `json:"index"`
	Started  uint64          `json:"started_ns"`
	Finished uint64          `json:"finished_ns"`
	Verdict  string          `json:"verdict"`
	Output   json.RawMessage `json:"output"`
}

// judgeParallel checks per-input attribution, exactly one winner per valid
// record and actual overlapping call intervals. A start gate alone is not overlap.
func judgeParallel(actual Expected, group int) (string, bool, int) {
	var out struct {
		Gate    string           `json:"start_gate"`
		Ready   int              `json:"workers_ready"`
		Workers []parallelWorker `json:"workers"`
	}
	if actual.Verdict != "ACCEPT" || decode(actual.Output, &out) != nil || out.Gate != "all-ready" || out.Ready != 8 || len(out.Workers) != 8 {
		return "FAIL", false, 0
	}
	accepted := map[string]int{}
	overlap := false
	for i, w := range out.Workers {
		if w.Index != i || w.Started == 0 || w.Finished < w.Started {
			return "FAIL", false, 0
		}
		for _, prior := range out.Workers[:i] {
			if w.Started < prior.Finished && prior.Started < w.Finished {
				overlap = true
			}
		}
		want := "61"
		if group == 1 {
			want = "63"
			if i >= 4 {
				want = "64"
			}
		}
		switch w.Verdict {
		case "ACCEPT":
			if group == 0 && i >= 4 {
				return "FAIL", overlap, 8
			}
			var plain struct {
				Plain string `json:"plaintext_hex"`
			}
			if decode(w.Output, &plain) != nil || plain.Plain != want {
				return "FAIL", overlap, 8
			}
			accepted[want]++
		case "REJECT":
			value, e := strictJSON(w.Output)
			if e != nil || !reflect.DeepEqual(value, map[string]any{}) {
				return "FAIL", overlap, 8
			}
		default:
			return "FAIL", overlap, 8
		}
	}
	if group == 0 && accepted["61"] != 1 || group == 1 && (accepted["63"] != 1 || accepted["64"] != 1) {
		return "FAIL", overlap, 8
	}
	if !overlap {
		return "INCOMPLETE", false, 8
	}
	return "PASS", true, 8
}

func RunConcurrentExchange(ctx context.Context, subjects []Subject, adapters []Adapter) (*ConcurrentReport, error) {
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
	report := &ConcurrentReport{SchemaVersion: 1, ProtocolVersion: ProtocolVersion, Created: time.Now().UTC().Format(time.RFC3339Nano), Environment: runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH, Subjects: subjects, Status: "PASS", Conformance: "NOT_ESTABLISHED", Counts: map[string]int{"PASS": 0, "FAIL": 0, "INCOMPLETE": 0, "NOT_RUN": 0}, Scope: "Bounded live legacy core contention: eight rounds per direction, eight start-gated workers per group, one core receiver per round. Overlap means measured API call intervals, not control of internal lock scheduling or proof of all interleavings. No Inspector replay lock/filter, expiry/recovery/close race, full 0.10.0 or host certification."}
	for sender := 0; sender < 2; sender++ {
		for _, direction := range []string{"c2s", "s2c"} {
			receiver := 1 - sender
			id := subjects[sender].Name + "-to-" + subjects[receiver].Name + "-" + direction
			controls := map[string]any{"seed_hex": strings.Repeat("01", 32), "sid": "inspector-concurrent-exchange", "direction": direction, "caller_aad_hex": "73616765", "messages_hex": []string{"61", "62", "63", "64", "65"}}
			batch := ConcurrentBatch{ID: id, Sender: subjects[sender].Name, Receiver: subjects[receiver].Name, Direction: direction}
			batch.Production = exchangeStep(ctx, adapters[sender], id+"-produce-sequence", "legacy.session.export-sequence", controls, "ACCEPT")
			var exported struct {
				Records []string `json:"records_hex"`
			}
			if batch.Production.Status == "PASS" {
				valid := decode(batch.Production.Actual.Output, &exported) == nil && len(exported.Records) == 5
				seen := map[string]bool{}
				for _, r := range exported.Records {
					b, e := hex.DecodeString(r)
					if e != nil || len(b) == 0 || len(b) > 2048 || seen[r] || hex.EncodeToString(b) != r {
						valid = false
					}
					seen[r] = true
				}
				if !valid {
					batch.Production.Status = "FAIL"
					batch.Production.Reason = "invalid producer sequence"
				}
			}
			for round := 0; round < 8; round++ {
				rid := fmt.Sprintf("%s-round-%d", id, round)
				r := ConcurrentRound{ID: rid, Reception: ExchangeStep{ID: rid + "-receive", ExpectedVerdict: "ACCEPT", Status: "NOT_RUN", Reason: "producer did not provide valid records"}, CheckStatuses: []string{"NOT_RUN", "NOT_RUN", "NOT_RUN", "NOT_RUN", "NOT_RUN", "NOT_RUN", "NOT_RUN"}, Overlap: []bool{false, false}}
				if batch.Production.Status == "PASS" {
					corrupted, _ := hex.DecodeString(exported.Records[1])
					corrupted[len(corrupted)-1] ^= 1
					first, second := []string{}, []string{}
					for i := 0; i < 8; i++ {
						a, b := exported.Records[0], exported.Records[2]
						if i >= 4 {
							a = hex.EncodeToString(corrupted)
							b = exported.Records[3]
						}
						first = append(first, a)
						second = append(second, b)
					}
					actions := []map[string]any{{"kind": "parallel_open", "records_hex": first}, {"kind": "open", "record_hex": exported.Records[1]}, {"kind": "open", "record_hex": exported.Records[0]}, {"kind": "parallel_open", "records_hex": second}, {"kind": "open", "record_hex": exported.Records[2]}, {"kind": "open", "record_hex": exported.Records[3]}, {"kind": "open", "record_hex": exported.Records[4]}}
					input := map[string]any{}
					for k, v := range controls {
						if k != "messages_hex" {
							input[k] = v
						}
					}
					input["actions"] = actions
					r.Reception = exchangeStep(ctx, adapters[receiver], r.Reception.ID, "legacy.session.receive-sequence", input, "ACCEPT")
					if r.Reception.Status == "PASS" {
						var results struct {
							Results []Expected `json:"results"`
						}
						if decode(r.Reception.Actual.Output, &results) != nil || len(results.Results) != 7 {
							r.Reception.Status = "FAIL"
							r.Reception.Reason = "missing contention observations"
						} else {
							for i, actual := range results.Results {
								if i == 0 || i == 3 {
									group := 0
									if i == 3 {
										group = 1
									}
									status, overlap, n := judgeParallel(actual, group)
									r.CheckStatuses[i] = status
									r.Overlap[group] = overlap
									report.ObservedWorkers += n
									continue
								}
								wanted := Expected{Verdict: "REJECT", Output: json.RawMessage(`{}`)}
								if i == 1 || i == 6 {
									plain := "62"
									if i == 6 {
										plain = "65"
									}
									wanted.Verdict = "ACCEPT"
									wanted.Output, _ = json.Marshal(map[string]string{"plaintext_hex": plain})
								}
								want, _ := strictJSON(wanted.Output)
								got, e := strictJSON(actual.Output)
								r.CheckStatuses[i] = "FAIL"
								if e == nil && actual.Verdict == wanted.Verdict && reflect.DeepEqual(got, want) {
									r.CheckStatuses[i] = "PASS"
								}
							}
						}
					}
				}
				if batch.Production.Status == "FAIL" || r.Reception.Status == "FAIL" {
					report.Status = "FAIL"
				} else if report.Status != "FAIL" && r.Reception.Status != "PASS" {
					report.Status = "INCOMPLETE"
				}
				for _, s := range r.CheckStatuses {
					report.Counts[s]++
					if s == "FAIL" {
						report.Status = "FAIL"
					} else if s != "PASS" && report.Status != "FAIL" {
						report.Status = "INCOMPLETE"
					}
				}
				batch.Rounds = append(batch.Rounds, r)
			}
			report.Batches = append(report.Batches, batch)
		}
	}
	return report, nil
}
