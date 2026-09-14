package conformance

import (
	"context"
	"encoding/json"
	"testing"
)

func parallelFixture(group int, mode string) Expected {
	workers := []map[string]any{}
	for i := 0; i < 8; i++ {
		started, finished := 10+i, 100+i
		if mode == "serial" {
			started = i*100 + 1
			finished = started + 10
		}
		verdict := "REJECT"
		out := map[string]any{}
		if i == 0 || group == 1 && i == 4 {
			verdict = "ACCEPT"
			plain := "61"
			if group == 1 {
				plain = "63"
				if i == 4 {
					plain = "64"
				}
			}
			out["plaintext_hex"] = plain
		}
		workers = append(workers, map[string]any{"index": i, "started_ns": started, "finished_ns": finished, "verdict": verdict, "output": out})
	}
	ready := 8
	switch mode {
	case "missing":
		workers = workers[:7]
	case "duplicate":
		workers[1]["verdict"] = "ACCEPT"
		workers[1]["output"] = workers[0]["output"]
	case "invalid-accepted":
		workers[6]["verdict"] = "ACCEPT"
		workers[6]["output"] = workers[0]["output"]
	case "no-winner":
		workers[0]["verdict"] = "REJECT"
		workers[0]["output"] = map[string]any{}
	case "wrong-index":
		workers[1]["index"] = 0
	case "wrong-time":
		workers[1]["finished_ns"] = 0
	case "not-ready":
		ready = 7
	}
	raw, _ := json.Marshal(map[string]any{"start_gate": "all-ready", "workers_ready": ready, "workers": workers})
	return Expected{Verdict: "ACCEPT", Output: raw}
}
func TestParallelJudgmentRequiresObservedContention(t *testing.T) {
	for _, mode := range []string{"valid", "serial", "missing", "duplicate", "invalid-accepted", "no-winner", "wrong-index", "wrong-time", "not-ready"} {
		t.Run(mode, func(t *testing.T) {
			status, overlap, _ := judgeParallel(parallelFixture(0, mode), 0)
			switch mode {
			case "valid":
				if status != "PASS" || !overlap {
					t.Fatal(status)
				}
			case "serial":
				if status != "INCOMPLETE" || overlap {
					t.Fatal(status)
				}
			default:
				if status != "FAIL" {
					t.Fatal("false PASS", status)
				}
			}
		})
	}
}

type concurrentFake struct{ mode string }

func (f concurrentFake) Observe(_ context.Context, q Request) (Observation, error) {
	if f.mode == "unsupported" {
		return Observation{1, q.CaseID, "UNSUPPORTED", json.RawMessage(`{}`)}, nil
	}
	var out any
	if q.Operation == "legacy.session.export-sequence" {
		out = map[string]any{"records_hex": []string{"aa00", "aa01", "aa02", "aa03", "aa04"}}
	} else {
		rejected := Expected{Verdict: "REJECT", Output: json.RawMessage(`{}`)}
		b := Expected{Verdict: "ACCEPT", Output: json.RawMessage(`{"plaintext_hex":"62"}`)}
		e := Expected{Verdict: "ACCEPT", Output: json.RawMessage(`{"plaintext_hex":"65"}`)}
		results := []Expected{parallelFixture(0, f.mode), b, rejected, parallelFixture(1, f.mode), rejected, rejected, e}
		out = map[string]any{"results": results}
	}
	raw, _ := json.Marshal(out)
	return Observation{1, q.CaseID, "ACCEPT", raw}, nil
}
func TestConcurrentExchangeBoundsAndIncompleteEvidence(t *testing.T) {
	for _, mode := range []string{"valid", "serial", "duplicate", "unsupported"} {
		r, e := RunConcurrentExchange(context.Background(), exchangeSubjects(), []Adapter{concurrentFake{mode}, concurrentFake{mode}})
		if e != nil {
			t.Fatal(e)
		}
		if r.Conformance != "NOT_ESTABLISHED" || len(r.Batches) != 4 {
			t.Fatal("false scope")
		}
		switch mode {
		case "valid":
			if r.Counts["PASS"] != 224 || r.ObservedWorkers != 512 || r.Status != "PASS" {
				t.Fatalf("%+v", r)
			}
		case "serial":
			if r.Status != "INCOMPLETE" || r.Counts["INCOMPLETE"] != 64 {
				t.Fatal("serial observations certified")
			}
		case "duplicate":
			if r.Status != "FAIL" {
				t.Fatal("duplicate accepted")
			}
		case "unsupported":
			if r.Status != "INCOMPLETE" || r.Counts["NOT_RUN"] != 224 || r.ObservedWorkers != 0 {
				t.Fatal("unexecuted workers certified")
			}
		}
	}
}
