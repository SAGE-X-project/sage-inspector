package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type replayFake struct {
	mode  string
	calls []Request
}

func (f *replayFake) Observe(_ context.Context, q Request) (Observation, error) {
	f.calls = append(f.calls, q)
	if f.mode == "error" {
		return Observation{}, fmt.Errorf("process error")
	}
	if f.mode == "unsupported" {
		return Observation{1, q.CaseID, "UNSUPPORTED", json.RawMessage(`{}`)}, nil
	}
	var out any
	if q.Operation == "legacy.session.export-sequence" {
		records := []string{"aa00", "aa01", "aa02", "aa03", "aa04"}
		if f.mode == "bad-producer" {
			records[4] = records[0]
		}
		out = map[string]any{"records_hex": records}
	} else {
		results := []Expected{}
		for _, p := range []string{"61", "reject", "reject", "62", "64", "63", "reject", "close", "reject"} {
			e := Expected{Verdict: "REJECT", Output: json.RawMessage(`{}`)}
			if p != "reject" {
				e.Verdict = "ACCEPT"
				if p != "close" {
					e.Output, _ = json.Marshal(map[string]string{"plaintext_hex": p})
				}
			}
			results = append(results, e)
		}
		switch f.mode {
		case "missing":
			results = results[:8]
		case "replay-accepted":
			results[1] = results[0]
		case "closed-accepted":
			results[8] = results[0]
		case "wrong-plaintext":
			results[3] = results[0]
		}
		if strings.HasSuffix(q.CaseID, "-fresh-record-control") {
			results = []Expected{{Verdict: "ACCEPT", Output: json.RawMessage(`{"plaintext_hex":"65"}`)}}
		}
		out = map[string]any{"results": results}
	}
	raw, _ := json.Marshal(out)
	return Observation{1, q.CaseID, "ACCEPT", raw}, nil
}
func TestReplayExchangeMaintainsBatchAndUnseenCloseControl(t *testing.T) {
	a, b := &replayFake{}, &replayFake{}
	r, e := RunReplayExchange(context.Background(), exchangeSubjects(), []Adapter{a, b})
	if e != nil || r.Status != "PASS" || r.ActionCounts["PASS"] != 36 {
		t.Fatalf("%+v %v", r, e)
	}
	if r.Conformance != "NOT_ESTABLISHED" {
		t.Fatal("full certification")
	}
	for _, f := range []*replayFake{a, b} {
		if len(f.calls) != 6 {
			t.Fatal("not one receiver call per direction")
		}
		for _, q := range f.calls {
			if q.Operation != "legacy.session.receive-sequence" || strings.HasSuffix(q.CaseID, "-fresh-record-control") {
				continue
			}
			var input struct {
				Actions []struct {
					Kind   string `json:"kind"`
					Record string `json:"record_hex"`
				} `json:"actions"`
			}
			if e := json.Unmarshal(q.Input, &input); e != nil {
				t.Fatal(e)
			}
			if len(input.Actions) != 9 || input.Actions[0].Record != input.Actions[1].Record || input.Actions[2].Record == input.Actions[3].Record || input.Actions[7].Kind != "close" || input.Actions[8].Record != "aa04" {
				t.Fatal("lost duplicate, corruption or fresh close control")
			}
		}
	}
}
func TestReplayExchangeDoesNotHideFailures(t *testing.T) {
	for _, mode := range []string{"error", "unsupported", "bad-producer", "missing", "replay-accepted", "closed-accepted", "wrong-plaintext"} {
		t.Run(mode, func(t *testing.T) {
			a, b := &replayFake{mode: mode}, &replayFake{}
			r, e := RunReplayExchange(context.Background(), exchangeSubjects(), []Adapter{a, b})
			if e != nil {
				t.Fatal(e)
			}
			if r.Status == "PASS" {
				t.Fatal("false PASS")
			}
			if mode == "unsupported" && (r.Status != "INCOMPLETE" || r.ActionCounts["NOT_RUN"] != 36) {
				t.Fatal("unsupported was executed")
			}
		})
	}
}
