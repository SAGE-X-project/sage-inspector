package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type exchangeFake struct {
	wire        string
	failProduce bool
	unsupported bool
	badIdentity bool
	wrongPlain  bool
	received    []string
}

func (f *exchangeFake) Observe(_ context.Context, q Request) (Observation, error) {
	if f.failProduce && q.Operation == "sage.session.record.export" {
		return Observation{}, fmt.Errorf("process failed")
	}
	if f.unsupported {
		return Observation{1, q.CaseID, "UNSUPPORTED", json.RawMessage(`{}`)}, nil
	}
	var input map[string]any
	if err := json.Unmarshal(q.Input, &input); err != nil {
		return Observation{}, err
	}
	o := Observation{1, q.CaseID, "ACCEPT", nil}
	if f.badIdentity {
		o.CaseID = "wrong"
	}
	if q.Operation == "sage.session.record.export" {
		o.Output, _ = json.Marshal(map[string]any{"record_hex": f.wire, "record_sha256": Digest([]byte{1, 2, 3, 4}), "record_bytes": 4})
		return o, nil
	}
	f.received = append(f.received, input["record_hex"].(string))
	if strings.HasSuffix(q.CaseID, "-valid") {
		plain := strings.Repeat("61", 32)
		if f.wrongPlain {
			plain = "00"
		}
		o.Output, _ = json.Marshal(map[string]string{"plaintext_hex": plain})
	} else {
		o.Verdict = "REJECT"
		o.Output = json.RawMessage(`{}`)
	}
	return o, nil
}
func exchangeSubjects() []Subject {
	return []Subject{{Name: "go", Revision: strings.Repeat("1", 40), Kind: "external", ExecutableSHA256: strings.Repeat("a", 64)}, {Name: "rust", Revision: strings.Repeat("2", 40), Kind: "external", ExecutableSHA256: strings.Repeat("b", 64)}}
}
func TestExchangeForwardsProducerBytes(t *testing.T) {
	a, b := &exchangeFake{wire: "01020304"}, &exchangeFake{wire: "01020304"}
	r, e := RunExchange(context.Background(), exchangeSubjects(), []Adapter{a, b})
	if e != nil || r.Counts["PASS"] != 32 || len(r.Exchanges) != 4 {
		t.Fatalf("%+v %v", r, e)
	}
	if r.Conformance != "NOT_ESTABLISHED" {
		t.Fatal("false certification")
	}
	for _, f := range []*exchangeFake{a, b} {
		if len(f.received) != 14 || f.received[0] != "01020304" || f.received[1] != "01020305" {
			t.Fatalf("wire not forwarded/mutated: %v", f.received)
		}
	}
}
func TestExchangeFailuresAreNotRejections(t *testing.T) {
	for _, kind := range []string{"process", "unsupported", "hash", "identity", "plaintext"} {
		t.Run(kind, func(t *testing.T) {
			a, b := &exchangeFake{wire: "01020304"}, &exchangeFake{wire: "01020304"}
			switch kind {
			case "process":
				a.failProduce = true
			case "unsupported":
				a.unsupported = true
			case "hash":
				a.wire = "deadbeef"
			case "identity":
				a.badIdentity = true
			case "plaintext":
				a.wrongPlain = true
			}
			r, e := RunExchange(context.Background(), exchangeSubjects(), []Adapter{a, b})
			if e != nil {
				t.Fatal(e)
			}
			if r.Status == "PASS" {
				t.Fatal("bad adapter promoted to pass")
			}
			if kind != "plaintext" && r.Counts["NOT_RUN"] < 14 {
				t.Fatal("receiver used nonexistent sender bytes")
			}
			if kind == "plaintext" && r.Exchanges[2].Checks[1].PositiveControl != "FAIL" {
				t.Fatal("lost failed positive control")
			}
		})
	}
}
func TestExchangeRejectsSameSubject(t *testing.T) {
	subjects := exchangeSubjects()
	subjects[1].ExecutableSHA256 = subjects[0].ExecutableSHA256
	if _, e := RunExchange(context.Background(), subjects, []Adapter{&exchangeFake{}, &exchangeFake{}}); e == nil {
		t.Fatal("same binary accepted")
	}
}
