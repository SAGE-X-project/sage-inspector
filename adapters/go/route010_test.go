package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func call(t *testing.T, profile, op, input string) (string, map[string]any) {
	t.Helper()
	req := `{"schema_version":1,"protocol_version":"0.10.0","profile":"` + profile +
		`","case_id":"x","operation":"` + op + `","input":` + input + `}`
	var out bytes.Buffer
	if err := run(strings.NewReader(req), &out); err != nil {
		t.Fatalf("%s %s: %v", profile, op, err)
	}
	var res struct {
		Verdict string         `json:"verdict"`
		Output  map[string]any `json:"output"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res.Verdict, res.Output
}

func TestProfile010RoutesCanonicalizationToGuard010(t *testing.T) {
	duplicate := `{"document_hex":"7b2261223a312c2261223a327d"}`
	if v, _ := call(t, "primitive-foundation", "jcs.canonicalize", duplicate); v != "ACCEPT" {
		t.Fatalf("legacy profile changed: %s", v)
	}
	if v, _ := call(t, profile010, "jcs.canonicalize", duplicate); v != "REJECT" {
		t.Fatalf("0.10.0 profile accepted a duplicate member: %s", v)
	}
	if v, out := call(t, profile010, "json.syntax", `{"document_hex":"7b7d"}`); v != "ACCEPT" || out["valid"] != true {
		t.Fatalf("0.10.0 syntax: %s %v", v, out)
	}
}

func TestProfile010UsesTranscriptBoundCombiner(t *testing.T) {
	in := `{"exporter_hex":"a8de62cfb50aae8058d494a86b9420a9a04fbb5f19c4b25bda7c4cf251aa882c",` +
		`"ss_e2e_hex":"7cc2b7b281a0742951106c397572ff7ba1fc702a9fc46c9d8a0d984f52ed166f",` +
		`"th_hex":"a4dcfbf2cfe2b3ffd09acd65fbb78c675612b93c93b512a11b9b064786ee5488"}`
	_, out := call(t, profile010, "sage.hpke.combine", in)
	if out["seed_hex"] != "a670cc6a4cf4eed950a26f2e85a185457e283ba617fd87da485625d96a2a61a6" {
		t.Fatalf("0.10.0 combine: %v", out)
	}
}

func TestProfile010NeverReachesLegacyOnlyOperations(t *testing.T) {
	for _, op := range []string{"sage.session.record.open", "sage.session.record.seal",
		"sage.session.record.export", "legacy.session.export-sequence",
		"legacy.session.receive-sequence", "sage.registry.pop.verify"} {
		// Empty input would make the legacy path fail, so UNSUPPORTED proves it was not reached.
		if v, _ := call(t, profile010, op, `{}`); v != "UNSUPPORTED" {
			t.Fatalf("%s: %s", op, v)
		}
	}
}

func TestProfile010DIDRouteFollowsBuildTag(t *testing.T) {
	v, _ := call(t, profile010, "sage.did.validate", `{"did":"did:sage:web:agents.example.com:alice"}`)
	want := "UNSUPPORTED"
	if strictDID010 {
		want = "ACCEPT"
	}
	if v != want {
		t.Fatalf("strict DID route: got %s want %s", v, want)
	}
}

func TestUnknownProfileIsRefused(t *testing.T) {
	req := `{"schema_version":1,"protocol_version":"0.10.0","profile":"other","case_id":"x","operation":"json.syntax","input":{}}`
	if err := run(strings.NewReader(req), &bytes.Buffer{}); err == nil {
		t.Fatal("unknown profile accepted")
	}
}
