package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestUnsupportedObservation(t *testing.T) {
	q := `{"schema_version":2,"protocol_version":"0.10.0","profile":"stateful-scenario","case_id":"test","step_id":"one","operation":"record010.inspect","input":{}}`
	var out bytes.Buffer
	if e := run(strings.NewReader(q+"\n"), &out); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), `"verdict":"UNSUPPORTED"`) || !strings.Contains(out.String(), `"core_open_success":0`) {
		t.Fatal(out.String())
	}
}
func TestInvalidStreamDoesNotProduceObservation(t *testing.T) {
	for _, q := range []string{`{"schema_version":1}`, `{"schema_version":2,"protocol_version":"0.10.0","profile":"stateful-scenario","case_id":"test","step_id":"one","operation":"record010.close","input":{}}`} {
		var out bytes.Buffer
		if e := run(strings.NewReader(q+"\n"), &out); e == nil || out.Len() != 0 {
			t.Fatalf("error=%v output=%s", e, out.String())
		}
	}
}
