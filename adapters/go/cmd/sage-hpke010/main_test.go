package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInvalidControlsHaveNoObservation(t *testing.T) {
	for _, input := range []string{`{"id":"x","operation":"domains","input":{"binding_hex":null}}`, `{"id":"x","operation":"domains","input":{"binding_hex":"zz"}}`, `{"id":"x","operation":"finish","input":{"transcript_hex":"00"}}`} {
		var out bytes.Buffer
		if run(strings.NewReader(input), &out) == nil || out.Len() != 0 {
			t.Fatal("invalid control produced observation")
		}
	}
}
func TestMissingOperationsStayUnsupported(t *testing.T) {
	var out bytes.Buffer
	if e := run(strings.NewReader(`{"id":"x","operation":"authenticate","input":{}}`), &out); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), `"verdict":"UNSUPPORTED"`) {
		t.Fatal(out.String())
	}
}
