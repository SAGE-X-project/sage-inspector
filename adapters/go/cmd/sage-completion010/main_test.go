package main

import "testing"

func TestControls(t *testing.T) {
	for _, s := range []string{`{}`, `{"id":"x","action":"start","mono_ms":0,"unix":100,"unexpected":true}`, `{"id":"x","action":"complete","mono_ms":0,"unix":100}`, `{"id":"x","action":"start","mono_ms":0,"unix":100,"mode":"arbitrary"}`} {
		if _, _, e := decode([]byte(s)); e == nil {
			t.Fatal("invalid accepted")
		}
	}
	if _, _, e := decode([]byte(`{"id":"x","action":"start","mono_ms":0,"unix":100}`)); e != nil {
		t.Fatal(e)
	}
}
