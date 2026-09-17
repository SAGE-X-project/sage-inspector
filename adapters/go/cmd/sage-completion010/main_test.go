package main

import (
	"encoding/json"
	"strings"
	"testing"
)

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

func TestHTTPControls(t *testing.T) {
	for _, action := range []string{"http-request-open", "http-response-open"} {
		for _, n := range []int{65538, 196608, 196610} {
			q := map[string]any{"id": "http", "action": action, "mono_ms": 0, "unix": 100, "wire_hex": strings.Repeat("00", n/2)}
			raw, _ := json.Marshal(q)
			_, _, e := decode(raw)
			if (e == nil) != (n <= 196608) {
				t.Fatal(action, n, e)
			}
		}
	}
	for _, q := range []map[string]any{{"action": "http-request-open"}, {"action": "http-bind", "wire_hex": ""}, {"action": "record-open", "wire_hex": strings.Repeat("0", 65538)}} {
		q["id"] = "http"
		q["mono_ms"] = 0
		q["unix"] = 100
		raw, _ := json.Marshal(q)
		if _, _, e := decode(raw); e == nil {
			t.Fatal("invalid control")
		}
	}
}
