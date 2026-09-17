package main

import "testing"

func TestControlDecoder(t *testing.T) {
	for _, s := range []string{`{"id":"x","request":{"action":"restart"}}`, `{"id":"x","request":{"action":"mutate"}}`} {
		if _, e := decode([]byte(s)); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{`{}`, `{"id":"x","request":{"action":"observe"}}`, `{"id":"x","request":{"action":"restart","expected":{}}}`, `{"id":"x","request":{"action":"restart"}} {}`} {
		if _, e := decode([]byte(s)); e == nil {
			t.Fatal("invalid control accepted", s)
		}
	}
}
