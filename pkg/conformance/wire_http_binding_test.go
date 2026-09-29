package conformance

import (
	"bytes"
	"os"
	"testing"
)

func TestWireHTTPBindingSuitePreservesBoundaryInput(t *testing.T) {
	f, err := os.Open("../../vectors/0.10.0/wire-http-binding.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	suite, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(suite.Cases) != 6 {
		t.Fatalf("cases = %d, want 6", len(suite.Cases))
	}
	var request []byte
	for _, c := range suite.Cases {
		if c.Operation != "sage.http.verify" {
			continue
		}
		message, err := DecodeHTTPBoundaryInput(c.Input)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		if message.Controls.NowUnix == nil || *message.Controls.NowUnix != 1730000010 ||
			message.Controls.ClockTrusted == nil || !*message.Controls.ClockTrusted {
			t.Fatalf("%s: trusted fixed clock missing", c.ID)
		}
		if c.ID == "wire-http-request-boundary" {
			request = message.Request
			if len(message.Response) != 0 {
				t.Fatal("request boundary contains a response")
			}
		} else if c.ID == "wire-http-response-boundary" {
			if !bytes.Equal(request, message.Request) ||
				!bytes.HasPrefix(message.Response, []byte("HTTP/1.1 503 Service Unavailable\r\n")) {
				t.Fatal("response lost the exact retained request or signed status")
			}
		} else {
			t.Fatalf("unexpected boundary case %s", c.ID)
		}
		if c.Expected.Verdict != "ACCEPT" {
			t.Fatalf("%s: unexpected reference expectation", c.ID)
		}
	}
	if len(request) == 0 {
		t.Fatal("missing request boundary")
	}
}
