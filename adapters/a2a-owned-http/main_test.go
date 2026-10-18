package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/sage/pkg/agent/hpke"
	"io"
	"strings"
	"testing"
)

func TestNativeOwnedHTTPScenarios(t *testing.T) {
	for _, completion := range []string{"bare", "http"} {
		for _, mode := range []string{"success", "repeat", "unsupported", "source-after-setup", "expired-after-setup", "cancel-after-setup", "close-after-setup", "source-after-handler", "expired-after-handler", "close-during-handler", "cancel-during-handler"} {
			t.Run(completion+"/"+mode, func(t *testing.T) {
				actual := observe(scenario{mode, completion})
				calls := 1
				if mode == "repeat" {
					calls = 2
				}
				handler := 0
				switch mode {
				case "success", "source-after-handler", "expired-after-handler", "close-during-handler", "cancel-during-handler":
					handler = 1
				case "repeat":
					handler = 2
				}
				requests, responses := 0, 0
				switch mode {
				case "success", "repeat", "unsupported":
					requests = calls
					responses = calls
				case "source-after-handler", "expired-after-handler", "close-during-handler", "cancel-during-handler":
					requests = 1
				}
				if actual.ClientCalls != calls || actual.TLSHandshakes != calls || actual.HandlerCalls != handler || actual.AcceptedRequests != requests || actual.AcceptedResponses != responses {
					t.Fatal("observed phase counts", actual.ClientCalls, actual.TLSHandshakes, actual.HandlerCalls, actual.AcceptedRequests, actual.AcceptedResponses)
				}
				if actual.OwnerType != "*a2abinding.HTTPTransportOwner" || actual.IngressType != "*a2abinding.HTTPIngress" || actual.SourceReads < 1 || actual.SourceObservations < 1 {
					t.Fatal("real public components were not observed")
				}
				if len(actual.HandlerPayloads) != handler {
					t.Fatal("missing actual Handler payload")
				}
				for _, raw := range actual.HandlerPayloads {
					if raw != hex.EncodeToString([]byte(requestText)) {
						t.Fatal("Handler request bytes changed")
					}
				}
				if len(actual.Errors) != calls || len(actual.Replies) != calls {
					t.Fatal("missing actual caller outcomes")
				}
				for n, code := range actual.Errors {
					if mode == "success" || mode == "repeat" {
						if code != "" || actual.Replies[n] != hex.EncodeToString([]byte(replyText)) {
							t.Fatal("successful exact reply not observed", code)
						}
					} else if mode == "unsupported" {
						data := must(hex.DecodeString(actual.Replies[n]))
						var reply struct {
							Error struct {
								Code int `json:"code"`
							} `json:"error"`
						}
						if code != "" || json.Unmarshal(data, &reply) != nil || reply.Error.Code != -32004 {
							t.Fatal("unsupported method lost signed A2A error", code)
						}
					} else if code != "authentication failed" || actual.Replies[n] != "" {
						t.Fatal("failed exchange returned usable output", code)
					}
				}
				if len(actual.SetupReservations) != 2 || actual.SetupReservations[0] != 1 || actual.SetupReservations[1] != 1 {
					t.Fatal("setup reservations confused with records")
				}
			})
		}
	}
}

func TestNativeSelectorAndIORefusals(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", "{}", `{"mode":"unknown","completion":"bare"}`, `{"mode":"success","completion":"unknown"}`, `{"mode":"success","completion":"bare","destination":"https://example.invalid"}`, "{}{}", strings.Repeat(" ", 4097)} {
		var out bytes.Buffer
		if run(strings.NewReader(raw), &out) == nil || out.Len() != 0 {
			t.Fatal("unsafe or incomplete selector accepted", raw[:min(len(raw), 100)])
		}
	}
	var out bytes.Buffer
	if run(fixtureReaderError{}, &out) == nil || out.Len() != 0 {
		t.Fatal("input error ignored")
	}
	if run(strings.NewReader(`{"mode":"success","completion":"http"}`), fixtureWriterError{}) == nil {
		t.Fatal("output failure ignored")
	}
}

type fixtureReaderError struct{}

func (fixtureReaderError) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type fixtureWriterError struct{}

func (fixtureWriterError) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestIndependentFixtureCardAndKeys(t *testing.T) {
	target := "https://127.0.0.1:12345/sage%2Fa?client=%2f"
	raw := signedCard(target)
	var card map[string]json.RawMessage
	if json.Unmarshal(raw, &card) != nil {
		t.Fatal("card JSON")
	}
	var signatures []map[string]string
	if json.Unmarshal(card["signatures"], &signatures) != nil || len(signatures) != 1 {
		t.Fatal("card signature")
	}
	delete(card, "signatures")
	payload := must(json.Marshal(card))
	header := signatures[0]["protected"]
	signature := must(base64.RawURLEncoding.DecodeString(signatures[0]["signature"]))
	pub := must(hex.DecodeString("31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc"))
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(header+"."+base64.RawURLEncoding.EncodeToString(payload)), signature) {
		t.Fatal("fixture signature not independently valid")
	}
	if hex.EncodeToString(signingKey(callerDID).Public().(ed25519.PublicKey)) != "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737" || hex.EncodeToString(kemKey().PublicKey().Bytes()) != "51ddf3cb36a42fdf3d6a81dfcaada9fe17818aa145548a08e51f2d73e9452478" {
		t.Fatal("independent Python fixture public keys disagree")
	}
}

func TestFixtureSourceFailureAndReservation(t *testing.T) {
	f := &fixture{unix: epoch, target: "https://127.0.0.1/owned"}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, e := f.Read(ctx, "did:sage:web:inspection.example:unknown"); e == nil {
			t.Fatal("unknown fixture authority accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := f.Read(ctx, callerDID); e == nil {
		t.Fatal("canceled Source accepted")
	}
	f.fail()
	if _, e := f.Read(context.Background(), callerDID); e == nil {
		t.Fatal("unavailable Source accepted")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("fixture construction failure hidden")
		}
	}()
	_ = must(0, errors.New("fixture error"))
}

// These synthetic reservations stay entirely in memory; no packet is sent.
func TestReplayFixtureReservations(t *testing.T) {
	s := &replay{denied: map[string]bool{}}
	v := hpke.Replay010{Sender: callerDID, Recipient: serverDID, ID: "setup", Nonce: "nonce", Context: "context"}
	if s.Reserve(v) != nil || s.Reserve(v) == nil {
		t.Fatal("setup duplicate was not refused")
	}
	if a, b := s.counts(); a != 1 || b != 0 {
		t.Fatal("setup counted as record acceptance")
	}
	v.ID = "another"
	v.Nonce = "other"
	if s.Reserve(v) == nil {
		t.Fatal("setup context reused")
	}
	v.ID = "request"
	v.Nonce = "record"
	rejected := errors.New("fixture validation refused")
	if e := s.ReserveRecord(v, func() error { return rejected }); !errors.Is(e, rejected) {
		t.Fatal("validation failure lost")
	}
	called := false
	if s.ReserveRecord(v, func() error { called = true; return nil }) == nil || called {
		t.Fatal("rejected reservation retried")
	}
	v.ID = "accepted"
	v.Nonce = "accepted-nonce"
	if s.ReserveRecord(v, func() error { return nil }) != nil {
		t.Fatal("valid record refused")
	}
	if a, b := s.counts(); a != 1 || b != 1 {
		t.Fatal("actual accepted counter")
	}
}
