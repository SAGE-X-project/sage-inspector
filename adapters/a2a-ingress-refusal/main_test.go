package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/sage-adk/core/a2abinding"
	"github.com/sage-x-project/sage/pkg/agent/hpke"
	"github.com/sage-x-project/sage/pkg/agent/registry010"
	"io"
	"reflect"
	"strings"
	"testing"
)

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
	if !errors.Is(run(strings.NewReader(`{"completion":"http"}`), fixtureWriterError{}), io.ErrClosedPipe) {
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

// Calibrate the Source through the real gate before using it in a handshake.
func TestFixtureCoreGateAdmissionAndDigest(t *testing.T) {
	f := &fixture{unix: epoch, target: "https://127.0.0.1:12345/sage%2Fa?client=%2f"}
	journal := must(registry010.OpenJournal(t.TempDir()+"/registry", true))
	defer journal.Close()
	gate := must(registry010.NewGate(registry010.Config{Source: "inspector-ingress-refusal", Registry: "web:inspection.example", Network: "owned-fixture"}, f, f, journal))
	for _, who := range []string{callerDID, serverDID} {
		pinned, e := gate.Select(context.Background(), who, who+"#sign", who == serverDID)
		if e != nil || pinned.Signing().Name != "sign" {
			t.Fatal("fixture not admitted by real registry gate", who, e)
		}
		if who == serverDID {
			if pinned.KEM() == nil || pinned.KEM().Name != "kem" || pinned.KEM().Material != "51ddf3cb36a42fdf3d6a81dfcaada9fe17818aa145548a08e51f2d73e9452478" || pinned.Signing().Material != "31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc" {
				t.Fatal("independent registered public keys disagree")
			}
		}
	}
	before := must(f.Read(context.Background(), serverDID))
	f.expire()
	after := must(f.Read(context.Background(), serverDID))
	if before.Digest != after.Digest || before.AcquiredMS != 0 || after.AcquiredMS != 6000 {
		t.Fatal("observation time changed immutable record identity")
	}
	if len(after.Keys) != 2 || after.Keys[0].Name != "kem" || after.Keys[1].Name != "sign" {
		t.Fatal("registry key order")
	}
}

func TestBenignIngressRuntime(t *testing.T) {
	for _, completion := range []string{"bare", "http"} {
		t.Run(completion, func(t *testing.T) {
			out := observe(scenario{Completion: completion})
			if !reflect.DeepEqual(out.EligibleInterfaces, []a2abinding.Interface{{URL: out.Target, Tenant: ""}}) || out.VerifiedDID != serverDID || out.VerifiedVersion != "17" || out.VerifiedCardHex != out.CardHex {
				t.Fatal("received document was not retained by actual Verifier")
			}
			if out.ClientCalls != 1 || out.TLSHandshakes != 1 || out.HandlerCalls != 1 || out.AcceptedRequests != 1 || out.AcceptedResponses != 1 {
				t.Fatal("benign exchange phases", out)
			}
			if len(out.Replies) != 1 || out.Replies[0] != hex.EncodeToString([]byte(replyText)) || len(out.Errors) != 1 || out.Errors[0] != "" || len(out.HandlerPayloads) != 1 || out.HandlerPayloads[0] != hex.EncodeToString([]byte(requestText)) {
				t.Fatal("actual payload/error changed")
			}
			if out.OwnerType != "*a2abinding.HTTPTransportOwner" || out.IngressType != "*a2abinding.HTTPIngress" || out.SourceReads < 1 || out.SourceObservations < 1 || !reflect.DeepEqual(out.SetupReservations, []int{1, 1}) {
				t.Fatal("missing actual public components")
			}
		})
	}
}

func TestFailedCompletionReleasesFixture(t *testing.T) {
	f := &fixture{unix: epoch, target: "https://inspection.invalid/authority"}
	f.fail()
	directory := t.TempDir()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("unavailable fixture setup accepted")
			}
		}()
		complete(context.Background(), directory, f, false)
	}()
	for _, name := range []string{"caller", "server"} {
		journal, e := registry010.OpenJournal(directory+"/"+name, false)
		if e != nil {
			t.Fatal("failed setup retained journal", e)
		}
		_ = journal.Close()
	}
}
