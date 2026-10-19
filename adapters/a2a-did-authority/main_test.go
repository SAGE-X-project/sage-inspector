package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	sagedid "github.com/sage-x-project/did-go/advanced/sage"
	didgo "github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/sage-adk/core/a2abinding"
	"github.com/sage-x-project/sage/pkg/agent/hpke"
	"github.com/sage-x-project/sage/pkg/agent/registry010"
	"io"
	"os"
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
	gate := must(registry010.NewGate(registry010.Config{Source: "inspector-did-authority", Registry: "web:inspection.example", Network: "owned-fixture"}, f, f, journal))
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

func TestBenignDocumentRuntime(t *testing.T) {
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

type authorityOutcome struct {
	Accepted        bool     `json:"accepted"`
	Error           string   `json:"error"`
	SourceDIDs      []string `json:"source_dids"`
	DID             string   `json:"did"`
	Version         string   `json:"version"`
	ReturnedCardHex string   `json:"returned_card_hex"`
}
type authorityCase struct {
	ID               string           `json:"id"`
	InputCardHex     string           `json:"input_card_hex"`
	SigningPublicHex string           `json:"signing_public_hex"`
	SourceMode       string           `json:"source_mode"`
	ExpectedPeer     string           `json:"expected_peer"`
	Expected         authorityOutcome `json:"expected"`
}
type authorityKey struct {
	Name        string `json:"name"`
	Alg         string `json:"alg"`
	State       string `json:"state"`
	MaterialHex string `json:"material_hex"`
}
type authorityRecord struct {
	DID        string         `json:"did"`
	Controller string         `json:"controller"`
	Version    string         `json:"version"`
	State      string         `json:"state"`
	Keys       []authorityKey `json:"keys"`
	Service    string         `json:"service"`
}
type authoritySource struct {
	base    *fixture
	mode    string
	calls   []string
	records []authorityRecord
}

// This is an isolated trusted test Source, never a document-ignoring verifier.
func (s *authoritySource) Observe(ctx context.Context, d didgo.DID) (sagedid.Record, error) {
	s.calls = append(s.calls, d.String())
	r, e := s.base.Observe(ctx, d)
	if e != nil {
		return r, e
	}
	switch s.mode {
	case "normal", "unavailable":
	case "missing-sign":
		keys := []sagedid.Key{}
		for _, key := range r.Keys {
			if key.Name != "sign" {
				keys = append(keys, key)
			}
		}
		r.Keys = keys
	case "revoked-sign":
		for n := range r.Keys {
			if r.Keys[n].Name == "sign" {
				r.Keys[n].State = sagedid.KeyRevoked
			}
		}
	default:
		panic("unknown static authority fixture")
	}
	if s.mode == "missing-sign" || s.mode == "revoked-sign" {
		// An active record still needs an unrelated accepted signing key. It
		// must never substitute for the exact name bound by the protected kid.
		other := sagedid.Key{Name: "other", Alg: sagedid.AlgEd25519, State: sagedid.KeyAccepted, Material: must(hex.DecodeString("bed7d2ab668da3efad613998f06f7abf7875f3a6b7677a9f3ce947d77d7760a6"))}
		keys := []sagedid.Key{}
		for _, key := range r.Keys {
			if key.Name == "sign" {
				keys = append(keys, other)
			}
			keys = append(keys, key)
		}
		if s.mode == "missing-sign" {
			keys = append(keys, other)
		}
		r.Keys = keys
	}
	if _, invalid := sagedid.Document(r, sagedid.Core10); invalid != nil {
		panic("structurally invalid authority fixture: " + invalid.Error())
	}
	// Capture the effective record actually returned to Verify, after variation.
	view := authorityRecord{DID: r.DID.String(), Controller: r.Controller, Version: r.Version, State: string(r.State), Keys: []authorityKey{}}
	for _, key := range r.Keys {
		view.Keys = append(view.Keys, authorityKey{key.Name, key.Alg, string(key.State), hex.EncodeToString(key.Material)})
	}
	for _, service := range r.Services {
		if service.Type == "A2AInterface" {
			view.Service = service.URI
		}
	}
	s.records = append(s.records, view)
	return r, nil
}

type authorityObservation struct {
	ID                     string                 `json:"id"`
	InputCardHex           string                 `json:"input_card_hex"`
	SigningPublicHex       string                 `json:"signing_public_hex"`
	SourceMode             string                 `json:"source_mode"`
	ConfiguredExpectedPeer string                 `json:"configured_expected_peer"`
	StdSignatureValid      bool                   `json:"std_signature_valid"`
	Result                 authorityOutcome       `json:"result"`
	SourceRecords          []authorityRecord      `json:"source_records"`
	EligibleInterfaces     []a2abinding.Interface `json:"eligible_interfaces"`
}

func independentSignature(raw, public []byte) bool {
	var card map[string]json.RawMessage
	if json.Unmarshal(raw, &card) != nil {
		return false
	}
	var signatures []map[string]string
	if json.Unmarshal(card["signatures"], &signatures) != nil || len(signatures) != 1 {
		return false
	}
	delete(card, "signatures")
	payload, e := json.Marshal(card)
	if e != nil {
		return false
	}
	header := signatures[0]["protected"]
	sig, e := base64.RawURLEncoding.DecodeString(signatures[0]["signature"])
	if e != nil {
		return false
	}
	return len(public) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(public), []byte(header+"."+base64.RawURLEncoding.EncodeToString(payload)), sig)
}

// All contradictory-key/signature/alias controls are memory-only test inputs.
// The production CLI cannot select any of these cases or a destination.
func TestCardAuthority(t *testing.T) {
	var vectors struct {
		Target string          `json:"target"`
		Cases  []authorityCase `json:"cases"`
	}
	raw := must(os.ReadFile("../../vectors/0.10.0/a2a-did-authority-observations.json"))
	if json.Unmarshal(raw, &vectors) != nil || len(vectors.Cases) != 13 || vectors.Target != "https://inspection.invalid/authority" {
		t.Fatal("independent authority fixture set")
	}
	for _, c := range vectors.Cases {
		t.Run(c.ID, func(t *testing.T) {
			input := must(hex.DecodeString(c.InputCardHex))
			public := must(hex.DecodeString(c.SigningPublicHex))
			f := &fixture{unix: epoch, target: vectors.Target}
			if c.SourceMode == "unavailable" {
				f.fail()
			}
			source := &authoritySource{base: f, mode: c.SourceMode, calls: []string{}, records: []authorityRecord{}}
			verifier := must(a2abinding.NewVerifier(a2abinding.VerifierConfig{Source: source, Clock: f, ExpectedPeer: c.ExpectedPeer}))
			independentlyValid := independentSignature(input, public)
			value, e := verifier.Verify(context.Background(), input)
			outcome := authorityOutcome{Accepted: e == nil && value != nil, SourceDIDs: source.calls}
			if e != nil {
				outcome.Error = e.Error()
			}
			interfaces := []a2abinding.Interface{}
			if value != nil {
				interfaces = value.Interfaces()
				outcome.DID = value.DID()
				outcome.Version = value.RecordVersion()
				outcome.ReturnedCardHex = hex.EncodeToString(value.JSON())
			}
			witness := authorityObservation{c.ID, c.InputCardHex, c.SigningPublicHex, c.SourceMode, c.ExpectedPeer, independentlyValid, outcome, source.records, interfaces}
			t.Log("AUTHORITY_OBSERVATION " + string(must(json.Marshal(witness))))
			if !independentlyValid {
				t.Fatal("Python fixture signature not independently valid")
			}
			wantInterfaces := []a2abinding.Interface{}
			if c.Expected.Accepted {
				wantInterfaces = []a2abinding.Interface{{URL: vectors.Target, Tenant: ""}}
			}
			if !reflect.DeepEqual(interfaces, wantInterfaces) {
				t.Fatal("actual eligible interfaces differ", interfaces)
			}
			if !reflect.DeepEqual(outcome, c.Expected) {
				t.Fatal("actual authority decision differs", outcome, c.Expected)
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
