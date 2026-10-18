// The only network destination this observer can use is its own loopback TLS
// listener. It accepts a closed scenario name, never arbitrary traffic or URLs.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sage-x-project/sage-adk/core/a2abinding"
)

var modes = map[string]bool{"success": true, "repeat": true, "unsupported": true, "source-after-setup": true, "expired-after-setup": true, "cancel-after-setup": true, "close-after-setup": true, "source-after-handler": true, "expired-after-handler": true, "close-during-handler": true, "cancel-during-handler": true}

const requestText = " {\"jsonrpc\":\"2.0\",\"id\":\"inspection\",\"method\":\"GetTask\",\"params\":{\"id\":\"owned-task\"}} "
const replyText = `{"jsonrpc":"2.0","id":"inspection","result":{"ok":true}}`
const unsupportedText = `{"jsonrpc":"2.0","id":"inspection","method":"GetExtendedAgentCard","params":{}}`

type scenario struct {
	Mode       string `json:"mode"`
	Completion string `json:"completion"`
}
type observation struct {
	Target             string       `json:"target"`
	OwnerType          string       `json:"owner_type"`
	IngressType        string       `json:"ingress_type"`
	CardHex            string       `json:"card_hex"`
	ClientCalls        int          `json:"client_calls"`
	TLSHandshakes      int          `json:"tls_handshakes"`
	HandlerCalls       int          `json:"handler_calls"`
	HandlerPayloads    []string     `json:"handler_payloads_hex"`
	Replies            []string     `json:"replies_hex"`
	Errors             []string     `json:"errors"`
	SetupReservations  []int        `json:"setup_reservations"`
	AcceptedRequests   int          `json:"accepted_requests"`
	AcceptedResponses  int          `json:"accepted_responses"`
	SourceReads        int          `json:"source_reads"`
	SourceObservations int          `json:"source_observations"`
	Records            []recordView `json:"records"`
}

type handlerFunc func(context.Context, []byte) ([]byte, error)

func (h handlerFunc) Handle(c context.Context, p []byte) ([]byte, error) { return h(c, p) }

func observe(in scenario) observation {
	if !modes[in.Mode] || (in.Completion != "bare" && in.Completion != "http") {
		panic("unsupported owned HTTP scenario")
	}
	listener := must(net.Listen("tcp", "127.0.0.1:0"))
	defer func() { _ = listener.Close() }()
	target := "https://" + listener.Addr().String() + "/sage%2Fa?client=%2f"
	directory := must(os.MkdirTemp("", "sage-owned-http-inspection-"))
	defer func() { _ = os.RemoveAll(directory) }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Client cancellation must not cancel the independent server context.
	serverCtx, stopServer := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopServer()
	f := &fixture{unix: epoch, target: target, records: []recordView{}}
	left, right, leftReplay, rightReplay, cleanup := complete(ctx, directory, f, in.Completion == "http")
	defer cleanup()
	cert, roots := certificate()
	owner := must(a2abinding.NewHTTPTransportOwner(a2abinding.HTTPTransportConfig{Session: left, URL: target, TLS: &tls.Config{RootCAs: roots}, TTL: 30, Timeout: 3 * time.Second}))
	defer owner.Close()
	verifier := must(a2abinding.NewVerifier(a2abinding.VerifierConfig{Source: f, Clock: f, ExpectedPeer: serverDID}))
	card := signedCard(target)
	out := observation{Target: target, OwnerType: fmt.Sprintf("%T", owner), CardHex: hex.EncodeToString(card), HandlerPayloads: []string{}, Replies: []string{}, Errors: []string{}, SetupReservations: []int{}, Records: []recordView{}}
	var effects, handshakes atomic.Int32
	var payloadMu sync.Mutex
	payloads := []string{}
	server := must(a2abinding.NewServer(a2abinding.ServerConfig{DID: serverDID, URL: target, Verifier: verifier, Card: func(context.Context) ([]byte, error) { return append([]byte(nil), card...), nil }, Handler: handlerFunc(func(_ context.Context, p []byte) ([]byte, error) {
		effects.Add(1)
		payloadMu.Lock()
		payloads = append(payloads, hex.EncodeToString(p))
		payloadMu.Unlock()
		switch in.Mode {
		case "source-after-handler":
			f.fail()
		case "expired-after-handler":
			f.expire()
		case "cancel-during-handler":
			cancel()
		case "close-during-handler":
			owner.Close()
		}
		return []byte(replyText), nil
	})}))
	tlsConfig := &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		handshakes.Add(1)
		switch in.Mode {
		case "source-after-setup":
			f.fail()
		case "expired-after-setup":
			f.expire()
		case "cancel-after-setup":
			cancel()
		case "close-after-setup":
			owner.Close()
		}
		return &cert, nil
	}}
	ingress := must(a2abinding.NewHTTPIngress(a2abinding.HTTPIngressConfig{Transport: a2abinding.HTTPTransportConfig{Session: right, URL: target, TLS: tlsConfig, TTL: 30, Timeout: 3 * time.Second}, Server: server}))
	defer ingress.Close()
	out.IngressType = fmt.Sprintf("%T", ingress)
	stopped := make(chan struct{})
	go func() { defer close(stopped); _ = ingress.ServeTLS(serverCtx, listener) }()
	client := must(a2abinding.NewClient(verifier, owner))
	text := requestText
	if in.Mode == "unsupported" {
		text = unsupportedText
	}
	calls := 1
	if in.Mode == "repeat" {
		calls = 2
	}
	for step := 0; step < calls; step++ {
		if step == 1 {
			copied := *owner
			client = must(a2abinding.NewClient(verifier, &copied))
		}
		out.ClientCalls++
		result, e := client.Call(ctx, card, []byte(text))
		out.Replies = append(out.Replies, hex.EncodeToString(result))
		code := ""
		if e != nil {
			code = e.Error()
		}
		out.Errors = append(out.Errors, code)
	}
	// Wait for the actual Handler/connection lifetime before reading state. A
	// canceled client can have an accepted request and an uncertain prior effect.
	owner.Close()
	ingress.Close()
	select {
	case <-stopped:
	case <-time.After(4 * time.Second):
		panic("owned listener did not terminate")
	}
	out.TLSHandshakes = int(handshakes.Load())
	out.HandlerCalls = int(effects.Load())
	payloadMu.Lock()
	out.HandlerPayloads = append(out.HandlerPayloads, payloads...)
	payloadMu.Unlock()
	ls, la := leftReplay.counts()
	rs, ra := rightReplay.counts()
	out.SetupReservations = []int{ls, rs}
	out.AcceptedRequests = ra
	out.AcceptedResponses = la
	f.mu.Lock()
	out.SourceReads = f.reads
	out.SourceObservations = f.observations
	out.Records = append(out.Records, f.records...)
	f.mu.Unlock()
	return out
}

func run(input io.Reader, output io.Writer) (err error) {
	defer func() {
		if failure := recover(); failure != nil {
			err = fmt.Errorf("owned fixture observation failed: %v", failure)
		}
	}()
	raw, e := io.ReadAll(io.LimitReader(input, 4097))
	if e != nil {
		return e
	}
	if len(raw) > 4096 {
		return errors.New("scenario exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var in scenario
	if e := decoder.Decode(&in); e != nil {
		return e
	}
	if e := decoder.Decode(new(any)); e != io.EOF {
		return errors.New("one scenario required")
	}
	return json.NewEncoder(output).Encode(observe(in))
}
func main() {
	if e := run(os.Stdin, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
