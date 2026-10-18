// This program performs only a benign exchange with its own loopback TLS listener.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sage-x-project/sage-adk/core/a2abinding"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const requestText = " {\"jsonrpc\":\"2.0\",\"id\":\"inspection\",\"method\":\"GetTask\",\"params\":{\"id\":\"owned-task\"}} "
const replyText = `{"jsonrpc":"2.0","id":"inspection","result":{"ok":true}}`

type scenario struct {
	Completion string `json:"completion"`
}
type observation struct {
	Target             string                 `json:"target"`
	OwnerType          string                 `json:"owner_type"`
	IngressType        string                 `json:"ingress_type"`
	CardHex            string                 `json:"card_hex"`
	VerifiedCardHex    string                 `json:"verified_card_hex"`
	VerifiedDID        string                 `json:"verified_did"`
	VerifiedVersion    string                 `json:"verified_version"`
	EligibleInterfaces []a2abinding.Interface `json:"eligible_interfaces"`
	ClientCalls        int                    `json:"client_calls"`
	TLSHandshakes      int                    `json:"tls_handshakes"`
	HandlerCalls       int                    `json:"handler_calls"`
	HandlerPayloads    []string               `json:"handler_payloads_hex"`
	Replies            []string               `json:"replies_hex"`
	Errors             []string               `json:"errors"`
	SetupReservations  []int                  `json:"setup_reservations"`
	AcceptedRequests   int                    `json:"accepted_requests"`
	AcceptedResponses  int                    `json:"accepted_responses"`
	SourceReads        int                    `json:"source_reads"`
	SourceObservations int                    `json:"source_observations"`
	Records            []recordView           `json:"records"`
}
type handlerFunc func(context.Context, []byte) ([]byte, error)

func (h handlerFunc) Handle(ctx context.Context, p []byte) ([]byte, error) { return h(ctx, p) }
func observe(in scenario) observation {
	if in.Completion != "bare" && in.Completion != "http" {
		panic("unsupported benign completion")
	}
	listener := must(net.Listen("tcp", "127.0.0.1:0"))
	defer listener.Close()
	target := "https://" + listener.Addr().String() + "/sage%2Fa?client=%2f"
	directory := must(os.MkdirTemp("", "sage-did-authority-inspection-"))
	defer os.RemoveAll(directory)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
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
	verified := must(verifier.Verify(ctx, card))
	out := observation{Target: target, OwnerType: fmt.Sprintf("%T", owner), CardHex: hex.EncodeToString(card), VerifiedCardHex: hex.EncodeToString(verified.JSON()), VerifiedDID: verified.DID(), VerifiedVersion: verified.RecordVersion(), EligibleInterfaces: verified.Interfaces(), HandlerPayloads: []string{}, Replies: []string{}, Errors: []string{}, SetupReservations: []int{}, Records: []recordView{}}
	var effects, handshakes atomic.Int32
	var payloadMu sync.Mutex
	payloads := []string{}
	server := must(a2abinding.NewServer(a2abinding.ServerConfig{DID: serverDID, URL: target, Verifier: verifier, Card: func(context.Context) ([]byte, error) { return append([]byte(nil), card...), nil }, Handler: handlerFunc(func(_ context.Context, p []byte) ([]byte, error) {
		effects.Add(1)
		payloadMu.Lock()
		payloads = append(payloads, hex.EncodeToString(p))
		payloadMu.Unlock()
		return []byte(replyText), nil
	})}))
	tlsConfig := &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { handshakes.Add(1); return &cert, nil }}
	ingress := must(a2abinding.NewHTTPIngress(a2abinding.HTTPIngressConfig{Transport: a2abinding.HTTPTransportConfig{Session: right, URL: target, TLS: tlsConfig, TTL: 30, Timeout: 3 * time.Second}, Server: server}))
	defer ingress.Close()
	out.IngressType = fmt.Sprintf("%T", ingress)
	stopped := make(chan struct{})
	go func() { defer close(stopped); _ = ingress.ServeTLS(serverCtx, listener) }()
	client := must(a2abinding.NewClient(verifier, owner))
	out.ClientCalls++
	result, e := client.Call(ctx, card, []byte(requestText))
	out.Replies = append(out.Replies, hex.EncodeToString(result))
	code := ""
	if e != nil {
		code = e.Error()
	}
	out.Errors = append(out.Errors, code)
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
			err = fmt.Errorf("owned authority fixture failed: %v", failure)
		}
	}()
	raw, e := io.ReadAll(io.LimitReader(input, 4097))
	if e != nil {
		return e
	}
	if len(raw) > 4096 {
		return errors.New("selector exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var in scenario
	if e := decoder.Decode(&in); e != nil {
		return e
	}
	if e := decoder.Decode(new(any)); e != io.EOF {
		return errors.New("one selector required")
	}
	return json.NewEncoder(output).Encode(observe(in))
}
func main() {
	if e := run(os.Stdin, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
