// Observe ADK policy through inert local fixtures. This is not a SAGE transport,
// Registry Source, Execution Guard, or deployed alternate-binding listener.
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
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	"github.com/sage-x-project/did-go/advanced/sage"
	didgo "github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/sage-adk/core/a2abinding"
	"github.com/sage-x-project/sage/pkg/agent/registry010"
)

const peer = "did:sage:web:agents.example.com:billing-bot"
const endpoint = "https://agents.example.com/a2a"

type fixtureInput struct {
	API               string            `json:"api"`
	Payload           string            `json:"payload"`
	Metadata          map[string]string `json:"metadata"`
	Recipient         string            `json:"recipient"`
	Card              string            `json:"card"`
	KeyHex            string            `json:"key_hex"`
	TenantRoute       string            `json:"tenant_route"`
	HeaderVersion     string            `json:"header_version"`
	SourceError       bool              `json:"source_error"`
	ClientCardInvalid bool              `json:"client_card_invalid"`
	ResponseSender    string            `json:"response_sender"`
	Reply             string            `json:"reply"`
}
type request struct {
	Mode    string       `json:"mode"`
	Fixture fixtureInput `json:"fixture"`
}
type output struct {
	Headers         []string `json:"fixture_headers"`
	Errors          []string `json:"errors"`
	Replies         []string `json:"replies_hex"`
	Dispatches      int      `json:"dispatch_count"`
	OwnerCalls      int      `json:"owner_calls"`
	FinalChecks     int      `json:"final_checks"`
	Payloads        []string `json:"payloads_hex"`
	HandlerPayloads []string `json:"handler_payloads_hex"`
	Targets         []string `json:"targets"`
	Recipients      []string `json:"recipients"`
	Versions        []string `json:"versions"`
	Extensions      []string `json:"extensions"`
	HTTPStatuses    []int    `json:"http_statuses"`
}

func emptyOutput() output {
	return output{Errors: []string{}, Replies: []string{}, Payloads: []string{}, HandlerPayloads: []string{}, Targets: []string{}, Recipients: []string{}, Versions: []string{}, Extensions: []string{}, Headers: []string{}, HTTPStatuses: []int{}}
}

type source struct {
	record sage.Record
	fail   bool
}

func (s source) Observe(context.Context, didgo.DID) (sage.Record, error) {
	if s.fail {
		return sage.Record{}, errors.New("fixture unavailable")
	}
	return s.record, nil
}

type clock struct{}

func (clock) Now() (registry010.Stamp, error) { return registry010.Stamp{MonoMS: 100, Unix: 101}, nil }

type ownerFunc func(context.Context, a2abinding.ProtectedCall, func(context.Context) error) (a2abinding.AuthenticatedResponse, error)

func (f ownerFunc) Exchange(c context.Context, p a2abinding.ProtectedCall, g func(context.Context) error) (a2abinding.AuthenticatedResponse, error) {
	return f(c, p, g)
}

type handlerFunc func(context.Context, []byte) ([]byte, error)

func (f handlerFunc) Handle(c context.Context, b []byte) ([]byte, error) { return f(c, b) }

type frame struct {
	Scope     string
	Target    string
	Recipient string
	Metadata  map[string]string
	Payload   []byte
}
type replyFrame struct {
	Sender  string
	Payload []byte
	Error   string
}
type observer struct {
	mu      sync.Mutex
	out     output
	server  *a2abinding.Server
	in      fixtureInput
	mode    string
	tls     *httptest.Server
	failure error
}

func (o *observer) deliver(ctx context.Context, f frame) replyFrame {
	o.mu.Lock()
	o.out.Payloads = append(o.out.Payloads, hex.EncodeToString(f.Payload))
	o.out.Targets = append(o.out.Targets, f.Target)
	o.out.Recipients = append(o.out.Recipients, f.Recipient)
	o.out.Versions = append(o.out.Versions, f.Metadata["a2a_version"])
	o.out.Extensions = append(o.out.Extensions, f.Metadata["a2a_extensions"])
	o.mu.Unlock()
	b, e := o.server.Handle(ctx, a2abinding.AuthenticatedRequest{URL: f.Target, Recipient: f.Recipient, Metadata: f.Metadata, Payload: f.Payload})
	if e != nil {
		return replyFrame{Error: e.Error()}
	}
	return replyFrame{Sender: o.in.ResponseSender, Payload: b}
}
func (o *observer) serve(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.Method != "POST" {
		w.WriteHeader(400)
		return
	}
	var f frame
	dec := json.NewDecoder(io.LimitReader(r.Body, 16385))
	dec.DisallowUnknownFields()
	if dec.Decode(&f) != nil || f.Scope != "fixture-policy-only" {
		w.WriteHeader(400)
		return
	}
	o.mu.Lock()
	o.out.Headers = append(o.out.Headers, r.Header.Get("A2A-Version"))
	o.mu.Unlock()
	reply := o.deliver(r.Context(), f)
	status := 200
	if reply.Error != "" {
		status = 403
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(reply)
}
func (o *observer) check(ctx context.Context, g func(context.Context) error) error {
	o.mu.Lock()
	o.out.FinalChecks++
	o.mu.Unlock()
	return g(ctx)
}
func (o *observer) exchange(ctx context.Context, f frame, g func(context.Context) error) (replyFrame, error) {
	if o.mode == "direct" {
		if g != nil {
			if e := o.check(ctx, g); e != nil {
				return replyFrame{}, e
			}
		}
		return o.deliver(ctx, f), nil
	}
	transport := o.tls.Client().Transport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	config := transport.TLSClientConfig.Clone()
	config.MinVersion = tls.VersionTLS13
	// The test dial is to our owned loopback fixture, not the card's public host.
	// Gate execution is after TLS setup and before the HTTP body is published.
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, e := (&tls.Dialer{Config: config}).DialContext(ctx, network, addr)
		if e != nil {
			return nil, e
		}
		if g != nil {
			if e = o.check(ctx, g); e != nil {
				c.Close()
				return nil, e
			}
		}
		return c, nil
	}
	defer transport.CloseIdleConnections()
	b, e := json.Marshal(f)
	if e != nil {
		return replyFrame{}, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", o.tls.URL+"/policy", bytes.NewReader(b))
	if e != nil {
		return replyFrame{}, e
	}
	req.Header.Set("Content-Type", "application/json")
	if o.in.HeaderVersion != "" {
		req.Header.Set("A2A-Version", o.in.HeaderVersion)
	}
	res, e := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(req)
	if e != nil {
		return replyFrame{}, e
	}
	defer res.Body.Close()
	o.mu.Lock()
	o.out.HTTPStatuses = append(o.out.HTTPStatuses, res.StatusCode)
	o.mu.Unlock()
	if res.StatusCode != 200 && res.StatusCode != 403 {
		return replyFrame{}, errors.New("fixture HTTP failure")
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, 16385))
	if e != nil || len(raw) > 16384 {
		return replyFrame{}, errors.New("fixture response bound")
	}
	return parseReply(raw, res.StatusCode)
}

func parseReply(raw []byte, status int) (replyFrame, error) {
	bad := func() (replyFrame, error) { return replyFrame{}, errors.New("invalid fixture reply frame") }
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, e := dec.Token()
	if e != nil || token != json.Delim('{') {
		return bad()
	}
	members := map[string]json.RawMessage{}
	for dec.More() {
		token, e = dec.Token()
		if e != nil {
			return bad()
		}
		name, ok := token.(string)
		if !ok {
			return bad()
		}
		if _, exists := members[name]; exists {
			return bad()
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return bad()
		}
		members[name] = value
	}
	if token, e = dec.Token(); e != nil || token != json.Delim('}') {
		return bad()
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return bad()
	}
	if len(members) != 3 || members["Sender"] == nil || members["Payload"] == nil || members["Error"] == nil || bytes.Equal(members["Sender"], []byte("null")) || bytes.Equal(members["Error"], []byte("null")) {
		return bad()
	}
	var reply replyFrame
	if json.Unmarshal(raw, &reply) != nil {
		return bad()
	}
	if status == 200 && reply.Error == "" && reply.Sender != "" && len(reply.Payload) > 0 {
		return reply, nil
	}
	if status == 403 && reply.Error == a2abinding.ErrRejected.Error() && reply.Sender == "" && reply.Payload == nil {
		return reply, nil
	}
	return bad()
}

func (o *observer) owner(ctx context.Context, p a2abinding.ProtectedCall, g func(context.Context) error) (a2abinding.AuthenticatedResponse, error) {
	o.mu.Lock()
	o.out.OwnerCalls++
	o.mu.Unlock()
	f := frame{Scope: "fixture-policy-only", Target: p.Target().URL, Recipient: p.Recipient(), Metadata: p.Metadata(), Payload: p.Payload()}
	reply, e := o.exchange(ctx, f, g)
	if e != nil {
		o.failure = e
		return a2abinding.AuthenticatedResponse{}, e
	}
	if reply.Error != "" {
		return a2abinding.AuthenticatedResponse{}, a2abinding.ErrRejected
	}
	return a2abinding.AuthenticatedResponse{Sender: reply.Sender, Payload: reply.Payload}, nil
}
func observe(in fixtureInput, mode string) (output, error) {
	if (mode != "direct" && mode != "tls") || (in.API != "client" && in.API != "server" && in.API != "uniform") {
		return output{}, errors.New("fixture mode")
	}
	material, e := hex.DecodeString(in.KeyHex)
	if e != nil || len(material) != 32 {
		return output{}, errors.New("fixture public key")
	}
	d, _ := didgo.Parse(peer)
	issued := int64(100)
	record := sage.Record{DID: d, Controller: "fixture-operator", State: sage.StateActive, Version: "3", Keys: []sage.Key{{Name: "sign", Alg: sage.AlgEd25519, Material: material, State: sage.KeyAccepted}}, Services: []sage.Service{{Name: "a2a", Type: "A2AInterface", URI: endpoint}}, Observation: sage.Observation{Issued: &issued, Time: 101, Source: "inspector-public-fixture"}}
	verifier := func(fail bool) *a2abinding.Verifier {
		v, _ := a2abinding.NewVerifier(a2abinding.VerifierConfig{Source: source{record, fail}, Clock: clock{}, ExpectedPeer: peer})
		return v
	}
	o := &observer{out: emptyOutput(), in: in, mode: mode}
	o.server, e = a2abinding.NewServer(a2abinding.ServerConfig{DID: peer, URL: endpoint, Verifier: verifier(in.SourceError), Card: func(context.Context) ([]byte, error) { return []byte(in.Card), nil }, Tenant: func(context.Context, string) (string, error) { return in.TenantRoute, nil }, Handler: handlerFunc(func(_ context.Context, b []byte) ([]byte, error) {
		o.mu.Lock()
		o.out.Dispatches++
		o.out.HandlerPayloads = append(o.out.HandlerPayloads, hex.EncodeToString(b))
		o.mu.Unlock()
		return []byte(in.Reply), nil
	})})
	if e != nil {
		return output{}, e
	}
	if mode == "tls" {
		o.tls = httptest.NewTLSServer(http.HandlerFunc(o.serve))
		defer o.tls.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	appendResult := func(b []byte, e error) {
		s := ""
		if e != nil {
			s = e.Error()
		}
		o.out.Errors = append(o.out.Errors, s)
		o.out.Replies = append(o.out.Replies, hex.EncodeToString(b))
	}
	if in.API == "client" {
		raw := []byte(in.Card)
		if in.ClientCardInvalid {
			var m map[string]any
			if e = json.Unmarshal(raw, &m); e != nil {
				return output{}, e
			}
			sig, ok := m["signatures"].([]any)
			if !ok || len(sig) != 1 {
				return output{}, errors.New("invalid card fixture")
			}
			entry, ok := sig[0].(map[string]any)
			if !ok {
				return output{}, errors.New("invalid signature fixture")
			}
			entry["signature"] = "AA"
			raw, e = json.Marshal(m)
			if e != nil {
				return output{}, e
			}
		}
		client, _ := a2abinding.NewClient(verifier(false), ownerFunc(o.owner))
		b, e := client.Call(ctx, raw, []byte(in.Payload))
		appendResult(b, e)
	} else {
		metas := []map[string]string{in.Metadata}
		recipients := []string{in.Recipient}
		if in.API == "uniform" {
			metas = []map[string]string{{"a2a_extensions": a2abinding.ExtensionURI}, {"a2a_version": "1.0", "a2a_extensions": a2abinding.ExtensionURI}}
			recipients = []string{peer, "did:sage:web:agents.example.com:other"}
		}
		for i, m := range metas {
			f := frame{Scope: "fixture-policy-only", Target: endpoint, Recipient: recipients[i], Metadata: m, Payload: []byte(in.Payload)}
			reply, e := o.exchange(ctx, f, nil)
			if e != nil {
				return output{}, e
			}
			if reply.Error != "" {
				appendResult(nil, a2abinding.ErrRejected)
			} else {
				appendResult(reply.Payload, nil)
			}
		}
	}
	if o.failure != nil {
		return output{}, o.failure
	}
	return o.out, nil
}
func run(stdin io.Reader, stdout, stderr io.Writer) int {
	raw, e := io.ReadAll(io.LimitReader(stdin, 1048577))
	var req request
	if e == nil && len(raw) <= 1048576 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		e = dec.Decode(&req)
		if e == nil {
			var trailing any
			if dec.Decode(&trailing) != io.EOF {
				e = errors.New("trailing fixture")
			}
		}
	} else {
		e = errors.New("input bound")
	}
	if e == nil {
		var out output
		out, e = observe(req.Fixture, req.Mode)
		if e == nil {
			e = json.NewEncoder(stdout).Encode(out)
		}
	}
	if e != nil {
		fmt.Fprintln(stderr, "invalid fixture")
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Stdin, os.Stdout, os.Stderr)) }
