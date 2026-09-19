// Bounded public fixture client. No network or external tools.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	g "github.com/sage-x-project/sage/pkg/agent/guard010"
	"io"
	"os"
)

type clientFixture struct {
	sentRPC    []byte
	sentID     string
	sentIntent []byte
	sendDelay  int64
	sendFail   bool
	sends      int

	f                     guardFixture
	utc, mono             int64
	clockOK, resultActive bool
	pub                   string
}

func (f *clientFixture) Sample(context.Context) (int64, int64, error) {
	if !f.clockOK {
		return 0, 0, g.ErrInvalid
	}
	return f.utc, f.mono, nil
}
func (f *clientFixture) Now(context.Context) (int64, error) {
	if !f.clockOK {
		return 0, g.ErrInvalid
	}
	return f.utc / 1000, nil
}
func (f *clientFixture) ActiveKey(ctx context.Context, issuer, kid string) (ed25519.PublicKey, error) {
	if issuer == "did:sage:web:agents.example.com:executor" {
		if !f.resultActive || kid != issuer+"#signing-1" {
			return nil, g.ErrInvalid
		}
		b, e := hex.DecodeString(f.pub)
		return ed25519.PublicKey(b), e
	}
	return f.f.ActiveKey(ctx, issuer, kid)
}
func (f *clientFixture) Bindings(ctx context.Context, i, r string) (string, []byte, []byte, error) {
	return f.f.Bindings(ctx, i, r)
}
func (f *clientFixture) Authorize(ctx context.Context, i, t string, a []byte) error {
	return f.f.Authorize(ctx, i, t, a)
}
func (f *clientFixture) Commit(_ context.Context, id string, raw []byte) error {
	f.sends++
	f.sentID = id
	f.sentIntent = append([]byte(nil), raw...)
	f.utc += f.sendDelay
	f.mono += f.sendDelay
	if f.sendFail {
		return g.ErrInvalid
	}
	return nil
}
func (f *clientFixture) Send(ctx context.Context, id string, raw []byte) error {
	intent, e := g.ParseMCPRequest(g.MCPVersion, id, raw)
	if e != nil {
		return e
	}
	f.sentRPC = append([]byte(nil), raw...)
	return f.Commit(ctx, id, intent)
}
func (f *clientFixture) services() g.ClientServices {
	return g.ClientServices{IntentAuthority: f, Policy: f, ResultAuthority: f, Clock: f, Sender: f}
}

type clientObservation struct {
	RPC      string `json:"rpc_hex,omitempty"`
	Handoffs int    `json:"handoffs"`
	OK       bool   `json:"ok"`
	ID       string `json:"id"`
	Intent   string `json:"intent_hex"`
	Status   string `json:"status"`
	First    bool   `json:"first"`
	Ignored  bool   `json:"ignored"`
	Output   string `json:"output_hex"`
}

type request struct {
	Version  string       `json:"mcp_version"`
	Action   string       `json:"action"`
	ID       string       `json:"id"`
	Input    guardFixture `json:"input"`
	Public   string       `json:"public_key_hex"`
	UTC      int64        `json:"utc"`
	Mono     int64        `json:"mono"`
	Field    string       `json:"field"`
	Value    bool         `json:"value"`
	Envelope string       `json:"envelope_hex"`
}

func run() error {
	if len(os.Args) != 3 || (os.Args[2] != "create" && os.Args[2] != "reopen") {
		return g.ErrInvalid
	}
	var client *g.Client
	var f *clientFixture
	tickets := map[string]*g.ClientInvocation{}
	ctx := context.Background()
	defer func() {
		if client != nil {
			_ = client.Close()
		}
	}()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 4<<20)
	out := json.NewEncoder(os.Stdout)
	count := 0
	for scan.Scan() {
		count++
		if count > 64 {
			return g.ErrInvalid
		}
		var q request
		dec := json.NewDecoder(bytes.NewReader(scan.Bytes()))
		dec.DisallowUnknownFields()
		var extra any
		if dec.Decode(&q) != nil || dec.Decode(&extra) != io.EOF {
			return g.ErrInvalid
		}
		o := clientObservation{OK: true}
		if client == nil && q.Action != "open" && q.Action != "open_rpc" {
			return g.ErrInvalid
		}
		switch q.Action {
		case "open", "open_rpc":
			if client != nil {
				return g.ErrInvalid
			}
			f = &clientFixture{f: q.Input, utc: q.UTC, mono: q.Mono, clockOK: true, resultActive: true, pub: q.Public}
			raw, e := hex.DecodeString(f.f.s("envelope_hex"))
			if e != nil {
				return e
			}
			services := f.services()
			if q.Action == "open_rpc" {
				services.Sender, e = g.NewMCPClientSender(q.Version, f)
				if e != nil {
					return e
				}
			}
			client, e = g.OpenClient(ctx, os.Args[1], os.Args[2] == "create", raw, services)
			if e != nil {
				return e
			}
		case "tick":
			f.utc = q.UTC
			f.mono = q.Mono
		case "set":
			switch q.Field {
			case "clock_ok":
				f.clockOK = q.Value
			case "result_active":
				f.resultActive = q.Value
			case "intent_active":
				f.f["active_key"], _ = json.Marshal(q.Value)
			case "policy_allow":
				f.f["policy_allow"], _ = json.Marshal(q.Value)
			default:
				return g.ErrInvalid
			}
		case "begin":
			v, e := client.Begin(ctx, q.ID)
			o.OK = e == nil
			if e == nil {
				tickets[q.ID] = v
				if len(f.sentRPC) != 0 {
					o.RPC = hex.EncodeToString(f.sentRPC)
				}
				o.ID = f.sentID
				o.Intent = hex.EncodeToString(f.sentIntent)
			}
		case "accept", "accept_mcp", "accept_rpc":
			raw, e := hex.DecodeString(q.Envelope)
			if e != nil {
				return e
			}
			var d *g.ClientDelivery
			if q.Action == "accept_rpc" {
				d, e = client.AcceptMCPResponse(ctx, tickets[q.ID], q.Version, raw)
			} else if q.Action == "accept_mcp" {
				d, e = client.AcceptMCP(ctx, tickets[q.ID], q.Version, raw)
			} else {
				d, e = client.Accept(ctx, tickets[q.ID], raw)
			}
			o.OK = e == nil
			if e == nil {
				o.Status = d.Status()
				o.First = d.FirstTerminal()
				o.Ignored = d.Ignored()
				o.Output = hex.EncodeToString(d.Output())
			}
		case "failed":
			o.OK = client.Failed(tickets[q.ID]) == nil
		case "close":
			o.OK = client.Close() == nil
		default:
			return g.ErrInvalid
		}
		o.Handoffs = f.sends
		if out.Encode(o) != nil {
			return g.ErrInvalid
		}
	}
	if scan.Err() != nil || client == nil {
		return g.ErrInvalid
	}
	return nil
}
func main() {
	if run() != nil {
		os.Exit(2)
	}
}
