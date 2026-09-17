package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sage-x-project/sage/pkg/agent/hpke"
	"github.com/sage-x-project/sage/pkg/agent/registry010"
	"io"
	"os"
)

type request struct {
	Target    string  `json:"target,omitempty"`
	Status    int     `json:"status,omitempty"`
	MessageID string  `json:"message_id,omitempty"`
	Success   *bool   `json:"success,omitempty"`
	Error     string  `json:"error,omitempty"`
	Expiry    int64   `json:"key_expires,omitempty"`
	ID        string  `json:"id"`
	Action    string  `json:"action"`
	Wire      *string `json:"wire_hex,omitempty"`
	Mode      string  `json:"mode"`
	Mono      *int64  `json:"mono_ms"`
	UTC       *int64  `json:"unix"`
	TTL       *int64  `json:"ttl,omitempty"`
}

func decode(b []byte) (request, []byte, error) {
	var q request
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || q.ID == "" || len(q.ID) > 128 || q.Mono == nil || q.UTC == nil {
		return q, nil, errors.New("invalid control")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return q, nil, errors.New("trailing control")
	}
	switch q.Mode {
	case "", "utc-delay", "source-error", "clock-error", "store-error", "store-delay", "revoke-init", "revoke-resp", "revoke-kem", "changed-material", "unrelated", "transport-id", "transport-nonce":
	default:
		return q, nil, errors.New("unknown control")
	}
	switch q.Action {
	case "respond", "complete", "record-seal", "record-open", "response-seal", "response-open", "http-request-seal", "http-request-open", "http-response-seal", "http-response-open", "http-respond-raw", "http-complete-raw", "http-record-seal-raw", "http-record-open-raw", "http-response-seal-raw", "http-response-open-raw":
		limit := 65536
		if q.Action == "http-request-open" || q.Action == "http-response-open" || q.Action == "http-respond-raw" || q.Action == "http-complete-raw" || q.Action == "http-record-open-raw" || q.Action == "http-response-open-raw" {
			limit = 196608
		}
		if q.Wire == nil || len(*q.Wire) > limit {
			return q, nil, errors.New("wire required")
		}
		b, e := hex.DecodeString(*q.Wire)
		return q, b, e
	case "start", "inspect", "check", "close", "endpoint-close", "pending-close", "dispatch", "record-inspect", "http-bind", "http-endpoint-bind", "http-start", "http-inspect":
		if q.Wire != nil {
			return q, nil, errors.New("unexpected wire")
		}
	default:
		return q, nil, errors.New("unknown action")
	}
	return q, nil, nil
}
func run() error {
	if len(os.Args) != 3 || (os.Args[1] != "alice" && os.Args[1] != "bob") {
		return errors.New("expected role and local journal path")
	}
	did := completionAlice
	n := byte(1)
	kem := []byte{}
	if os.Args[1] == "bob" {
		did = completionBob
		n = 2
		kem = bytes.Repeat([]byte{3}, 32)
	}
	c := &completionControl{utc: 100}
	j, x := registry010.OpenJournal(os.Args[2], true)
	if x != nil {
		return x
	}
	defer func() { _ = j.Close() }()
	g, x := registry010.NewGate(registry010.Config{Source: "fixture-authority", Registry: completionRegistry, Network: "local"}, c, c, j)
	if x != nil {
		return x
	}
	e, x := hpke.NewCompletionEndpoint010(did, did+"#signing-1", bytes.Repeat([]byte{n}, 32), kem, g, c, &completionReplay{c, map[string]bool{}})
	if x != nil {
		return x
	}
	defer e.Close()
	target := "https://agent.example/messages"
	var p *hpke.PendingCompletion010
	var result *hpke.AuthenticatedCompletion010
	defer func() {
		if p != nil {
			p.Close()
		}
		if result != nil {
			result.Close()
		}
	}()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 256*1024)
	seen := map[string]bool{}
	for count := 0; scan.Scan(); count++ {
		if count >= 128 {
			return errors.New("step limit")
		}
		q, wire, x := decode(scan.Bytes())
		if x != nil || seen[q.ID] {
			return errors.New("invalid request")
		}
		seen[q.ID] = true
		c.expiry = q.Expiry
		c.mode = q.Mode
		c.mono = *q.Mono
		c.utc = *q.UTC
		ttl := int64(300)
		if q.TTL != nil {
			ttl = *q.TTL
		}
		out := map[string]any{}
		verdict := "ACCEPT"
		switch q.Action {
		case "start":
			if p != nil {
				x = errors.New("already started")
			} else {
				p, wire, x = e.Start(context.Background(), completionBob, completionBob+"#signing-1", ttl)
			}
			if x == nil {
				out = map[string]any{"state": p.State(), "wire_hex": hex.EncodeToString(wire)}
			}
		case "respond":
			var next *hpke.AuthenticatedCompletion010
			next, wire, x = e.Respond(context.Background(), wire, ttl)
			if x == nil {
				if result != nil {
					result.Close()
				}
				result = next
				out = map[string]any{"state": result.State(), "tuple": result.Tuple(), "wire_hex": hex.EncodeToString(wire)}
			}
		case "complete":
			if p == nil {
				x = errors.New("no pending")
			} else {
				var next *hpke.AuthenticatedCompletion010
				next, x = p.Complete(context.Background(), wire)
				if x == nil {
					if result != nil {
						result.Close()
					}
					result = next
					out = map[string]any{"state": result.State(), "tuple": result.Tuple()}
				}
			}
		case "http-endpoint-bind":
			x = e.BindHTTP(q.Target)
			if x == nil {
				target = q.Target
			}
		case "http-inspect":
			ps, rs := "NONE", "NONE"
			if p != nil {
				ps = p.State()
			}
			if result != nil {
				rs = result.State()
			}
			out = map[string]any{"handshakes": c.handshakes, "records": c.records, "pending": ps, "session": rs}
		case "http-start":
			if p != nil {
				x = errors.New("already started")
			} else {
				var m hpke.HTTPMessage010
				p, m, x = e.StartHTTP(context.Background(), completionBob, completionBob+"#signing-1", ttl)
				if x == nil {
					wire, x = hpke.EncodeHTTP010(m, target)
					if x == nil {
						out = map[string]any{"wire_hex": hex.EncodeToString(wire)}
					}
				}
			}
		case "http-respond-raw":
			var m hpke.HTTPMessage010
			m, x = hpke.ParseHTTP010(wire, target, false)
			if x == nil {
				var next *hpke.AuthenticatedCompletion010
				next, m, x = e.RespondHTTP(context.Background(), m, ttl)
				if x == nil {
					wire, x = hpke.EncodeHTTP010(m, target)
					if x == nil {
						if result != nil {
							result.Close()
						}
						result = next
						out = map[string]any{"wire_hex": hex.EncodeToString(wire)}
					} else {
						next.Close()
					}
				}
			}
		case "http-complete-raw":
			if p == nil {
				x = errors.New("no pending")
			} else {
				var m hpke.HTTPMessage010
				m, x = hpke.ParseHTTP010(wire, target, true)
				if x == nil {
					var next *hpke.AuthenticatedCompletion010
					next, x = p.CompleteHTTP(context.Background(), m)
					if x == nil {
						if result != nil {
							result.Close()
						}
						result = next
						out = map[string]any{"state": result.State(), "tuple": result.Tuple()}
					}
				} else {
					p.Close()
				}
			}
		case "http-record-seal-raw", "http-response-seal-raw":
			if result == nil {
				x = errors.New("no result")
			} else {
				var m hpke.HTTPMessage010
				if q.Action == "http-record-seal-raw" {
					m, x = result.SealHTTPRequest(context.Background(), wire, ttl)
				} else if q.Success == nil {
					x = errors.New("missing response control")
				} else {
					m, x = result.SealHTTPResponse(context.Background(), q.MessageID, wire, *q.Success, q.Error, ttl, 200)
				}
				if x == nil {
					wire, x = hpke.EncodeHTTP010(m, target)
					if x == nil {
						out = map[string]any{"wire_hex": hex.EncodeToString(wire)}
					}
				}
			}
		case "http-record-open-raw", "http-response-open-raw":
			if result == nil {
				x = errors.New("no result")
			} else {
				var m hpke.HTTPMessage010
				m, x = hpke.ParseHTTP010(wire, target, q.Action == "http-response-open-raw")
				if x == nil {
					if q.Action == "http-record-open-raw" {
						wire, x = result.OpenHTTPRequest(context.Background(), m)
						if x == nil {
							out = map[string]any{"plaintext_hex": hex.EncodeToString(wire)}
						}
					} else {
						var v *hpke.SessionResponse010
						v, x = result.OpenHTTPResponse(context.Background(), m)
						if x == nil {
							out = map[string]any{"message_id": v.MessageID, "success": v.Success, "error": v.Error, "plaintext_hex": hex.EncodeToString(v.Data)}
						}
					}
				}
			}

		case "http-bind":
			if result == nil {
				x = errors.New("no result")
			} else {
				x = result.BindHTTP("https://agent.example/messages")
			}
		case "http-request-seal", "http-response-seal":
			if result == nil {
				x = errors.New("no result")
			} else {
				var m hpke.HTTPMessage010
				if q.Action == "http-request-seal" {
					m, x = result.SealHTTPRequest(context.Background(), wire, ttl)
				} else if q.Success == nil {
					x = errors.New("missing response control")
				} else {
					status := q.Status
					if status == 0 {
						status = 200
					}
					m, x = result.SealHTTPResponse(context.Background(), q.MessageID, wire, *q.Success, q.Error, ttl, status)
				}
				if x == nil {
					wire, x = json.Marshal(m)
					out = map[string]any{"wire_hex": hex.EncodeToString(wire)}
				}
			}
		case "http-request-open", "http-response-open":
			var m hpke.HTTPMessage010
			d := json.NewDecoder(bytes.NewReader(wire))
			d.DisallowUnknownFields()
			if result == nil || d.Decode(&m) != nil {
				x = errors.New("invalid HTTP control")
			} else {
				if q.Action == "http-request-open" {
					wire, x = result.OpenHTTPRequest(context.Background(), m)
					if x == nil {
						out = map[string]any{"plaintext_hex": hex.EncodeToString(wire)}
					}
				} else {
					var v *hpke.SessionResponse010
					v, x = result.OpenHTTPResponse(context.Background(), m)
					if x == nil {
						out = map[string]any{"message_id": v.MessageID, "success": v.Success, "error": v.Error, "plaintext_hex": hex.EncodeToString(v.Data)}
					}
				}
			}

		case "response-seal":
			if result == nil || q.Success == nil {
				x = errors.New("missing response control")
			} else {
				wire, x = result.SealResponse(context.Background(), q.MessageID, wire, *q.Success, q.Error, ttl)
				if x == nil {
					out = map[string]any{"wire_hex": hex.EncodeToString(wire)}
				}
			}
		case "response-open":
			if result == nil {
				x = errors.New("no result")
			} else {
				var v *hpke.SessionResponse010
				v, x = result.OpenResponse(context.Background(), wire)
				if x == nil {
					out = map[string]any{"message_id": v.MessageID, "success": v.Success, "error": v.Error, "plaintext_hex": hex.EncodeToString(v.Data)}
				}
			}

		case "record-seal":
			if result == nil {
				x = errors.New("no result")
			} else {
				wire, x = result.SealRequest(context.Background(), wire, ttl)
				if x == nil {
					out = map[string]any{"wire_hex": hex.EncodeToString(wire), "state": result.State()}
				}
			}
		case "record-open":
			if result == nil {
				x = errors.New("no result")
			} else {
				wire, x = result.OpenRequest(context.Background(), wire)
				if x == nil {
					out = map[string]any{"plaintext_hex": hex.EncodeToString(wire), "state": result.State()}
				}
			}
		case "record-inspect":
			state := "NONE"
			if result != nil {
				state = result.State()
			}
			out = map[string]any{"state": state, "reservations": c.records}

		case "check":
			if result == nil {
				x = errors.New("no result")
			} else {
				x = result.Check(context.Background())
				if x == nil {
					out = map[string]any{"state": result.State()}
				}
			}
		case "close":
			if result != nil {
				result.Close()
			}
			if p != nil {
				p.Close()
			}
		case "pending-close":
			if p != nil {
				p.Close()
			}
		case "endpoint-close":
			e.Close()
		case "inspect":
			pending, state := "NONE", "NONE"
			if p != nil {
				pending = p.State()
			}
			if result != nil {
				state = result.State()
			}
			out = map[string]any{"pending_state": pending, "result_state": state}
		case "dispatch":
			verdict = "UNSUPPORTED"
		}
		if x != nil {
			verdict = "REJECT"
			out = map[string]any{}
		}
		if x = json.NewEncoder(os.Stdout).Encode(map[string]any{"id": q.ID, "verdict": verdict, "output": out}); x != nil {
			return x
		}
	}
	return scan.Err()
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
}
