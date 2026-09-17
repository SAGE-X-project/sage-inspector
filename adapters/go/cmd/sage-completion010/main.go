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
	Expiry int64   `json:"key_expires,omitempty"`
	ID     string  `json:"id"`
	Action string  `json:"action"`
	Wire   *string `json:"wire_hex,omitempty"`
	Mode   string  `json:"mode"`
	Mono   *int64  `json:"mono_ms"`
	UTC    *int64  `json:"unix"`
	TTL    *int64  `json:"ttl,omitempty"`
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
	case "", "utc-delay", "source-error", "clock-error", "store-error", "store-delay", "revoke-init", "revoke-resp", "revoke-kem", "changed-material", "unrelated":
	default:
		return q, nil, errors.New("unknown control")
	}
	switch q.Action {
	case "respond", "complete":
		if q.Wire == nil || len(*q.Wire) > 65536 {
			return q, nil, errors.New("wire required")
		}
		b, e := hex.DecodeString(*q.Wire)
		return q, b, e
	case "start", "inspect", "check", "close", "endpoint-close", "pending-close", "dispatch":
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
