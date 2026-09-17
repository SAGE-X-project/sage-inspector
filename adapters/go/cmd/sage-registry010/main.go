// This executable supplies synthetic trusted dependencies for local core tests.
// It is not a network resolver or a production authorization service.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	core "github.com/sage-x-project/sage/pkg/agent/registry010"
	"io"
	"os"
	"strconv"
)

const registry = "eip155:1:0xabababababababababababababababababababab"

var config = core.Config{Source: "fixture-authority", Registry: registry, Network: "1", Blockchain: true}

type stamp struct {
	MonoMS int64 `json:"mono_ms"`
	Unix   int64 `json:"unix"`
}
type request struct {
	Action     string        `json:"action"`
	DID        string        `json:"did,omitempty"`
	Snapshot   core.Snapshot `json:"snapshot,omitempty"`
	Times      []stamp       `json:"times,omitempty"`
	ClockOK    bool          `json:"clock_ok,omitempty"`
	SourceOK   bool          `json:"source_ok,omitempty"`
	SigningURL string        `json:"signing_url,omitempty"`
	RequireKEM bool          `json:"require_kem,omitempty"`
}
type envelope struct {
	ID      string  `json:"id"`
	Request request `json:"request"`
}

func decode(b []byte) (envelope, error) {
	var q envelope
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&q); e != nil {
		return q, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF || q.ID == "" || len(q.ID) > 128 {
		return q, errors.New("invalid envelope")
	}
	var raw struct{ Request map[string]json.RawMessage }
	if json.Unmarshal(b, &raw) != nil {
		return q, errors.New("invalid request")
	}
	required := []string{"action"}
	switch q.Request.Action {
	case "observe", "select", "check":
		required = append(required, "did", "snapshot", "times", "clock_ok", "source_ok")
		if len(q.Request.Times) != 3 {
			return q, errors.New("three clock samples required")
		}
	case "inspect":
		required = append(required, "did")
	case "restart", "mutate":
	default:
		return q, errors.New("unknown action")
	}
	if q.Request.Action == "select" {
		required = append(required, "signing_url", "require_kem")
	}
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		v, ok := raw.Request[k]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return q, errors.New("missing control")
		}
	}
	for k := range raw.Request {
		if !allowed[k] {
			return q, errors.New("unexpected control")
		}
	}
	return q, nil
}

type controls struct {
	q     request
	index int
}

func (c *controls) Now() (core.Stamp, error) {
	if !c.q.ClockOK {
		return core.Stamp{}, errors.New("test clock unavailable")
	}
	i := c.index
	c.index++
	if i > 2 {
		i = 2
	}
	t := c.q.Times[i]
	return core.Stamp{MonoMS: t.MonoMS, Unix: t.Unix}, nil
}
func (c *controls) Read(context.Context, string) (core.Snapshot, error) {
	if !c.q.SourceOK {
		return core.Snapshot{}, errors.New("test source unavailable")
	}
	return c.q.Snapshot, nil
}
func run() error {
	if len(os.Args) != 3 || (os.Args[2] != "create" && os.Args[2] != "reopen") {
		return errors.New("expected journal path and create or reopen")
	}
	path := os.Args[1]
	j, e := core.OpenJournal(path, os.Args[2] == "create")
	if e != nil {
		return e
	}
	defer func() { _ = j.Close() }()
	c := &controls{}
	gate, e := core.NewGate(config, c, c, j)
	if e != nil {
		return e
	}
	var pin *core.Pinned
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	n := 0
	for scanner.Scan() {
		n++
		if n > 128 {
			return errors.New("step limit")
		}
		q, e := decode(scanner.Bytes())
		if e != nil {
			return e
		}
		c.q = q.Request
		c.index = 0
		out := map[string]any{}
		verdict := "ACCEPT"
		switch c.q.Action {
		case "observe":
			var s core.Snapshot
			s, e = gate.Observe(context.Background(), c.q.DID)
			if e == nil {
				out = map[string]any{"state": s.State, "version": s.Version}
			}
		case "select":
			pin, e = gate.Select(context.Background(), c.q.DID, c.q.SigningURL, c.q.RequireKEM)
			if e == nil {
				kem := ""
				if k := pin.KEM(); k != nil {
					kem = pin.DID() + "#" + k.Name
				}
				out = map[string]any{"signing_keyid": pin.DID() + "#" + pin.Signing().Name, "kem_keyid": kem}
			}
		case "check":
			if pin == nil || pin.DID() != c.q.DID {
				e = errors.New("no matching pin")
			} else {
				e = gate.CheckPinned(context.Background(), pin)
			}
			if e == nil {
				out = map[string]any{"valid": true}
			}
		case "inspect":
			w, ok := j.Get(core.Scope{Registry: registry, DID: c.q.DID})
			version := "0"
			if ok {
				version = strconv.FormatUint(w.Version, 10)
			}
			out = map[string]any{"highest_finalized_version": version, "tombstone": w.Terminal}
		case "restart":
			if e = j.Close(); e != nil {
				return e
			}
			j, e = core.OpenJournal(path, false)
			if e != nil {
				return e
			}
			gate, e = core.NewGate(config, c, c, j)
			if e != nil {
				return e
			}
			pin = nil
		case "mutate":
			verdict = "UNSUPPORTED"
		}
		if e != nil {
			verdict = "REJECT"
			out = map[string]any{}
		}
		if e = json.NewEncoder(os.Stdout).Encode(map[string]any{"id": q.ID, "verdict": verdict, "output": out}); e != nil {
			return e
		}
	}
	return scanner.Err()
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
}
