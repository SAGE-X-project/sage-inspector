// Bounded fixture-only local dispatch sink. No shell, network or external tools.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	g "github.com/sage-x-project/sage/pkg/agent/guard010"
)

const recipient = "did:sage:web:agents.example.com:executor"

type request struct {
	Action   string       `json:"action"`
	Input    guardFixture `json:"input"`
	Instance string       `json:"instance"`
	Envelope string       `json:"envelope_hex"`
}
type effect struct {
	Instance  string `json:"instance"`
	Envelope  string `json:"envelope_hex"`
	Arguments string `json:"arguments_hex"`
	Tool      string `json:"tool"`
	Manifest  string `json:"manifest_digest"`
	Digest    string `json:"intent_digest"`
}
type reply struct {
	OK        bool     `json:"ok"`
	Created   bool     `json:"created"`
	Committed bool     `json:"committed"`
	State     string   `json:"state"`
	Digest    string   `json:"intent_digest"`
	Effects   []effect `json:"effects"`
}
type sink struct {
	fixture        guardFixture
	instance, path string
	effects        *[]effect
}

func (s *sink) Check(_ context.Context, manifest, tool string) error {
	raw, _ := json.Marshal(s.fixture["approved_manifest"])
	digest, e := g.VerifyManifest(raw, []g.Artifact{{Path: "engine.bin", Bytes: []byte("public pinned evaluator")}, {Path: "rules.json", Bytes: []byte(`{"allow":["read"]}`)}})
	if e != nil || manifest != digest || tool != "read" {
		return g.ErrInvalid
	}
	return nil
}
func (s *sink) Commit(ctx context.Context, i *g.Invocation) error {
	if ctx.Err() != nil {
		return g.ErrInvalid
	}
	raw, e := os.ReadFile(s.path)
	if e != nil {
		return e
	}
	rows := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	var row map[string]any
	if json.Unmarshal(rows[len(rows)-1], &row) != nil || row["state"] != "EXECUTING" {
		return g.ErrInvalid
	}
	*s.effects = append(*s.effects, effect{s.instance, hex.EncodeToString(i.CanonicalIntent()), hex.EncodeToString(i.Arguments()), i.Tool(), i.ManifestDigest(), i.IntentDigest()})
	return nil
}
func run() error {
	if len(os.Args) != 3 || (os.Args[2] != "create" && os.Args[2] != "reopen") {
		return g.ErrInvalid
	}
	var gate *g.DispatchGate
	effects := []effect{}
	defer func() {
		if gate != nil {
			_ = gate.Close()
		}
	}()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 4<<20)
	out := json.NewEncoder(os.Stdout)
	n := 0
	for scan.Scan() {
		n++
		if n > 64 {
			return g.ErrInvalid
		}
		var q request
		d := json.NewDecoder(bytes.NewReader(scan.Bytes()))
		d.DisallowUnknownFields()
		var extra any
		if d.Decode(&q) != nil || d.Decode(&extra) != io.EOF {
			return g.ErrInvalid
		}
		r := reply{}
		switch q.Action {
		case "configure":
			if q.Instance != "old" && q.Instance != "new" {
				return g.ErrInvalid
			}
			s := &sink{q.Input, q.Instance, os.Args[1], &effects}
			if gate == nil {
				var e error
				gate, e = g.OpenDispatchGate(os.Args[1], os.Args[2] == "create", recipient, q.Input, q.Input, s)
				if e != nil {
					return e
				}
				r.OK = true
			} else {
				r.OK = gate.Replace(q.Input, q.Input, s) == nil
			}
		case "retire":
			if gate == nil {
				return g.ErrInvalid
			}
			r.OK = gate.Retire() == nil
		case "dispatch":
			if gate == nil {
				return g.ErrInvalid
			}
			raw, e := hex.DecodeString(q.Envelope)
			if e != nil {
				return e
			}
			v, e := gate.Dispatch(context.Background(), raw)
			r.OK = e == nil
			if e == nil {
				r.Created = v.Created()
				r.Committed = v.Committed()
				r.State = v.State()
				r.Digest = v.IntentDigest()
			}
		default:
			return g.ErrInvalid
		}
		r.Effects = effects
		if out.Encode(r) != nil {
			return g.ErrInvalid
		}
	}
	if scan.Err() != nil || gate == nil {
		return g.ErrInvalid
	}
	return gate.Close()
}
func main() {
	if run() != nil {
		os.Exit(2)
	}
}
