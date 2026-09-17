// A bounded schema2 bridge to the real record core, not a session simulator.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/sage/pkg/agent/session"
	"io"
	"os"
)

type request struct {
	Schema    int             `json:"schema_version"`
	Version   string          `json:"protocol_version"`
	Profile   string          `json:"profile"`
	Case      string          `json:"case_id"`
	Step      string          `json:"step_id"`
	Operation string          `json:"operation"`
	Input     json.RawMessage `json:"input"`
}

func decode(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(value); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing input")
	}
	return nil
}

type bridge struct {
	core    *session.RecordSession010
	effects map[string]uint64
}

func (b *bridge) observe(q request) (string, map[string]any, error) {
	out := map[string]any{}
	if q.Operation == "record010.create" {
		if b.core != nil {
			return "", nil, fmt.Errorf("session replacement is forbidden")
		}
		var in struct {
			Seed      *string `json:"seed_hex"`
			TH        *string `json:"th_hex"`
			Initiator *bool   `json:"initiator"`
		}
		if e := decode(q.Input, &in); e != nil {
			return "", nil, e
		}
		if in.Seed == nil || in.TH == nil || in.Initiator == nil {
			return "", nil, fmt.Errorf("missing create control")
		}
		seed, e := hex.DecodeString(*in.Seed)
		if e != nil {
			return "", nil, e
		}
		th, e := hex.DecodeString(*in.TH)
		if e != nil {
			return "", nil, e
		}
		b.core, e = session.NewRecordSession010(seed, th, *in.Initiator)
		if e != nil {
			return "", nil, e
		}
		out["session_id"] = b.core.ID()
		return "ACCEPT", out, nil
	}
	if q.Operation != "record010.open" && q.Operation != "record010.seal" && q.Operation != "record010.close" {
		return "UNSUPPORTED", out, nil
	}
	if b.core == nil {
		return "", nil, fmt.Errorf("create a record session first")
	}
	if q.Operation == "record010.close" {
		var in struct{}
		if string(q.Input) == "null" {
			return "", nil, fmt.Errorf("object required")
		}
		if e := decode(q.Input, &in); e != nil {
			return "", nil, e
		}
		b.core.Close()
		b.effects["core_close_calls"]++
		return "ACCEPT", out, nil
	}
	var in map[string]json.RawMessage
	if e := decode(q.Input, &in); e != nil {
		return "", nil, e
	}
	field := "record_hex"
	if q.Operation == "record010.seal" {
		field = "plaintext_hex"
	}
	if len(in) != 2 || in[field] == nil || in["caller_aad_hex"] == nil {
		return "", nil, fmt.Errorf("invalid record controls")
	}
	get := func(key string) ([]byte, error) {
		var s *string
		if e := json.Unmarshal(in[key], &s); e != nil {
			return nil, e
		}
		if s == nil {
			return nil, fmt.Errorf("string required")
		}
		return hex.DecodeString(*s)
	}
	data, e := get(field)
	if e != nil {
		return "", nil, e
	}
	aad, e := get("caller_aad_hex")
	if e != nil {
		return "", nil, e
	}
	var result []byte
	if q.Operation == "record010.open" {
		result, e = b.core.Open(data, aad)
	} else {
		result, e = b.core.Seal(data, aad)
	}
	if e != nil {
		return "REJECT", out, nil
	}
	if q.Operation == "record010.open" {
		out["plaintext_hex"] = hex.EncodeToString(result)
		b.effects["core_open_success"]++
	} else {
		out["record_hex"] = hex.EncodeToString(result)
		b.effects["core_seal_success"]++
	}
	return "ACCEPT", out, nil
}
func run(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	b := bridge{effects: map[string]uint64{"core_open_success": 0, "core_seal_success": 0, "core_close_calls": 0}}
	defer func() {
		if b.core != nil {
			b.core.Close()
		}
	}()
	caseID := ""
	seen := map[string]bool{}
	for scanner.Scan() {
		var q request
		if e := decode(scanner.Bytes(), &q); e != nil {
			return e
		}
		if q.Schema != 2 || q.Version != "0.10.0" || q.Profile != "stateful-scenario" || q.Case == "" || q.Step == "" || len(seen) >= 128 || seen[q.Step] {
			return fmt.Errorf("invalid step header")
		}
		if caseID == "" {
			caseID = q.Case
		}
		if q.Case != caseID {
			return fmt.Errorf("case changed")
		}
		seen[q.Step] = true
		v, out, e := b.observe(q)
		if e != nil {
			return e
		}
		if e = json.NewEncoder(w).Encode(map[string]any{"schema_version": 2, "case_id": q.Case, "step_id": q.Step, "verdict": v, "output": out, "effects": b.effects}); e != nil {
			return e
		}
	}
	return scanner.Err()
}
func main() {
	if e := run(os.Stdin, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
}
