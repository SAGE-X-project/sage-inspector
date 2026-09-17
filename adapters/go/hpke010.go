package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/sage-x-project/sage/pkg/agent/hpke"
)

func hpke010Observe(op string, input json.RawMessage) (string, map[string]any, error) {
	names := []string{"seed_hex", "th_hex"}
	switch op {
	case "sage.hpke.schedule010.combine":
		names = []string{"exporter_hex", "ss_e2e_hex", "th_hex"}
	case "sage.hpke.schedule010.ack":
	case "sage.hpke.schedule010.verify":
		names = append(names, "ack_tag_hex")
	default:
		return "UNSUPPORTED", map[string]any{}, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(input, &fields); err != nil {
		return "", nil, err
	}
	if len(fields) != len(names) {
		return "", nil, fmt.Errorf("invalid schedule input fields")
	}
	values := make([][]byte, len(names))
	for i, name := range names {
		var s *string
		if err := json.Unmarshal(fields[name], &s); err != nil || s == nil {
			return "", nil, fmt.Errorf("invalid schedule input")
		}
		b, err := hex.DecodeString(*s)
		if err != nil {
			return "", nil, fmt.Errorf("invalid schedule input hex")
		}
		values[i] = b
	}
	if op == "sage.hpke.schedule010.verify" {
		if hpke.VerifyAckTag010(values[0], values[1], values[2]) {
			return "ACCEPT", map[string]any{"valid": true}, nil
		}
		return "REJECT", map[string]any{}, nil
	}
	var out []byte
	var err error
	field := "seed_hex"
	if op == "sage.hpke.schedule010.combine" {
		out, err = hpke.CombineSecrets010(values[0], values[1], values[2])
	} else {
		out, err = hpke.MakeAckTag010(values[0], values[1])
		field = "ack_tag_hex"
	}
	if err != nil {
		return "REJECT", map[string]any{}, nil
	}
	defer clear(out)
	return "ACCEPT", map[string]any{field: hex.EncodeToString(out)}, nil
}
