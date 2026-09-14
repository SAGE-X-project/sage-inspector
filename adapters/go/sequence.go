package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/sage/pkg/agent/session"
	"time"
)

// One core object survives the entire explicit batch. No replay state or
// acceptance policy is implemented in the adapter.
func sequenceObserve(op string, raw json.RawMessage) (string, map[string]any, error) {
	var in struct {
		Seed      string   `json:"seed_hex"`
		SID       string   `json:"sid"`
		Direction string   `json:"direction"`
		AAD       string   `json:"caller_aad_hex"`
		Messages  []string `json:"messages_hex"`
		Actions   []struct {
			Kind    string   `json:"kind"`
			Record  string   `json:"record_hex"`
			Records []string `json:"records_hex"`
		} `json:"actions"`
	}
	if e := json.Unmarshal(raw, &in); e != nil {
		return "", nil, e
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return "", nil, e
	}
	for _, name := range []string{"seed_hex", "sid", "direction", "caller_aad_hex"} {
		var value *string
		if e := json.Unmarshal(fields[name], &value); e != nil || value == nil {
			return "", nil, fmt.Errorf("missing string control %s", name)
		}
	}
	seed, e := hex.DecodeString(in.Seed)
	if e != nil || len(seed) != 32 || in.SID == "" || (in.Direction != "c2s" && in.Direction != "s2c") {
		return "", nil, fmt.Errorf("invalid sequence controls")
	}
	aad, e := hex.DecodeString(in.AAD)
	if e != nil || len(aad) > 1024 {
		return "", nil, fmt.Errorf("invalid sequence AAD")
	}
	sending := op == "legacy.session.export-sequence"
	if sending && (len(in.Messages) == 0 || len(in.Messages) > 16) || !sending && (len(in.Actions) == 0 || len(in.Actions) > 32) {
		return "", nil, fmt.Errorf("invalid batch size")
	}
	core, e := session.NewSecureSessionFromExporterWithRole(in.SID, seed, (in.Direction == "c2s") == sending, session.Config{MaxAge: time.Hour, IdleTimeout: 10 * time.Minute, MaxMessages: 1000, RekeyInterval: 256})
	if e != nil {
		return "", nil, e
	}
	defer func() { _ = core.Close() }()
	if sending {
		records := []string{}
		for _, encoded := range in.Messages {
			message, e := hex.DecodeString(encoded)
			if e != nil || len(message) > 512 {
				return "", nil, fmt.Errorf("invalid message")
			}
			record, e := core.EncryptWithAADOutbound(message, aad)
			if e != nil {
				return "REJECT", map[string]any{}, nil
			}
			records = append(records, hex.EncodeToString(record))
		}
		return "ACCEPT", map[string]any{"records_hex": records}, nil
	}
	results := []map[string]any{}
	for _, a := range in.Actions {
		if a.Kind == "parallel_open" {
			result, e := parallelOpen(core, a.Records, aad)
			if e != nil {
				return "", nil, e
			}
			results = append(results, result)
			continue
		}
		if a.Kind == "close" {
			if e := core.Close(); e != nil {
				return "", nil, e
			}
			results = append(results, map[string]any{"verdict": "ACCEPT", "output": map[string]any{}})
			continue
		}
		if a.Kind != "open" {
			return "", nil, fmt.Errorf("unknown sequence action")
		}
		record, e := hex.DecodeString(a.Record)
		if e != nil || len(record) > 2048 {
			return "", nil, fmt.Errorf("invalid record control")
		}
		plain, e := core.DecryptWithAADInbound(record, aad)
		result := map[string]any{"verdict": "REJECT", "output": map[string]any{}}
		if e == nil {
			result = map[string]any{"verdict": "ACCEPT", "output": map[string]any{"plaintext_hex": hex.EncodeToString(plain)}}
		}
		results = append(results, result)
	}
	return "ACCEPT", map[string]any{"results": results}, nil
}
