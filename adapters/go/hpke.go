package main

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/sage-x-project/sage/pkg/agent/crypto/keys"
	"github.com/sage-x-project/sage/pkg/agent/hpke"
)

func hpkeObserve(op string, input json.RawMessage) (string, map[string]any, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(input, &fields); err != nil {
		return "", nil, err
	}
	decode := func(name string) ([]byte, error) {
		value, ok := fields[name]
		if !ok {
			return nil, fmt.Errorf("missing %s", name)
		}
		var encoded *string
		if err := json.Unmarshal(value, &encoded); err != nil || encoded == nil {
			return nil, fmt.Errorf("invalid %s", name)
		}
		return hex.DecodeString(*encoded)
	}
	var names []string
	if op == "rfc9180.export" {
		names = []string{"private_key_hex", "enc_hex", "info_hex", "export_context_hex"}
	} else {
		names = []string{"exporter_hex", "ss_e2e_hex", "th_hex"}
	}
	values := make([][]byte, len(names))
	for n, name := range names {
		value, err := decode(name)
		if err != nil {
			return "", nil, err
		}
		values[n] = value
	}
	var output []byte
	var err error
	field := "seed_hex"
	if op == "rfc9180.export" {
		// Private bytes are deterministic local fixture controls. Encapsulation and
		// domain inputs go unchanged to the actual core's recipient/export API.
		private, e := ecdh.X25519().NewPrivateKey(values[0])
		if e != nil {
			return "", nil, e
		}
		output, err = keys.HPKEOpenSharedSecretWithX25519Priv(private, values[1], values[2], values[3], 32)
		field = "exporter_hex"
	} else {
		// Pass the normative transcript salt to the existing combiner. Its old
		// expansion label is observable as FAIL, not replaced inside this adapter.
		output, err = hpke.CombineSecrets(values[0], values[1], values[2])
	}
	if err != nil {
		return "REJECT", map[string]any{}, nil
	}
	return "ACCEPT", map[string]any{field: hex.EncodeToString(output)}, nil
}
