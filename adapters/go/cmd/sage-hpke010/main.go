// Local test process for cryptographic derivation; never a network service.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sage-x-project/sage/pkg/agent/hpke"
)

type request struct {
	ID        string             `json:"id"`
	Operation string             `json:"operation"`
	Input     map[string]*string `json:"input"`
}

func result(v *hpke.Derivation010) map[string]any {
	defer clear(v.Seed)
	return map[string]any{"transcript_hex": hex.EncodeToString(v.Transcript), "th_hex": hex.EncodeToString(v.TH), "seed_hex": hex.EncodeToString(v.Seed), "ack_tag_hex": hex.EncodeToString(v.AckTag), "sid": v.SID}
}
func run(r io.Reader, w io.Writer) error {
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 4096), 256*1024)
	var state *hpke.Initiator010
	defer func() {
		if state != nil {
			state.Close()
		}
	}()
	started := false
	seen := map[string]bool{}
	for step := 0; scan.Scan(); step++ {
		if step >= 16 {
			return errors.New("step limit")
		}
		var q request
		d := json.NewDecoder(bytes.NewReader(scan.Bytes()))
		d.DisallowUnknownFields()
		if d.Decode(&q) != nil || q.ID == "" || seen[q.ID] {
			return errors.New("invalid request")
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return errors.New("trailing request")
		}
		seen[q.ID] = true
		var names []string
		switch q.Operation {
		case "domains":
			names = []string{"binding_hex"}
		case "respond":
			names = []string{"initiation_hex", "kem_private_hex", "e2e_private_hex", "kid"}
		case "respond-fresh":
			names = []string{"initiation_hex", "kem_private_hex"}
		case "start":
			names = []string{"binding_hex", "kem_private_hex"}
		case "finish":
			names = []string{"transcript_hex"}
		default:
			if e := json.NewEncoder(w).Encode(map[string]any{"id": q.ID, "verdict": "UNSUPPORTED", "output": map[string]any{}}); e != nil {
				return e
			}
			continue
		}
		if len(q.Input) != len(names) {
			return errors.New("invalid controls")
		}
		values := map[string][]byte{}
		for _, n := range names {
			v := q.Input[n]
			if v == nil {
				return errors.New("invalid control")
			}
			if n != "kid" {
				b, e := hex.DecodeString(*v)
				if e != nil {
					return errors.New("invalid hex control")
				}
				values[n] = b
			}
		}
		var out map[string]any
		var err error
		switch q.Operation {
		case "domains":
			var v hpke.Domains010
			v, err = hpke.BuildDomains010(values["binding_hex"])
			if err == nil {
				out = map[string]any{"binding_hex": hex.EncodeToString(v.Binding), "info_hex": hex.EncodeToString(v.Info), "export_context_hex": hex.EncodeToString(v.ExportContext)}
			}
		case "respond", "respond-fresh":
			var v *hpke.Derivation010
			if q.Operation == "respond" {
				v, err = hpke.DeriveResponder010(values["initiation_hex"], values["kem_private_hex"], values["e2e_private_hex"], *q.Input["kid"])
			} else {
				v, err = hpke.RespondFresh010(values["initiation_hex"], values["kem_private_hex"])
			}
			if err == nil {
				out = result(v)
			}
		case "start":
			if started {
				return errors.New("state replacement")
			}
			started = true
			// The private key here is a trusted public-test control used only to obtain
			// the recipient public key; the sender core receives no recipient secret.
			sk, e := ecdh.X25519().NewPrivateKey(values["kem_private_hex"])
			if e != nil {
				return errors.New("invalid private control")
			}
			var init []byte
			state, init, err = hpke.StartInitiator010(values["binding_hex"], sk.PublicKey().Bytes())
			if err == nil {
				out = map[string]any{"initiation_hex": hex.EncodeToString(init)}
			}
		case "finish":
			if state == nil {
				return errors.New("missing sender state")
			}
			var v *hpke.Derivation010
			v, err = state.Derive(values["transcript_hex"])
			state.Close()
			state = nil
			if err == nil {
				out = result(v)
			}
		}
		verdict := "ACCEPT"
		if err != nil {
			verdict = "REJECT"
			out = map[string]any{}
		}
		if e := json.NewEncoder(w).Encode(map[string]any{"id": q.ID, "verdict": verdict, "output": out}); e != nil {
			return e
		}
	}
	return scan.Err()
}
func main() {
	if e := run(os.Stdin, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
}
