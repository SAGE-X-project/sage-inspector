// Bounded local test adapter. Fixture controls emulate trusted dependencies;
// this executable is not a production authenticated service or dispatcher.
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
	Action string       `json:"action"`
	Input  guardFixture `json:"input"`
}
type reply struct {
	OK      bool   `json:"ok"`
	Created bool   `json:"created"`
	State   string `json:"state"`
	Digest  string `json:"intent_digest"`
}

func run() error {
	if len(os.Args) != 3 || (os.Args[2] != "create" && os.Args[2] != "reopen") {
		return g.ErrInvalid
	}
	l, e := g.OpenLedger(os.Args[1], os.Args[2] == "create", recipient)
	if e != nil {
		return e
	}
	defer func() { _ = l.Close() }()
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
		case "reserve":
			raw, err := hex.DecodeString(q.Input.s("envelope_hex"))
			if err != nil {
				return err
			}
			v, err := l.Reserve(context.Background(), raw, q.Input, q.Input)
			r.OK = err == nil
			if err == nil {
				r.Created = v.Created()
				r.State = v.State()
				r.Digest = v.IntentDigest()
			}
		case "reopen":
			if e = l.Close(); e != nil {
				return e
			}
			l, e = g.OpenLedger(os.Args[1], false, recipient)
			if e != nil {
				return e
			}
			r.OK = true
		default:
			return g.ErrInvalid
		}
		if e = out.Encode(r); e != nil {
			return e
		}
	}
	if e = scan.Err(); e != nil {
		return e
	}
	return l.Close()
}
func main() {
	if run() != nil {
		os.Exit(2)
	}
}
