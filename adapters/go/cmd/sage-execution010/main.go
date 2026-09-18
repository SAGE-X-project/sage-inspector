// Local storage adapter; it does not authenticate intents or invoke tools.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	core "github.com/sage-x-project/sage/pkg/agent/execution010"
	"io"
	"os"
)

type request struct {
	Action string     `json:"action"`
	Entry  core.Entry `json:"entry"`
	Issuer string     `json:"issuer"`
	CallID string     `json:"call_id"`
}
type reply struct {
	OK      bool        `json:"ok"`
	Changed bool        `json:"changed"`
	Entry   *core.Entry `json:"entry"`
}

func main() {
	if len(os.Args) != 3 || (os.Args[2] != "create" && os.Args[2] != "reopen") {
		os.Exit(2)
	}
	l, e := core.Open(os.Args[1], os.Args[2] == "create")
	if e != nil {
		os.Exit(2)
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 5*1024*1024)
	out := json.NewEncoder(os.Stdout)
	count := 0
	for scan.Scan() {
		count++
		if count > 128 {
			_ = l.Close()
			os.Exit(2)
		}
		var q request
		decoder := json.NewDecoder(bytes.NewReader(scan.Bytes()))
		decoder.DisallowUnknownFields()
		var trailing any
		if decoder.Decode(&q) != nil || decoder.Decode(&trailing) != io.EOF {
			_ = l.Close()
			os.Exit(2)
		}
		result := reply{}
		var err error
		switch q.Action {
		case "commit":
			result.Changed, err = l.Commit(q.Entry)
		case "lookup":
			var value core.Entry
			var found bool
			value, found, err = l.Lookup(q.Issuer, q.CallID)
			if found {
				result.Entry = &value
			}
		case "reopen":
			if err = l.Close(); err == nil {
				l, err = core.Open(os.Args[1], false)
			}
		case "abandon":
			if out.Encode(reply{OK: true}) != nil {
				os.Exit(2)
			}
			os.Exit(0)
		default:
			_ = l.Close()
			os.Exit(2)
		}
		result.OK = err == nil
		if out.Encode(result) != nil {
			os.Exit(2)
		}
		if l == nil {
			os.Exit(2)
		}
	}
	if scan.Err() != nil {
		_ = l.Close()
		os.Exit(2)
	}
	if l.Close() != nil {
		os.Exit(2)
	}
}
