// Bounded local test controls for the real durable replay API; never a server.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sage-x-project/sage/pkg/agent/hpke"
	"github.com/sage-x-project/sage/pkg/agent/registry010"
	"io"
	"os"
)

type clock struct{ utc, mono int64 }

func (c *clock) Now() (registry010.Stamp, error) {
	return registry010.Stamp{Unix: c.utc, MonoMS: c.mono}, nil
}

type control struct {
	Action    string `json:"action"`
	Unix      int64  `json:"unix"`
	Mono      int64  `json:"mono_ms"`
	Create    bool   `json:"create,omitempty"`
	Gate      bool   `json:"gate,omitempty"`
	ID        string `json:"id,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Recipient string `json:"recipient,omitempty"`
	Context   string `json:"context,omitempty"`
	Expires   int64  `json:"expires,omitempty"`
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("path required")
	}
	var j *hpke.ReplayJournal010
	c := &clock{}
	defer func() {
		if j != nil {
			_ = j.Close()
		}
	}()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 1024), 65536)
	for n := 0; scan.Scan(); n++ {
		if n >= 128 {
			return errors.New("bound")
		}
		var q control
		d := json.NewDecoder(bytes.NewReader(scan.Bytes()))
		d.DisallowUnknownFields()
		if d.Decode(&q) != nil {
			return errors.New("control")
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return errors.New("trailing control")
		}
		c.utc, c.mono = q.Unix, q.Mono
		calls := 0
		ok := false
		var err error
		switch q.Action {
		case "open":
			if j != nil {
				return errors.New("already open")
			}
			j, err = hpke.OpenReplayJournal010(os.Args[1], q.Create, c)
			ok = err == nil
		case "close":
			if j == nil {
				return errors.New("not open")
			}
			err = j.Close()
			j = nil
			ok = err == nil
		case "ready":
			if j == nil {
				return errors.New("not open")
			}
			ok = j.Ready()
		case "reserve", "record":
			if j == nil {
				return errors.New("not open")
			}
			if q.ID == "" {
				q.ID = "id"
			}
			if q.Nonce == "" {
				q.Nonce = "nonce"
			}
			if q.Recipient == "" {
				q.Recipient = "bob"
			}
			if q.Expires == 0 {
				q.Expires = 760
			}
			v := hpke.Replay010{Sender: "alice", Recipient: q.Recipient, ID: q.ID, Nonce: q.Nonce, Context: q.Context, Expires: q.Expires}
			if q.Action == "record" {
				err = j.ReserveRecord(v, func() error {
					calls++
					if !q.Gate {
						return errors.New("gate")
					}
					return nil
				})
			} else {
				err = j.Reserve(v)
			}
			ok = err == nil
		case "abandon":
			fmt.Println(`{"ok":true,"calls":0}`)
			os.Exit(0)
		default:
			return errors.New("action")
		}
		if json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": ok, "calls": calls}) != nil {
			return errors.New("output")
		}
	}
	return scan.Err()
}
func main() {
	if run() != nil {
		os.Exit(2)
	}
}
