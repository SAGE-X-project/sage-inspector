// Thin adapter: the core alone decides document acceptance.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/sage/pkg/agent/crypto/jcs"
	"io"
	"os"
)

func run(r io.Reader, w io.Writer) error {
	var q struct {
		Schema    int             `json:"schema_version"`
		Version   string          `json:"protocol_version"`
		Profile   string          `json:"profile"`
		Case      string          `json:"case_id"`
		Operation string          `json:"operation"`
		Input     json.RawMessage `json:"input"`
	}
	d := json.NewDecoder(io.LimitReader(r, (4<<20)+1))
	d.DisallowUnknownFields()
	if e := d.Decode(&q); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing input")
	}
	if q.Schema != 1 || q.Version != "0.10.0" || q.Profile != "primitive-foundation" || q.Case == "" {
		return fmt.Errorf("invalid request")
	}
	verdict := "UNSUPPORTED"
	output := map[string]any{}
	if q.Operation == "json.syntax" {
		var in struct {
			Document string `json:"document_hex"`
		}
		if e := json.Unmarshal(q.Input, &in); e != nil {
			return e
		}
		b, e := hex.DecodeString(in.Document)
		if e != nil {
			return e
		}
		_, e = jcs.Canonicalize(b)
		verdict = "REJECT"
		if e == nil {
			verdict = "ACCEPT"
			output["valid"] = true
		}
	}
	return json.NewEncoder(w).Encode(map[string]any{"schema_version": 1, "case_id": q.Case, "verdict": verdict, "output": output})
}
func main() {
	if e := run(os.Stdin, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
}
