// sage-scenario runs one stateful scenario in a bounded, operator-selected process.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/sage-x-project/sage-inspector/pkg/conformance"
	"os"
)

func main() { os.Exit(run()) }
func run() int {
	fixture := flag.String("scenario", "", "scenario JSON file")
	adapter := flag.String("adapter", "", "trusted executable")
	subject := flag.String("subject", "", "subject name")
	revision := flag.String("revision", "", "source revision")
	flag.Parse()
	if flag.NArg() != 0 || *fixture == "" || *adapter == "" || *subject == "" || *revision == "" {
		fmt.Fprintln(os.Stderr, "scenario, adapter, subject and revision are required")
		return 2
	}
	f, e := os.Open(*fixture)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	s, e := conformance.LoadScenario(f)
	f.Close()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	p, e := conformance.NewProcess(*adapter, nil)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	r, e := conformance.RunScenario(context.Background(), s, p, conformance.Subject{Name: *subject, Revision: *revision})
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	if e = json.NewEncoder(os.Stdout).Encode(r); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	switch r.Status {
	case "PASS":
		return 0
	case "INCOMPLETE":
		return 3
	default:
		return 1
	}
}
