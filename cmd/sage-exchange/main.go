// sage-exchange records live bytes exchanged between two explicit core adapters.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sage-x-project/sage-inspector/pkg/conformance"
)

func run() int {
	left := flag.String("go-adapter", "", "Go core adapter executable")
	right := flag.String("rust-adapter", "", "Rust core adapter executable")
	leftRev := flag.String("go-revision", "", "Go core source revision")
	rightRev := flag.String("rust-revision", "", "Rust core source revision")
	stateful := flag.Bool("stateful", false, "Keep receiver state across replay and close actions")
	flag.Parse()
	a, err := conformance.NewProcess(*left, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	b, err := conformance.NewProcess(*right, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	subjects := []conformance.Subject{{Name: "sage-go", Revision: *leftRev, Kind: "external", ExecutableSHA256: a.ExpectedSHA256}, {Name: "sage-rust", Revision: *rightRev, Kind: "external", ExecutableSHA256: b.ExpectedSHA256}}
	var report any
	var status string
	if *stateful {
		r, e := conformance.RunReplayExchange(ctx, subjects, []conformance.Adapter{a, b})
		err = e
		report = r
		if e == nil {
			status = r.Status
		}
	} else {
		r, e := conformance.RunExchange(ctx, subjects, []conformance.Adapter{a, b})
		err = e
		report = r
		if e == nil {
			status = r.Status
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if status == "FAIL" {
		return 1
	}
	if status == "INCOMPLETE" {
		return 3
	}
	return 0
}
func main() { os.Exit(run()) }
