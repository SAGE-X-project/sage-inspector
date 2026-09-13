// This example tests the adapter transport, not a second independent crypto core.
// Replace Reference.Observe with an implementation-specific operation mapping.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sage-x-project/sage-inspector/pkg/conformance"
)

func main() {
	q, e := conformance.ReadRequest(os.Stdin)
	if e != nil {
		_, _ = fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	o, e := (conformance.Reference{}).Observe(context.Background(), q)
	if e != nil {
		_, _ = fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if e = json.NewEncoder(os.Stdout).Encode(o); e != nil {
		os.Exit(1)
	}
}
