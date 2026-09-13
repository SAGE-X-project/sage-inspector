// sage-conformance runs the 0.10.0 independent fixture/report foundation without
// importing the historical SAGE core dependency.
package main

import (
	"os"

	"github.com/sage-x-project/sage-inspector/internal/conformancecli"
)

var Version = "dev"

func main() { os.Exit(conformancecli.Run(os.Args[1:], os.Stdout, os.Stderr, Version)) }
