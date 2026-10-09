//go:build !strictdid010

package main

import "errors"

// Without the strictdid010 tag the core may predate the 0.10.0 DID parser, so
// the 0.10.0 profile reports DID validation UNSUPPORTED.
const strictDID010 = false

func parseDID010(string) error { return errors.New("0.10.0 DID parser not built") }
