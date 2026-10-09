//go:build strictdid010

package main

import "github.com/sage-x-project/sage/pkg/agent/did"

// strictDID010 is set when the pinned core exposes the 0.10.0 DID parser.
const strictDID010 = true

func parseDID010(id string) error {
	_, err := did.ParseDID010(id)
	return err
}
