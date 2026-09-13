//go:build !unix

package conformance

import (
	"fmt"
	"os/exec"
)

func prepareCommand(*exec.Cmd) error {
	return fmt.Errorf("external adapters currently require Unix process-group support")
}
