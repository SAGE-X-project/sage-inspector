package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Process is an explicitly chosen trusted adapter, not code named by a fixture.
// Arguments are passed directly; no shell is used. This is not a sandbox.
type Process struct {
	Path           string
	Args           []string
	ExpectedSHA256 string
}

func NewProcess(path string, args []string) (*Process, error) {
	p, e := exec.LookPath(path)
	if e != nil {
		return nil, e
	}
	p, e = filepath.Abs(p)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return nil, e
	}
	return &Process{p, append([]string(nil), args...), Digest(b)}, nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.exceeded = true
		return 0, fmt.Errorf("adapter output limit")
	}
	return b.Buffer.Write(p)
}
func (p *Process) Observe(ctx context.Context, q Request) (Observation, error) {
	// Detect ordinary replacement between cases. This does not pin interpreter,
	// dynamic libraries, or defend against a malicious host/check-use race.
	b, e := os.ReadFile(p.Path)
	if e != nil || Digest(b) != p.ExpectedSHA256 {
		return Observation{}, fmt.Errorf("adapter executable changed or unreadable")
	}
	input, e := json.Marshal(q)
	if e != nil {
		return Observation{}, e
	}
	cmd := exec.CommandContext(ctx, p.Path, p.Args...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.WaitDelay = 100 * time.Millisecond
	out := &boundedBuffer{limit: MaxJSONBytes}
	errout := &boundedBuffer{limit: 64 << 10}
	cmd.Stdout = out
	cmd.Stderr = errout
	if e = prepareCommand(cmd); e != nil {
		return Observation{}, e
	}
	e = cmd.Run()
	if ctx.Err() != nil {
		return Observation{}, ctx.Err()
	}
	if out.exceeded || errout.exceeded {
		return Observation{}, fmt.Errorf("adapter output exceeded limit")
	}
	if e != nil {
		return Observation{}, fmt.Errorf("adapter process failed: %w", e)
	}
	var obs Observation
	if e = decode(out.Bytes(), &obs); e != nil {
		return Observation{}, fmt.Errorf("malformed adapter JSON: %w", e)
	}
	return obs, nil
}
