package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyntaxInventoryDoesNotExecuteOrExposeLiterals(t *testing.T) {
	root := t.TempDir()
	code := `package sample
var ignored = build("PRIVATE_SENTINEL")
type Host[T any] struct{}
func (h *Host[T]) Execute() { callback("PRIVATE_SENTINEL"); go func(){ h.apply() }(); defer stop() }
func init(){ panic("must never execute") }
`
	if err := os.WriteFile(filepath.Join(root, "source.go"), []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := inspect(root, strings.NewReader(`["source.go"]`), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "PRIVATE_SENTINEL") || strings.Contains(out.String(), "must never execute") {
		t.Fatal("literal disclosure")
	}
	var got inventory
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	f := got.Files[0]
	if f.Package != "sample" || len(f.SHA256) != 64 || f.Declarations[0].Name != "Host.Execute" || !f.Declarations[0].Exported {
		t.Fatalf("unexpected declarations: %+v", f)
	}
	want := []string{"callback", "<function-literal>", "h.apply", "stop"}
	if len(f.Declarations[0].Calls) != len(want) {
		t.Fatal("missing or extra calls")
	}
	for i, c := range f.Declarations[0].Calls {
		if c.Callee != want[i] {
			t.Fatalf("call %d: %s", i, c.Callee)
		}
	}
	if len(f.InitializerCalls) != 1 || f.InitializerCalls[0].Callee != "build" {
		t.Fatal("missing calls")
	}
	var again bytes.Buffer
	if err := inspect(root, strings.NewReader(`["source.go"]`), &again); err != nil || !bytes.Equal(out.Bytes(), again.Bytes()) {
		t.Fatal("non-deterministic inventory", err)
	}
}
func TestRejectInvalidSourceSets(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(root, "ok.go"), []byte("package ok"), 0600))
	must(os.WriteFile(filepath.Join(root, "bad.go"), []byte("package {"), 0600))
	must(os.WriteFile(filepath.Join(root, "large.go"), bytes.Repeat([]byte(" "), maxFile+1), 0600))
	must(os.Symlink(filepath.Join(root, "ok.go"), filepath.Join(root, "link.go")))
	must(os.Mkdir(filepath.Join(root, "directory.go"), 0700))
	must(os.Mkdir(filepath.Join(root, "dir"), 0700))
	must(os.Symlink(filepath.Join(root, "dir"), filepath.Join(root, "linked")))
	for _, input := range []string{`null`, `[]`, `["ok.go","ok.go"]`, `["ok.go","bad.go"]`, `["../ok.go"]`, `["/ok.go"]`, `["dir/../ok.go"]`, `["ok_test.go"]`, `["link.go"]`, `["linked/source.go"]`, `["directory.go"]`, `["bad.go"]`, `["large.go"]`, `["missing.go"]`, `["ok.go"] {}`, `{}`, `["dir\\ok.go"]`} {
		t.Run(input, func(t *testing.T) {
			var out bytes.Buffer
			if inspect(root, strings.NewReader(input), &out) == nil || out.Len() != 0 {
				t.Fatal("accepted invalid input or emitted partial report")
			}
		})
	}
	var out bytes.Buffer
	if inspect(root, strings.NewReader(strings.Repeat(" ", maxList+1)), &out) == nil {
		t.Fatal("unbounded list")
	}
}
