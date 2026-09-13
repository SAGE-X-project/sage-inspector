package conformancecli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sage-x-project/sage-inspector/pkg/conformance"
)

type arguments []string

func (a *arguments) String() string     { return strings.Join(*a, " ") }
func (a *arguments) Set(s string) error { *a = append(*a, s); return nil }

// Run returns0 for all-case PASS,1 for observed failures,2 for input/config errors,
// and3 for incomplete runs. A reference run never certifies another implementation.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	fs := flag.NewFlagSet("conformance", flag.ContinueOnError)
	fs.SetOutput(stderr)
	suite := fs.String("suite", "vectors/0.10.0/foundation.json", "version-pinned suite")
	reportPath := fs.String("report", "", "save JSON report atomically")
	adapter := fs.String("adapter", "", "trusted executable adapter; default is inspector reference")
	subject := fs.String("subject", "", "external subject name (required with adapter)")
	revision := fs.String("revision", "", "external subject revision (required with adapter)")
	timeout := fs.Duration("timeout", 5*time.Second, "per-case adapter timeout, at most1m")
	selection := fs.String("case", "", "comma-separated case IDs; others are NOT_RUN")
	var argv arguments
	fs.Var(&argv, "adapter-arg", "adapter argument; repeatable")
	if e := fs.Parse(args); e != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	f, e := os.Open(*suite)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return 2
	}
	s, e := conformance.Load(f)
	f.Close()
	if e != nil {
		fmt.Fprintln(stderr, e)
		return 2
	}
	if *reportPath != "" {
		a, _ := filepath.Abs(*suite)
		b, _ := filepath.Abs(*reportPath)
		if a == b {
			fmt.Fprintln(stderr, "report must not overwrite suite")
			return 2
		}
		if st1, e1 := os.Stat(*suite); e1 == nil {
			if st2, e2 := os.Stat(*reportPath); e2 == nil && os.SameFile(st1, st2) {
				fmt.Fprintln(stderr, "report aliases suite")
				return 2
			}
		}
	}
	var a conformance.Adapter = conformance.Reference{}
	sub := conformance.Subject{Name: "inspector-reference", Revision: version, Kind: "reference"}
	if exe, err := os.Executable(); err == nil {
		if b, err := os.ReadFile(exe); err == nil {
			sub.ExecutableSHA256 = conformance.Digest(b)
		}
	}
	if *adapter != "" {
		if *subject == "" || *revision == "" {
			fmt.Fprintln(stderr, "adapter requires subject and revision")
			return 2
		}
		pa, e := conformance.NewProcess(*adapter, argv)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return 2
		}
		a = pa
		sub = conformance.Subject{Name: *subject, Revision: *revision, Kind: "external", ExecutableSHA256: pa.ExpectedSHA256}
	} else if len(argv) > 0 || *subject != "" || *revision != "" {
		fmt.Fprintln(stderr, "subject/revision/adapter-arg require adapter")
		return 2
	}
	var ids []string
	if *selection != "" {
		ids = strings.Split(*selection, ",")
	}
	r, e := conformance.Run(context.Background(), s, a, conformance.Options{Subject: sub, RunnerVersion: version, Timeout: *timeout, Select: ids})
	if e != nil {
		fmt.Fprintln(stderr, e)
		return 2
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		fmt.Fprintln(stderr, e)
		return 2
	}
	b = append(b, '\n')
	if *reportPath != "" {
		if e = save(*reportPath, b); e != nil {
			fmt.Fprintln(stderr, e)
			return 2
		}
	}
	if _, e = stdout.Write(b); e != nil {
		fmt.Fprintln(stderr, e)
		return 2
	}
	return r.ExitCode()
}
func save(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".sage-report-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
