package conformance

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryStatefulFixturesLoad(t *testing.T) {
	paths, err := filepath.Glob("../../vectors/0.10.0/registry-scenarios/*.json")
	if err != nil || len(paths) != 17 {
		t.Fatalf("missing Registry lifecycle fixtures: %v", err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f, err := os.Open(path) // #nosec G304 -- Repository-owned fixture glob.
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			s, err := LoadScenario(f)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Steps) < 3 || s.Steps[0].Operation != "control.registry.create" {
				t.Fatal("missing create/action/inspect sequence")
			}
			process, err := NewProcess(os.Args[0], []string{"-test.run=TestScenarioChild", "scenario-child", "unsupported"})
			if err != nil {
				t.Fatal(err)
			}
			report, err := RunScenario(context.Background(), s, process, Subject{Name: "synthetic-contract-only", Revision: "test"})
			if err != nil {
				t.Fatal(err)
			}
			if report.Status != "INCOMPLETE" || report.Steps[0].Status != "UNSUPPORTED" {
				t.Fatal("unsupported state control was certified")
			}
			for _, step := range report.Steps[1:] {
				if step.Status != "NOT_RUN" {
					t.Fatal("unexecuted state step was certified")
				}
			}
		})
	}
}
