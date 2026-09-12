// Package inspect implements the checks behind the sage-inspector command:
// running the sage-spec vectors against the Go core and explaining
// individual SAGE messages.
package inspect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/sage-x-project/sage/pkg/vectors"
)

// VectorResult is the outcome of one vector.
type VectorResult struct {
	Suite  string `json:"suite"`
	Name   string `json:"name"`
	Mode   string `json:"mode"`
	Status string `json:"status"` // pass, fail, missing, unknown
	Error  string `json:"error,omitempty"`
}

// VectorReport summarises a run over a vectors directory.
type VectorReport struct {
	Dir         string         `json:"dir"`
	SpecVersion string         `json:"spec_version,omitempty"`
	Results     []VectorResult `json:"results"`
	Passed      int            `json:"passed"`
	Failed      int            `json:"failed"`
}

// OK reports whether every vector passed.
func (r *VectorReport) OK() bool { return r.Failed == 0 }

// RunVectors checks every suite the Go core defines against the JSON files
// in dir and reports per vector (the Go core's own sage-vectors check
// reports only the first failure per run).
func RunVectors(dir string) (*VectorReport, error) {
	report := &VectorReport{Dir: dir}
	for _, s := range vectors.Suites() {
		path := filepath.Join(dir, s.Name+".json")
		data, err := os.ReadFile(path) // #nosec G304 -- directory chosen by the operator
		if err != nil {
			for _, c := range s.Cases {
				report.add(VectorResult{Suite: s.Name, Name: c.Name, Mode: string(c.Mode), Status: "missing", Error: err.Error()})
			}
			continue
		}
		var f vectors.File
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if report.SpecVersion == "" {
			report.SpecVersion = f.SpecVersion
		}
		stored := map[string]vectors.Vector{}
		for _, v := range f.Vectors {
			stored[v.Name] = v
		}
		for _, c := range s.Cases {
			res := VectorResult{Suite: s.Name, Name: c.Name, Mode: string(c.Mode)}
			v, ok := stored[c.Name]
			if !ok {
				res.Status, res.Error = "missing", "not in file"
			} else if err := checkCase(c, v); err != nil {
				res.Status, res.Error = "fail", err.Error()
			} else {
				res.Status = "pass"
			}
			report.add(res)
			delete(stored, c.Name)
		}
		for name, v := range stored {
			report.add(VectorResult{Suite: s.Name, Name: name, Mode: string(v.Mode), Status: "unknown", Error: "not produced by this implementation"})
		}
	}
	return report, nil
}

func (r *VectorReport) add(res VectorResult) {
	r.Results = append(r.Results, res)
	if res.Status == "pass" {
		r.Passed++
	} else {
		r.Failed++
	}
}

func checkCase(c vectors.Case, v vectors.Vector) error {
	if v.Mode != c.Mode {
		return fmt.Errorf("mode is %q, expected %q", v.Mode, c.Mode)
	}
	if !reflect.DeepEqual(normalise(v.Input), normalise(c.Input)) {
		return fmt.Errorf("input differs from this implementation's fixed input")
	}
	switch c.Mode {
	case vectors.ModeDeterministic:
		out, err := c.Produce(c.Input)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(normalise(out), normalise(v.Output)) {
			return fmt.Errorf("output mismatch")
		}
		if c.Verify != nil {
			return c.Verify(c.Input, v.Output)
		}
		return nil
	case vectors.ModeVerify:
		if c.Verify == nil {
			return fmt.Errorf("verify-mode case without a verifier")
		}
		return c.Verify(c.Input, v.Output)
	}
	return fmt.Errorf("unknown mode %q", c.Mode)
}

func normalise(v any) any {
	data, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return v
	}
	return out
}
