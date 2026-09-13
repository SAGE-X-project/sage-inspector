// Package conformance loads externally sourced expectations and reports bounded
// adapter observations. It has no dependency on the SAGE core.
package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

const ProtocolVersion = "0.10.0"
const MaxJSONBytes = 4 << 20
const Profile = "primitive-foundation"

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Source struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	URI       string `json:"uri"`
	Reference string `json:"reference"`
}
type Expected struct {
	Verdict string          `json:"verdict"`
	Output  json.RawMessage `json:"output"`
}
type Case struct {
	ID         string          `json:"id"`
	Operation  string          `json:"operation"`
	RuleIDs    []string        `json:"rule_ids"`
	SourceIDs  []string        `json:"source_ids"`
	Derivation string          `json:"derivation"`
	Input      json.RawMessage `json:"input"`
	Expected   Expected        `json:"expected"`
}
type Suite struct {
	SchemaVersion   int      `json:"schema_version"`
	ProtocolVersion string   `json:"protocol_version"`
	Profile         string   `json:"profile"`
	ID              string   `json:"id"`
	Sources         []Source `json:"sources"`
	Cases           []Case   `json:"cases"`
	Digest          string   `json:"-"`
	raw             []byte
}

func Digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func Load(r io.Reader) (*Suite, error) {
	b, e := io.ReadAll(io.LimitReader(r, MaxJSONBytes+1))
	if e != nil {
		return nil, e
	}
	var s Suite
	if e = decode(b, &s); e != nil {
		return nil, e
	}
	if e = s.Validate(); e != nil {
		return nil, e
	}
	s.Digest = Digest(b)
	s.raw = append([]byte(nil), b...)
	return &s, nil
}
func object(b []byte) bool {
	v, e := strictJSON(b)
	if e != nil {
		return false
	}
	_, ok := v.(map[string]any)
	return ok
}
func (s *Suite) Validate() error {
	if s.SchemaVersion != 1 || s.ProtocolVersion != ProtocolVersion || s.Profile != Profile || !namePattern.MatchString(s.ID) {
		return fmt.Errorf("unsupported suite schema/version/profile or invalid id")
	}
	if len(s.Cases) == 0 || len(s.Cases) > 512 || len(s.Sources) == 0 || len(s.Sources) > 128 {
		return fmt.Errorf("suite needs1..512 cases and1..128 sources")
	}
	src := map[string]bool{}
	for _, x := range s.Sources {
		if !namePattern.MatchString(x.ID) || src[x.ID] || len(x.URI) == 0 || len(x.URI) > 2048 || len(x.Reference) == 0 || len(x.Reference) > 4096 || (x.Kind != "published" && x.Kind != "spec-derived") {
			return fmt.Errorf("invalid/duplicate source %q", x.ID)
		}
		src[x.ID] = true
	}
	ids := map[string]bool{}
	for _, c := range s.Cases {
		if !namePattern.MatchString(c.ID) || ids[c.ID] || !namePattern.MatchString(c.Operation) {
			return fmt.Errorf("invalid/duplicate case %q", c.ID)
		}
		ids[c.ID] = true
		if len(c.RuleIDs) == 0 || len(c.RuleIDs) > 32 || len(c.SourceIDs) == 0 || len(c.SourceIDs) > 32 || len(c.Derivation) == 0 || len(c.Derivation) > 4096 {
			return fmt.Errorf("case %s missing/bounded provenance", c.ID)
		}
		seen := map[string]bool{}
		for _, id := range c.RuleIDs {
			if !namePattern.MatchString(id) || seen[id] {
				return fmt.Errorf("invalid/duplicate rule id")
			}
			seen[id] = true
		}
		seen = map[string]bool{}
		for _, id := range c.SourceIDs {
			if !src[id] || seen[id] {
				return fmt.Errorf("unknown/duplicate source %q", id)
			}
			seen[id] = true
		}
		if !object(c.Input) || !object(c.Expected.Output) || (c.Expected.Verdict != "ACCEPT" && c.Expected.Verdict != "REJECT") {
			return fmt.Errorf("case %s invalid input/expectation", c.ID)
		}
		v, _ := strictJSON(c.Expected.Output)
		if c.Expected.Verdict == "REJECT" && len(v.(map[string]any)) != 0 {
			return fmt.Errorf("rejection output must be empty")
		}
	}
	return nil
}

// ReadRequest validates the versioned stdin protocol used by an external adapter.
// It contains no expected values or source-derived answers.
func ReadRequest(r io.Reader) (Request, error) {
	b, e := io.ReadAll(io.LimitReader(r, MaxJSONBytes+1))
	if e != nil {
		return Request{}, e
	}
	var q Request
	if e = decode(b, &q); e != nil {
		return q, e
	}
	if q.SchemaVersion != 1 || q.ProtocolVersion != ProtocolVersion || q.Profile != Profile || !namePattern.MatchString(q.CaseID) || !namePattern.MatchString(q.Operation) || !object(q.Input) {
		return q, fmt.Errorf("invalid adapter request")
	}
	return q, nil
}
