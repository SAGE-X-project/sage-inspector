package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"time"
)

const ScenarioProfile = "stateful-scenario"

type ScenarioStep struct {
	ID        string          `json:"id"`
	Operation string          `json:"operation"`
	Input     json.RawMessage `json:"input"`
	TimeoutMS int             `json:"timeout_ms"`
	Expected  Expected        `json:"expected"`
	// Effects is an exact cumulative counter map; adapters must not invent it.
	Effects map[string]uint64 `json:"effects"`
}
type Scenario struct {
	SchemaVersion   int            `json:"schema_version"`
	ProtocolVersion string         `json:"protocol_version"`
	Profile         string         `json:"profile"`
	ID              string         `json:"id"`
	Sources         []Source       `json:"sources"`
	Steps           []ScenarioStep `json:"steps"`
	raw             []byte
}
type StepRequest struct {
	SchemaVersion   int             `json:"schema_version"`
	ProtocolVersion string          `json:"protocol_version"`
	Profile         string          `json:"profile"`
	CaseID          string          `json:"case_id"`
	StepID          string          `json:"step_id"`
	Operation       string          `json:"operation"`
	Input           json.RawMessage `json:"input"`
}
type StepObservation struct {
	SchemaVersion int               `json:"schema_version"`
	CaseID        string            `json:"case_id"`
	StepID        string            `json:"step_id"`
	Verdict       string            `json:"verdict"`
	Output        json.RawMessage   `json:"output"`
	Effects       map[string]uint64 `json:"effects"`
}
type StepResult struct {
	Input           json.RawMessage   `json:"input"`
	StepID          string            `json:"step_id"`
	RequestSHA256   string            `json:"request_sha256"`
	Expected        Expected          `json:"expected"`
	ExpectedEffects map[string]uint64 `json:"expected_effects"`
	Actual          *StepObservation  `json:"actual,omitempty"`
	Status          string            `json:"status"`
	Reason          string            `json:"reason,omitempty"`
	DurationMS      int64             `json:"duration_ms"`
}
type ScenarioReport struct {
	ProtocolVersion string       `json:"protocol_version"`
	Environment     string       `json:"environment"`
	Created         string       `json:"created"`
	Sources         []Source     `json:"sources"`
	SchemaVersion   int          `json:"schema_version"`
	Profile         string       `json:"profile"`
	CaseID          string       `json:"case_id"`
	FixtureSHA256   string       `json:"fixture_sha256"`
	Subject         Subject      `json:"subject"`
	Status          string       `json:"status"`
	Reason          string       `json:"reason,omitempty"`
	Steps           []StepResult `json:"steps"`
}

func LoadScenario(r io.Reader) (*Scenario, error) {
	b, e := io.ReadAll(io.LimitReader(r, MaxJSONBytes+1))
	if e != nil {
		return nil, e
	}
	var s Scenario
	if e = decode(b, &s); e != nil {
		return nil, e
	}
	if s.SchemaVersion != 2 || s.ProtocolVersion != ProtocolVersion || s.Profile != ScenarioProfile || !namePattern.MatchString(s.ID) || len(s.Steps) == 0 || len(s.Steps) > 128 || len(s.Sources) == 0 || len(s.Sources) > 128 {
		return nil, fmt.Errorf("invalid scenario header")
	}
	seen := map[string]bool{}
	for _, src := range s.Sources {
		if !namePattern.MatchString(src.ID) || seen[src.ID] || len(src.URI) == 0 || len(src.URI) > 2048 || len(src.Reference) == 0 || len(src.Reference) > 4096 || (src.Kind != "published" && src.Kind != "spec-derived") {
			return nil, fmt.Errorf("invalid source")
		}
		seen[src.ID] = true
	}
	seen = map[string]bool{}
	for _, st := range s.Steps {
		if !namePattern.MatchString(st.ID) || seen[st.ID] || !namePattern.MatchString(st.Operation) || !object(st.Input) || st.TimeoutMS < 1 || st.TimeoutMS > 10000 || !object(st.Expected.Output) || st.Effects == nil || len(st.Effects) > 32 || (st.Expected.Verdict != "ACCEPT" && st.Expected.Verdict != "REJECT") {
			return nil, fmt.Errorf("invalid step %s", st.ID)
		}
		for key := range st.Effects {
			if !namePattern.MatchString(key) {
				return nil, fmt.Errorf("invalid effect key")
			}
		}
		if st.Expected.Verdict == "REJECT" {
			v, _ := strictJSON(st.Expected.Output)
			if len(v.(map[string]any)) != 0 {
				return nil, fmt.Errorf("nonempty rejection")
			}
		}
		seen[st.ID] = true
	}
	s.raw = append([]byte(nil), b...)
	return &s, nil
}

// RunScenario keeps one process alive for one scenario. A failed/unsupported step
// stops the scenario; subsequent steps remain NOT_RUN. It never sends expectations.
func RunScenario(parent context.Context, s *Scenario, p *Process, subject Subject) (*ScenarioReport, error) {
	if s == nil || len(s.raw) == 0 || p == nil || subject.Name == "" || subject.Revision == "" {
		return nil, fmt.Errorf("loaded scenario, process and subject required")
	}
	frozen, e := LoadScenario(bytes.NewReader(s.raw))
	if e != nil || !reflect.DeepEqual(s, frozen) {
		return nil, fmt.Errorf("scenario changed")
	}
	binary, e := os.ReadFile(p.Path)
	if e != nil || Digest(binary) != p.ExpectedSHA256 {
		return nil, fmt.Errorf("adapter changed")
	}
	subject.Kind = "external"
	subject.ExecutableSHA256 = p.ExpectedSHA256
	report := &ScenarioReport{ProtocolVersion: ProtocolVersion, Environment: runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH, Created: time.Now().UTC().Format(time.RFC3339Nano), Sources: s.Sources, SchemaVersion: 2, Profile: ScenarioProfile, CaseID: s.ID, FixtureSHA256: Digest(s.raw), Subject: subject, Status: "PASS"}
	for _, st := range s.Steps {
		report.Steps = append(report.Steps, StepResult{Input: st.Input, StepID: st.ID, Expected: st.Expected, ExpectedEffects: st.Effects, Status: "NOT_RUN"})
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Path, p.Args...)
	cmd.WaitDelay = 100 * time.Millisecond
	stderr := &boundedBuffer{limit: 64 << 10}
	cmd.Stderr = stderr
	if e = prepareCommand(cmd); e != nil {
		return nil, e
	}
	in, e := cmd.StdinPipe()
	if e != nil {
		return nil, e
	}
	defer in.Close()
	out, e := cmd.StdoutPipe()
	if e != nil {
		return nil, e
	}
	defer out.Close()
	if e = cmd.Start(); e != nil {
		return nil, e
	}
	reader := bufio.NewReaderSize(out, MaxJSONBytes+1)
	for i, st := range s.Steps {
		result := &report.Steps[i]
		started := time.Now()
		q := StepRequest{2, ProtocolVersion, ScenarioProfile, s.ID, st.ID, st.Operation, st.Input}
		wire, _ := json.Marshal(q)
		result.RequestSHA256 = Digest(wire)
		type answer struct {
			b []byte
			e error
		}
		done := make(chan answer, 1)
		go func() {
			_, err := in.Write(append(wire, '\n'))
			if err != nil {
				done <- answer{e: err}
				return
			}
			line, err := reader.ReadSlice('\n')
			done <- answer{append([]byte(nil), line...), err}
		}()
		timer := time.NewTimer(time.Duration(st.TimeoutMS) * time.Millisecond)
		var a answer
		select {
		case a = <-done:
		case <-timer.C:
			a.e = fmt.Errorf("step timeout")
			cancel()
			in.Close()
			out.Close()
			<-done
		case <-ctx.Done():
			a.e = ctx.Err()
			in.Close()
			out.Close()
			<-done
		}
		timer.Stop()
		result.DurationMS = time.Since(started).Milliseconds()
		var obs StepObservation
		if a.e == nil {
			a.e = decode(a.b, &obs)
		}
		if a.e == nil && (obs.SchemaVersion != 2 || obs.CaseID != s.ID || obs.StepID != st.ID || !object(obs.Output) || obs.Effects == nil || (obs.Verdict != "ACCEPT" && obs.Verdict != "REJECT" && obs.Verdict != "UNSUPPORTED")) {
			a.e = fmt.Errorf("invalid step observation")
		}
		if a.e == nil && obs.Verdict != "ACCEPT" {
			v, _ := strictJSON(obs.Output)
			if len(v.(map[string]any)) != 0 {
				a.e = fmt.Errorf("nonempty rejection/unsupported output")
			}
		}
		if a.e != nil {
			result.Status = "FAIL"
			result.Reason = a.e.Error()
		} else {
			result.Actual = &obs
			if obs.Verdict == "UNSUPPORTED" {
				result.Status = "UNSUPPORTED"
			} else {
				actual, _ := strictJSON(obs.Output)
				expected, _ := strictJSON(st.Expected.Output)
				if obs.Verdict != st.Expected.Verdict || !reflect.DeepEqual(actual, expected) || !reflect.DeepEqual(obs.Effects, st.Effects) {
					result.Status = "FAIL"
					result.Reason = "verdict, output or cumulative effects mismatch"
				} else {
					result.Status = "PASS"
				}
			}
		}
		if result.Status != "PASS" {
			report.Status = "FAIL"
			if result.Status == "UNSUPPORTED" {
				report.Status = "INCOMPLETE"
			}
			cancel()
			break
		}
	}
	in.Close()
	// EOF is required after the last response; close/timeout bounds escaped pipe holders.
	extra := make(chan bool, 1)
	go func() { _, err := reader.ReadByte(); extra <- err != io.EOF }()
	var trailing bool
	select {
	case trailing = <-extra:
	case <-ctx.Done():
		trailing = true
		out.Close()
		<-extra
	}
	waitErr := cmd.Wait()
	if report.Status == "PASS" && (waitErr != nil || stderr.exceeded || trailing || ctx.Err() != nil) {
		report.Status = "FAIL"
		report.Reason = "adapter exit, trailing output or scenario deadline failure"
	}
	return report, nil
}
