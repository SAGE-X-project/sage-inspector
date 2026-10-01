// A bounded Inspector adapter for the explicit Go 0.10.0 DID parser.
package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/sage-x-project/sage/pkg/agent/did"
)

func run(input io.Reader, output io.Writer) error {
	var request struct {
		Schema    int             `json:"schema_version"`
		Version   string          `json:"protocol_version"`
		Profile   string          `json:"profile"`
		CaseID    string          `json:"case_id"`
		Operation string          `json:"operation"`
		Input     json.RawMessage `json:"input"`
	}
	decoder := json.NewDecoder(io.LimitReader(input, 4<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || request.Schema != 1 ||
		request.Version != "0.10.0" || request.Profile != "primitive-foundation" ||
		request.CaseID == "" {
		return errors.New("invalid inspector request")
	}
	var fields struct {
		DID    *string `json:"did"`
		DIDURL *string `json:"did_url"`
	}
	if err := json.Unmarshal(request.Input, &fields); err != nil {
		return err
	}
	verdict := "REJECT"
	parsed := map[string]any{}
	switch request.Operation {
	case "sage.did010.parse":
		if fields.DID == nil || fields.DIDURL != nil {
			return errors.New("invalid DID input")
		}
		identity, err := did.ParseDID010(*fields.DID)
		if err == nil {
			verdict = "ACCEPT"
			parsed = map[string]any{"kind": identity.Kind, "locator": identity.Locator,
				"agent_id": identity.AgentID}
		}
	case "sage.did-url010.parse":
		if fields.DIDURL == nil || fields.DID != nil {
			return errors.New("invalid DID URL input")
		}
		identity, err := did.ParseDIDURL010(*fields.DIDURL)
		if err == nil {
			verdict = "ACCEPT"
			parsed = map[string]any{"kind": identity.DID.Kind,
				"locator": identity.DID.Locator, "agent_id": identity.DID.AgentID,
				"key_id": identity.KeyID}
		}
	default:
		return errors.New("unsupported inspector operation")
	}
	return json.NewEncoder(output).Encode(struct {
		Schema  int            `json:"schema_version"`
		CaseID  string         `json:"case_id"`
		Verdict string         `json:"verdict"`
		Output  map[string]any `json:"output"`
	}{1, request.CaseID, verdict, parsed})
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}
