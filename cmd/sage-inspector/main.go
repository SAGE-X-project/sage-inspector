// sage-inspector checks SAGE implementations and messages against sage-spec.
//
//	sage-inspector vectors -dir ../sage-spec/vectors [-json]
//	sage-inspector request  -f request.http  [-key <hex public key>] [-ignore-age] [-json]
//	sage-inspector response -f response.http -request request.http [-key <hex>] [-ignore-age] [-json]
//	sage-inspector card     -f agent-card.json [-json]
//	sage-inspector version
//
// request/response read raw HTTP/1.x messages (as captured on the wire);
// without -key they only explain the signature, with it they verify.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sage-x-project/sage-inspector/pkg/inspect"
)

// Version is set at build time.
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	var ok bool
	switch os.Args[1] {
	case "vectors":
		ok, err = runVectors(os.Args[2:])
	case "request":
		ok, err = runMessage(os.Args[2:], false)
	case "response":
		ok, err = runMessage(os.Args[2:], true)
	case "card":
		ok, err = runCard(os.Args[2:])
	case "version":
		fmt.Println("sage-inspector", Version)
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sage-inspector:", err)
		os.Exit(2)
	}
	if !ok {
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sage-inspector <vectors|request|response|card|version> [flags]")
}

func runVectors(args []string) (bool, error) {
	fs := flag.NewFlagSet("vectors", flag.ExitOnError)
	dir := fs.String("dir", "vectors", "sage-spec vectors directory")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	_ = fs.Parse(args)
	report, err := inspect.RunVectors(*dir)
	if err != nil {
		return false, err
	}
	if *asJSON {
		return report.OK(), printJSON(report)
	}
	for _, r := range report.Results {
		line := fmt.Sprintf("%-5s %-8s %-28s %s", r.Status, r.Suite, r.Name, r.Mode)
		if r.Error != "" {
			line += "  " + firstLine(r.Error)
		}
		fmt.Println(line)
	}
	fmt.Printf("%d passed, %d failed (spec %s)\n", report.Passed, report.Failed, report.SpecVersion)
	return report.OK(), nil
}

func runMessage(args []string, response bool) (bool, error) {
	name := "request"
	if response {
		name = "response"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	file := fs.String("f", "", "raw HTTP message file")
	reqFile := fs.String("request", "", "raw HTTP request the response answers (response only)")
	keySpec := fs.String("key", "", "signer's public key (hex; 32 bytes Ed25519, 33/65 secp256k1, p256:<65 bytes>)")
	label := fs.String("label", "", "signature label (default: first)")
	ignoreAge := fs.Bool("ignore-age", false, "do not fail on old created timestamps")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	_ = fs.Parse(args)
	if *file == "" {
		return false, fmt.Errorf("-f is required")
	}
	raw, err := os.ReadFile(*file) // #nosec G304 -- operator-supplied path
	if err != nil {
		return false, err
	}
	opts := inspect.MessageOptions{Label: *label, IgnoreAge: *ignoreAge}
	if *keySpec != "" {
		pub, err := inspect.ParsePublicKey(*keySpec)
		if err != nil {
			return false, fmt.Errorf("-key: %w", err)
		}
		opts.PublicKey = pub
	}
	var report *inspect.MessageReport
	if response {
		if *reqFile == "" {
			return false, fmt.Errorf("-request is required for responses")
		}
		rawReq, err := os.ReadFile(*reqFile) // #nosec G304 -- operator-supplied path
		if err != nil {
			return false, err
		}
		req, err := inspect.ReadRequest(rawReq)
		if err != nil {
			return false, fmt.Errorf("parse request: %w", err)
		}
		resp, err := inspect.ReadResponse(raw, req)
		if err != nil {
			return false, fmt.Errorf("parse response: %w", err)
		}
		opts.Request = req
		report = inspect.InspectResponse(resp, opts)
	} else {
		req, err := inspect.ReadRequest(raw)
		if err != nil {
			return false, fmt.Errorf("parse request: %w", err)
		}
		report = inspect.InspectRequest(req, opts)
	}
	if *asJSON {
		return okChecks(report.Checks), printJSON(report)
	}
	fmt.Printf("%s  label=%s keyid=%s alg=%s\n", report.Kind, report.Label, report.KeyID, report.Algorithm)
	if len(report.Components) > 0 {
		fmt.Printf("covered: %s\n", strings.Join(report.Components, " "))
	}
	for _, c := range report.Checks {
		fmt.Printf("  %-5s %-18s %s\n", c.Status, c.Name, c.Detail)
	}
	if report.SignatureBase != "" {
		fmt.Println("signature base:")
		for _, l := range strings.Split(report.SignatureBase, "\n") {
			fmt.Println("  | " + l)
		}
	}
	return okChecks(report.Checks), nil
}

func runCard(args []string) (bool, error) {
	fs := flag.NewFlagSet("card", flag.ExitOnError)
	file := fs.String("f", "", "agent card JSON file")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	_ = fs.Parse(args)
	if *file == "" {
		return false, fmt.Errorf("-f is required")
	}
	raw, err := os.ReadFile(*file) // #nosec G304 -- operator-supplied path
	if err != nil {
		return false, err
	}
	report := inspect.InspectCard(raw)
	if *asJSON {
		return okChecks(report.Checks), printJSON(report)
	}
	fmt.Printf("card %s\n", report.DID)
	for _, k := range report.Keys {
		fmt.Println("  key", k)
	}
	for _, c := range report.Checks {
		fmt.Printf("  %-5s %-10s %s\n", c.Status, c.Name, c.Detail)
	}
	return okChecks(report.Checks), nil
}

func okChecks(checks []inspect.Check) bool {
	for _, c := range checks {
		if c.Status == "fail" {
			return false
		}
	}
	return true
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
