package conformance

import (
	"context"
	"os"
	"testing"
	"time"
)

// The reference must never appear to certify operations it does not implement.
func TestCryptographicSuiteRequiresSubject(t *testing.T) {
	f, err := os.Open("../../vectors/0.10.0/jcs-signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	suite, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), suite, Reference{}, Options{Timeout: time.Second, Subject: Subject{Name: "reference", Revision: "test", Kind: "reference"}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "INCOMPLETE" || report.Counts["UNSUPPORTED"] != len(suite.Cases) || report.Counts["PASS"] != 0 {
		t.Fatalf("unsupported operations certified: %+v", report.Counts)
	}
}
