package conformancecli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReportsAndExitCodes(t *testing.T) {
	suite := "../../vectors/0.10.0/foundation.json"
	report := filepath.Join(t.TempDir(), "result.json")
	var out, err bytes.Buffer
	code := Run([]string{"-suite", suite, "-report", report}, &out, &err, "test")
	if code != 0 {
		t.Fatalf("%d %s", code, &err)
	}
	saved, e := os.ReadFile(report) // #nosec G304 -- Test-owned temporary report path.
	if e != nil || !bytes.Equal(saved, out.Bytes()) {
		t.Fatal("report differs from stdout")
	}
	var r map[string]any
	if json.Unmarshal(saved, &r) != nil || r["status"] != "PASS" {
		t.Fatal("bad report")
	}
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"-suite", suite, "-case", "hkdf-a1"}, 3},
		{[]string{"-suite", suite, "-case", "not-a-case"}, 2},
		{[]string{"-suite", suite, "-timeout", "0s"}, 2},
		{[]string{"-suite", suite, "-report", suite}, 2},
		{[]string{"-suite", suite, "-report", filepath.Join(t.TempDir(), "missing", "out.json")}, 2},
		{[]string{"-suite", suite, "-subject", "pretend-core"}, 2},
	} {
		out.Reset()
		err.Reset()
		if got := Run(tc.args, &out, &err, "test"); got != tc.code {
			t.Fatalf("%v: %d %s", tc.args, got, &err)
		}
	}
}
