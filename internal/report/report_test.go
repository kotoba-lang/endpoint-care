package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONRoundTrip(t *testing.T) {
	r := New("endpoint-care", "0.0.1")
	r.SetSection("disk", Section{
		CSF: []string{"ID.AM-01"}, Status: "ok", Measured: true,
		Data: map[string]any{"used_pct": 42.5},
		Findings: []Finding{{Kind: "x", Subject: "y", Flags: []string{"z"}}},
	})
	r.Finalize()
	raw, err := r.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.SchemaVersion != Schema {
		t.Errorf("schema: %q", back.SchemaVersion)
	}
	if !back.Sections["disk"].Measured {
		t.Error("measured flag lost in round trip")
	}
	if back.Hostname == "" {
		t.Error("hostname must be stamped")
	}
}

func TestExitCodeContract(t *testing.T) {
	r := New("t", "1")
	r.SetSection("a", Section{Status: "ok", Measured: true})
	if r.ExitCode() != 0 {
		t.Errorf("all-ok must be 0, got %d", r.ExitCode())
	}
	// an error section stays 0: problems are visible in JSON status
	r.SetSection("b", Section{Status: "error"})
	if r.ExitCode() != 0 {
		t.Errorf("error section must keep exit 0, got %d", r.ExitCode())
	}
	// unsupported sub-feature → 2
	r.SetSection("c", Section{Status: "unsupported"})
	if r.ExitCode() != 2 {
		t.Errorf("unsupported must be 2, got %d", r.ExitCode())
	}
}

func TestErrData(t *testing.T) {
	d := ErrData(nil)
	if len(d) != 0 {
		t.Errorf("nil error should be empty map: %v", d)
	}
}

func TestHTMLReport(t *testing.T) {
	r := New("endpoint-care", "0.0.1")
	r.SetSection("disk", Section{
		CSF: []string{"PR.IR-04"}, Status: "ok", Measured: true,
		Data: map[string]any{
			"dir_scan": map[string]any{
				"dirs": []map[string]any{
					{"path": "/tmp/big", "size_bytes": 1048576},
					{"path": "/tmp/small", "size_bytes": 1024},
				},
			},
		},
	})
	r.SetSection("malware", Section{
		CSF: []string{"ID.RA-03"}, Status: "unavailable", Measured: false,
		Note: "engine none",
	})
	r.Finalize()

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTMLFile(path, r); err != nil {
		t.Fatalf("write html: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, needle := range []string{"endpoint-care", "disk", "malware", "unavailable", "/tmp/big", "not measured", "PR.IR-04"} {
		if !strings.Contains(html, needle) {
			t.Errorf("html missing %q", needle)
		}
	}
	// the template must not have leaked raw Go actions
	if strings.Contains(html, "{{") {
		t.Error("unrendered template action in output")
	}
}

func TestWriteHTMLNoPanicOnOddData(t *testing.T) {
	r := New("t", "1")
	r.SetSection("disk", Section{Status: "ok", Measured: true, Data: "not-a-struct"})
	var buf bytes.Buffer
	_ = buf
	if err := WriteHTMLFile(filepath.Join(t.TempDir(), "r.html"), r); err != nil {
		t.Fatalf("unexpected error on reshaped data: %v", err)
	}
}
