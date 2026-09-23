// Package report defines the endpoint-care report schema: every section
// carries an explicit measured/status pair so a reader can never mistake
// "not measured" for "clean".
package report

import (
	"encoding/json"
	"os"
	"runtime"
	"time"
)

// Schema is the report schema identifier.
const Schema = "kotoba.endpoint-care.report.v1"

// Finding is one flagged item inside a section.
type Finding struct {
	Kind    string   `json:"kind"`
	Subject string   `json:"subject"`
	Flags   []string `json:"flags"`
	CSF     []string `json:"csf,omitempty"`
}

// Section is one measured area of the host.
//
//	Status:   ok | error | unsupported | unavailable | refused
//	  refused = the check itself declined to grade the input (e.g. a denylist
//	  that could not be trusted); it is neither ok nor unavailable.
//	Measured: true only when data was actually collected this run.
type Section struct {
	CSF      []string  `json:"csf"`
	Status   string    `json:"status"`
	Measured bool      `json:"measured"`
	Note     string    `json:"note,omitempty"`
	Data     any       `json:"data,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

// Tool names the producing binary.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Report is the top-level artifact written by scan/audit.
type Report struct {
	SchemaVersion string             `json:"schema_version"`
	GeneratedAt   string             `json:"generated_at"`
	OS            string             `json:"os"`
	Arch          string             `json:"arch"`
	Hostname      string             `json:"hostname"`
	Tool          Tool               `json:"tool"`
	Sections      map[string]Section `json:"sections"`
}

// New returns an empty report for the named tool version.
func New(name, version string) *Report {
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	return &Report{
		SchemaVersion: Schema,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Hostname:      host,
		Tool:          Tool{Name: name, Version: version},
		Sections:      map[string]Section{},
	}
}

// SetSection stores a section under name.
func (r *Report) SetSection(name string, s Section) {
	if r.Sections == nil {
		r.Sections = map[string]Section{}
	}
	r.Sections[name] = s
}

// Finalize stamps anything a caller may have left unset. Idempotent.
func (r *Report) Finalize() {
	if r.GeneratedAt == "" {
		r.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if r.SchemaVersion == "" {
		r.SchemaVersion = Schema
	}
	if r.Hostname == "" {
		if host, err := os.Hostname(); err == nil {
			r.Hostname = host
		}
	}
}

// JSON encodes the report.
func (r *Report) JSON() ([]byte, error) {
	return json.Marshal(r)
}

// ExitCode follows the documented contract:
//
//	0  report produced (section-level problems are visible in JSON status)
//	2  at least one sub-feature is unsupported on this platform
//
// Usage errors (1) are decided by the command layer before a report exists.
func (r *Report) ExitCode() int {
	for _, s := range r.Sections {
		if s.Status == "unsupported" {
			return 2
		}
	}
	return 0
}

// ErrData renders an error as report payload instead of hiding it.
func ErrData(err error) map[string]string {
	if err == nil {
		return map[string]string{}
	}
	return map[string]string{"error": err.Error()}
}
