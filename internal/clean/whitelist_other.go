//go:build !darwin && !linux && !windows

package clean

// Unverified platforms get no cleanup roots: the whitelist only grows per
// platform after that platform's cache layout is verified (ADR-2609221849).
// Nothing being a candidate is the safe reading of "not verified", not an
// error to report.
func osWhitelist() []string { return nil }
func osProtected() []string { return nil }
