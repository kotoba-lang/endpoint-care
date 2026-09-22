// Command endpoint-care is a local-first endpoint hygiene and monitoring agent.
//
// It offers read-only scanning and inventory (scan, audit) plus a whitelist-only,
// dry-run-by-default cleanup (clean). Deletion always requires --apply, and
// unmeasured sections are always reported as such: unmeasured must never be
// read as clean.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

// Version is the endpoint-care release version.
const Version = "0.1.0-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return 0
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "endpoint-care %s (%s %s/%s)\n",
			Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "audit":
		return cmdAudit(args[1:], stdout, stderr)
	case "clean":
		return cmdClean(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "endpoint-care: unknown subcommand %q\n\n", args[0])
		usage(stderr)
		return 1
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `endpoint-care - local-first endpoint hygiene and monitoring agent

Usage:
  endpoint-care <subcommand> [flags]

Subcommands:
  version    Print version and build information
  scan       One-shot JSON report: disk, processes, network, malware hash check
               --path <dir>    directory to scan (default ".")
               --html <file>   also write a single-file HTML report
  clean      Whitelist-only cache/log cleanup (DRY-RUN by default)
               --apply         actually delete (without it, nothing is removed)
  audit      JSON process list + network connections with v0 heuristics
  help       Show this help

Exit codes:
  0   success (report produced; section-level problems appear in JSON status)
  1   usage error
  2   a sub-feature is unsupported on this platform (status "unsupported")

Safety model: read-only by default, dry-run by default, whitelist-only
deletion, fail-closed reporting (unmeasured is never reported as clean).
See docs/csf2-mapping.md for the NIST CSF 2.0 mapping.
`)
}
