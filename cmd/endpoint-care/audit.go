package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/kotoba-lang/endpoint-care/internal/report"
)

// cmdAudit emits the enterprise audit view: the process list and the network
// connection list, each carrying per-entry v0 heuristics and CSF 2.0 tags.
func cmdAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	rep := report.New("endpoint-care", Version)
	addProcsSection(rep)
	addNetSection(rep)
	rep.Finalize()

	data, err := rep.JSON()
	if err != nil {
		fmt.Fprintf(stderr, "endpoint-care: encode audit: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n", data)
	return rep.ExitCode()
}
