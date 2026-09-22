package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/kotoba-lang/endpoint-care/internal/clean"
)

// cmdClean prints the cleanup plan as JSON. It is a dry run unless --apply is
// passed; only whitelist roots are ever considered and protected prefixes
// (~/Documents, ~/Downloads, ~/Desktop, ~/github) are never touched.
func cmdClean(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clean", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apply := fs.Bool("apply", false, "actually delete eligible files (default is dry-run)")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	plan := clean.Build(*apply)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(plan); err != nil {
		fmt.Fprintf(stderr, "endpoint-care: encode clean plan: %v\n", err)
		return 1
	}
	return 0
}
