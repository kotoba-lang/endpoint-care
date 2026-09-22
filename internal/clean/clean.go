// Package clean builds the whitelist-only cleanup plan.
//
// Deletion is dry-run unless apply is true, and only the explicit whitelist
// below is ever considered. Protected prefixes (Documents, Downloads,
// Desktop, ~/github, .Trash, credentials) are refused even if they somehow
// appear as candidates. No globs, no variable-expanded rm: every removal is
// one explicit path per operation.
package clean

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Entry is one candidate path in the plan.
type Entry struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"` // dir | file
	SizeBytes uint64 `json:"size_bytes"`
	Eligible  bool   `json:"eligible"`
	Refused   string `json:"refused,omitempty"`
	Deleted   bool   `json:"deleted,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Plan is the JSON document `clean` prints.
type Plan struct {
	Mode          string  `json:"mode"` // dry-run | apply
	WhitelistRoot []string `json:"whitelist_roots"`
	Candidates    []Entry `json:"candidates"`
	EligibleBytes uint64  `json:"eligible_bytes"`
	FreedBytes    uint64  `json:"freed_bytes"`
	DeletedCount  int     `json:"deleted_count"`
	RefusedCount  int     `json:"refused_count"`
	Note          string  `json:"note"`
}

// protectedPrefixes are never deleted regardless of whitelist membership.
func protectedPrefixes() []string {
	home := home()
	return []string{
		filepath.Join(home, "Documents"),
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "github"),
		filepath.Join(home, ".Trash"),
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".gnupg"),
	}
}

func home() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// whitelist returns the fixed roots this version may clean. macOS-focused
// today; linux/windows roots are added per-platform as they are verified —
// never by widening a glob.
func whitelist() []string {
	home := home()
	if home == "" {
		return nil
	}
	caches := filepath.Join(home, "Library", "Caches")
	return []string{
		filepath.Join(caches, "go-build"),
		filepath.Join(caches, "node-gyp"),
		filepath.Join(caches, "pnpm"),
		filepath.Join(caches, "electron"),
		filepath.Join(caches, "pip"),
		filepath.Join(caches, "deno"),
		filepath.Join(caches, "org.swift.swiftpm"),
		filepath.Join(home, "Library", "Logs"),
	}
}

// isProtected reports whether path sits under a protected prefix.
func isProtected(path string) (string, bool) {
	clean := filepath.Clean(path)
	for _, p := range protectedPrefixes() {
		if p == "" {
			continue
		}
		if clean == p || strings.HasPrefix(clean, p+string(filepath.Separator)) {
			return p, true
		}
	}
	return "", false
}

// sizeOf sums a tree (entry-capped so a runaway dir cannot stall the plan).
func sizeOf(path string, limit int) uint64 {
	var total uint64
	count := 0
	filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || count >= limit {
			return nil
		}
		if d.Type().IsRegular() {
			if info, ierr := d.Info(); ierr == nil {
				total += uint64(info.Size())
				count++
			}
		}
		return nil
	})
	return total
}

// Build returns the plan for this host. When apply is true, eligible
// whitelist entries are removed and marked; when false nothing is touched.
func Build(apply bool) Plan {
	mode := "dry-run"
	if apply {
		mode = "apply"
	}
	plan := Plan{
		Mode:          mode,
		WhitelistRoot: whitelist(),
		Candidates:    []Entry{},
		Note: "whitelist-only cleanup; protected paths (Documents/Downloads/Desktop/" +
			"github/.Trash/.ssh/.aws/.gnupg) are refused by construction",
	}
	roots := map[string]bool{}
	for _, w := range plan.WhitelistRoot {
		roots[filepath.Clean(w)] = true
	}
	for _, root := range plan.WhitelistRoot {
		info, err := os.Lstat(root)
		if err != nil {
			continue // absent roots are not candidates
		}
		e := Entry{Path: root}
		if info.IsDir() {
			e.Kind = "dir"
			e.SizeBytes = sizeOf(root, 200000)
		} else {
			e.Kind = "file"
			e.SizeBytes = uint64(info.Size())
		}
		if p, bad := isProtected(root); bad {
			e.Refused = "protected prefix: " + p
			plan.RefusedCount++
		} else if !roots[filepath.Clean(root)] {
			e.Refused = "not in whitelist"
			plan.RefusedCount++
		} else {
			e.Eligible = true
			plan.EligibleBytes += e.SizeBytes
			if apply {
				// one explicit path per operation; no globs, no shell.
				before := e.SizeBytes
				if err := os.RemoveAll(root); err != nil {
					e.Error = err.Error()
				} else {
					e.Deleted = true
					plan.DeletedCount++
					plan.FreedBytes += before
				}
			}
		}
		plan.Candidates = append(plan.Candidates, e)
	}
	if !apply && plan.DeletedCount == 0 {
		plan.Note += "; dry-run: nothing was removed"
	}
	_ = time.Now // keep time imported for future age-based eligibility
	return plan
}
