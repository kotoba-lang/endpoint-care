package clean

import "testing"

func TestProtectedPathsRefused(t *testing.T) {
	// protectedPrefixes() is anchored at the real home dir — build fixtures
	// there so the test exercises the shipped logic, not a hardcoded path.
	h := home()
	if h == "" {
		t.Fatal("no home dir — cannot exercise protection")
	}
	for _, p := range []string{
		h + "/Documents/x",
		h + "/Downloads/y",
		h + "/Desktop/z",
		h + "/github/repo",
		h + "/.Trash/old",
		h + "/.ssh/id_rsa",
	} {
		if _, bad := isProtected(p); !bad {
			t.Errorf("%s must be protected", p)
		}
	}
	// whitelist roots are not protected
	for _, p := range []string{
		h + "/Library/Caches/go-build",
		h + "/Library/Logs",
	} {
		if _, bad := isProtected(p); bad {
			t.Errorf("%s must NOT be protected", p)
		}
	}
}

func TestBuildDryRunTouchesNothing(t *testing.T) {
	plan := Build(false)
	if plan.Mode != "dry-run" {
		t.Errorf("mode: %q", plan.Mode)
	}
	if plan.DeletedCount != 0 || plan.FreedBytes != 0 {
		t.Errorf("dry-run deleted something: %+v", plan)
	}
	for _, c := range plan.Candidates {
		if c.Deleted {
			t.Errorf("candidate marked deleted in dry-run: %+v", c)
		}
	}
	if plan.Note == "" {
		t.Error("plan must explain itself")
	}
}
