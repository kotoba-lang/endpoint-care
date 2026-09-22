package clean

import (
	"path/filepath"
	"testing"
)

func TestKeepUnderHomeGuard(t *testing.T) {
	h := home()
	if h == "" {
		t.Fatal("no home dir")
	}
	in := []string{
		filepath.Join(h, ".cache", "go-build"), // kept: under home
		"/var/tmp/anything",                    // dropped: system path
		filepath.Join(h, "..", "elsewhere"),    // dropped: traversal via clean
		h,                                      // dropped: home itself is never a root
		"/",                                    // dropped: filesystem root
	}
	got := keepUnderHome(in)
	want := 1
	if len(got) != want {
		t.Fatalf("keepUnderHome kept %d roots %v, want %d", len(got), got, want)
	}
	if got[0] != filepath.Clean(filepath.Join(h, ".cache", "go-build")) {
		t.Errorf("kept %q", got[0])
	}
}

func TestWhitelistIsPlatformScoped(t *testing.T) {
	wl := whitelist()
	if len(wl) == 0 {
		t.Skip("platform not verified — empty whitelist is the safe default")
	}
	for _, w := range wl {
		if _, bad := isProtected(w); bad {
			t.Errorf("whitelist root %s is also protected", w)
		}
		if w == filepath.Clean(home()) {
			t.Errorf("home itself must never be a root")
		}
	}
}

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
