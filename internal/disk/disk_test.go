package disk

import "testing"

func TestPct(t *testing.T) {
	cases := []struct {
		total, free uint64
		want        float64
	}{
		{100, 0, 100},
		{0, 0, 0}, // unmeasurable: callers must read raw bytes too
		{1000, 100, 90},
		{3, 1, 66.7},
		{100, 200, 0}, // free > total is clamped: used becomes 0, not negative
	}
	for _, c := range cases {
		if got := Pct(c.total, c.free); got != c.want {
			t.Errorf("Pct(%d, %d) = %v, want %v", c.total, c.free, got, c.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{
		0:       "0 B",
		512:     "512 B",
		1024:    "1 KiB",
		1536:    "1.5 KiB",
		1 << 20: "1 MiB",
		1 << 30: "1 GiB",
	}
	for in, want := range cases {
		if got := HumanBytes(in); got != want {
			t.Errorf("HumanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestVolumeUsageMeasured(t *testing.T) {
	v, err := VolumeUsage(".")
	if err != nil {
		t.Fatalf("VolumeUsage: %v", err)
	}
	if v.TotalBytes == 0 {
		t.Fatal("total bytes is zero — volume reported but not measured")
	}
	if v.UsedPct <= 0 || v.UsedPct > 100 {
		t.Errorf("used_pct out of range: %v", v.UsedPct)
	}
}

func TestLargestDirsTopNAndTruncationFlags(t *testing.T) {
	scan, err := LargestDirs(t.TempDir(), Limits{TopN: 3, MaxDepth: 2, MaxEntries: 50})
	if err != nil {
		t.Fatalf("LargestDirs: %v", err)
	}
	if len(scan.Dirs) > 3 {
		t.Errorf("top-N respected: got %d dirs", len(scan.Dirs))
	}
	if scan.Limits.TopN != 3 {
		t.Errorf("limits echoed back: %+v", scan.Limits)
	}
	// an empty temp dir is a measured zero, not an error
	if scan.SkippedErrors != 0 {
		t.Errorf("unexpected skipped errors on empty dir: %d", scan.SkippedErrors)
	}
}
