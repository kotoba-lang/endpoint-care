// Package disk reports filesystem capacity and largest-directory data.
package disk

import "math"

// Volume describes capacity for the filesystem containing a path.
type Volume struct {
	Path       string  `json:"path"`
	TotalBytes uint64  `json:"total_bytes"`
	FreeBytes  uint64  `json:"free_bytes"`
	UsedBytes  uint64  `json:"used_bytes"`
	UsedPct    float64 `json:"used_pct"`
}

// VolumeUsage measures the filesystem that contains path. The platform
// implementation lives in statfs_unix.go / statfs_windows.go.
func VolumeUsage(path string) (Volume, error) {
	return volumeUsage(path)
}

// Pct returns used capacity as a percentage of total, rounded to one decimal.
// total == 0 is treated as unmeasurable and returns 0 (callers must read the
// accompanying raw byte fields, not the percentage alone).
func Pct(total, free uint64) float64 {
	if total == 0 {
		return 0
	}
	if free > total {
		free = total
	}
	used := total - free
	return math.Round(float64(used)*1000/float64(total)) / 10
}

// HumanBytes formats a byte count with binary units, for reports.
func HumanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return formatFloat(n) + " B"
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return trimFloat(float64(n)/float64(div)) + " " + []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}[exp]
}

func formatFloat(n uint64) string { return trimFloat(float64(n)) }

func trimFloat(v float64) string {
	// One decimal place, trailing ".0" dropped.
	s := trimRune(round1(v))
	return s
}
