//go:build darwin || linux

package disk

import (
	"path/filepath"
	"syscall"
)

// volumeUsage uses syscall.Statfs on darwin and linux.
func volumeUsage(path string) (Volume, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Volume{}, err
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(abs, &st); err != nil {
		return Volume{}, err
	}
	bs := uint64(st.Bsize)
	total := st.Blocks * bs
	free := st.Bavail * bs
	if free > total {
		free = total
	}
	return Volume{
		Path:       abs,
		TotalBytes: total,
		FreeBytes:  free,
		UsedBytes:  total - free,
		UsedPct:    Pct(total, free),
	}, nil
}
