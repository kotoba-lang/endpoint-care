//go:build !darwin && !linux && !windows

package disk

import "fmt"

// volumeUsage is unsupported on platforms without a known implementation.
// It reports an error instead of fabricating numbers.
func volumeUsage(path string) (Volume, error) {
	return Volume{}, fmt.Errorf("volume usage unsupported on this platform (path %q)", path)
}
