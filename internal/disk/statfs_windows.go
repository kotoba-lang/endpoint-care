//go:build windows

package disk

import (
	"path/filepath"
	"syscall"
	"unsafe"
)

// volumeUsage uses GetDiskFreeSpaceExW from kernel32.dll on windows.
func volumeUsage(path string) (Volume, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Volume{}, err
	}
	dll := syscall.NewLazyDLL("kernel32.dll")
	proc := dll.NewProc("GetDiskFreeSpaceExW")
	dirp, err := syscall.UTF16PtrFromString(abs)
	if err != nil {
		return Volume{}, err
	}
	var freeToCaller, total, free uint64
	r1, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(dirp)),
		uintptr(unsafe.Pointer(&freeToCaller)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&free)),
	)
	if r1 == 0 {
		return Volume{}, callErr
	}
	freeBytes := freeToCaller
	if freeBytes > total {
		freeBytes = total
	}
	return Volume{
		Path:       abs,
		TotalBytes: total,
		FreeBytes:  freeBytes,
		UsedBytes:  total - freeBytes,
		UsedPct:    Pct(total, freeBytes),
	}, nil
}
