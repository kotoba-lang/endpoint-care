package disk

import (
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// DirSize is the aggregate size of one directory tree.
type DirSize struct {
	Path      string `json:"path"`
	FileCount int    `json:"file_count"`
	SizeBytes uint64 `json:"size_bytes"`
}

// Limits bounds a directory scan so it stays predictable on large hosts.
type Limits struct {
	TopN       int `json:"top_n"`
	MaxDepth   int `json:"max_depth"`
	MaxEntries int `json:"max_entries"`
}

// DirScan is the result of a bounded largest-directory scan.
type DirScan struct {
	Dirs           []DirSize `json:"dirs"`
	Limits         Limits    `json:"limits"`
	EntriesVisited int       `json:"entries_visited"`
	SkippedErrors  int       `json:"skipped_errors"`
	Truncated      bool      `json:"truncated"`
}

// DefaultLimits returns conservative scan bounds (top 10, 4 levels, 50k entries).
func DefaultLimits() Limits {
	return Limits{TopN: 10, MaxDepth: 4, MaxEntries: 50000}
}

// LargestDirs walks root with depth and entry caps and returns the top-N
// directories by aggregated regular-file size. Unreadable entries are skipped
// and counted in SkippedErrors rather than failing the scan; hitting the entry
// cap sets Truncated so a partial scan is never presented as complete.
func LargestDirs(root string, lim Limits) (DirScan, error) {
	if lim.TopN <= 0 {
		lim.TopN = 10
	}
	if lim.MaxDepth <= 0 {
		lim.MaxDepth = 4
	}
	if lim.MaxEntries <= 0 {
		lim.MaxEntries = 50000
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return DirScan{}, err
	}

	res := DirScan{Limits: lim}
	sizes := map[string]*DirSize{}

	walkErr := filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			res.SkippedErrors++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if res.EntriesVisited >= lim.MaxEntries {
			res.Truncated = true
			return fs.SkipAll
		}
		rel, rerr := filepath.Rel(abs, path)
		if rerr != nil {
			return nil
		}
		depth := 0
		if rel != "." {
			depth = strings.Count(rel, string(filepath.Separator)) + 1
		}
		if d.IsDir() {
			if depth > lim.MaxDepth {
				return fs.SkipDir
			}
			res.EntriesVisited++
			if _, ok := sizes[path]; !ok {
				sizes[path] = &DirSize{Path: path}
			}
			return nil
		}
		if depth > lim.MaxDepth {
			return nil
		}
		res.EntriesVisited++
		if !d.Type().IsRegular() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			res.SkippedErrors++
			return nil
		}
		if info.Size() <= 0 {
			return nil
		}
		addSize(sizes, abs, path, uint64(info.Size()))
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return res, walkErr
	}

	list := make([]DirSize, 0, len(sizes))
	for _, ds := range sizes {
		if ds.SizeBytes == 0 && ds.FileCount == 0 {
			continue
		}
		list = append(list, *ds)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].SizeBytes != list[j].SizeBytes {
			return list[i].SizeBytes > list[j].SizeBytes
		}
		return list[i].Path < list[j].Path
	})
	if len(list) > lim.TopN {
		list = list[:lim.TopN]
	}
	res.Dirs = list
	return res, nil
}

// addSize credits a file's size to its own directory and every ancestor up to
// and including root.
func addSize(sizes map[string]*DirSize, root, file string, n uint64) {
	dir := filepath.Dir(file)
	for {
		if ds, ok := sizes[dir]; ok {
			ds.SizeBytes += n
			ds.FileCount++
		}
		if dir == root || dir == filepath.Dir(dir) {
			return
		}
		dir = filepath.Dir(dir)
	}
}

// trimFloat helpers live in fmt_util.go; strconv kept here for clarity of dir math.
var _ = strconv.Itoa
