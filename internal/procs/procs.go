// Package procs lists processes with per-entry v0 heuristics.
//
// Every platform names its source method in Proc.Source so a report reader
// knows where the numbers came from. A missing tool is an error or
// ErrUnsupported — never an empty list presented as "no processes".
package procs

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// ErrUnsupported means no known method exists on this platform.
var ErrUnsupported = errors.New("process listing unsupported on this platform")

// Proc is one process row.
type Proc struct {
	ID     int      `json:"id"`
	PPID   int      `json:"ppid,omitempty"`
	Name   string   `json:"name"`
	CPU    float64  `json:"cpu_pct,omitempty"`
	Mem    float64  `json:"mem_pct,omitempty"`
	Path   string   `json:"path,omitempty"`
	Source string   `json:"source"`
	Flags  []string `json:"flags,omitempty"`
}

// suspiciousTokens is the v0 heuristic token list. It is deliberately tiny
// and clearly a heuristic, not a signature engine: see docs/csf2-mapping.md.
var suspiciousTokens = []string{
	"xmrig", "minerd", "cpuminer", "cryptonight", "nicehash",
	"kdevtmpfs", "kthreaddi",
}

// suspiciousPathPrefixes are directories nothing normal should run from.
var suspiciousPathPrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// flag evaluates the v0 heuristics for one process.
func flag(name, path string) []string {
	lower := strings.ToLower(name)
	for _, t := range suspiciousTokens {
		if strings.Contains(lower, t) {
			return []string{"name-token:" + t}
		}
	}
	pl := filepath.ToSlash(path)
	for _, p := range suspiciousPathPrefixes {
		if strings.HasPrefix(pl, p) {
			return []string{"path:" + p}
		}
	}
	return nil
}

// List returns every process visible with a platform-appropriate method.
func List() ([]Proc, error) {
	switch runtime.GOOS {
	case "linux":
		return listProc()
	case "darwin":
		return listPs()
	case "windows":
		return listTasklist()
	default:
		return nil, ErrUnsupported
	}
}

// ---- linux: /proc ----

func listProc() ([]Proc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}
	var out []Proc
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p := Proc{ID: pid, Source: "proc"}
		if raw, err := os.ReadFile("/proc/" + e.Name() + "/stat"); err == nil {
			parseProcStat(string(raw), &p)
		}
		if raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline"); err == nil && len(raw) > 0 {
			cmd := strings.Split(string(raw), "\x00")[0]
			if p.Name == "" {
				p.Name = filepath.Base(cmd)
			}
			p.Path = cmd
		}
		if p.Name == "" {
			p.Name = "?"
		}
		p.Flags = flag(p.Name, p.Path)
		out = append(out, p)
	}
	return out, nil
}

// parseProcStat fills name/ppid from a /proc/<pid>/stat line. comm may
// contain spaces and parentheses, so it is sliced between the first '(' and
// the last ')'.
func parseProcStat(line string, p *Proc) {
	open := strings.IndexByte(line, '(')
	close := strings.LastIndexByte(line, ')')
	if open < 0 || close < open {
		return
	}
	if p.Name == "" {
		p.Name = line[open+1 : close]
	}
	fields := strings.Fields(line[close+2:])
	// after comm: state ppid ...
	if len(fields) >= 2 {
		if v, err := strconv.Atoi(fields[1]); err == nil {
			p.PPID = v
		}
	}
}

// ---- darwin: ps ----

// parsePs parses `ps -axo pid=,ppid=,pcpu=,pmem=,comm=` output.
func parsePs(out string) []Proc {
	var list []Proc
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// pid ppid pcpu mem comm — comm is the remainder (may contain spaces)
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		id, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		cpu, _ := strconv.ParseFloat(fields[2], 64)
		mem, _ := strconv.ParseFloat(fields[3], 64)
		// comm begins after the 4th whitespace-delimited token's start;
		// recover it by walking the original line.
		rest := line
		for i := 0; i < 4; i++ {
			rest = strings.TrimLeft(rest, " \t")
			if idx := strings.IndexAny(rest, " \t"); idx >= 0 {
				rest = rest[idx:]
			} else {
				rest = ""
			}
		}
		path := strings.TrimSpace(rest)
		name := filepath.Base(path)
		list = append(list, Proc{
			ID: id, PPID: ppid, CPU: cpu, Mem: mem,
			Name: name, Path: path, Source: "ps",
			Flags: flag(name, path),
		})
	}
	return list
}

func listPs() ([]Proc, error) {
	cmd := exec.Command("ps", "-axo", "pid=,ppid=,pcpu=,pmem=,comm=")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	return parsePs(string(out)), nil
}

// ---- windows: tasklist ----

// parseTasklist parses `tasklist /fo csv /nh` output:
//
//	"name.exe","1234","Console","1","12,345 K"
func parseTasklist(out string) []Proc {
	var list []Proc
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		cols := splitCSV(line)
		if len(cols) < 2 {
			continue
		}
		id, err := strconv.Atoi(cols[1])
		if err != nil {
			continue
		}
		list = append(list, Proc{
			ID: id, Name: cols[0], Source: "tasklist",
			Flags: flag(cols[0], ""),
		})
	}
	return list
}

// splitCSV handles the two-column-enough quoted CSV tasklist emits.
func splitCSV(line string) []string {
	var cols []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQ = !inQ
		case c == ',' && !inQ:
			cols = append(cols, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	cols = append(cols, cur.String())
	return cols
}

func listTasklist() ([]Proc, error) {
	cmd := exec.Command("tasklist", "/fo", "csv", "/nh")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tasklist: %w", err)
	}
	return parseTasklist(string(out)), nil
}
