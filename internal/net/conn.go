// Package ecnet (imported as ecnet from the main package to avoid colliding
// with stdlib net) lists network connections with per-entry v0 heuristics.
//
// Method order per platform is documented in Result.Source; a platform where
// no method tool exists reports ErrUnsupported rather than an empty list.
package ecnet

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// ErrUnsupported means no known method exists on this platform.
var ErrUnsupported = errors.New("network connection listing unsupported on this platform")

// Conn is one socket row.
type Conn struct {
	Proto   string   `json:"proto"`
	Local   string   `json:"local"`
	Remote  string   `json:"remote,omitempty"`
	State   string   `json:"state,omitempty"`
	PID     int      `json:"pid,omitempty"`
	Process string   `json:"process,omitempty"`
	Source  string   `json:"source"`
	Flags   []string `json:"flags,omitempty"`
}

// Result is the connection inventory for one run.
type Result struct {
	Source    string `json:"source"`
	Listeners int    `json:"listeners"`
	Conns     []Conn `json:"connections"`
}

// suspiciousProcessTokens mirrors the procs heuristics (v0, not a signature
// engine): a socket owned by one of these names is flagged.
var suspiciousProcessTokens = []string{
	"xmrig", "minerd", "cpuminer", "cryptonight", "nicehash", "kdevtmpfs",
}

func flagConn(proc string) []string {
	lower := strings.ToLower(proc)
	for _, t := range suspiciousProcessTokens {
		if strings.Contains(lower, t) {
			return []string{"owner-token:" + t}
		}
	}
	return nil
}

// Connections collects sockets with the platform's best available method.
func Connections() (Result, error) {
	switch runtime.GOOS {
	case "linux":
		if r, err := ss(); err == nil {
			return r, nil
		}
		return procNet()
	case "darwin":
		if r, err := lsof(); err == nil {
			return r, nil
		}
		return netstatAn()
	case "windows":
		return netstatAno()
	default:
		return Result{}, ErrUnsupported
	}
}

func finish(res Result) Result {
	sortConns(res.Conns)
	for _, c := range res.Conns {
		if c.State == "LISTEN" || c.State == "LISTENING" {
			res.Listeners++
		}
	}
	return res
}

func sortConns(cs []Conn) {
	// stable, cheap ordering: listeners first, then by local address
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0; j-- {
			a, b := cs[j-1], cs[j]
			aL := a.State == "LISTEN" || a.State == "LISTENING"
			bL := b.State == "LISTEN" || b.State == "LISTENING"
			if aL == bL && a.Local <= b.Local {
				break
			}
			if aL || (!bL && a.Local > b.Local) {
				break
			}
			cs[j-1], cs[j] = b, a
		}
	}
}

// ---- linux: ss, fallback /proc/net ----

// parseSs parses `ss -tunap` output. Header lines are skipped; the users:(...)
// clause yields pid+process when present.
// ssNetids are the tokens `ss` prints in the Netid column.
var ssNetids = map[string]bool{
	"tcp": true, "tcp4": true, "tcp6": true,
	"udp": true, "udp4": true, "udp6": true,
	"udplite": true, "unix": true, "vsock": true,
}

func parseSs(out string) []Conn {
	var cs []Conn
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "State") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		// The local address is the first field containing ':' (or '*:') —
		// column positions differ between ss versions, content does not.
		idx := -1
		for i, tok := range f {
			if strings.Contains(tok, ":") {
				idx = i
				break
			}
		}
		if idx < 0 || idx+1 >= len(f) {
			continue
		}
		prefix := f[:idx]
		// trailing numerics in the prefix are Recv-Q / Send-Q
		for len(prefix) > 0 {
			if _, err := strconv.Atoi(prefix[len(prefix)-1]); err == nil {
				prefix = prefix[:len(prefix)-1]
			} else {
				break
			}
		}
		proto, state := "", ""
		if len(prefix) > 0 && ssNetids[prefix[0]] {
			proto = prefix[0]
			if len(prefix) > 1 {
				state = prefix[1]
			}
		} else if len(prefix) > 0 {
			state = prefix[0]
			proto = "tcp" // ss -t without a Netid column: TCP-family only
		}
		local, peer := f[idx], f[idx+1]
		c := Conn{Proto: proto, Local: local, Remote: peer, State: normState(state), Source: "ss"}
		if idx := strings.Index(line, `users:(("`); idx >= 0 {
			rest := line[idx+len(`users:(("`):]
			if q := strings.IndexByte(rest, '"'); q > 0 {
				c.Process = rest[:q]
			}
			if p := strings.Index(rest, "pid="); p >= 0 {
				rest2 := rest[p+4:]
				end := strings.IndexAny(rest2, ",)")
				if end < 0 {
					end = len(rest2)
				}
				if v, err := strconv.Atoi(rest2[:end]); err == nil {
					c.PID = v
				}
			}
		}
		c.Flags = flagConn(c.Process)
		cs = append(cs, c)
	}
	return cs
}

func guessProto(f []string) string {
	switch f[0] {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "unix":
		return f[0]
	}
	return "tcp"
}

func isAddrToken(s string) bool {
	return strings.ContainsAny(s, ":[]") || s == "*"
}

func normState(s string) string {
	switch strings.ToUpper(s) {
	case "LISTEN", "LISTENING":
		return "LISTEN"
	case "ESTAB":
		return "ESTABLISHED"
	default:
		return strings.ToUpper(s)
	}
}

func ss() (Result, error) {
	out, err := exec.Command("ss", "-tunap").Output()
	if err != nil {
		return Result{}, fmt.Errorf("ss: %w", err)
	}
	return finish(Result{Source: "ss", Conns: parseSs(string(out))}), nil
}

// parseProcNet parses /proc/net/{tcp,tcp6,udp,udp6}. Addresses are hex;
// only local/remote/state are decoded (owner resolution needs root and is
// left empty rather than guessed).
func parseProcNet(out string) []Conn {
	var cs []Conn
	sc := bufio.NewScanner(strings.NewReader(out))
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			if strings.HasPrefix(line, "sl") {
				continue
			}
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		cs = append(cs, Conn{
			Proto:  "tcp",
			Local:  decodeHexAddr(f[1]),
			Remote: decodeHexAddr(f[2]),
			State:  tcpState(f[3]),
			Source: "/proc/net",
		})
	}
	return cs
}

// decodeHexAddr turns "0100007F:0050" into "127.0.0.1:80" (IPv4 only;
// IPv6 rows are passed through as the raw hex so nothing is invented).
func decodeHexAddr(s string) string {
	host, port, ok := strings.Cut(s, ":")
	if !ok || len(host) != 8 {
		return s
	}
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(host[i*2:i*2+2], 16, 8)
		if err != nil {
			return s
		}
		b[3-i] = byte(v)
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return s
	}
	return fmt.Sprintf("%d.%d.%d.%d:%d", b[0], b[1], b[2], b[3], p)
}

func tcpState(code string) string {
	switch strings.ToUpper(code) {
	case "01":
		return "ESTABLISHED"
	case "0A":
		return "LISTEN"
	case "06":
		return "TIME_WAIT"
	case "08":
		return "CLOSE_WAIT"
	default:
		return "STATE_" + code
	}
}

func procNet() (Result, error) {
	var all []Conn
	found := false
	for _, name := range []string{"tcp", "tcp6"} {
		out, err := exec.Command("cat", "/proc/net/"+name).Output()
		if err != nil {
			continue
		}
		found = true
		all = append(all, parseProcNet(string(out))...)
	}
	if !found {
		return Result{}, ErrUnsupported
	}
	return finish(Result{Source: "/proc/net", Conns: all}), nil
}

// ---- darwin: lsof, fallback netstat -an ----

// parseLsof parses `lsof -nP -iTCP -sTCP:LISTEN`-style output. The header
// ("COMMAND PID USER ...") is skipped by requiring a numeric PID column.
func parseLsof(out string) []Conn {
	var cs []Conn
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 8 {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		// For IP sockets NODE is empty, so the NAME column starts at its
		// TCP/UDP prefix token. Find that token from column 6 onward.
		start := -1
		for i := 6; i < len(f); i++ {
			u := strings.ToUpper(f[i])
			if u == "TCP" || u == "UDP" {
				start = i
				break
			}
		}
		if start < 0 {
			continue // not an -i style row
		}
		proto := strings.ToLower(f[start])
		// NAME may contain spaces (address + state): rejoin the remainder.
		name := strings.Join(f[start+1:], " ")
		local, remote, state := splitLsofName(name)
		cs = append(cs, Conn{
			Proto: proto, Local: local, Remote: remote,
			State: state, PID: pid, Process: f[0], Source: "lsof",
			Flags: flagConn(f[0]),
		})
	}
	return cs
}

func splitLsofName(name string) (local, remote, state string) {
	state = ""
	if i := strings.LastIndex(name, "("); i >= 0 && strings.HasSuffix(name, ")") {
		state = strings.TrimSpace(name[i+1 : len(name)-1])
		name = strings.TrimSpace(name[:i])
	}
	if i := strings.Index(name, "->"); i >= 0 {
		return name[:i], name[i+2:], normState(state)
	}
	return name, "", normState(state)
}

func lsof() (Result, error) {
	out, err := exec.Command("lsof", "-nP", "-iTCP").Output()
	if err != nil {
		return Result{}, fmt.Errorf("lsof: %w", err)
	}
	return finish(Result{Source: "lsof", Conns: parseLsof(string(out))}), nil
}

// parseNetstatAn parses BSD `netstat -an` (no pids available → owner left
// empty rather than guessed).
func parseNetstatAn(out string) []Conn {
	var cs []Conn
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		proto := f[0]
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}
		c := Conn{Proto: proto, Local: f[1], Source: "netstat"}
		if strings.HasPrefix(proto, "tcp") {
			if len(f) >= 4 {
				c.Remote = f[2]
				c.State = normState(f[3])
			}
		} else if len(f) >= 3 {
			c.Remote = f[2]
		}
		cs = append(cs, c)
	}
	return cs
}

func netstatAn() (Result, error) {
	out, err := exec.Command("netstat", "-an").Output()
	if err != nil {
		return Result{}, fmt.Errorf("netstat: %w", err)
	}
	return finish(Result{Source: "netstat", Conns: parseNetstatAn(string(out))}), nil
}

// ---- windows: netstat -ano ----

// parseNetstatAno parses `netstat -ano` rows:
//
//	TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    1234
func parseNetstatAno(out string) []Conn {
	var cs []Conn
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		proto := strings.ToUpper(f[0])
		if proto != "TCP" && proto != "UDP" {
			continue
		}
		c := Conn{Proto: strings.ToLower(proto), Local: f[1], Source: "netstat"}
		if proto == "TCP" && len(f) >= 5 {
			c.Remote = f[2]
			c.State = normState(f[3])
			if v, err := strconv.Atoi(f[4]); err == nil {
				c.PID = v
			}
		} else if len(f) >= 3 {
			c.Remote = f[1+1]
			if v, err := strconv.Atoi(f[len(f)-1]); err == nil {
				c.PID = v
			}
		}
		cs = append(cs, c)
	}
	return cs
}

func netstatAno() (Result, error) {
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return Result{}, fmt.Errorf("netstat: %w", err)
	}
	return finish(Result{Source: "netstat", Conns: parseNetstatAno(string(out))}), nil
}
