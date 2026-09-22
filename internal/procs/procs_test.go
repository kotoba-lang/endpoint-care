package procs

import "testing"

func TestParsePs(t *testing.T) {
	out := `  1     1   0.0   0.1 /sbin/launchd
  101    1   0.3   1.2 /usr/sbin/cfprefsd
  202    1   99.9  0.4 /tmp/xmrig --donate
  303    1   0.1   0.2 /Applications/Weird App.app/Contents/MacOS/Weird App
`
	list := parsePs(out)
	if len(list) != 4 {
		t.Fatalf("parsed %d rows, want 4", len(list))
	}
	if list[0].ID != 1 || list[0].Name != "launchd" || list[0].PPID != 1 {
		t.Errorf("row 0: %+v", list[0])
	}
	// name with spaces survives because comm is the line remainder
	if list[3].Name != "Weird App" {
		t.Errorf("space-containing comm: %q", list[3].Name)
	}
	// miner token in a temp path is flagged
	if len(list[2].Flags) == 0 {
		t.Errorf("xmrig in /tmp not flagged: %+v", list[2])
	}
	if list[0].Source != "ps" {
		t.Errorf("source: %q", list[0].Source)
	}
}

func TestParseProcStat(t *testing.T) {
	p := &Proc{ID: 42}
	parseProcStat("42 (my proc name) S 1 42 42 0 -1", p)
	if p.Name != "my proc name" {
		t.Errorf("name: %q", p.Name)
	}
	if p.PPID != 1 {
		t.Errorf("ppid: %d", p.PPID)
	}
}

func TestParseTasklist(t *testing.T) {
	out := `"System Idle Process","0","Services","0","8 K"
"explorer.exe","1234","Console","1","50,000 K"

"badline"
`
	list := parseTasklist(out)
	if len(list) != 2 {
		t.Fatalf("parsed %d rows, want 2 (bad line skipped)", len(list))
	}
	if list[1].ID != 1234 || list[1].Name != "explorer.exe" {
		t.Errorf("row 1: %+v", list[1])
	}
	// quoted CSV with embedded comma in memory column
	if list[1].Source != "tasklist" {
		t.Errorf("source: %q", list[1].Source)
	}
}

func TestFlagHeuristics(t *testing.T) {
	if f := flag("xmrig", ""); len(f) == 0 {
		t.Error("token in name not flagged")
	}
	if f := flag("bash", "/tmp/evil"); len(f) == 0 {
		t.Error("temp path not flagged")
	}
	if f := flag("bash", "/bin/bash"); len(f) != 0 {
		t.Errorf("clean process flagged: %v", f)
	}
}
