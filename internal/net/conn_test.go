package ecnet

import "testing"

func TestParseSs(t *testing.T) {
	out := `Netid  State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port
LISTEN 0       128      0.0.0.0:22            0.0.0.0:*    users:(("sshd",pid=712,fd=3))
ESTAB  0       0       10.0.0.5:22            10.0.0.9:51234  users:(("sshd",pid=714,fd=3))
udp    UNCONN  0       0            0.0.0.0:68      0.0.0.0:*
`
	cs := parseSs(out)
	if len(cs) != 3 {
		t.Fatalf("parsed %d, want 3", len(cs))
	}
	if cs[0].State != "LISTEN" || cs[0].Local != "0.0.0.0:22" {
		t.Errorf("listener row: %+v", cs[0])
	}
	if cs[0].Process != "sshd" || cs[0].PID != 712 {
		t.Errorf("owner clause: %+v", cs[0])
	}
	if cs[1].State != "ESTABLISHED" && cs[1].State != "ESTAB" {
		// normState maps ESTAB -> ESTABLISHED
		t.Errorf("state norm: %q", cs[1].State)
	}
}

func TestParseProcNet(t *testing.T) {
	out := `  sl  local_address rem_address   st
   0: 0100007F:0016 00000000:0000 0A
   1: 00000000:0035 00000000:0000 0A
`
	cs := parseProcNet(out)
	if len(cs) != 2 {
		t.Fatalf("parsed %d, want 2 (header skipped)", len(cs))
	}
	if cs[0].Local != "127.0.0.1:22" {
		t.Errorf("hex decode: %q", cs[0].Local)
	}
	if cs[0].State != "LISTEN" {
		t.Errorf("state: %q", cs[0].State)
	}
}

func TestParseLsof(t *testing.T) {
	out := `COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
ssh       712 root    3u  IPv4 0xdeadbeef      0t0  TCP 0.0.0.0:22 (LISTEN)
curl      800 me      4u  IPv4 0xcafe         0t0  TCP 10.0.0.5:51234->93.184.216.34:443 (ESTABLISHED)
`
	cs := parseLsof(out)
	if len(cs) != 2 {
		t.Fatalf("parsed %d, want 2", len(cs))
	}
	if cs[0].PID != 712 || cs[0].Process != "ssh" || cs[0].State != "LISTEN" {
		t.Errorf("listen row: %+v", cs[0])
	}
	if cs[1].Local != "10.0.0.5:51234" || cs[1].Remote != "93.184.216.34:443" {
		t.Errorf("split ->: %+v", cs[1])
	}
}

func TestParseNetstatAno(t *testing.T) {
	out := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1148
  TCP    [::]:445               [::]:0                 LISTENING       4
  UDP    0.0.0.0:5353           *:*                                    2212
`
	cs := parseNetstatAno(out)
	if len(cs) != 3 {
		t.Fatalf("parsed %d, want 3", len(cs))
	}
	if cs[0].State != "LISTENING" && cs[0].State != "LISTEN" {
		t.Errorf("state norm: %q", cs[0].State)
	}
	if cs[0].PID != 1148 {
		t.Errorf("pid: %d", cs[0].PID)
	}
	if cs[2].Proto != "udp" {
		t.Errorf("udp proto: %q", cs[2].Proto)
	}
}

func TestFlagConn(t *testing.T) {
	if f := flagConn("xmrig"); len(f) == 0 {
		t.Error("suspicious owner not flagged")
	}
	if f := flagConn("nginx"); len(f) != 0 {
		t.Errorf("clean owner flagged: %v", f)
	}
}
