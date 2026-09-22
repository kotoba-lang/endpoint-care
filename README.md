# Endpoint Care

A CleanMyMac-style **local hygiene and monitoring agent** in one binary —
for consumer machines and enterprise fleets, on macOS, Linux, Windows and
servers.

```
endpoint-care scan              # one-shot JSON report (disk, procs, net, malware)
endpoint-care scan --html r.html # ...and a single-file HTML report
endpoint-care audit             # process list + network connections + v0 heuristics
endpoint-care clean             # whitelist-only cleanup, DRY-RUN by default
endpoint-care clean --apply     # actually delete (whitelist only)
endpoint-care version
```

## What it does

| Area | v0 |
|---|---|
| Disk cleanup | whitelist-only roots, dry-run default, `--apply` required; protected paths (Documents/Downloads/Desktop/github/.Trash/.ssh/.aws/.gnupg) refused by construction |
| Storage visualisation | top-N directory scan with depth/entry caps + bar chart in the HTML report |
| Maintenance | capacity report (`used_pct`) with CSF PR.IR-04/PR.PS-02 tags |
| Malware check | SHA-256 vs bundled denylist — **ships empty**, reports `unavailable`, never "clean" (ClamAV/YARA = roadmap) |
| Suspicious process monitoring | v0 heuristics (temp-path exec, miner tokens) over `ps` / `/proc` / `tasklist` |
| Network connection audit | listeners + established sockets via `ss` / `lsof` / `netstat` / `/proc/net` with owning process where available |

## Platform support

| Platform | Volume | Processes | Connections | Cleanup roots |
|---|---|---|---|---|
| macOS 13+ (arm64/x86_64) | Statfs | `ps` | `lsof` → `netstat` | `~/Library/Caches/*` subset + `~/Library/Logs` |
| Linux (amd64/arm64, incl. headless servers) | Statfs | `/proc` | `ss` → `/proc/net` | (per-platform roots land as they are verified) |
| Windows 10+/Server 2019+ (amd64) | GetDiskFreeSpaceEx | `tasklist` | `netstat -ano` | (per-platform roots land as they are verified) |
| anything else | *unsupported* — reported as such | unsupported | unsupported | none |

A sub-feature with no implementation reports
`status: "unsupported"` (JSON) and exit code `2` — it never fabricates data.
Same binary, same subcommands, on every OS (`GOOS` build tags only where the
OS API differs).

### Server / headless note

On a server, `scan --html` produces a self-contained artifact (no JS, no
server) you can attach to a ticket or cron mail. `clean` without `--apply`
prints the plan JSON — safe to schedule for review.

## Safety model

1. **Read-only by default.** Only `clean --apply` deletes.
2. **Whitelist-only deletion.** No globs, no variable-expanded `rm`; one
   explicit path per `RemoveAll`, and protected prefixes are refused even if
   a whitelist entry somehow overlaps them.
3. **Fail-closed reporting.** `measured: false` + `status` distinguishes
   "could not measure" from "measured and fine". An empty denylist is
   `unavailable`, not `ok`.
4. **Bounded scans.** Directory and hash walks carry depth/entry/file caps;
   hitting a cap sets `truncated` instead of pretending completeness.

## NIST CSF 2.0

Primary function **DETECT**, supporting **PROTECT** + **IDENTIFY**. Full
capability-by-capability table (validated against the live 106-subcategory
kotoba.cloud catalog): [docs/csf2-mapping.md](docs/csf2-mapping.md).

## Development

```sh
go build ./...
go vet ./...
go test ./...
GOOS=linux GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
```

Status: **in development (v0 scaffold)** — no distributed binaries yet.
Tracked on [apps.kotoba.cloud](https://apps.kotoba.cloud/) as *Endpoint Care*
(status: 開発中 / In development).

Apache-2.0 © Kotoba
