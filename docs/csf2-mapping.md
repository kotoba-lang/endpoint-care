# NIST CSF 2.0 mapping — Endpoint Care

Every subcategory code below is validated against the live kotoba.cloud
NIST CSF 2.0 catalog (`https://kotoba.cloud/security-data/csf2/index.json`,
106 subcategories, NIST CSWP 29). The same codes are tagged in the JSON
report per section (`sections.<name>.csf`) and listed per finding.

**Primary CSF function: DETECT (DE).**
Supporting: PROTECT (PR) and IDENTIFY (ID).

| Capability | Subcategory | Category | How it contributes | Coverage |
|---|---|---|---|---|
| Disk / volume monitoring | DE.CM-01 | Continuous Monitoring | Free/used capacity sampled from the OS (Statfs / GetDiskFreeSpaceEx) so storage-state drift is found | full |
| Process monitoring | DE.CM-09 | Continuous Monitoring | Full process inventory from `/proc`, `ps`, or `tasklist`; runtime state observed each run | full |
| Network connection audit | DE.CM-01 | Continuous Monitoring | Listening + established sockets from `ss`, `lsof`, `netstat`, `/proc/net` | full |
| Suspicious-process heuristics | DE.CM-09 | Continuous Monitoring | v0 token/path heuristics flag runtime anomalies for review | partial (heuristic, not a detection engine) |
| Report correlation | DE.AE-02 | Adverse Event Analysis | Sections, findings and per-finding CSF tags are joined into one JSON/HTML artifact per run | partial (single-host, no timeline correlation in v0) |
| Operator-facing report | DE.AE-06 | Adverse Event Analysis | Single-file HTML + JSON handed to whoever runs the tool (the authorized staff/tools role) | partial (local only; no fleet forwarding yet) |
| Hardware/volume inventory | ID.AM-01 | Asset Management | Volumes with capacity, measured | full |
| Network flow inventory | ID.AM-03 | Asset Management | Local/remote address pairs + owning process where the OS exposes it | partial (authorized-flow modeling is manual) |
| Threat/flag recording | ID.RA-03 | Risk Assessment | Every heuristic hit and denylist match is recorded as a finding, not dropped | partial (v0 heuristics, empty denylist) |
| Maintenance (software/disk) | PR.PS-02 | Platform Security | Whitelist-only cleanup removes stale caches/build artifacts | full (macOS roots today; linux/windows roots follow) |
| Maintenance (hardware lifecycle) | PR.PS-03 | Platform Security | Capacity report informs replacement/retirement decisions | partial (advisory only) |
| Log records for monitoring | PR.PS-04 | Platform Security | Each run emits a versioned JSON report (schema `kotoba.endpoint-care.report.v1`) suitable for continuous monitoring pipelines | full |
| Resource capacity | PR.IR-04 | Technology Infrastructure Resilience | `used_pct` against volume capacity, with thresholds visible in the report | full |
| Malware hash check | ID.RA-03 + DE.AE-02 | Risk Assessment / Adverse Event Analysis | SHA-256 of candidate files vs bundled denylist; empty denylist reports `unavailable`, never "clean" | **partial / roadmap** — engine (ClamAV/YARA) not integrated in v0 |

## Explicitly out of scope (no claims made)

- **PR.PS-05** (preventing installation/execution of unauthorized software) —
  Endpoint Care does not block or prevent anything in v0; it reports.
- **RS.\*** (Respond) — no containment, eradication, or incident workflow.
- **RC.\*** (Recover) — no backup or recovery automation.
- **GV.\*** — governance/policy surfaces belong to the organization, not to
  this agent.

## Honest coverage rule

A section that could not be measured reports `status: unsupported|error` with
`measured: false`. An empty denylist reports `status: unavailable` with
`compared: N`. **Unmeasured is never rendered as clean** — this is enforced
in `internal/report` (status/measured fields are separate) and tested in
`internal/report/report_test.go`.
