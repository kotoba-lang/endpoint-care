# Linux install surface (ADR-2609221849, install plane)

Status: **build + systemd install are real; signed release distribution is
not.** No certificate is provisioned yet, so per the fail-closed rule in the
ADR no distribution claim is made — these artifacts are for direct-from-source
installation on machines you control.

## 1. Static binary

External dependencies are zero (`go.mod` requires nothing), so a fully static
ELF64 needs only the standard library and `CGO_ENABLED=0`:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags='-s -w -buildmode=exe' -o endpoint-care-linux-amd64 ./cmd/endpoint-care
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -ldflags='-s -w -buildmode=exe' -o endpoint-care-linux-arm64 ./cmd/endpoint-care
```

Verify the result is actually static before shipping it anywhere (a dynamically
linked binary is a different install surface than the one documented here):

```sh
file endpoint-care-linux-amd64        # expect: ELF 64-bit ... statically linked
```

## 2. Install (direct, no package yet)

deb/rpm packaging is a later lever; until it exists the artifact installs by
copy. Place the binary, the unit, and the timer:

```sh
install -m 0755 endpoint-care-linux-amd64 /usr/local/bin/endpoint-care
install -m 0644 packaging/linux/endpoint-care.service \
  /etc/systemd/system/endpoint-care.service
install -m 0644 packaging/linux/endpoint-care.timer \
  /etc/systemd/system/endpoint-care.timer
systemctl daemon-reload
systemctl enable --now endpoint-care.timer
```

## 3. What the service does and does not do

- `endpoint-care audit` is read-only evidence collection (disk usage,
  listening sockets, process inventory, denylist hash check). It deletes
  nothing; cleanup stays an explicit, human-invoked `clean` decision.
- The unit runs as a `DynamicUser`, with `ProtectSystem=strict` and
  `ProtectHome=read-only`.
- **Outbound only.** `IPAddressDeny=any` is set because today's audit path
  performs no network egress. When a verdict feed (aratame) is wired in, that
  line must be replaced with an explicit outbound allowlist — it must never
  simply be removed, and no inbound port is ever opened.
- A oneshot unit whose `ExecStart` exits non-zero is marked failed by systemd
  (there is no `FailureExitCode=` directive to set): an unrunnable scan is
  never recorded as a clean one.

## 4. Server (headless) profile

The same static binary and the same unit serve the headless-server profile;
there is no separate server build. Long-running watch modes, if added later,
get their own unit — this timer unit is scan-only by design.
