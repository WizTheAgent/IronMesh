# IronMesh v0.8.5.5 — Release Notes

## Headline

Big-batch quality-of-life patch on top of v0.8.5.4. Fifteen new
items: OS keychain backend, CLI named profiles, `ironmesh upgrade`
self-check, Windows service installer, reverse-proxy-friendly
dashboard mode, OpenTelemetry tracing, TS client out of alpha
(0.2.0 with TOFU pin enforcement), full configuration reference,
two new reference deployments (off-grid + multi-tenant), CodeQL
scanning, citation metadata, leak-scan glob exclusions, ruff in
the release checklist.

No protocol or schema changes. Every v0.8.x peer stays
interoperable. Default behavior is unchanged unless you explicitly
opt into the new optional features.

## Highlights

### OS keychain backend

The mesh passphrase can now live in the OS-native keychain (macOS
Keychain, Windows Credential Manager, Linux Secret Service) instead
of a passphrase file. New CLI:

```bash
pip install ironmesh[keychain]
ironmesh keys keychain-store --name alice
# (enter passphrase twice at the prompt)

# Use it on startup:
export IRONMESH_PASSPHRASE_KEYCHAIN=true
ironmesh run --name alice --port 8765
```

Other subcommands: `ironmesh keys keychain-clear --name <node>`,
`ironmesh keys keychain-check`. Service identifier is
`ironmesh:<node-name>`, so multiple node configs on the same
machine coexist without collision.

### CLI named profiles — `--profile=secure|dev|offline`

```bash
# Production hardening — pending-trust gate ON, warns about insecure flags
ironmesh run --name alice --port 8765 --profile=secure

# Localhost testing — open-discovery + plaintext-ws shortcuts
ironmesh run --name alice --port 8765 --profile=dev

# Off-grid — Reticulum / LoRa transport on
ironmesh run --name alice --port 8765 --profile=offline
```

Explicit flags always win over the profile but emit a warning if they
contradict the profile's intent (e.g., `--profile=secure
--allow-plaintext-ws` warns and respects the user's flag).

### `ironmesh upgrade`

```bash
$ ironmesh upgrade
Installed: ironmesh==0.8.5.4
Latest:    ironmesh==0.8.5.5

A newer release is available: v0.8.5.5

Upgrade with one of:
  pip install -U ironmesh==0.8.5.5
  docker pull wiztheagent/ironmesh:0.8.5.5

Release notes:
  https://github.com/WizTheAgent/IronMesh/releases/tag/v0.8.5.5
```

`--json` mode for automation. Exits 0 if up-to-date, 0 if running a
newer-than-PyPI version (e.g. local dev checkout), 1 only on
network failure.

### Windows service wrapper

`scripts/install-windows-service.ps1` + `docs/WINDOWS_SERVICE.md`.
NSSM-based PowerShell installer with stdout/stderr redirection,
automatic restart on failure with backoff, graceful 30-second
shutdown, automatic boot start. Removes "no Windows daemon docs"
from the adopter-objection list.

```powershell
# Elevated PowerShell:
choco install nssm
.\scripts\install-windows-service.ps1 install -Name alice `
    -PassphraseFile $env:USERPROFILE\.ironmesh\passphrase
Start-Service IronMesh
```

### Reverse-proxy-friendly dashboard mode

Two changes in v0.8.5.5:

- New `--gui-bind <addr>` flag (default `127.0.0.1`). Set to
  `0.0.0.0` or a specific interface to expose the dashboard for a
  reverse proxy on a different host.
- The startup banner emits an `INSECURE BIND` warning whenever
  `--gui-bind` is non-loopback, so a misconfiguration cannot
  quietly make it into a production config.

Plus a complete `docs/REVERSE_PROXY.md` with nginx, Caddy, and
Traefik recipes. CSRF + Origin-allowlist enhancements are queued
for the next minor release.

### OpenTelemetry tracing

```bash
pip install ironmesh[otel]
export OTEL_SERVICE_NAME=ironmesh-alice
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
ironmesh run --name alice --port 8765 ...
```

Spans emit on `ironmesh.send_message` with attributes for peer
node id, message type, priority, and payload size. Per-stage
handshake / routing / MCP spans are queued for subsequent releases
— this release lands the wrapper, the optional dep, the doc, and
the reference Grafana dashboard JSON.

The wrapper module (`ironmesh/telemetry.py`) is a no-op shim by
default: importing it on a vanilla install is safe and free.
Telemetry only activates when both the extra is installed AND
`OTEL_EXPORTER_OTLP_ENDPOINT` is set.

### TS client out of alpha — 0.2.0 with TOFU pin enforcement

`@wiztheagent/ironmesh-client@0.2.0` adds the previously
"recognized but not enforced" `pinFile` option as actual
enforcement:

```typescript
import { IronMeshClient } from "@wiztheagent/ironmesh-client";

const c = new IronMeshClient({
  url: "wss://daemon.example.com:8765/ws",
  passphrase: process.env.IRONMESH_PASSPHRASE!,
  pinFile: "/home/me/.ironmesh/ts-pins.json",
  tofu: "trust-on-first-use",  // or "strict"
});
await c.connect();
```

On first contact, the daemon's Ed25519 fingerprint is written to
the pin file. On subsequent connects, mismatch throws
`PinMismatchError` and refuses the connection. Atomic-write
persistence (write-to-tmp + fsync + rename) — same pattern as the
Python TrustStore in v0.8.5.2. 10 new tests in
`clients/ts/tests/pinstore.test.ts`.

### `docs/CONFIGURATION.md`

The single page that answers "what can I configure?" Indexes every
CLI flag, env var, file path, and profile preset. Replaces "read
five different docs to find the right knob" with "Ctrl-F here."

### Two new reference deployments

- **Off-grid** (`docs/deployments/off-grid.md`) — Heltec V3 + Pi
  Zero 2 W + LoRa, end-to-end recipe. ~$60/node, days of runtime
  per power bank, RF-only operation.
- **Multi-tenant** (`docs/deployments/multi-tenant.md`) — multiple
  isolated tenant daemons on shared hardware. Cryptographic +
  OS-account isolation. Optional federation gateway for controlled
  cross-tenant talk.

Both complement the existing `docs/deployments/homelab.md` (Ollama
+ CrewAI, shipped in v0.8.5.4).

### `docs/OBSERVABILITY.md` + Grafana dashboard

End-to-end observability guide covering Prometheus metrics,
structured JSON logs, OpenTelemetry traces, and audit-log
inspection. Reference Grafana dashboard JSON at
`docs/grafana/ironmesh-dashboard.json` — five panels covering peer
health, RTT, lifetime quantiles, backpressure events, and
pending-trust gate activity.

### CodeQL scanning + CITATION.cff

- `.github/workflows/codeql.yml` — GitHub's free security linter.
  Runs on push, PR, and weekly. Catches a class of bugs that ruff
  and bandit don't (taint tracking, unsafe deserialization, etc.).
- `CITATION.cff` — academic-citation metadata at the repo root.
  Small but real signal of project maturity for anyone evaluating
  IronMesh for a publication or thesis.

### leak-scan + RELEASE_CHECKLIST polish

- `scripts/leak-scan.sh` exclusion list now supports glob patterns.
  `docs/RELEASE_NOTES_v*.md` and `docs/migration/*.md` are
  auto-excluded — no more per-release maintenance.
- `.github/RELEASE_CHECKLIST.md` Section 5 now explicitly requires
  `ruff check . --exclude tests --exclude examples` locally before
  tagging. Closes the gap that landed a red tag-CI on v0.8.5.4.

## Upgrade guidance

```bash
pip install --upgrade ironmesh
# or with new optional dep groups:
pip install --upgrade 'ironmesh[keychain,otel]'

# Docker
docker pull wiztheagent/ironmesh:0.8.5.5
```

No config changes required. No protocol changes. Existing peers
stay on the mesh. New flags / env vars / subcommands are all
additive — nothing previously working is removed or renamed.

## Action required (one-time, optional)

- **Codecov authorization** — to make the README's coverage badge
  show real numbers, sign in at codecov.io with GitHub, add
  IronMesh as a repo, copy the upload token to the GitHub repo's
  secrets as `CODECOV_TOKEN`. (Already wired in CI from v0.8.5.4.)
- **GitHub Sponsors profile** — to make the README's Sponsor link
  resolve, enable Sponsors in your GitHub account settings.
  (Already wired in `.github/FUNDING.yml` from v0.8.5.4.)

Neither blocks anything — both are signals that activate when the
backing service is configured.

## Verifying the release

| Check | Command |
|---|---|
| PyPI | `pip install ironmesh==0.8.5.5 && ironmesh --version` |
| Docker | `docker pull wiztheagent/ironmesh:0.8.5.5` |
| Smoke test | `ironmesh demo` |
| Upgrade check | `ironmesh upgrade` |
| Setup wizard | `ironmesh setup --name testnode --non-interactive --passphrase-from-env` (with `IRONMESH_SETUP_PASSPHRASE` set) |
| Keychain backend | `pip install ironmesh[keychain] && ironmesh keys keychain-check` |
| Leak-scan defense | `bash scripts/install-hooks.sh && bash scripts/leak-scan.sh --all` (expect: `clean`) |

## Diff stats

```
.github/workflows/codeql.yml                           NEW
.github/RELEASE_CHECKLIST.md                           +ruff line in §5
CHANGELOG.md                                           v0.8.5.5 entry
CITATION.cff                                           NEW
README.md                                              banner, docker pull, "Latest:",
                                                       new "(current)" para, install line
WHATS_NEW.md                                           — (will be updated next minor)
__init__.py                                            version bump
bridge.py                                              +span() on send_message,
                                                       +gui_bind, +loud bind warning
cli.py                                                 +cmd_setup wizard (v0.8.5.4),
                                                       +cmd_upgrade,
                                                       +keys keychain-store/clear/check,
                                                       +--profile preset,
                                                       +--gui-bind flag,
                                                       +keychain-backed get_passphrase
clients/ts/package.json                                version 0.1.0-alpha.2 → 0.2.0
clients/ts/src/client.ts                               TOFU pin enforcement post-handshake
clients/ts/src/index.ts                                exports pinstore symbols
clients/ts/src/pinstore.ts                             NEW
clients/ts/tests/pinstore.test.ts                      NEW (10 tests)
docker-compose.demo.yml                                — (shipped in v0.8.5.4)
docs/CONFIGURATION.md                                  NEW
docs/NAT_TRAVERSAL.md                                  — (shipped in v0.8.5.4)
docs/OBSERVABILITY.md                                  NEW
docs/RELEASE_NOTES_v0.8.5.5.md                         NEW (this file)
docs/REVERSE_PROXY.md                                  NEW
docs/WINDOWS_SERVICE.md                                NEW
docs/deployments/multi-tenant.md                       NEW
docs/deployments/off-grid.md                           NEW
docs/grafana/ironmesh-dashboard.json                   NEW
keychain.py                                            NEW
pyproject.toml                                         version bump + [keychain] + [otel] extras
scripts/install-windows-service.ps1                    NEW
scripts/leak-scan.sh                                   glob-pattern exclusions
telemetry.py                                           NEW
```
