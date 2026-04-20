# IronMesh v0.8.5.4 — Release Notes

## Headline

Patch release on top of v0.8.5.3. Repo-hygiene + onboarding +
credibility-documentation drop.

Three new layers (pre-commit hook, pre-push hook, CI workflow) catch
internal-only content before it can enter the public repo. Personal
identifiers in shipped CLI examples and docs replaced with generic
`alice`/`bob`/TEST-NET-1 placeholders. New first-run wizard
(`ironmesh setup`) walks operators through node configuration end-to-
end. New instant-demo docker compose (`docker-compose.demo.yml`)
spawns two preconfigured nodes with one command. New `WHATS_NEW.md`,
`docs/BENCHMARKS.md`, `docs/TESTING.md`, `docs/NAT_TRAVERSAL.md`,
`docs/deployments/homelab.md`, `docs/migration/v0_9_default_deny.md`,
GitHub Sponsors configuration, and a Codecov coverage badge.

No protocol or schema changes. Every v0.8.x peer stays interoperable.
Default behavior is unchanged.

## Highlights

### Three-layer leak-scan defense

A single shared scanner (`scripts/leak-scan.sh`) is wired into three
checkpoints, each catching what the previous layer might miss:

1. **`.githooks/pre-commit`** — fires on every `git commit`. Blocks
   the commit if any staged file matches a reserved internal-only
   filename pattern (audit reports, plan docs, gap analyses,
   top-level roadmap files) or contains content markers that should
   never appear in shipped text (audit hardening codes, decision-tree
   shorthand like `RAZOR #N` or `Path A/B`, personal identifiers,
   personal absolute paths, mesh-fleet personal node names,
   mesh-wide passphrase substring).
2. **`.githooks/pre-push`** — fires on every `git push`. Same scan
   against the diff being pushed. Catches anything that bypassed the
   pre-commit hook (e.g. via `--no-verify`).
3. **`.github/workflows/leak-scan.yml`** — fires on every push and
   pull request. Same scan against the change range. Catches anything
   that bypassed both local hooks.

The scanner has separate pattern groups for code (where some markers
like `INTERNAL` as an enum value are legitimate) and doc files (where
they are not). Bypassing the local hooks requires explicit
`--no-verify`; the CI workflow has no bypass.

Run `bash scripts/install-hooks.sh` once after cloning to point your
local clone at the tracked `.githooks/` directory. Documented in
`CONTRIBUTING.md` under "First-time setup."

### Personal-identifier sanitization

The scanner found pre-existing matches in shipped baseline code and
docs from earlier sessions. Sanitized:

- **Personal node names** (the maintainer's actual mesh-fleet names)
  used as CLI examples in README, ARCHITECTURE.md, QUICKSTART.md,
  SECURITY.md, USE_CASES.md, DASHBOARD.md, OPENCLAW_MCP_SETUP.md,
  PROTOCOL_SPEC.md, examples/README.md,
  examples/ai_to_ai_dialogue.py, cli.py, protocol.py, the TS client
  README, the ironmesh-status skill, and tests/test_mcp.py. Replaced
  with the generic `alice` / `bob` convention used throughout
  cryptography literature.
- **Personal LAN IP examples** replaced with TEST-NET-1
  (`192.0.2.0/24`, RFC 5737, reserved for documentation) addresses
  across QUICKSTART.md, SECURITY.md, USE_CASES.md, and the
  mesh_bench harness docstring.
- **Test-name prefixes** that started with audit-class identifiers
  (`describe("H2: ...")`, `describe("C2: ...")`) in
  `clients/ts/tests/*.test.ts` renamed to plain descriptive labels.
- **Internal milestone reference** (`M0 spike`) in
  `clients/ts/README.md` reworded to plain language.

Historical files (CHANGELOG.md, every `docs/RELEASE_NOTES_v0.*.md`)
were not rewritten. They are immutable release history and are
explicitly excluded from the scanner. Rewriting release history is
more confusing than helpful.

### `WHATS_NEW.md`

A one-page narrative of where IronMesh has been and where it is
going. Per-version summary table from v0.7.2-beta through v0.8.5.4,
where the project stands today (test count, MCP tool count,
transports, distribution channels), and what's coming: the v1.0 hard
gates, the post-v1.0 expansion (CRDTs, Signed IOUs, agent migration),
and the sovereignty layer (mixnet, native mobile, anti-coercion,
federation bridges, productized hardware).

Replaces "read 9 release-notes files in chronological order" with
"read one page."

### `docs/BENCHMARKS.md`

Real published numbers, not marketing copy:

- **LAN (WebSocket, 1 hop, x86 ↔ Pi 5):** 100% delivery, p50
  12–13 ms, p95 72–78 ms across 64 B / 256 B / 1 KB payloads.
  Goodput from 6.2 KB/s at 64 B up to 76.9 KB/s at 1 KB.
- **LoRa (RNode, 915 MHz, SF8/BW125, 1 hop):** 100% delivery across
  9 probes, p50 ~1.2 s for 16–64 B, scaling cleanly to ~1.8 s at
  256 B. Each payload-size doubling adds roughly 200 ms.
- **Behavior under loss (`mesh_bench.py --chaos 0.25`):** delivery
  rate tracks injection rate within 2 percentage points; p50 RTT
  unchanged for delivered messages.
- **Resource footprint:** Pi 5 idle ~45 MB / <1% CPU; under 100
  msg/s ~55 MB / 8–12% CPU. Numbers for Pi Zero 2 W and commodity
  x86 also published.
- **Reproduction recipe** included; numbers refresh every minor
  version per the release checklist.

Honest gaps documented: multi-hop on the same LAN, WAN over
overlay, large-mesh stress test, LoRa multi-hop.

### `docs/TESTING.md`

Walkthrough of the four test layers:

- **~600 unit tests** — one file per code module, structured around
  the public API.
- **~30 Hypothesis property / fuzz tests** — frame decoder
  invariants, ConvEnvelope round-trip, adversarial inputs into the
  v0.8.5.2 hardened paths.
- **~20 concurrency tests** — simultaneous-dial collisions,
  concurrent trust-store writes (the v0.8.5.2 atomic-write fix is
  verified here), queue draining under load, audit-log rotation
  under concurrent writers.
- **~30 framework-adapter integration tests** — real LangChain,
  CrewAI, AutoGen against live in-process two-node IronMesh meshes.
  Run separately on Ubuntu only (`pytest tests/integration`).

Explains the deliberate `--cov-fail-under=60` floor (chasing 100%
rewards ceremony tests over correctness tests; Hypothesis +
concurrency catch a category line coverage cannot reach), what is
deliberately not in CI (live LoRa, multi-node hardware mesh,
24-hour soak), and how to add a test in the right layer.

### Coverage badge wired (Codecov)

The CI workflow now uploads `coverage.xml` to Codecov from every
matrix combo (Ubuntu / Windows / macOS × Python 3.10–3.13) using
`codecov/codecov-action@v4`, conditional on the file existing and
flagged best-effort so Codecov outages cannot fail CI. README gains
a live coverage-percentage badge next to the existing CI / PyPI /
Docker badges.

**Action required for badge to show real numbers:** the repo owner
must (a) sign in at codecov.io with GitHub, (b) add the IronMesh
repo, (c) copy the upload token into the GitHub repo's secrets as
`CODECOV_TOKEN`. One-time setup; takes about a minute.

### `ironmesh setup` — interactive first-run wizard

A new CLI subcommand walks an operator through a complete
end-to-end node configuration:

1. Pick a node name (defaults to hostname)
2. Pick a port (defaults to 8765)
3. Set or reuse the shared mesh passphrase (minimum 12 characters,
   confirmed twice, written to a `chmod 600` file)
4. Generate or reuse the encrypted identity keypair (Argon2id,
   matched to the passphrase)
5. Optionally configure a peer allowlist (`--allowed-peers`)
6. Optionally enable the pending-trust message gate (with a one-
   sentence explanation)

The wizard prints the exact `ironmesh run` command that uses the
files it just wrote, plus a shorter env-var-based form, plus next
steps (run on a second machine with the same passphrase, link them
via `--allowed-peers`, where to find the homelab recipe and NAT
traversal doc).

For automation / CI: `ironmesh setup --non-interactive
--passphrase-from-env` reads the passphrase from
`IRONMESH_SETUP_PASSPHRASE` and takes defaults for everything else.
Idempotent — re-running detects existing files and either reuses
them or honors `--force`. Four new tests in `tests/test_cli.py`
cover the non-interactive paths.

### `docker-compose.demo.yml` — two-peer instant demo

A purpose-built compose file for "I want to see two IronMesh nodes
talking right now." Spawns `alice` and `bob` on an isolated bridge
network with hardcoded demo passphrase. Both dashboards exposed
on localhost ports `8866` and `8868`. Run:

```bash
docker compose -f docker-compose.demo.yml up
```

The existing `docker-compose.yml` (production-style single-container
with `--profile pair` for testing) is unchanged in shape but bumped
to image `ironmesh:0.8.5.4` (it had been stale at `0.8.5` through
three patch releases).

### `docs/NAT_TRAVERSAL.md` — operator recipes

Three step-by-step recipes for running IronMesh across NATs by
layering on an overlay network that already solved the problem:

- **Tailscale** (easiest, managed WireGuard mesh)
- **Yggdrasil** (privacy-maximalist, fully decentralized)
- **Reticulum** (already a native IronMesh transport; bridges
  internet + LoRa into a single mesh)

Trade-offs explicit per option. Native hole-punching stays on the
v1.1+ roadmap (`docs/NAT_TRAVERSAL_DESIGN.md` is the design doc);
this is the recommended path until that ships.

### `docs/deployments/homelab.md` — first reference deployment

Working recipe for the most-asked-about IronMesh setup: two
IronMesh nodes + local Ollama + a CrewAI two-agent crew talking
across the encrypted mesh. End-to-end walkthrough from `pip install`
to running the crew, with hardware suggestions, troubleshooting,
and pointers to the dashboard / LoRa hop / production hardening.

### `docs/migration/v0_9_default_deny.md` — pending-trust migration

Walkthrough for the pending-trust gate becoming default-on in v0.9.
Two preparation paths (opt in early; pin legacy behavior with the
planned `--no-message-promotion` flag). Lists what does NOT change
(wire protocol, existing pinned peers, audit-log shape) and the
operator-visible failure modes to expect when the gate is enabled.
Closes the file pointer that the v0.8.5.3 deprecation warning
references.

### GitHub Sponsors configuration

`.github/FUNDING.yml` points at the maintainer's Sponsors profile
(must be enabled separately in account settings before the link
resolves). README gains a brief "Sponsor" section. No monthly
target, no perks tier, no public donor wall — just a funding path
for an external security audit, infrastructure budget, and time on
the v1.0 hard gates.

## Removed (from prior commit on main)

- Four internal-only documents (`docs/AUDIT_v0.8.3.md`,
  `docs/BUG-PY310-TIMEOUTERROR-CLASS-SPLIT.md`,
  `docs/BUG-RNS-HANDSHAKE-RACE.md`,
  `docs/OPENCLAW_WS_API_GAPS.md`) removed from the repo and from
  full git history via `git filter-repo`. They were committed in
  earlier sessions before the broader internal-docs ignore patterns
  existed and the leak-scan defense was built. The history rewrite
  was a one-time operation; the leak-scan layers prevent recurrence.

## Upgrade guidance

```bash
pip install --upgrade ironmesh
# or
docker pull wiztheagent/ironmesh:0.8.5.4
```

No config changes required. No protocol changes — your existing
peers stay on the mesh. No behavior changes that affect a running
deployment.

## Verifying the release

| Check | Command |
|---|---|
| PyPI | `pip install ironmesh==0.8.5.4 && ironmesh --version` |
| Docker | `docker pull wiztheagent/ironmesh:0.8.5.4` |
| Smoke test | `ironmesh demo` |
| Leak-scan defense (after clone) | `bash scripts/install-hooks.sh && bash scripts/leak-scan.sh --all` (expect: `clean`) |

## Diff stats

```
.github/FUNDING.yml                          | NEW
.github/workflows/ci.yml                     | +13 lines (Codecov upload step)
CHANGELOG.md                                 | v0.8.5.4 entry
README.md                                    | banner, docker pull, "Latest:",
                                             |   new "(current)" para, badge,
                                             |   test count 686→688, Sponsor section
WHATS_NEW.md                                 | NEW (~150 lines)
cli.py                                       | +cmd_setup wizard (~250 lines),
                                             |   subparser, dispatch, help banner
docker-compose.demo.yml                      | NEW (two-peer instant demo)
docker-compose.yml                           | image tag 0.8.5 → 0.8.5.4
docs/BENCHMARKS.md                           | NEW (~140 lines)
docs/NAT_TRAVERSAL.md                        | NEW (~190 lines)
docs/RELEASE_NOTES_v0.8.5.4.md               | NEW (this file)
docs/TESTING.md                              | NEW (~165 lines)
docs/deployments/homelab.md                  | NEW (~230 lines)
docs/migration/v0_9_default_deny.md          | NEW (~100 lines)
tests/test_cli.py                            | wiz→alice fixture rename
                                             |   + 4 new TestSetupWizard tests
__init__.py                                  | version bump
pyproject.toml                               | version bump
```
