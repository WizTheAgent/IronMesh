# What's New in IronMesh

A one-page narrative of where IronMesh is and how it got here. For the
per-release detail, see [`CHANGELOG.md`](CHANGELOG.md) and the
`docs/RELEASE_NOTES_v0.*.md` files.

## Six-month trajectory

IronMesh started Q1 2026 as a working three-stage cryptographic
handshake (passphrase HMAC → signed ephemeral X25519 ECDH →
XSalsa20-Poly1305 session) with mDNS discovery and a single binary
WebSocket transport. Six months later it is a maturing local-first
agent-to-agent mesh protocol with multi-hop routing, capability
discovery, framework adapters, an operator dashboard, an MCP server,
two reference clients (Go and TypeScript), audited cryptography, and
a trust-fabric foundation that defaults to deny.

The arc, version by version:

| Version | Date | Theme |
|---|---|---|
| **v0.7.2-beta** | 2026-04-14 | Backpressure, throttling, per-peer Prometheus observability. The first release that could survive a misbehaving peer. |
| **v0.8.0** | 2026-04-16 | Public 1.0-track launch. Agent SDK, framework adapters (LangChain, CrewAI, AutoGen), multi-mesh federation, Go reference client, MCP server. The "you can integrate IronMesh with your agent stack today" release. |
| **v0.8.1** | 2026-04-16 | Bug-fix release: simultaneous-dial race, Windows proactor shutdown, `ironmesh demo` smoke test. |
| **v0.8.2** | 2026-04-16 | Structured multi-turn AI-to-AI dialogue (`ConvEnvelope`), seven persona presets, byte + time budgets, `[DONE]` smart termination, opt-in tool-use registry. |
| **v0.8.3** | 2026-04-16 | Operator dashboard rebuilt from scratch with TOFU trust tri-state, concurrent transport view, regex-capable message feed. Plus a full E2E audit: Hypothesis fuzzing, concurrency test suite, fixed TOCTOU race in `DedupCache`, macOS added to CI. |
| **v0.8.4** | 2026-04-18 | OpenClaw channel plugin lands at `0.1.0` with `configSchema`. TypeScript reference client published as `@wiztheagent/ironmesh-client` (alpha). Dashboard polish. |
| **v0.8.5** | 2026-04-19 | Pending-trust message gate — opt-in default-deny mode for new TOFU peers, with operator promote/block via dashboard, MCP, or `/ws`. Three new MCP tools (18 → 21). |
| **v0.8.5.2** | 2026-04-19 | Operator polish on top of the trust gate: HMAC-chained audit events for every gate decision, offline `ironmesh trust set-state` CLI, `ironmesh doctor` self-diagnostic, ten security hardening fixes from a deep audit. |
| **v0.8.5.3** | 2026-04-19 | Quickstart hardening: explicit `INSECURE` startup warnings on the two opt-in shortcut flags, dated deprecation notice for the pending-trust gate (default-on in v0.9), two new examples (`conv_multiturn.py`, `persona_debate.py`), `.github/RELEASE_CHECKLIST.md`. |
| **v0.8.5.4** | 2026-04-20 | Repo-hygiene release. Three-layer leak-scan defense (pre-commit hook, pre-push hook, CI workflow). Personal identifiers in shipped CLI examples and docs replaced with generic `alice`/`bob`/TEST-NET-1 placeholders. Coverage badge wired (Codecov). New `WHATS_NEW.md`, `BENCHMARKS.md`, `TESTING.md`. |

## Where IronMesh is today

- **686 tests** passing on Ubuntu + Windows + macOS across Python 3.10–3.13, plus a 3-node live-mesh validation pass on every release.
- **17 core modules**, ~11,300 lines of Python, audit-graded crypto stack (Ed25519 + X25519 + XSalsa20-Poly1305 via PyNaCl).
- **21 MCP tools** exposed via stdio JSON-RPC, usable from Claude Desktop and any MCP-capable agent.
- **Three transports:** WebSocket (default), Reticulum/LoRa (opt-in via `ironmesh[rns]`), federation between meshes via `FederationGateway`.
- **Two reference clients** beyond Python: Go (full wire protocol, crypto verified against Python) and TypeScript (alpha, published to npm).
- **Distribution:** PyPI, Docker Hub, GitHub Releases. Each release follows `.github/RELEASE_CHECKLIST.md` end-to-end with a wheel-packaging smoke gate (`scripts/release-smoke.sh`) before any `twine upload`.

## What's coming

Roughly in priority order. See the master plan for the full sequence.

### Before v1.0

- **External cryptographic audit** — single highest-leverage action on the path to v1.0. Targeting Radically Open Security, Cure53, or Trail of Bits.
- **`PROTOCOL_SPEC.md` v1.0** — RFC 2119 spec covering wire format, handshake state machine, trust model, message types, routing, error codes, failure semantics. Plus a conformance test suite as a standalone repo.
- **Capability Routing v2** — weighted scoring engine: each candidate node receives a composite score from measured latency, trust level, load, and capability match quality. Decision-trace metadata for every routing decision.
- **Pending-trust default-on** in v0.9. Migration guide + `--no-message-promotion` escape hatch for legacy behavior.
- **10-minute quickstart** + Docker compose preset + first-run wizard. Removes the single biggest onboarding drop-off.
- **OpenTelemetry tracing + Prometheus metrics endpoint + reference Grafana dashboard** — observability stack for serious adopters.

### v1.0 hard gates

- External audit report published and linked from README
- 10–20 real deployments confirmed
- One upstream framework integration merged (CrewAI is the warmest candidate)
- Windows / Linux / macOS first-class with documented install paths
- TypeScript client out of alpha
- Benchmarks published and reproducible
- `PROTOCOL_SPEC.md` v1.0 published with conformance test suite

### Post-v1.0 (Q4 2026+)

- **Signed IOUs** — mesh-native value exchange, offline-capable, no blockchain. The wedge nothing else has.
- **Reputation system** — decentralized trust scoring, gossip-propagated, feeds back into routing.
- **Agent migration** — move a running agent from one node to another with full state, cryptographic integrity verification, rollback on failure.
- **CRDT encrypted shared state**, **steganographic transport**, **lightweight BFT consensus**, **dead drops**, **distributed inference**, **XMR payment tiers**.

### Sovereignty layer (Q1 2027+)

The features that turn IronMesh from "good infrastructure" into "the protocol you reach for when your freedom actually depends on it":

- **Onion routing / mixnet layer** — metadata resistance, not just content encryption.
- **Native mobile clients** (Android first, iOS second).
- **Anti-coercion suite** — duress passphrases (already MVP'd in v0.8.5.3), hidden vaults, deniable encryption.
- **Federation bridges** to Briar, SimpleX, Session, Matrix.
- **Pre-flashed IronMesh hardware** — productized devices with reproducible firmware.
- **Traffic shaping + cover traffic** — flatten the activity signal so even encrypted-traffic timing leaks nothing.

## How to follow along

- **GitHub releases:** https://github.com/WizTheAgent/IronMesh/releases
- **CHANGELOG:** [`CHANGELOG.md`](CHANGELOG.md) for every change since v0.5
- **Per-release notes:** `docs/RELEASE_NOTES_v0.*.md`
- **Site:** https://ironmesh.org
- **Issues + Discussions:** https://github.com/WizTheAgent/IronMesh/issues
