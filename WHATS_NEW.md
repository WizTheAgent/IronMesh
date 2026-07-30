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
two reference clients (Go and TypeScript), cryptography built on
audited libsodium primitives, and a trust-fabric foundation that
defaults to deny. It is still alpha — the external protocol audit
below is a v1.0 hard gate, not a done deal.

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

## Where IronMesh is today (v0.9.5)

- **1357 tests** collected, 1347 passing on Ubuntu + Windows + macOS across Python 3.10–3.13, plus live cross-host validation on every wire-surface change. The 14-phase E2E driver (`scripts/stress_e2e_round4.py`) runs 37 checks across multi-hop routing, burst load, dedup/replay defense, audit-tamper detection, connect storm, shutdown-under-load, and a 5-probe attack-surface battery — last run green during the v0.9.5 hardening cycle. A five-area adversarial harness (`tests/test_stress_security.py`) additionally drives the invite, source-signature, profile, and doctor controls with the malicious inputs they exist to reject.
- **27 core modules** in the wheel, a crypto stack built on audited libsodium primitives (Ed25519 + X25519 + XSalsa20-Poly1305 via PyNaCl — the IronMesh protocol layer itself has not yet been externally audited), formal threat model in `docs/THREAT_MODEL.md`, v1.0 surface contract in `docs/STABILITY_PROMISE.md`.
- **25 MCP tools** exposed via stdio JSON-RPC, usable from Claude Desktop and any MCP-capable agent.
- **Three transports:** WebSocket (default), Reticulum/LoRa (opt-in via `ironmesh[rns]`), and LXMF (Sideband / Nomadnet interop). A bundled NAT relay server (Option A — pure relay, sealed envelopes, never holds session keys) also ships, though the daemon-side attach flag is not wired up yet — see `docs/NAT_TRAVERSAL.md`. Federation between meshes via `FederationGateway` with v2 per-source matchers.
- **Three reference clients** beyond Python: Go (full wire protocol, crypto verified against Python), TypeScript (`@wiztheagent/ironmesh-client`), and the OpenClaw channel adapter (`@wiztheagent/openclaw-ironmesh`).
- **Wire format:** the `ironmesh/0.8` opt-in feature flags (`hskip` for handshake-skip on identified RNS Links, `group` for shared-secret broadcast) plus the **`ironmesh/0.9` protocol line** (v0.9.5) — domain-separated HELLO signatures, RNS link binding on the Reticulum transport, and receive-side verification of the inner end-to-end source signature in a bound v2 form (additive scheme tag, no negotiation). Every addition is version-gated with a legacy fallback, so v0.9.x peers stay interoperable and v0.8.x peers continue to interoperate on the unchanged legacy surfaces.
- **Operator surface:** `ironmesh setup` (interactive first-run wizard, now with profile selection, a passphrase generator, and keyring storage), `ironmesh invite create` / `ironmesh setup --from-invite` (single-use, verified-first-use bootstrap tokens with optional QR transport), `ironmesh demo` (60-second two-agent local demo), `ironmesh doctor` (mesh-health diagnostic with `--onboard` walkthroughs and `--fix` for safe local repairs), canonical `--profile` postures (`lan / lora / homelab / tactical / custom`), `ironmesh upgrade` (PyPI version check), 9 new metrics + 4 Prometheus alert rules + a Grafana dashboard, OpenTelemetry spans on the v0.9.x agent surfaces.
- **Distribution:** PyPI, Docker Hub, and GitHub Releases (a `docs.ironmesh.org` mkdocs site is planned). Each release follows `.github/RELEASE_CHECKLIST.md` end-to-end with a wheel-packaging smoke gate (`scripts/release-smoke.sh`) before any `twine upload`.

## What's coming

Roughly in priority order. See the master plan for the full sequence.

### Before v1.0

- **External cryptographic audit** — single highest-leverage action on the path to v1.0. Targeting Radically Open Security, Cure53, or Trail of Bits.
- **`PROTOCOL_SPEC.md` v1.0** — RFC 2119 spec covering wire format, handshake state machine, trust model, message types, routing, error codes, failure semantics. Plus a conformance test suite as a standalone repo.
- **Capability Routing v2** — weighted scoring engine: each candidate node receives a composite score from measured latency, trust level, load, and capability match quality. Decision-trace metadata for every routing decision.
- **Pending-trust default-on** in v0.9. Migration guide + `--no-message-promotion` escape hatch for legacy behavior.

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
