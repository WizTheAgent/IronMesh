# Roadmap to 1.0

This document is the public commitment for what lands in each v0.9.x
release between v0.9.1 (shipped 2026-04-24) and v1.0.0. The cadence is
deliberately spread out so each piece bakes before the next one builds
on it — and so 1.0 itself ships with no surprises.

The headline rule: **breaking changes are fair game in any v0.9.x
release.** Once 1.0 ships, the public API and wire protocol are
committed-to under semantic versioning. Anything that needs to break
has to break before then.

## Release ladder

### v0.9.2 — Wire protocol v5 + scale baseline

Theme: lock down the wire-format changes that have been queued, then
prove the protocol holds at scale.

* **Handshake skip on RNS Links.** When transport is an established
  RNS Link with mutual `link.identify()` complete, optionally
  short-circuit the IronMesh stage-1+2 handshake. The Link already
  provides forward-secret AEAD plus mutually-authenticated identity
  via Identity hash; running the IronMesh handshake on top is pure
  overhead — painful on a 3.12 kbps LoRa link. Behind a config flag,
  default off.
* **Group destinations for HELLO/PING broadcast.** Replace N unicast
  HELLO/PING messages with one symmetric-key Group destination per
  mesh. Symmetric key derived from the mesh passphrase. On a 10-peer
  mesh, this drops keep-alive bandwidth roughly 10x.
* **Wire format v5.** Bumps the protocol version to carry both
  changes. Negotiation matrix tested across v0.7 / v0.8 / v0.9 / v1.0
  peers — every combination must converge to a working session or fail
  cleanly with a documented error code.
* **100-node scale test.** Current stress matrix tops out at three
  peers. v0.9.2 includes a synthetic-mesh test fixture that spins up
  100 daemons in containers, runs sustained throughput against them,
  and publishes the baseline numbers (msg/s per node, RAM, CPU,
  audit-log growth). Anything above this baseline is a regression in
  later releases.

### v0.9.3 — NAT traversal

Theme: make "decentralized" actually work outside the local LAN.

* **ICE-style hole punching.** STUN for public-IP discovery,
  symmetric-NAT-to-cone hole punching for the common cases.
* **TURN-style relay fallback.** When direct connectivity fails, route
  through a federation gateway acting as a relay. Operators decide
  whether to run a relay; clients fall back automatically.
* **`docs/NAT_TRAVERSAL.md`** — design doc has been queued since v0.7;
  this release is its implementation.
* **Live test on a real two-NAT topology** — at least one peer behind
  CGNAT, one behind a residential NAT, validating end-to-end without
  shared infrastructure.

### v0.9.4 — Conformance test suite + threat model

Theme: turn IronMesh from "an implementation" into "a protocol with
implementations."

* **Wire-protocol golden vectors.** For every `MessageType` and every
  state transition, a golden frame-bytes fixture lives in
  `tests/conformance/`. Anyone implementing IronMesh in Go, Rust, JS,
  or Swift can run this suite against their build and prove
  compliance.
* **Handshake state machine tests** as a portable spec — same fixture
  format, language-agnostic.
* **Mesh routing convergence tests** — distance-vector behaviour
  should match across implementations.
* **`docs/THREAT_MODEL.md`** — a single formal document covering
  what IronMesh defends against, what's out of scope, the security
  assumptions on each layer, and the cryptographic primitive
  justifications. Currently this content is scattered across
  `SECURITY.md`, individual release notes, and code comments.
* **State-machine diagrams** for handshake, mesh routing, capability
  binding — published as PDFs alongside the threat model.
* **External-audit pre-pack.** Threat model + state diagrams + golden
  vectors + repo tour assembled into a single deliverable an external
  audit firm can consume on day one.

### v0.9.5 — Federation gateway v2 + capability-aware routing

Theme: the cross-mesh and cross-peer surface that 1.0 needs to take
seriously.

* **Federation gateway v2.** Production-harden the existing
  `federation.py` (currently MVP). Adds a policy DSL for cross-mesh
  allow/deny, multi-hop federation (mesh-of-meshes), and a per-peer
  audit log of cross-mesh forwards.
* **Capability-aware routing.** Currently `agent.send_to(name)`
  resolves a specific peer. Adds
  `agent.send_to_capability("llm:llama3", payload)` which picks any
  peer advertising that capability — load-balanced when several
  qualify, with automatic failover when a provider drops.
* **Capability negotiation extensions** — peers can advertise
  capability versions and parameter ranges (`llm:llama3 ctx<=8192`)
  for finer matching.

### v0.9.6 — Observability v2

Theme: 1.0 ships with proper operator tooling — not just metrics.

* **OpenTelemetry spans on every public surface** — `send_to`,
  handshake, mesh routing decisions, Resource transfers, federation
  forwards. Distributed tracing across federation gateways works
  end-to-end.
* **Pre-canned Grafana dashboard JSON** — operators import once and
  get the full ops view: peer count, throughput, handshake latency,
  audit-chain status, capability registry depth.
* **Prometheus alert-rule pack** — common-case alerts for stuck
  handshakes, audit-chain tamper, mesh-route convergence failures,
  Resource-transfer stalls.
* **Audit log query language** — beyond `audit verify` and `audit
  tail`, a small filter syntax for ops queries.

### v0.9.7 — Docs site + final polish

Theme: everything 1.0 will be judged by.

* **Docs site migration.** The current `index.html` got us to v0.9 —
  for 1.0 it needs to be a real docs platform. Migrating to
  mkdocs-material on `docs.ironmesh.org`. Tutorials, recipes,
  deployment patterns, an auto-generated API reference, and search
  that scales.
* **Public migration guide** — step-by-step v0.8.x → v0.9.x → v1.0
  with config diffs, behaviour changes called out.
* **CHANGELOG hygiene pass** — back-fill any v0.8.x entries that were
  terse; ensure every public API change in the entire v0.x history is
  documented.
* **`README.md` overhaul** — make the front door of the repo carry
  its weight for the 1.0 era.

### v1.0.0 — Stability promise

Theme: no new features. The promise is stability.

* **Public API contract.** Every symbol exported from the `ironmesh`
  package is documented as stable, experimental, or deprecated. The
  stable surface is the SemVer commitment going forward.
* **Wire protocol v5 frozen.** No further breaking changes without a
  v2.0.
* **External security audit results published** — with whatever
  remediations the audit recommends already merged.
* **External protocol review** — submission to a venue (r/crypto,
  Real World Crypto, equivalent) for the protocol design itself.
* **First conformance-suite-validated third-party implementation.**
  At least one alternate implementation (Go or Rust) passes the
  conformance tests. Proves the protocol is implementable from spec
  alone, not just by reading the Python.
* **Final docs polish.** Migration guide complete. Tutorials cover
  the common deployment patterns. Recipes for the standard agent
  patterns.

## Out of scope for the v0.9.x → 1.0 line

These are real wants but explicitly post-1.0:

* **Plugin sandbox** — adds API surface area; better landed after the
  1.0 contract is set so the sandbox API itself isn't a moving target.
* **Mobile-specific work** beyond what Termux already supports —
  battery-aware modes, push integration, etc.
* **Rust port** — community implementation work; conformance suite
  unblocks it but the project doesn't own it.
* **Anything that requires the wire protocol to bump again.**

## Cadence

Each v0.9.x is a focused release with a single headline theme. Aim for
a roughly two-week cycle on the smaller themes and a full month on
v0.9.2 (wire-protocol cluster + scale test) and v0.9.3 (NAT
traversal). v1.0.0 ships when v0.9.7 has been in the wild long enough
to surface anything that needs a final patch — minimum one month after
v0.9.7 lands.

Hard commitment: **no release in the v0.9.x line introduces a
breaking change without a clear migration path documented in the
release notes.** That's the contract that makes the 1.0 stability
promise credible.
