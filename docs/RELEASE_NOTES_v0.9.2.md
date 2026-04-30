# IronMesh v0.9.2 — 1.0 prep mega-release

**Released:** 2026-04-27
**Type:** minor (additive surfaces only; no breaking change to wire,
SDK, CLI, or config)
**Compatibility:** every v0.9.x peer stays interoperable on the mesh.
v0.8.x peers continue to interoperate on the existing wire surfaces.

The mega-release on the road to v1.0. Every piece originally scheduled
across v0.9.2 → v0.9.7 (per `docs/ROADMAP_TO_1.0.md`) landed in this
single release so that v1.0 is a pure stability promise rather than a
feature push.

The headline artifacts are **`docs/STABILITY_PROMISE.md`**, the v1.0
contract for everything we commit to keeping stable, and **wire
protocol `ironmesh/0.8`**, which adds two opt-in feature flags
(`hskip`, `group`) without disturbing any existing path.

## Highlights

### Wire + transport

- **Stage-1 handshake skip on identified RNS Links** (chunk A,
  protocol/0.8). Opt-in via `--rns-skip-handshake`. When both peers
  advertise `hskip` in their RNS announces, the IronMesh stage-1
  challenge / verify is replaced by a deterministic 32-byte SHA-256
  sentinel used as channel binding. RNS Link Identity authentication
  takes the place of the IronMesh-layer passphrase on these
  connections.

  **Server-driven negotiation.** The server is the active party and
  SPEAKS FIRST — when both sides are eligible it emits a new
  `SKIP_OFFER` message carrying the channel binding sentinel;
  otherwise it emits the legacy `PASSPHRASE_CHALLENGE`. The client
  type-dispatches on the first server message — never decides skip
  unilaterally. This eliminates the asymmetric-decision race where
  one side would commit to skip while the other expected challenge,
  silently breaking the handshake.

  **Three correctness fixes landed in this release on top of the
  initial chunk A code:**

  1. Server-driven `SKIP_OFFER` negotiation (above) — the protocol
     half of the fix.
  2. Outbound side now calls `link.identify(self._identity)` after
     the RNS Link reaches ACTIVE so the receiving side learns the
     RNS Identity hash needed for the eligibility check.
  3. Server briefly polls (1.5 s budget) for the identify proof to
     land before checking eligibility — the 500 ms RNS-thread sleep
     in `_on_incoming_link` was blocking the identify callback from
     firing in time.

  **Defense-in-depth:** the client rejects any `SKIP_OFFER` whose
  `channel_binding` is not byte-equal to
  `Handshake.skip_channel_binding()` (downgrade-attempt guard).

  **Verified live cross-host:** both sides' counters
  (`ironmesh_handshake_skips_activated_total`) incremented to 1 on
  the first identified RNS Link with announces propagated.
  14 unit tests + cross-host live-fire validation. Documented in
  `PROTOCOL_SPEC.md §2 Stage 1 skip` + `THREAT_MODEL.md` cross-asset
  attacks (downgrade path).
- **Shared-secret mesh-wide broadcast** (chunk B). Opt-in via
  `--rns-group-broadcast`. Both the group Identity (64 B) and the
  symmetric group key (32 B) are derived from the daemon passphrase
  via HKDF-SHA256 with domain-separated `info` labels — every peer
  that opts in independently arrives at the **identical** destination
  hash and can decrypt group traffic without any negotiation.
  Verified live: two hosts independently derived the identical GROUP
  hash `03d735e82db6d97ef2ba551d6f91198c` from the shared passphrase.

  **Two-phase delivery** addresses the RNS architectural constraint
  that GROUP destinations cannot be `announce()`d (RNS rejects with
  "Only SINGLE destination types can be announced"):

    Phase 1 — RNS GROUP packet (O(1)). Reaches every listener that
              shares the same RNS Transport. Examples: all daemons
              connected to one rnsd shared instance; all radio nodes
              on one LoRa medium where every packet is physically
              broadcast. This is the cheap path.

    Phase 2 — IronMesh GROUP_BROADCAST fan-out (O(N)). For every
              ONLINE peer that advertised the `group` feature in its
              RNS announce, the sender enqueues a GROUP_BROADCAST
              frame over the existing IronMesh connection. This is
              the path that covers cross-host meshes where Phase 1
              alone wouldn't reach a remote GROUP listener.

  **Receivers dedup on payload SHA-256** (60 s window, 10,000-entry
  hard cap with `OrderedDict` O(1) eviction) — a peer that hears the
  same payload via BOTH phases processes it exactly once.
  `broadcast_via_rns_group(payload)` now returns a small dict:

    `{"local_segment": bool, "fanout_sent": int, "fanout_skipped": int}`

  so callers + tests + logs can see exactly which phases reached
  which peers.

  New `MessageType.GROUP_BROADCAST` carries the broadcast payload
  over established Links; the inbound dispatch routes it to the same
  `_on_rns_group_message` hook as the RNS GROUP packet, so the
  application-level surface (`on_group_broadcast(payload)`) is
  unchanged. Senders gate phase 2 on the receiving peer having
  declared `group` in its announce — non-participants are never
  shouted at.

  Documented in `PROTOCOL_SPEC.md §8 feature flags`.
- **Wire-format v5 / `ironmesh/0.8`** (chunk C). Bytes unchanged from
  v4; v5 just names the optional Stage 1 skip and the new `hskip`
  feature flag. Documented in `PROTOCOL_SPEC.md §8` (announce app_data)
  + `§11` (per-feature stable-since table).

### Agent SDK

- **`Agent.send_to_capability(pattern, payload)`** (chunk E).
  Resolves an fnmatch glob against the capability registry and
  dispatches via the unified-transport layer. Three strategies:
  `first` (best-RTT online peer wins, falls through on failure),
  `random` (load distribution), `all` (parallel fan-out with per-target
  results). Local node never picked. Documented in
  `PROTOCOL_SPEC.md §11`.

### NAT traversal

- **Bundled NAT relay — operator-run rendezvous for WAN meshes.** New
  module `ironmesh.nat_relay` + entry `python -m ironmesh.nat_relay`
  implements Option A (pure relay) from `NAT_TRAVERSAL_DESIGN.md`. A
  single-purpose WebSocket server that forwards sealed envelopes
  between registered peers by `node_id`. The relay never holds session
  keys, never sees plaintext — it only reads the outermost
  `{type, to}` envelope. Per-peer forward-rate caps (100/s sustained)
  and registry caps (10k peers per instance) bound abuse. Documented
  in `NAT_TRAVERSAL.md §4`.

### Federation

- **Federation policy v2 — per-source matchers.** `FederationPolicy`
  now accepts a `per_source` list of glob-matched rules that override
  the global allow/deny for a specific sender. First match wins; falls
  through to global on no match. Backwards compatible — omit
  `per_source` and behavior is identical to v0.9.1.

### Operator + observability

- **Metrics — 9 new counters for the v0.9.2 surfaces.**
  `ironmesh_capability_routes_{attempted,succeeded,no_match}_total`,
  `ironmesh_handshake_skips_{offered,activated,rejected}_total`
  (three-way split: server emitted SKIP_OFFER / client accepted /
  client rejected for malformed or wrong channel binding — divergence
  between offered vs activated reveals send failures, and any non-zero
  `_rejected` rate is alert-worthy as a downgrade-attempt signal),
  `ironmesh_group_broadcasts_{sent,received,deduped}_total`. Four
  Prometheus alert rules at `scripts/observability/prometheus-alerts.yml`:
  `IronMeshCapabilityRouteNoMatchSpike`,
  `IronMeshGroupBroadcastDedupStorm`,
  `IronMeshHandshakeSkipActivationGap`,
  `IronMeshHandshakeSkipRejected` (severity: critical). Full catalog
  in the new `docs/METRICS_REFERENCE.md`.
- **OpenTelemetry spans on the v0.9.x agent surfaces** (chunk I).
  `Agent.send_to_name`, `Agent.send_to_capability`, handshake-skip
  activations all instrumented. Spans are no-ops on installs without
  the `otel` extra. Pre-canned **Grafana dashboard JSON** under
  `scripts/observability/grafana-dashboard.json`.

### Reliability fixes

- **RNS multiprocess RPC authkey collision — opt-in mitigation.**
  Two ironmesh daemons on one host without rnsd can collide on the
  default RNS shared-instance RPC port (37428) with different
  per-configdir authkeys, causing the second daemon's client handshake
  to fail with `multiprocessing.context.AuthenticationError: digest
  sent was rejected`. Set `IRONMESH_SEED_RNS_CONFIG=1` to enable a
  per-daemon config seeder that writes unique `shared_instance_port`
  + `instance_control_port` (deterministically derived from the
  daemon's node_id hash) into the daemon's configdir. **Off by
  default** because turning it on prevents the daemon from joining
  an existing rnsd shared instance. AutoInterface settings
  (`group_id`, `discovery_port`, `data_port`) are NEVER overridden —
  doing so would fragment the global cross-host mesh. The standard
  multi-daemon-on-one-host pattern remains rnsd; this seeder is for
  no-rnsd test setups only. 5 new unit tests in
  `TestRnsConfigSeeding`.
- **Shutdown WARN-spam quieted.** Graceful shutdown previously fired
  `logger.warning("Failed to send frame to %s: %s", ...)` for every
  in-flight route announce hitting a closing peer. `ConnectionClosed`
  is now logged at DEBUG; unexpected exceptions still surface at
  WARNING.

### Conformance + threat model

- **Conformance test suite skeleton** (chunk H) at
  `tests/conformance/vectors/`. Language-agnostic golden vectors with
  a documented JSON format. The Python reference implementation runs
  them via `tests/test_conformance_vectors.py`. First wave covers
  announce app_data (3 vectors), handshake-skip sentinel (1 vector),
  and shared-secret group key derivation (2 vectors — identity
  material + symmetric key, both HKDF-SHA256 with documented
  salt+info+length so non-Python implementations can byte-equal the
  reference).
- **Threat model formalised for v1.0 audit prep** (chunk G). New STRIDE
  entries for v0.9.x assets (RNS Identity + ratchets, LXMF delivery
  identity, pending-trust queue, RNS admin allow-list). New cross-asset
  attack rows for RNS announce spoofing, capability forgery, federation
  forwards, Resource transfer lockout, handshake-skip downgrade. New
  trust-boundary diagram. New external-audit pre-pack listing every
  doc + fixture an auditor needs.

### Headline doc — `docs/STABILITY_PROMISE.md`

The v1.0 stability contract. Enumerates every wire-protocol surface,
Python API, CLI flag, config-file field, metric name, and OTel span
name that is frozen at v1.0. Defines the deprecation procedure (one
minor of warnings + migration guide + next-major removal), security
backport policy (≥ 6 months on the previous minor), and the wire-
version negotiation matrix.

The §6 commitment: **v1.0 is the label, not a feature drop — nothing
on the wire changes.**

### Synthetic scale harness

- **100-node synthetic scale harness** (chunk D) at
  `scripts/stress_scale_100.py`. Spawns N daemons on sequential
  localhost ports, wires a random mostly-connected bootstrap
  topology, then validates (a) full mesh convergence within a
  deadline, (b) broadcast fan-out delivered exactly once, (c) no
  daemon crashes. Operator-run, not pytest-collected.

### Comprehensive E2E driver

- **`scripts/stress_e2e_round4.py`** (989 lines) — 14-phase
  comprehensive end-to-end pressure test covering multi-hop routing,
  many-to-one burst, 64 KB payload, dedup/replay defense, persistent
  state, Prometheus parseability, conversation envelope, live
  handshake-skip eligibility matrix, group broadcast roundtrip, rate-
  limit trigger, audit-chain tamper detection, connect storm,
  shutdown-under-load, and a 5-probe attack surface battery (garbage
  frame, oversized 2 MB frame, malformed announce, admin RPC
  identity gate, trust-store MAC tamper).

## Validation summary

* Full pytest: **892 passed / 2 skipped / 1 xpassed** in 4:42
* Targeted regression on touched modules: **125/125** in 2.7 s
* E2E round-4 driver: **37/37 PASS** across 14 phases
* Leak scan on the staged set: clean
* RNS multiprocess authkey fix: validated by manual bash dual-daemon
  launch + 4 unit tests + in-process singleton-reuse round-4 phase

## Deferred from this release

- Hole-punching layer of NAT traversal. The relay half (Option A in
  `NAT_TRAVERSAL_DESIGN.md`) ships in v0.9.2; the STUN-based hole-
  punching optimisation on top remains a future-release item — the
  relay is always a correct fallback, so the gap is a latency
  optimisation rather than a correctness one.
- 100-node synthetic scale baseline numbers published to the docs site.
  The fixture ships in v0.9.2; the first published baseline will land
  once the harness runs on dedicated hardware instead of a shared
  workstation.
- Multi-hop federation gateway cascades. Federation v2 per-source
  rules ship in v0.9.2; cascading multi-mesh → multi-mesh → multi-mesh
  topologies are tracked for a later release.

## Upgrade notes

* No action required. v0.9.2 is a drop-in upgrade from v0.9.1.
* New CLI flags `--rns-skip-handshake` and `--rns-group-broadcast`
  default to off — opt in only when the operator wants the latency
  saving on LoRa or the broadcast primitive on identified meshes.
* If you run two ironmesh daemons on one host without rnsd, the new
  RNS config-seeder will auto-create a fresh `config` file in each
  daemon's `--rns-configdir` with unique RPC + AutoInterface ports.
  Existing config files are never overwritten — operators with
  custom RNS configs keep them.
