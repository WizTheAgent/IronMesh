# IronMesh Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.2] — Mesh stability, observability, and backpressure

Focused on production-readiness for multi-node deployments. Closes
Wiz's hardening checklist (per-hop RTT + retries + message lifetime,
queue backpressure, peer-drop alerting, per-peer bandwidth throttle).
All 5 critical and 11/11 high-severity items from the prior audit now
fixed. 456 tests passing, zero regressions.

### Breaking: Python 3.10+ required

`requires-python` bumped from `>=3.9` to `>=3.10`. Python 3.9 went
EOL in October 2025. The codebase relies on `asyncio.Lock()` being
constructible outside a running loop (a 3.10 change) — keeping the
3.9 compat shim is more complexity than the shrinking 3.9 user base
justifies. If you're on 3.9, pin to `ironmesh==0.7.1` until you
upgrade.

### Major protocol bugs fixed

- **Event loop not started on `BridgeDaemon.run(background=True)`** —
  `loop.run_forever()` was never called, so every scheduled coroutine
  (mDNS auto-connect, server handshakes, LXMF→IronMesh forwarding)
  was a dead letter. The LXMF gateway couldn't forward messages until
  this was fixed. The daemon now spawns a `run_forever()` thread
  before returning the loop to the caller.
- **Simultaneous-dial collision storm** — both ends of an mDNS pair
  dialed each other at the same tick, creating duplicate sessions
  that both sides tore down, producing a rapid online→offline flap.
  Added a deterministic agent-name tie-breaker: the lexicographically
  smaller name dials; the larger waits for incoming. Applied uniformly
  in `_on_peer_discovered`, `_discover_loop`, and `_reconnect_loop`.
- **`_local_ip()` returned the wrong NIC on multi-homed hosts** —
  `getaddrinfo(hostname)` picked up VirtualBox/WSL/Docker bridge IPs
  ahead of the real LAN adapter. Reordered to prefer route-based
  detection (UDP-connect to common RFC1918 gateways).
- **Zeroconf responded on every interface** — when operator sets an
  explicit `--bind`, Zeroconf now binds only to that interface.
- **Single-peer mDNS auto-connect gate** — `any(peer.is_online)`
  globally skipped auto-dial of *any* new peer once *any* peer was
  online. Broke 3+ node meshes. Changed to per-peer check.
- **Session-key race after connect_to_peer** — harness and normal
  client callers could send their first message on a connection the
  tie-breaker was about to tear down. Added `wait_peer_online(stability_seconds)`
  that waits for session_key to stay unchanged for ≥2s before returning.

### Observability — Wiz's hardening checklist

- **Per-peer metrics**: `ironmesh_peer_{online,rtt_ms,retries_total,
  bytes_sent_total,bytes_received_total}{peer="…",name="…"}` — Prometheus-labelled
  per-peer gauges/counters. Retries tagged by reason (`direct_send_failed`,
  `routed_send_failed`, `queued_offline`, `queue_full_dropped`,
  `bandwidth_throttled`, `rekey_failed`).
- **Message lifetime summary**: `ironmesh_message_lifetime_seconds`
  sampled from inbound frame timestamps — p50/p90/p99 quantiles
  populated from a bounded rolling window (512 samples).
- **`/api/mesh_stats` endpoint**: compact JSON snapshot optimized for
  harness/dashboard polling. Stable schema — additive across releases.
- **Dashboard**: peer table now shows Bytes (sent/received), RTT, and
  retry count with hover tooltip listing per-reason breakdown.

### DoS guard: backpressure on queues

- **Offline queue cap** (`MessageStore(max_pending_per_peer=1000)`) —
  prevents a perpetually-offline peer from consuming unbounded disk.
  Priority-aware eviction: CRITICAL/HIGH displace oldest LOW/NORMAL;
  a queue full of CRITICAL refuses new LOW admits.
- **Per-peer bandwidth throttle** — `TokenBucket` in bytes/sec
  (default 1 MB/s sustained, 1 MB burst). If required wait exceeds
  5s, the frame is dropped with `record_retry("bandwidth_throttled")`.
  Prevents one noisy peer from starving mesh bandwidth.
- New metrics: `ironmesh_pending_queue_dropped_total`,
  `ironmesh_pending_queue_evicted_total`,
  `ironmesh_peer_bandwidth_drops_total`.

### Peer-drop alerting

- `PeerState.offline_since` stamped on transition (preserved across
  rapid flaps — not reset per event).
- New `_long_drop_watchdog` task emits `EVENT_PEER_DROPPED_LONG` to the
  audit log exactly once per drop when a peer stays offline past
  `_long_drop_threshold_seconds` (default 300s). Metric:
  `ironmesh_peer_long_drops_total`.

### Bandwidth: RNS transport hardening

- Outbound `send()` now enforces `MAX_RNS_MSG` (1 MB) matching the
  inbound deframe bound — closes an asymmetric bounds-check gap.

### Operations

- **`scripts/startup-capture.sh`** — systemd-friendly wrapper that
  extracts the GUI token from daemon stdout and appends it to
  `/var/log/ironmesh-token.log` (mode 0600) so operators can retrieve
  dashboard access without grep'ing the journal.
- **`docs/REPIN.md`** — complete playbook for compromised-peer
  revocation, legitimate key rotation, corrupted trust store, offline
  pubkey backup, and reinstall recovery.
- **`scripts/chaos-netem.sh`** — `tc netem` wrapper for injecting
  packet loss, delay, jitter, or corruption into the mesh for
  resilience testing.

### Benchmark harness

- New `tests/harness/mesh_bench.py` — parametric RTT/goodput
  measurement tool. Sweeps payload sizes, supports `--chaos <rate>`
  for drop injection, writes CSV for trend analysis.
- New `tests/harness/bench_responder.py` — companion BENCH echo
  responder (also usable as a library via `attach_responder()`).
- Baseline measured live on a 3-node LAN mesh: 100% delivery at 64B/256B/1024B,
  p50 ≈ 12-14 ms, goodput 38-77 KB/s. Chaos 25% drop → 78% delivered
  (matches injection rate within 2%).

### Test suite

- 430 → 456 tests (+26 new covering discovery multi-NIC, queue
  bounds, bandwidth throttle, long-drop alerts, TokenBucket.wait_time,
  mesh_stats schema, TOFU test fixture repair).
- Four pre-existing failures and 16 errors from v0.5/v0.6 feature
  changes all repaired — test suite is now clean (zero failures,
  zero errors).

### Deferred to v0.8

- Signed capability announcements (schema change; needs v0.8 wire version)
- Circuit-breaker persistence across restarts
- Adaptive LoRa message sizing (RNS already fragments at its layer)
- Native Android client (Sideband + LXMF gateway covers the Android
  use case for v0.7)

---

## [0.7.1] — Security audit fixes (53/62 items)

Addresses a 62-item security/code-quality audit. This release closes
all 5 critical and 10 of 11 high-severity findings, plus 14 medium and
13 low-severity items. The remaining 9 items (signed capability
announcements, circuit-breaker persistence, rate-limiting future
frames, two new test suites, mypy-blocking in CI) are deferred to
v0.7.2 — each requires more scope than this release permits.

### Security fixes — Critical

- **C-01** Peer state race condition — added `asyncio.Lock` covering
  the duplicate-detection check, peer-state assignment, and
  `_handle_connection` finally cleanup. Fixes identity hijacking when
  two connections race to the same peer_id.
- **C-02** `secure_wipe` rewritten — the old implementation used
  CPython-specific ctypes offsets that silently failed. The new
  version uses `nacl.bindings.sodium_memzero` when available and
  refuses silently on immutable `bytes`, logging honestly about its
  limits.
- **C-03** Trust store MAC is now bound to the agent's identity key
  (required parameter). The old machine-home-derived key is kept only
  as a one-shot migration detector. `ironmesh trust` CLI now loads the
  identity key before constructing the store.
- **C-04** Replay-guard monotonic check verified already in place
  (`protocol.py:522` rejects `seq <= last_seq` before window lookup).
  Comment added.
- **C-05** Bound the 4-byte length field in the RNS Buffer deframe
  loop to `MAX_RNS_MSG = 1_048_576` — prevents memory exhaustion from
  a malformed prefix.

### Security fixes — High

- **H-01** `_handle_connection` always closes the websocket in its
  finally block, even on early handshake failure.
- **H-02** `_is_ip_blocked` / `_record_auth_failure` made async and
  serialized under `asyncio.Lock` to prevent rate-limit bypass.
- **H-03** Audit log emits `logger.critical(...)` when initialized
  without an HMAC key — never silently disabled.
- **H-04** `MeshRouter.__init__` raises `RuntimeError` if the daemon
  has no keypair (routes are HMAC-protected using that key).
- **H-05** `store._encrypt_payload` no longer falls back to plaintext
  on encryption failure — errors propagate.
- **H-06** `transport.recv` takes a `timeout: float = 300.0` parameter
  and uses `asyncio.wait_for` — prevents stalled peers from blocking.
- **H-07** `reticulum_transport._active_adapters` now protected by
  `threading.Lock`.
- **H-08** mDNS property decoding validates length, UTF-8 strictness,
  charset (alnum + `-_.`), port range, and idhash hex format.
- **H-09** `ed25519_to_curve25519_secret` uses a `bytearray` for the
  intermediate buffer and zeroes it in `finally`.
- **H-10** `AsyncMessageStore.open` serialized under `asyncio.Lock`
  with an `_opened` idempotency flag.
- **H-11** Created 4 missing test files: `test_cli.py` (11 tests),
  `test_hooks.py` (8), `test_config.py` (10), `test_backup.py` (6).

### Security fixes — Medium

M-01, M-03, M-04, M-05 (partial), M-06, M-07, M-09, M-10, M-12, M-13,
M-15, M-16, M-19.

### Security fixes — Low

L-01, L-02, L-03, L-04, L-05, L-06, L-07, L-08, L-09, L-11, L-12, L-13, L-14.

### Deferred (v0.7.2 candidates)

- **M-02** Rate-limit future-timestamped frames per peer.
- **M-08** Sign capability announcements with Ed25519.
- **M-11** Persist circuit-breaker state to HMAC-protected file.
- **M-14** Two-daemon integration test suite.
- **M-17** Concurrency test suite with `asyncio.gather`.
- **M-18** Separate `revoked_peers` set (today tracked inside
  `_revoked` dict; the race is theoretical, not yet observed).
- **L-10** Replace `time.sleep(0.01)` in rate-limit test with
  `freezegun` time mocking.
- **M-16** Make mypy blocking in CI (needs existing type errors fixed
  first; kept non-blocking to avoid breaking CI in the same commit).

### Test results
- 410 tests pass (up from 375 pre-v0.7.1; +35 from new test files +
  C-03 migration fixtures).
- 4 pre-existing failures unchanged (v0.5.1 TOFU address-change and
  v0.6 revocation — these tests need updating, not core code).
- 16 pre-existing `test_reticulum_transport.py` errors unchanged
  (from v0.5.1 RNS adapter rewrite).

## [0.7.0] — Ecosystem release: Docker, LXMF bridge, conformance suite

This release focuses on making IronMesh publish-ready and easier to
interoperate with. No wire-protocol changes — v0.7 interoperates with
v0.3–0.6 peers.

### Added

**Deployment**
- `Dockerfile` (multi-stage, non-root UID 1000) + `docker-compose.yml`
  with sensible defaults, healthcheck, and optional paired-peer profile.
- `scripts/install.sh` — one-line installer. Detects OS, installs
  Python if missing, creates a venv, prompts for a passphrase, and
  optionally installs the systemd user unit.
- `scripts/ironmesh.service` — hardened systemd user unit with
  `PrivateTmp`, `ProtectSystem=strict`, `ReadWritePaths`,
  `SystemCallFilter=@system-service`, etc.

**Mobile / Web**
- GUI dashboard is now mobile-responsive: new `@media (max-width: 600px)`
  breakpoint with touch-friendly form controls (44px min-height), 2-col
  cards grid, compressed tables.
- PWA manifest served at `/manifest.json` — Chrome "Install app" works.
- Theme colour, apple-mobile-web-app-capable meta tags.

**LXMF gateway** — `examples/lxmf_gateway.py`
- Bidirectional bridge between IronMesh and Reticulum LXMF.
- Anyone on [Sideband](https://unsigned.io/sideband) (iOS/Android) or
  NomadNet can message IronMesh peers and receive replies, without
  running IronMesh themselves.
- JSON config file maps LXMF destination hashes to IronMesh peer_ids.
- Loop-prevention via `[LXMF] ` / `[IM] ` prefixes.
- Thread-safe bridging from RNS delivery callback to the asyncio loop.

**Specification**
- `docs/PROTOCOL.md` — added formal header with protocol identifier
  `ironmesh/0.6`, version / compatibility matrix, conformance section.
- `tests/test_conformance.py` — 28 invariant tests covering wire
  format, replay guard, handshake, signatures, TOFU, version
  negotiation, and message type catalog. Usable as a reference by
  future ports (Rust, Go).

**Docs**
- `GETTING_STARTED.md` — 5-minute quickstart separate from the
  feature-heavy README.
- `docs/TERMUX.md` — Android/Termux install guide.
- README additions: examples table, mobile section, Docker/installer
  options.

### Changed
- Version bumped to 0.7.0 in `__init__.py` and `pyproject.toml`.
- Roadmap in README reflects completed v0.5/0.6/0.7 milestones and
  sets v1.0 as the next major target (after 10-20 real-world deployments).

### Strategy
Per open-source-first guidance:
- Core stays MIT (see `LICENSE`).
- Future commercial surface (hardware kits, managed dashboards, custom
  transport adapters, deployment services) will sit on top of the open
  core without wrapping key management.

## [0.6.1] — Connection stability + LLM bridge example

### Fixed
- **Connection churn**: Native WebSocket ping/pong is now enabled on both
  server and client (`ping_interval=20, ping_timeout=10`). Previously
  disabled, which meant dead connections weren't detected until the
  app-level heartbeat tried to send (up to 15 s) and then spammed
  `Failed to send frame` until the next reconnect cycle. The websockets
  library now detects dead peers within ~30 s and fires the normal
  `ConnectionClosed` path cleanly.
- **Send timeout in `_send_frame`**: wraps `ws.send()` with a 5-second
  `asyncio.wait_for`. On timeout or send error, the peer is marked
  OFFLINE immediately and the stale ws is closed — no more "Failed to
  send frame" loops on half-dead connections.
- **Reconnect race**: four reconnect paths (`_reconnect_loop`,
  `_try_transport_failover`, `_discover_loop`, `_on_peer_discovered`)
  could race when a peer dropped. Added a `_reconnecting` gate keyed by
  peer_id/agent_name with 60 s staleness timeout — at most one
  reconnect attempt in flight per peer.

### Added
- **`examples/llm_bridge.py`** — a ~200-line standalone example that
  turns any IronMesh node into an encrypted LLM agent:
  - Subscribes to `MSG` on the bus.
  - For each prompt, calls the Ollama HTTP API (`/api/generate`).
  - Sends the response back to the original sender, prefixed with
    `[LLM] ` so we don't loop on our own replies.
  - Configurable model, system prompt, timeout, max prompt size.
  - Error responses are prefixed with `[LLM-ERR] `.
  - Uses only stdlib `urllib.request` (no extra deps) + `asyncio.to_thread`.

  This is the canonical use case for IronMesh: end-to-end encrypted LLM
  agents that work fully offline over LoRa.

## [0.6.0] — Hardening release: backup, revocation, version floor, fuzzing

This release focuses on operational readiness and long-term trust
management.  No wire-protocol breaking changes — v0.6 interoperates with
v0.3–0.5 peers.

### Added

**Operational tooling**
- `ironmesh backup --out <file>` and `ironmesh restore --in <file>`
  produce encrypted archives of keys + trust store + audit log tail
  (Argon2id + SecretBox, same crypto as identity key files).
- `ironmesh audit verify [--archives]` walks the HMAC chain and
  reports tamper/integrity.
- `ironmesh audit export --out <file>` produces an Ed25519-signed JSON
  bundle of audit entries; `ironmesh audit verify-export <file>` checks it.
- `ironmesh session rotate <peer_id> --token <t>` forces an immediate
  session key rotation with a peer via the local GUI WebSocket.
- `ironmesh trust list-revoked` shows currently revoked peers.
- GUI WebSocket actions: `rotate_session`, `broadcast_revocation`.

**Protocol hardening**
- `--min-protocol-version` flag (default `ironmesh/0.3`): refuses peers
  below the floor. Raise to `ironmesh/0.5` once all nodes are upgraded.
- Jittered exponential backoff for reconnection (5 s → 300 s cap, ±2 s
  jitter). Prevents reconnect storms after network partition.
- mDNS `idhash`: 8-byte SHA-256 prefix of identity public key in TXT
  records. Non-identifying but lets peers correlate announcements to
  pinned identities before handshake.

**Security features**
- `REVOCATION` message type: Ed25519-signed broadcast to mark a peer as
  revoked. Receivers verify the signature came from a pinned peer, then
  add the target to `revoked_peers` in the trust store. Revoked peers
  are refused at TOFU check.
- Fuzzing harness (`tests/test_fuzz_protocol.py`) using `hypothesis`:
  500+ random inputs per test, verifies frame parser and version
  parser raise only known exception classes on malformed input.

**Documentation**
- `docs/THREAT_MODEL.md`: full STRIDE analysis with assets, mitigations,
  residual risks, and out-of-scope items.
- `docs/ARCHITECTURE.md`: version compatibility matrix (v0.3 → v0.6)
  and upgrade path.

### Changed
- Protocol version bumped to `ironmesh/0.6` in HELLO messages.
- Trust store file format gains a `revoked` section (backward-compatible
  — old stores without it still load cleanly).
- mDNS `idhash` is an additional TXT field (older peers ignore unknown
  fields).

### Fixed
- Simultaneous-rekey race (both peers initiate at the same interval): now
  the node with the lexicographically-smaller `node_id` initiates; the
  other responds.
- Protocol version was stuck at `ironmesh/0.4` in v0.5.x — rekey path
  checks `>= 0.5` so v0.5 peers never rekeyed with each other. Fixed as
  part of the v0.6 version bump.

### Deferred to future releases
- Shamir's Secret Sharing for key recovery (v0.7 candidate).
- Full HTTPS GUI with auto-generated certificates.
- C/Rust SDK for embedded firmware.
- Message batching and large-payload fragmentation over LoRa.
- Ephemeral mDNS aliases.

## [0.5.2] — Metrics, session rotation, LoRa QoS, and test harness

### Added
- **Per-hop RTT measurement**: Heartbeat PING/PONG now measures actual
  round-trip time and populates `PeerState.latency_ms` (previously always
  `null`). Dashboard and `/api/state` show live RTT per peer.
- **Delivery metrics**: `messages_delivered` (real-time) and `messages_failed`
  (fell back to offline queue) counters in Metrics class and Prometheus.
- **`avg_rtt_ms`**: New Prometheus gauge showing average RTT across online peers.
- **Session key rotation** (`REKEY_REQUEST`/`REKEY_RESPONSE`): Periodic
  re-derivation of ECDH session keys without full re-handshake. Configurable
  via `--rekey-interval` (default 30 min, 0 to disable). Only activates with
  v0.5+ peers. Forward secrecy maintained — ephemeral keys wiped after each
  rotation.
- **LoRa QoS / adaptive sizing**: `--lora-max-payload` flag (default 128 bytes).
  Messages to RNS peers exceeding the limit are automatically gzip-compressed.
  `routing["compressed"]` flag signals the receiver to decompress. WebSocket
  peers are unaffected.
- **Test harness** (`scripts/test_harness.py`): Standalone tool that sends
  incremental payload sizes through the bridge, measures latency per size, and
  outputs a CSV with per-size min/max/avg/p95 statistics.

### Changed
- Prometheus endpoint now exposes 26 metrics (was 21), including delivery,
  RTT, rekey, and LoRa QoS counters.

## [0.5.1] — Transport resilience and RNS bug fixes

### Fixed
- **RNS handshake race condition**: Outbound `RNSLinkAdapter` callbacks were
  registered after the link went ACTIVE, causing the server's
  `PASSPHRASE_CHALLENGE` to be silently dropped.  Rewrote adapter to use
  `RNS.Buffer.create_bidirectional_buffer()` over the link's Channel API
  with length-prefixed message framing — handles fragmentation and delivery
  automatically.
- **RNS incoming link callback**: `_on_incoming_link` exceptions were silently
  swallowed by the RNS thread.  Added try/except with `logger.exception()`.
- **TOFU address pinning too strict**: mDNS address changes (e.g. port change
  after restart) were hard-rejected, blocking all reconnection.  Now accepts
  address changes and updates the pin — identity is verified via Ed25519 key
  during the handshake.
- **RNS configdir default**: `--rns-configdir` defaulted to `None` instead of
  `~/.reticulum`, causing the RNS identity file to not persist and the
  destination hash to change on every restart.

### Added
- **Transport failover**: When a WebSocket connection drops, the bridge
  automatically attempts reconnection over RNS if a destination hash is known
  (and vice versa).  2-second cooldown prevents tight reconnect loops.
- **Transport-aware duplicate guard**: If a peer is connected via RNS and a
  WebSocket connection becomes available, the bridge upgrades to WebSocket
  (preferred, faster) and tears down the RNS link.  Same-transport duplicates
  are still dropped.
- **RNS reconnection**: `_reconnect_loop` now tries RNS destinations for
  offline peers when no WebSocket address is available.
- **Transport tracking**: `PeerState` gained `transport_type` (`"websocket"` or
  `"rns"`), `rns_dest_hash`, and `ws_address` fields.  Dashboard API exposes
  these in `/api/state`.
- **`_known_rns_hashes` dict**: Remembers RNS destination hashes for peers
  across reconnections.

### Changed
- `RNSLinkAdapter` now uses `RNS.Buffer` (bidirectional buffered stream over
  Channel) instead of raw `RNS.Packet` / `RNS.Resource`.  Messages are framed
  with 4-byte big-endian length prefixes.  Server uses stream IDs (recv=0,
  send=1), client uses (recv=1, send=0).

## [0.5.0] — Reticulum (LoRa) transport release

IronMesh goes radio. v0.5 adds Reticulum as an optional second transport
layer so agents can communicate over LoRa (915 MHz) with no internet and no
LAN — just RNode hardware. Both WebSocket and Reticulum transports run
simultaneously.

### Added

#### Reticulum / LoRa transport
- New `reticulum_transport.py` module with `RNSLinkAdapter` (duck-typed
  WebSocket interface over an RNS Link) and `ReticulumTransport` (lifecycle
  manager: init, announce, incoming links, outbound connections, shutdown).
- `RNSLinkAdapter` implements `send()`, `recv()`, `async for`, `async with`,
  `remote_address`, `open`, and `close()` — slots into `ws_clients` alongside
  real WebSockets with zero changes to the handshake or message loop.
- Small payloads (≤ 400 bytes) sent via `RNS.Packet`; larger payloads via
  `RNS.Resource` (automatic chunking over LoRa).
- Thread-safe bridging from RNS callbacks to asyncio via
  `loop.call_soon_threadsafe()` + `asyncio.Queue`.
- Periodic RNS announces with agent name as `app_data`.
- Double encryption by design: IronMesh NaCl crypto on top of Reticulum's
  own link-level encryption (defense in depth).

#### Bridge integration
- Extracted `_do_client_handshake(ws, label)` from `connect_to_peer` — the
  transport-agnostic core of the outbound handshake. Both `connect_to_peer`
  (WebSocket) and `_connect_rns_peer` (Reticulum) use it.
- New `_connect_rns_peer(dest_hash)` method: resolves destination, creates
  RNS link, wraps in adapter, runs standard IronMesh handshake.
- `_start()` conditionally initializes `ReticulumTransport` and connects to
  startup destinations from `--rns-connect`.
- `shutdown()` tears down Reticulum transport before mDNS cleanup.

### CLI
- `--reticulum` — enable Reticulum transport.
- `--rns-configdir PATH` — Reticulum config directory.
- `--rns-announce-interval SECONDS` — announce interval (default: 300).
- `--rns-connect HASHES` — comma-separated destination hashes for startup.

### Configuration
- New `IronMeshConfig` fields: `rns_enabled`, `rns_configdir`,
  `rns_announce_interval`.
- Environment variables: `IRONMESH_RNS_ENABLED`, `IRONMESH_RNS_CONFIGDIR`.

### Dependencies
- `rns>=0.9.0` added as optional dependency group (`pip install ironmesh[rns]`).
- Keywords updated to include `lora`, `reticulum`.

### Migration notes from 0.4.x
- No breaking changes. The `--reticulum` flag is off by default; existing
  WebSocket-only deployments are unaffected.
- The `connect_to_peer` method was refactored to use `_do_client_handshake`
  internally — behavior is identical, but the handshake logic is now shared.

---

## [0.4.0] — Mesh routing release

This is a major release. v0.3 was a working A2A protocol with WebSocket + mDNS
+ per-pair encrypted sessions; v0.4 makes the "mesh" in IronMesh real.

### Added

#### Multi-hop mesh routing
- New `mesh.py` module with `RoutingTable`, `DedupCache`, `CircuitBreaker`,
  and `MeshRouter` (announce loop, cleanup loop, relay, partition detection).
- Proactive distance-vector routing with split horizon + poisoned reverse.
- New message types: `ROUTE_ANNOUNCE`, `ROUTE_UNREACHABLE`,
  `CAPABILITY_ANNOUNCE`, `CAPABILITY_QUERY`.
- TTL-based loop prevention plus explicit hop-list inspection.
- Per-source-sharded dedup cache (`128` sources × `1024` entries × `5min` TTL
  by default) to bound memory under flooding.
- Routing table persistence at `~/.ironmesh/routes.json`, HMAC-protected with
  a key derived from the node identity.
- Circuit breaker that opens after 3 failures within a 60s window and is
  consulted before every route lookup.
- Mesh partition detection with `EVENT_MESH_PARTITION_SUSPECTED` audit event.
- `BridgeDaemon.send_message()` now falls back to mesh routing when no direct
  WebSocket session exists; the offline queue remains the final fallback.

#### End-to-end encryption
- New `mesh_crypto.py` wrapping NaCl `SealedBox` over X25519 keys derived
  from each node's existing Ed25519 identity (`keys.ed25519_to_curve25519_*`).
- `seal_to_destination(plaintext, dest_ed25519_pub)` and
  `unseal_from_source(sealed, my_ed25519_secret)` provide forward-secret per-
  message ephemeral encryption that relays cannot read.
- E2E payloads carried in the new `Frame.e2e_payload` field, untouched by per-
  hop re-encryption.
- Inner Ed25519 source signature (`Frame.source_signature`) over the
  *plaintext* survives per-hop re-encryption and provides end-to-end
  authenticity in addition to the existing per-hop outer signature.

#### Capability discovery
- New `capabilities.py` module with `CapabilityRegistry`: local advertisement,
  remote learning, glob-pattern lookup (`find("llm:*")`), HMAC-protected
  persistence.
- New CLI flag: `--capability llm:llama3` (repeatable).
- Public API: `daemon.advertise_capability(cap)` and
  `daemon.find_capability(pattern)`.
- `_capability_announce_loop` propagates the local capability set to direct
  neighbors every 60 seconds; remote nodes are reachable via mesh routing.

#### Wire format v0.4
- `Frame.VERSION` bumped from 3 to 4.
- New optional fields: `source_signature`, `e2e_payload`.
- Protocol version negotiated in HELLO; v0.3 peers remain interoperable as
  direct-only nodes (mesh forwarding is refused for them with no silent
  degradation).

#### Observability
- `/metrics` endpoint now serves Prometheus exposition format by default.
  JSON format remains available via `?format=json` or
  `--metrics-format=json`.
- New mesh metrics: `ironmesh_routes_known`,
  `ironmesh_messages_relayed_total`, `ironmesh_route_lookup_failures_total`,
  `ironmesh_dedup_cache_size`, `ironmesh_dedup_sources`,
  `ironmesh_capabilities_known`, `ironmesh_circuit_breakers_open`,
  `ironmesh_e2e_decrypt_failures_total`.
- New `--log-format json` flag uses a structured `JsonFormatter` that emits
  one JSON object per log record.
- New audit events: `EVENT_ROUTE_ANNOUNCED`, `EVENT_ROUTE_LEARNED`,
  `EVENT_ROUTE_EXPIRED`, `EVENT_MESSAGE_RELAYED`, `EVENT_TTL_EXPIRED`,
  `EVENT_ROUTE_LOOP`, `EVENT_NO_ROUTE`, `EVENT_DUPLICATE_DROPPED`,
  `EVENT_MESH_PARTITION_SUSPECTED`, `EVENT_CIRCUIT_BREAKER_TRIPPED`,
  `EVENT_CAPABILITY_LEARNED`, `EVENT_E2E_DECRYPT_FAILURE`,
  `EVENT_LOG_ROTATED`.

#### Reliability
- Audit log rotation: when the live log exceeds `audit_log_max_bytes`
  (default 10 MB), the file is rotated to `audit.log.1` (older archives shift
  to `.2`, `.3`, … up to `.5`) and a fresh `EVENT_LOG_ROTATED` entry is
  written whose `previous_tail_hmac` field anchors the chain across the
  rotation boundary.
- `AuditLog.verify_chain_across_archives()` walks every archive plus the live
  log, validating the per-file HMAC chain *and* the rotation anchors.

### Changed
- `BridgeDaemon._dispatch_message` now takes a full `Frame` object so it can
  inspect `destination`, `ttl`, `hops`, `source_signature`, and
  `e2e_payload`. Both call sites (`_handle_binary_frame` and
  `_handle_json_message`) were updated and a new
  `Frame.from_json_message` classmethod synthesizes a Frame from the legacy
  JSON path.
- `BridgeDaemon._send_frame` now passes the source signing key only when
  the daemon is the original source, so relays do not overwrite the inner
  source signature.

### CLI
- `--mesh-routing {off,passive,relay}` (default: `relay`)
- `--max-hops N` (default: 5)
- `--route-announce-interval SECONDS`
- `--route-ttl SECONDS`
- `--routes-path PATH`
- `--capability NAME` (repeatable)
- `--capabilities-path PATH`
- `--metrics-format {prometheus,json}`
- `--log-format {text,json}`

### Migration notes from 0.3.x
- The default routing mode is `relay`. Operators who do not want their node
  to forward traffic for others should run with `--mesh-routing=passive` (or
  `off` to disable the routing subsystem entirely). The trust implications of
  relaying are documented in `docs/MESH.md` and `docs/SECURITY.md`.
- The `/metrics` endpoint default format changed from JSON to Prometheus.
  Existing JSON consumers should append `?format=json` to their scrape URL or
  pass `--metrics-format=json` on the daemon.
- Wire version is now 4. v0.4 daemons happily interoperate with v0.3 peers
  for direct messaging but will not relay through them.

## [0.3.0] — Hardened bilateral release

The first release deployed in production between two nodes (kingpi and wiz).
This entry is reconstructed retroactively for completeness.

### Added
- WebSocket transport with mDNS auto-discovery.
- Per-pair NaCl SecretBox session encryption with X25519 ECDH key agreement
  bound to the long-term Ed25519 identity.
- TOFU peer pinning with HMAC-protected trust store.
- HMAC-chained tamper-evident audit log.
- GUI dashboard at `/` with token-gated WebSocket telemetry feed.
- 18 specific security findings addressed in `tests/test_audit_fixes.py`
  (replay guard, signature canonicalization, GUI auth, SQL parameterization,
  passphrase-from-file, mDNS allowlist, hook circuit breaker, etc.).
- Offline message queue per peer.
- 268 passing tests across 11 modules.
