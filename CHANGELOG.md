# IronMesh Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.5.3] — Quickstart hardening and onboarding polish

Patch release on top of v0.8.5.2. No protocol or schema changes; every
v0.8.x peer stays interoperable. Default behavior is unchanged for
existing deployments — the new warnings only fire when the relevant
flags or env vars are set (or absent in the deprecation case).

### Added

- **Startup `INSECURE` warning when `--open-discovery` is set.**
  Previously the daemon emitted a warning only when default-deny mode
  was active; the explicit insecure case was silent. Setting the flag
  now logs a clear warning naming the flag, the security implication,
  and the recommended replacement (`--allowed-peers`).
- **Startup `INSECURE` warning when `--allow-plaintext-ws` is set.**
  Same pattern — explicit warning naming the flag, the implication
  (plaintext `ws://` fallback enabled), and the recommended fix
  (generate a TLS cert and pass `--tls-cert`/`--tls-key`).
- **Startup `DEPRECATION` warning when the pending-trust message gate
  is opt-in disabled.** Cites the v0.9 default-on commitment and points
  at the planned `--no-message-promotion` escape hatch and the
  `docs/migration/v0_9_default_deny.md` migration doc (to be written
  ahead of the v0.9 ship).
- **`examples/conv_multiturn.py`** — minimal `ConvEnvelope` walkthrough.
  Two terminals, two roles (`pinger`/`ponger`), no LLM dependency.
  Reference for: open a conversation, exchange bounded turns,
  recognize end-of-conversation, no orphaned state.
- **`examples/persona_debate.py`** — persona-vs-persona debate
  orchestrator. Discovers two peers advertising different
  `role:<persona>` capabilities, seeds a debate motion, relays bounded
  turns. Pair `assistant` vs `devil` for classic debate,
  `security-analyst` vs `ops` for a real-world tradeoff discussion,
  etc.
- **`.github/RELEASE_CHECKLIST.md`** — explicit doc-sync, public-facing
  scrub, smoke-gate, and post-release verification sections so the
  README/version drift that motivated this release cannot recur.
  Section 3 ("Documentation in sync") enumerates every shipped doc
  with the exact sweep command for catching stale current-version
  claims.

### Changed

- **README quickstart restructured.** The `60-second demo` section in
  Quick Start now leads with pointers to the secure deployment path
  (`Running two physical machines`) and to a clearly labeled
  `Advanced / Testing — same-machine localhost demo` subsection. The
  insecure-flag walkthrough still exists in full — it just no longer
  appears in the headline quickstart where a stranger could mistake it
  for the recommended path.
- **README "Recent changes" section** has a new `v0.8.5.3` paragraph
  at the top; the `v0.8.5.2` paragraph is preserved as historical
  context with `(current)` removed.

### Documentation

- New `docs/RELEASE_NOTES_v0.8.5.3.md`.
- README current-version references (top banner, docker-pull commands,
  `Latest:` line) all updated to `v0.8.5.3`.

## [0.8.5.2] — Operator polish and security hardening

Patch release on top of v0.8.5. Operator UX polish for the pending-
trust gate plus a batch of security hardening fixes. No protocol
or schema changes; every v0.8.x peer stays interoperable; default
behavior is unchanged.

### Added

- **HMAC-chained audit events for gate decisions**: `MSG_GATED_QUEUE`,
  `MSG_GATED_DROP`, `PEER_PROMOTED`, `PEER_BLOCKED`. Wired into
  `_gate_inbound_msg`, `promote_pending_peer`, `block_pending_peer`.
  Operators get a tamper-evident forensic trail instead of only
  stderr logs.
- **`ironmesh trust set-state <node_id> <pending|trusted|blocked>`**
  CLI subcommand. Works offline against the trust file. Paired with
  a new `--trust-path` flag on the `trust` subcommand for
  multi-daemon operators.
- **Trust-state column** in `ironmesh trust list` output.
- **`trust_gate_state` in `/api/state`** — dashboard PEERS table now
  surfaces the v0.8.5 trust enum in the main peer row alongside the
  existing TOFU labels.
- **Gate counters in `/api/mesh_stats` + `/metrics` Prometheus**:
  `gate_enabled`, `pending_trust_evicted`, `pending_trust_dropped`,
  `messages_received_blocked`.
- **`ironmesh doctor`** — one-shot diagnostic subcommand. Checks
  identity key, trust store MAC, SQLite schema, pending-trust queue,
  gate env vars, port availability, audit chain integrity. Exit code
  non-zero on failure.

### Fixed (security)

- **Constant-time GUI token comparison.** Both the `?token=`
  query-param and `Authorization: Bearer` header paths in
  `_is_gui_authorized` used variable-time `==`. A LAN attacker
  could have recovered the 256-bit token via response-latency timing
  on `/ws` upgrade. Now uses `hmac.compare_digest`.
- **Atomic trust-file write.** `TrustStore._save` wrote
  non-atomically with `open(path, "w") + json.dump`. SIGKILL or
  power loss mid-write would leave an empty or truncated file, and
  operators would lose every pinned peer on restart. Now writes
  `path.tmp` + `fsync` + `os.replace` (atomic on POSIX and
  same-drive NTFS).
- **Strict `Frame.from_dict` type validation.** Previously accepted
  malformed inputs like `{"type": 123}` and crashed deep in dispatch.
  Now validates `type`, `msg_id`, `source`, `destination`, and
  `sequence` at the deserialization boundary.

### Fixed (observability)

- **Conflated pending-queue counter.** The v0.8.5 trust-gate queue
  eviction was incrementing `self.pending_evicted` on
  `MessageStore`, which is also the offline-queue counter. Operators
  looking at `/metrics` couldn't tell which queue was under
  pressure. Split into separate fields: `pending_trust_evicted` and
  `pending_trust_dropped` for the gate; `pending_evicted` /
  `pending_dropped` remain the offline-queue fields.
- **`/api/mesh_stats` was missing the new gate counters.** Only
  `/metrics` Prometheus carried them. Fixed so both surfaces expose
  `gate_enabled`, `pending_trust_evicted`, `pending_trust_dropped`,
  `messages_received_blocked`.
- **`ironmesh doctor` stdin-closed hang.** The tool previously
  called `getpass.getpass()` unconditionally, blocking forever when
  run from automation or `< /dev/null`. Now tries env + plaintext
  key first and only prompts when `sys.stdin.isatty()`.

### Fixed (operator-facing error messages)

- **Trust integrity-check message.** Upgraded from the generic
  "file may be tampered" to include the stored-vs-expected HMAC
  prefix + file path + explicit pointer to `--trust-path` for the
  multi-daemon collision pattern this release closes in v0.8.5.

### Fixed (additional security hardening)

- **MCP tool resource caps.** `ironmesh_request_service` timeout
  clamped to [1, 300]s and prompt capped at 1 MB;
  `ironmesh_send_message` and `ironmesh_broadcast` payload capped
  at 16 MB; `ironmesh_subscribe_events` limit clamped to
  [1, 1000], cursor must be non-negative, kinds filter capped at
  64 entries. Any of these could previously have been weaponized
  against the MCP handler for resource exhaustion.
- **TypeScript persistence `fsync`.** `PluginState.save` in
  `@wiztheagent/openclaw-ironmesh-channel` now `fsync`s before
  rename. Same class as the Python trust-file atomic-write fix.
- **Framework adapter error leakage.** `langchain_adapter` and
  `autogen_adapter` previously returned raw `str(e)` on exception,
  leaking internal paths and config into the LLM's tool-result
  context. Now returns only the exception class name plus a
  generic category; full trace logs server-side.
- **Federation targeted forwarding.**
  `FederationGateway._forward_handler` previously broadcast to
  every peer on the destination mesh as long as any peer there
  advertised a policy-allowed capability. Now iterates destination
  peers and forwards only to those whose own advertised
  capabilities pass policy. Closes a cross-mesh data-leakage
  vector.
- **MCP stdio EOF zombie.** When an MCP host closed stdio, the
  MCP server's long-running background tasks kept non-daemon
  threads alive for 20+ seconds (or indefinitely). Now `main()`
  calls `daemon.shutdown()` with a 3 s cap then `os._exit(0)` to
  kill any surviving threads. Exits in 3 s.
- **Audit log bombing rate-limit.** `MSG_GATED_DROP` events
  rate-limited to one per peer per second. A blocked peer sending
  1000 MSGs/sec could previously flood the audit chain at
  ~200 KB/sec, rotating older forensic entries out of the retained
  5-archive window within ~4 minutes. Counter in `/api/mesh_stats`
  still increments on every drop for visibility.
- **Passphrase-file hardening.** `_read_passphrase_file_safe`
  refuses non-regular files (blocks symlinks to `/dev/urandom`
  that would hang reads), caps size at 4096 bytes, rejects empty
  files, warns on world-readable mode on POSIX, validates UTF-8.

### Added documentation

- `SECURITY.md` gained sections: "Storage-at-rest properties"
  (documents ciphertext in SQLite WAL/SHM, metadata plaintext
  by design), "Reticulum (LoRa) transport caveats" (opt-in path,
  known gaps), "TLS and peer authentication" (design choice —
  TOFU+Ed25519 authenticates, TLS for confidentiality only).
- `docs/OPERATOR_TRUST_RUNBOOK.md` gained sections: "Running
  multiple daemons on one host" with the exact multi-daemon
  collision error message, "Audit events you can grep for" with
  the full event-name table + forensic grep recipe,
  "`ironmesh doctor` diagnostic" with the 7-check breakdown.
- `docs/RELEASE_NOTES_v0.8.5.2.md` — complete release notes.
- `tests/test_fuzz_v0852.py` — property-based fuzz tests for
  `Frame.from_dict`, `TrustStore._load`, and
  `MessageStore.queue_pending_trust` against arbitrary inputs
  including unicode, SQL-injection attempts, binary bytes, and
  empty strings.

### Verification

- **656 unit tests and 29 vitest tests green.**
- **Adversarial security review** — findings fixed (see Fixed
  sections above).
- **Cross-version handshake** — v0.8.5.2 daemon interoperates with
  v0.8.4 peers running on Raspberry Pi and NAS (verified on a live
  3-node mesh).
- **Malformed frame fuzz** — 11 payloads (garbage, oversized,
  negative sequence, wrong types) all rejected cleanly. Daemon
  survived.
- **SIGKILL + restart** — trust file intact, SQLite
  `PRAGMA integrity_check` returns `ok`, peers re-handshaken <1s.
- **Trust file deletion mid-run** — daemon survives, file recreated
  on next trust operation.
- **Concurrent promote/block race** — final state consistent, both
  operations captured in audit chain.
- **Real-mesh gate flow** — live MSG blocked at the gate,
  `MSG_GATED_DROP` event fired with the message's msg_id,
  `pending_trust_dropped` counter incremented.

## [0.8.5] — Pending-trust gate + OpenClaw channel

Two themes:

1. **Pending-trust message gate** — opt-in default-deny mode for new
   peers. When enabled, MSG/REQ/RESP frames from peers awaiting
   operator promotion queue at the daemon instead of reaching clients.
   Closes the "any new TOFU-pinned peer can immediately push messages
   into your agents" gap.
2. **OpenClaw channel plugin** — IronMesh peers as a chat surface in
   OpenClaw, complementing the v0.8.4 MCP bridge.

No wire-protocol changes — every v0.8.x peer stays interoperable.

### Added — pending-trust message gate

- **Daemon-side gate** at `bridge.py` `_gate_inbound_msg` — inbound
  user-payload frames (MSG / REQ / RESP) from a peer in trust state
  `pending` are queued in a new SQLite table; `blocked` peers are
  silently dropped; `trusted` peers fall through to the existing
  delivery path. Control frames (HEARTBEAT / REKEY / ROUTE_*) are
  always delivered. Self-loopback bypasses the gate.
- **Trust state machine** in `trust.py` — every pinned peer carries a
  `trust_state` of `pending` | `trusted` | `blocked`. Pre-v0.8.5 stores
  read missing field as `trusted` so existing operators see no
  behavior change on upgrade. New methods: `get_trust_state`,
  `set_trust_state`, `list_by_trust_state`. `pin_peer` accepts an
  initial state (defaults to `trusted`).
- **SQLite schema v3** in `store.py` — `pending_trust_messages` table
  with per-peer FIFO queue (default cap 100/peer with eviction +
  observability counter). New methods: `queue_pending_trust`,
  `drain_pending_trust`, `discard_pending_trust`,
  `list_pending_trust_summary`, `pending_trust_count_for`. Schema
  migrates automatically from v2; existing message + peer data preserved.
- **Operator API** on the daemon: `promote_pending_peer(node_id)` flips
  to trusted and drains the queue back through the normal inbound
  path (history + bus + GUI fanout) in arrival order;
  `block_pending_peer(node_id)` flips to blocked and discards the queue;
  `list_pending_trust()` returns one entry per peer awaiting promotion
  with queued counts and identity metadata.
- **Three new MCP tools** (`ironmesh_mcp/server.py`) — tool count
  18 → 21:
  - `ironmesh_list_pending_trust` — list peers awaiting promotion +
    queued message counts; reports `gate_enabled` so the caller knows
    whether the daemon is actually gating
  - `ironmesh_trust_peer` — promote a pending peer, drain its queued
    messages back through the normal inbound path (idempotent on
    already-trusted peers)
  - `ironmesh_block_peer` — local-only quiet block (requires
    `confirm=true`); distinct from `ironmesh_revoke_peer`, which
    propagates a signed REVOCATION across the mesh
- **`/ws` operator actions** on the dashboard control channel —
  `list_pending_trust`, `promote_peer`, `block_peer` (all guarded by
  the existing GUI session token).
- **Dashboard panel** — new "PENDING TRUST" section under PEERS shows
  the queue at a glance with `PROMOTE` / `BLOCK` action buttons and a
  `gate on` / `gate off` indicator. Auto-refreshes on every gate event.
- **CLI flag** `--require-message-promotion` (env
  `IRONMESH_REQUIRE_MSG_PROMOTION=true`). Default **off** for
  backwards compatibility — opt-in security default for v0.8.5;
  v0.9.0 is the natural place to flip the default with a release of
  operator feedback. Companion knob:
  `--pending-trust-queue-cap N` (default 100).
- **34 hardened tests** in `tests/test_trust_gate.py` — state machine,
  queue admit / cap eviction / drain order / discard / summary,
  schema v2 → v3 migration with data preservation, MCP tool dispatch +
  arg validation, end-to-end gate behavior, concurrent inbound
  serialization, backwards-compat default for pre-v0.8.5 stores.

### Added — OpenClaw channel plugin (alpha)

- **OpenClaw channel plugin** at [`clients/ts-channel/`](clients/ts-channel/),
  package `@wiztheagent/openclaw-ironmesh-channel@0.1.0`.
  OpenClaw agents treat IronMesh peers as a chat channel: incoming
  peer messages arrive as inbound chat, outbound replies go back over
  the encrypted mesh. Adapters implemented: `id`, `meta`,
  `capabilities`, `config`, `lifecycle.start/stop`, `outbound.send`,
  `messaging.subscribe`, `directory.self/listPeers/listPeersLive`,
  `status.describe`. Setup walkthrough:
  [`docs/OPENCLAW_CHANNEL_SETUP.md`](docs/OPENCLAW_CHANNEL_SETUP.md).
- **Persistence layer** (`src/persistence.ts`) — atomic JSON-per-account
  state file under `~/.openclaw/ironmesh-channel/`. Survives gateway
  restart. `PeerRecord` shape: `{nodeId, agentName, lastSeenMs,
  pinnedFingerprint, trust}`. TOFU fingerprint pinned on first
  observation.
- **Peer-mapper** (`src/peer-mapper.ts`) — translates IronMesh node_id
  ↔ OpenClaw `ChannelDirectoryEntry`. Peers seen on the mesh appear in
  OpenClaw's contact list with their agent name + online status.

### Changed

- **TS channel plugin no longer holds its own pending-trust queue.**
  Initial alpha.3 shipped a TS-side gate; in alpha.4 trust gating is
  daemon-authoritative. Pending peers' messages don't reach the plugin
  at all when the daemon gate is on. Operators promote/block via the
  daemon dashboard or the new MCP tools — there is no per-channel
  trust UX. Removes ~400 lines of TS code that would have duplicated
  daemon state.

### Security

- **Pre-release audit caught + fixed**: the gate originally judged
  trust against `frame.source`, an unauthenticated envelope field. A
  pending peer could forge `source = self.node_id` and bypass the
  self-loopback exemption. Trust judgement now keys on `peer_id`, the
  wire-authenticated peer that signed the frame. Regression test
  added (`test_pending_peer_cannot_bypass_via_forged_source`). Trade-
  off: relayed messages now gate on the relay, not the originator —
  documented limitation, may be revisited in v0.9.0.
- **TrustStore failure is fail-closed**: a corrupted or unreadable
  trust file drops gated traffic instead of silently delivering.
- **Multi-daemon trust file collision fixed**: `BridgeDaemon` now
  accepts an explicit `trust_path` (CLI: `--trust-path`). Previously
  every daemon shared `~/.ironmesh/known_peers.json`, causing MAC
  mismatches and silent trust resets when running two daemons on one
  host. The default is unchanged, so single-daemon hosts see no
  difference.

### Notes

- Default behavior unchanged: `--require-message-promotion` is off, so
  upgrading a daemon does not change message delivery for any
  existing peer. Operators opt in; v0.9.0 will revisit defaulting.
- The pending-trust queue is **not encrypted at rest beyond the
  daemon's existing `_encrypt_payload` storage key** — same protection
  as `messages` and `pending_messages` tables.
- The OpenClaw channel plugin remains alpha — single-peer DMs only,
  no setup wizard, no offline replay, no multi-peer routing. Those
  remain on the v0.8.6+ roadmap.
- Python package version remains `0.8.4` until the v0.8.5 cut. The
  channel plugin is npm-only and has its own version (`alpha.4`).

## [0.8.4] — Expanded MCP surface + functional TypeScript client

Incremental release on top of v0.8.3. Lands the MCP-side OpenClaw
integration and a working TypeScript client that speaks the full
IronMesh wire protocol against a live Python daemon. v0.9.0 stays
reserved for when the OpenClaw Channel Plugin also ships. No protocol
changes — every v0.8.x peer stays on the mesh.

### Added

- **OpenClaw integration — MCP bridge.** Ten new tools in
  `ironmesh_mcp/server.py` make agent-to-agent collaboration first-class
  for any MCP host (OpenClaw, Claude Desktop, Claude Code). The existing
  8 tools are unchanged; total is now 18 (8 core + 5 collaboration +
  5 introspection/responder):
  - `ironmesh_discover_capabilities` — fnmatch glob across the mesh
    (`llm:*`, `role:assistant`, etc.)
  - `ironmesh_get_peer_capabilities` — full capability set for one peer
  - `ironmesh_request_service` — REQ/RESP with correlation-id + timeout
    (D5 envelope convention from the integration plan)
  - `ironmesh_broadcast` — send to every online peer, returns
    `{sent_to, failed}` lists. Now uses `asyncio.gather`
    so one slow peer doesn't serialize the whole call N×10 s
  - `ironmesh_subscribe_events` — cursor-based event poll (peer
    connect/disconnect + message arrivals); cursors past
    `high_water_mark` are clamped to keep desynced clients alive
  - `ironmesh_advertise_capability` / `ironmesh_withdraw_capability` —
    declare/retract capabilities mid-session without restarting
  - `ironmesh_get_my_identity` — own `node_id` + name + advertised caps
  - `ironmesh_pending_requests` — observability into in-flight
    REQ/RESP correlation slots
  - `ironmesh_reply_to_request` — first-class responder helper that
    wraps the correlation-id JSON envelope
  Setup walkthrough: [`docs/OPENCLAW_MCP_SETUP.md`](docs/OPENCLAW_MCP_SETUP.md).
  SOUL.md snippet: [`examples/openclaw/soul_mesh_snippet.md`](examples/openclaw/soul_mesh_snippet.md).
- **TypeScript client — functional alpha.** `@wiztheagent/ironmesh-client@0.1.0-alpha.2`
  in [`clients/ts/`](clients/ts/) implements the full wire protocol:
  3-stage passphrase + ECDH + signed-HELLO handshake, binary frame v4
  encode/decode, SecretBox + Ed25519 signing, WebSocket client with
  reconnect (real exponential backoff + jitter, capped at 30 s).
  51 vitest tests including a live e2e that spawns a real Python
  `BridgeDaemon` and exchanges a MSG round-trip (~6 s), plus
  parallel-send and large-payload (256 KiB) e2e coverage.
- **WS API gap analysis** at [`docs/OPENCLAW_WS_API_GAPS.md`](docs/OPENCLAW_WS_API_GAPS.md)
  — five-gap audit concluding the channel plugin is feasible with
  ~120 LOC of new daemon code (under the spike's 200-LOC ceiling).
- **`__main__.py`** so `python -m ironmesh` works from a checkout (the
  installed `ironmesh` script entry already worked).

### Fixed

- **`agent.py`: catch `concurrent.futures.TimeoutError` explicitly in
  `Agent.stop()`.** PEP 616 unified `concurrent.futures.TimeoutError`
  with `builtins.TimeoutError` in Python 3.11; on 3.10 they are
  distinct classes, so a bare `except TimeoutError` missed the timeout
  raised by `fut.result(timeout=5)` when daemon shutdown took longer
  than 5 s on a slow runner. The exception leaked out of the
  `finally:` block in `tests/test_concurrency_audit.py::
  test_100_parallel_sends_no_drops` even though the test body had
  already passed. Same widening applied defensively to `bridge.py`'s
  handshake-failure handler. Full analysis at
  [`docs/BUG-PY310-TIMEOUTERROR-CLASS-SPLIT.md`](docs/BUG-PY310-TIMEOUTERROR-CLASS-SPLIT.md).
- **CI: collapsed dual pytest runs + `scripts/ci-pytest.sh` wrapper.**
  Every job since 04-17 was hitting the 20-min cap because the second
  "Check coverage threshold" step silently re-ran the entire suite
  under `-q`, and pytest itself sometimes hung in atexit cleanup on
  hosted runners despite reporting all tests passing. Now a single
  pytest invocation handles both report + 60% floor, and the wrapper
  exits 0 the moment a green-summary line appears (10 s grace then
  SIGKILL on the hung interpreter).
- **MCP server peer-dict thread safety.** Wrapped every
  `daemon.peers.items()` iteration in `list(...)` so concurrent
  peer connect/disconnect on the daemon's loop thread can't raise
  `RuntimeError: dictionary changed size during iteration` against
  an in-flight MCP tool handler.
- **TS client no longer drops mesh-relayed binary frames.**
  Previously the outer Ed25519 verification used the handshake peer's
  identity key; for relayed frames the outer sig is the relayer's
  identity, so every relayed frame raised "verification failed" and
  was dropped. Now treated as a soft warning — frame is dispatched on
  AEAD authenticity alone (the inner end-to-end source signature,
  when present, remains the originator's trust anchor).
- **MCP correlation-id slots are peer-keyed.**
  `ironmesh_request_service` now records the addressed peer and rejects
  responses from any other peer that knows the cid, recording the spoof
  as a `request_service:cross_peer_echo` observability event.
- **TS client resets `state.sequence` on each `connect()`.**
  Each session has its own sequence space; carrying a counter across
  reconnect would tag the first frame of a new `session_key` with a
  sequence number that has no meaning to the new session.
- **TS client real exponential backoff with jitter.** Was
  a fixed 500 ms delay despite types.ts advertising "doubles up to
  30 s cap." Now `min(initial × 2^attempt, 30000)` ± 20% jitter,
  reset to 0 on successful connect.
- **`tool_get_mesh_stats` errors on a non-started daemon.**
  Was returning a misleading partial snapshot.
- **`tool_get_audit_log` opens with `encoding="utf-8"`.**
  Windows cp1252 default would corrupt non-ASCII fields.
- **TS client drops frames with `sequence == 0`.** Daemon
  already enforces; this catches buggy/malicious peers at the
  application layer.
- **TS `canonicalJson` ASCII-escapes non-BMP chars (audit follow-up).**
  Matches Python's `json.dumps(ensure_ascii=True)` default; without
  this, an agent named `Zoë` or carrying an emoji in a HELLO field
  would fail signature verification.
- **MCP `SERVER_INFO` reads version dynamically** from
  `ironmesh.__version__` so future bumps can't leave it stale.
- **Eleven inline doc / version-bump fixes** — README, Dockerfile,
  docker-compose, dashboard pill, OpenClaw setup doc: all 0.8.3 →
  0.8.4 references corrected.

## [0.8.3] — Operator console redesign, capability GUI fix, E2E audit

Polish release on top of v0.8.2. The dashboard is rebuilt from scratch
to match the ironmesh.org visual identity — a monospace operator
console with the site's 3-stage handshake diagram baked in, a TOFU
trust tri-state column, concurrent WS/RNS transport view, stat-strip
sparklines, regex-capable message feed with pause/export, bearer-token
masked reveal, and a CSP meta tag that locks the page to same-origin
so `pull the plug on your router` still renders. Two latent backend
serialization bugs that kept capabilities and peer names invisible in
`/api/state` are fixed. Plus the full v0.8.3 E2E audit:
Hypothesis fuzzing, concurrency tests, crash matrix, macOS added to CI.
No wire-protocol changes — any v0.8.2 peer stays on the mesh.
Full write-up: [`docs/RELEASE_NOTES_v0.8.3.md`](docs/RELEASE_NOTES_v0.8.3.md).

### Changed

- **Dashboard rebuild.** `bridge.GUI_HTML` replaced end-to-end. New
  layout: IRONMESH wordmark + `v0.8.3 · PRE-1.0` pill, truncated node
  fingerprint (click-to-copy), mesh state pill (OPERATIONAL /
  DEGRADED / ISOLATED), `OFFLINE-FIRST` badge, masked bearer token
  with reveal / copy-URL / rotate icons. Six stat cards with inline
  SVG sparklines rendered from a rolling client-side buffer (zero
  charting libs). Peer table gains Transport (WS/RNS/BOTH), Trust
  (`✓ TOFU-PINNED` / `… HANDSHAKING` / `✗ MISMATCH`), Last-contact
  relative, Capabilities pills. Selecting a peer lights the stages
  of the site's canonical ASCII handshake diagram. Transport panel
  shows live WS LAN throughput + Reticulum status (disabled with
  "install ironmesh[rns] to enable" hint when RNS is absent).
  Hardened terminal-style feed: per-line severity gutter, pause-tail,
  regex or substring search, CSV export, chatter-toggle for
  PING/PONG. Footer ops row: Audit Log / Rotate Keys / Session Rekey
  / Panic Wipe (2-step confirm). System fonts only — no Google Fonts
  or CDN icons; all SVGs inlined as `<symbol>` sprites.
- **Dashboard feed (pre-audit fix, carried forward from the
  unreleased v0.8.2.1 branch):** CONV envelopes render as
  `[response turn N/M] <body>`; peer name resolved from `state.peers`
  rather than raw node_id; PING/PONG/ROUTE_ANNOUNCE/CAPABILITY_ANNOUNCE
  filtered from the operator view by default, behind a chatter
  toggle.
- **Sent-message UX:** Enter-to-send (Shift+Enter for newline, chat
  convention); `ws.send` failures now surface as an alarm row + red
  statusline instead of vanishing. Empty-feed copy disambiguates
  "cleared · waiting for traffic" from "no matching events".

### Fixed

- **`PeerState.to_dict()` never serialized `agent_name`.** v0.8.1
  populated `peer_state.agent_name` from the HELLO exchange, but the
  GUI serializer dropped it. Every peer in `/api/state` showed
  `name: null`, so the dashboard rendered truncated hashes everywhere
  a human name belonged. Now emitted as `"name"`.
- **`_build_full_state()` never serialized the capability registry.**
  Dashboard JS read `state.capabilities` for the A2A dropdown filter
  and per-peer capability pills; the backend never set the key, so
  the filter silently matched zero peers and pills were always empty.
  Now inverted to `{capability -> [node_ids]}` — the shape every
  consumer actually wants.
- **`DedupCache` TOCTOU race.** `is_duplicate()` and `add()` were
  separate lock acquisitions, leaving a window where two concurrent
  handlers could both decide a message was novel and process it
  twice. Replaced with atomic `check_and_add()`. Regression test
  in `tests/test_concurrency.py`.
- **Dashboard `<img>` tag was live with no file at the referenced
  path**, producing a broken image icon on GitHub rendering. The tag
  is now active and points at `docs/assets/dashboard.png`.
- **Docker image was missing `adapters/`, `ironmesh_mcp/`,
  `examples/`**, so `import ironmesh.adapters.langchain_adapter`
  failed inside the container. `pyproject.toml` `[tool.setuptools]
  package-dir` / `packages` re-declared to include every subpackage.
- **User-Agent header leak in `reticulum_transport.py` HTTP probes.**
  Replaced `urllib`'s default `Python-urllib/3.x` with
  `ironmesh/<version>` so passive observers can't fingerprint the
  Python version.
- **Stale `LICENSE` year + author**, missing `NOTICE` file.

### Added

- **v0.8.3 E2E debugging audit.** Nine Hypothesis properties × 400
  inputs on `ConvEnvelope` round-trip + invariants; 6 new concurrency
  tests (`ReplayGuard`, `TokenBucket`, `DedupCache`); a 4-scenario
  crash matrix (SIGKILL mid-handshake, corrupt trust store, corrupt
  routes.json, disk-full on audit.log); 7 pathological payloads
  fired at the dashboard. `pip-audit` + `bandit` clean. Full matrix
  and findings in [`docs/AUDIT_v0.8.3.md`](docs/AUDIT_v0.8.3.md).
- **Real-adapter integration tests.** `tests/integration/` exercises
  `adapters/langchain_adapter.py`, `crewai_adapter.py`,
  `autogen_adapter.py` against a `fake_ollama` stub so the adapters
  can't silently drift.
- **macOS in CI matrix** — now 12 jobs: Ubuntu / Windows / macOS ×
  Python 3.10 / 3.11 / 3.12 / 3.13.
- **Roadmap** at [`docs/ROADMAP.md`](docs/ROADMAP.md) (NAT traversal,
  Android native, Rust port, plugin sandbox).
- **NAT traversal design doc** at
  [`docs/NAT_TRAVERSAL_DESIGN.md`](docs/NAT_TRAVERSAL_DESIGN.md)
  (accepted, implementation deferred to v0.9).
- **`docs/assets/dashboard.png`** — live 3-node mesh screenshot used
  as the README hero.
- **`NOTICE`** file with third-party attribution.

### Verification

582 tests pass (+3 GUI assertion tests for the redesign —
`test_html_has_handshake_diagram`, `test_html_has_csp`,
`test_html_has_trust_tri_state`), +9 Hypothesis fuzz properties,
+6 concurrency tests. ruff clean, mypy clean, bandit clean,
pip-audit clean on Ubuntu + Windows + macOS across Python 3.10–3.13.

## [0.8.2] — Multi-turn AI dialogue, personas, tools, A2A dashboard

Feature release on top of v0.8.1. Adds structured multi-turn
conversations, seven persona presets, byte/time budgets + smart
termination, a one-click AI-to-AI panel in the dashboard, and an
opt-in tool-use registry. No wire-protocol version bump — the new
`CONV` frame is additive. Full write-up:
[`docs/RELEASE_NOTES_v0.8.2.md`](docs/RELEASE_NOTES_v0.8.2.md).

### Added

- `MessageType.CONV` and `ironmesh.conversation` (`ConvEnvelope`,
  `Budget`, `make_reply`, `is_terminal`) for multi-turn agent
  dialogue with turn caps and budgets. Documented in
  [`docs/PROTOCOL_SPEC.md §4.1`](docs/PROTOCOL_SPEC.md).
- `ironmesh.roles` with 7 persona presets; `--role` on
  `examples/llm_bridge.py`. Also advertised as `role:<name>` capability.
- Budgets + `[DONE] <reason>` smart termination in `llm_bridge.py`.
- Dashboard `start_dialogue` GUI WS action + "Start A2A" panel.
- `ironmesh.tools` registry with `echo` / `http-get` / `file-read`
  tools; `--tools` + `--file-read-allow` on `llm_bridge.py`.

### Fixed

- **GUI `message_event` emitted empty `peer_id` and `payload`.**
  `MessageBus.publish` wraps dict payloads in `MappingProxyType`
  which is not a `dict` subclass; the old `isinstance(data, dict)`
  check silently dropped the fields. Now uses
  `collections.abc.Mapping`. Regression in
  `tests/test_hardening.py::TestGUIBroadcastMappingProxy`.

### Verification

559 tests pass (+45 new), ruff/mypy/bandit clean.

## [0.8.1] — Mesh stability: duplicate-handshake race fix

Bug-fix release on top of v0.8.0. No wire-protocol changes.

### Fixed

- **Duplicate-handshake race.** When two peers dial each other at
  nearly the same time, the losing handshake's `finally` block in
  `_handle_connection` used to unconditionally pop
  `ws_clients[peer_id]`, transition the peer to `OFFLINE`, and clear
  the session key — clobbering the winning handshake's still-live
  connection. Symptoms: peers appearing online then immediately
  offline in the dashboard, streams of `No session key for peer X —
  dropping message` warnings, and a mesh that could only keep one
  peer online at a time. The teardown is now scoped to the
  *owning* websocket: `self.ws_clients.get(peer_id) is websocket`.
- **Client-side message-loop cleanup.** The mirror path in
  `_do_client_handshake` previously had no cleanup at all when the
  connection died, leaving stale `ONLINE` state that blocked the
  reconnect loop from ever re-dialing. Same scoped teardown applied.
- **Windows proactor shutdown noise.** Installed a scoped exception
  handler on the daemon's event loop that silences only the known
  CPython `AssertionError` from `proactor_events._start_serving` that
  fires when an `accept()` completes between `server.close()` and
  socket shutdown. Every other exception still surfaces normally.
- **`Agent.peer_by_name()` always returned `None`.** `PeerState.agent_name`
  was never populated during the handshake, so the SDK's friendly-name
  lookup (and the `name` field in `Agent.peers`) didn't work. The
  HELLO-advertised name is now stored on `PeerState` in both the
  server and client handshake paths.

### Added

- **`ironmesh demo` subcommand.** One command spawns two temporary
  agents on `127.0.0.1`, does the full mutual-auth + ECDH handshake,
  sends an encrypted ping, prints the round-trip latency, and exits.
  No keys, ports, or state written to `~/.ironmesh`. Use it as a
  10-second smoke test after `pip install ironmesh`. Pass `--gui` to
  keep both agents up with the dashboard enabled on `alice`'s port+1
  (handy for screenshots and poking around the state endpoints).
- **`docs/USE_CASES.md`.** Five concrete deployment patterns with
  runnable commands: home AI mesh, offline LLM swarm, robotics
  coordination, air-gapped lab, off-grid LoRa comms.
- **`examples/ollama_swarm.py`.** Two local-LLM agents talking over
  an encrypted IronMesh session — the flagship "multiple AI agents
  on your home network, no cloud" demo.
- **`docs/assets/`.** Slot for the README dashboard screenshot.

### Docs + positioning

- README now leads with a stack diagram showing IronMesh *under*
  MCP / LangChain / CrewAI rather than competing with them. Four
  Q&A cards address the common "but doesn't X already do this?"
  objections (MCP, LangGraph, Tailscale, Reticulum).
- Feature comparison table retitled to acknowledge it's one axis
  (offline-first), not a universal ranking.
- Site (ironmesh.org) mirrors the same reframing.

### Regression tests

Two new tests in `tests/test_hardening.py::TestDuplicateHandshakeTeardown`
cover both branches of the fix (loser must not clobber winner; winner
still cleans up its own state). Total: 514 tests, ruff clean, mypy
clean, bandit clean on Ubuntu + Windows across Python 3.10–3.13.

## [0.8.0] — Agent SDK, framework adapters, federation, Go client

First release above the "transport" layer. Turns IronMesh from a
protocol you integrate by hand into a platform you build on.

### Added

- **Agent SDK** (`ironmesh.Agent`) — high-level wrapper over
  `BridgeDaemon` with decorator handlers, sync+async send, capability
  discovery. Joins the mesh in 3 lines.
- **Framework adapters** for LangChain (`create_ironmesh_toolkit`),
  CrewAI (`create_mesh_crew_agent`), and AutoGen (`register_ironmesh`).
- **Federation gateway** (`FederationGateway`, `FederationPolicy`) —
  bridges two independent meshes with allow/deny glob rules on
  capabilities. Runs two Agent instances, one per mesh.
- **Go reference client** (`clients/go/`) — full wire-protocol
  implementation: frame serialization, X25519 ECDH, XSalsa20-Poly1305,
  Ed25519 detached signatures, 3-stage handshake. Crypto primitives
  verified against the Python reference.
- **Docker + PyPI + GitHub release** — `pip install ironmesh`,
  `docker pull wiztheagent/ironmesh:0.8.0`, GitHub release with
  wheel + sdist attached.

### Changed

- Default keys path migrated from `~/.kingpi-secure/ironmesh/keys.json`
  to `~/.ironmesh/keys.json`.
- Python minimum: 3.10 (3.9 was already dropped in 0.7.2).

### Fixed (security)

- Tarfile path-traversal guard in `backup.py` (rejects `..`,
  absolute paths, backslash).
- Narrowed bare `except` clauses in `agent.py` and `crypto.secure_wipe`.

## [0.7.2] — Mesh stability, observability, and backpressure

Focused on production-readiness for multi-node deployments. Closes
Wiz's hardening checklist (per-hop RTT + retries + message lifetime,
queue backpressure, peer-drop alerting, per-peer bandwidth throttle).
All 5 critical and 11/11 high-severity items from the prior audit now
fixed. 472 tests passing, zero regressions.

### Distribution (post-0.7.2 initial commit)

- **PyPI** — `pip install ironmesh` live at
  https://pypi.org/project/ironmesh/0.7.2/ . The wheel ships both
  `ironmesh` and `ironmesh-mcp` console scripts.
- **Docker Hub** — `docker pull wiztheagent/ironmesh:0.7.2` (also
  `:0.7.2-beta` and `:latest`) at
  https://hub.docker.com/r/wiztheagent/ironmesh .
  Dockerfile now copies the `ironmesh_mcp/` subpackage so the MCP
  server is included in the image.
- **GitHub** — public at https://github.com/WizTheAgent/IronMesh
  with v0.7.2-beta tagged as a pre-release.
- **Website** — public at https://ironmesh.org .

### CI + polish (post-0.7.2 initial commit)

- Ruff config tightened: `known-first-party = ["ironmesh", "ironmesh_mcp"]`
  and `combine-as-imports = true` so lint results are reproducible
  between local and GitHub Actions (the env-dependent heuristic was
  firing I001 only on CI).
- Ignore `E501` (line-too-long) and `E402` (import-not-at-top) — both
  were triggering on legitimate patterns (long URLs in docstrings,
  conditional imports).
- Bandit threshold in CI raised to `-lll` (HIGH only). The 5 Medium
  findings are all `B104` (bind to `0.0.0.0`) — intentional for a
  mesh daemon, not a vulnerability. Zero HIGH findings.
- Added `hypothesis>=6.0` to `[dev]` deps so `test_fuzz_protocol.py`
  runs on fresh CI.
- Removed `scripts/sanitize.py` — it was a private→public migration
  tool that itself contained the identifiers it was designed to
  redact.
- `test_refills_over_time` sleep extended to 100 ms to avoid flaky
  failures on Windows (~15.6 ms scheduler granularity).
- GitHub repo metadata set: description, homepage
  (https://ironmesh.org), README BETA banner, Contact section.
- `SECURITY.md` / disclosure email: `info@ironmesh.org`.

### Breaking: Python 3.10+ required

`requires-python` bumped from `>=3.9` to `>=3.10`. Python 3.9 went
EOL in October 2025. The codebase relies on `asyncio.Lock()` being
constructible outside a running loop (a 3.10 change) — keeping the
3.9 compat shim is more complexity than the shrinking 3.9 user base
justifies. If you're on 3.9, pin to `ironmesh==0.7.1` until you
upgrade.

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
