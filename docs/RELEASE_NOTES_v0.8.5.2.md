# IronMesh v0.8.5.2 — Release Notes

## Headline

Patch release on top of v0.8.5. Operator polish for the pending-trust
message gate plus a batch of security hardening fixes.

No protocol changes. Every v0.8.x peer stays interoperable. Default
behavior is unchanged — upgrading a daemon touches no live state.

## Highlights

### Operator polish

- **Audit-log coverage for gate decisions.** Four new HMAC-chained
  event types — `MSG_GATED_QUEUE`, `MSG_GATED_DROP`, `PEER_PROMOTED`,
  `PEER_BLOCKED` — capture every gate decision and every operator
  promote/block. Tamper-evident forensic trail that previously
  existed only as stderr logs.
- **`ironmesh trust set-state <node_id> <pending|trusted|blocked>`
  CLI** for operators who don't run the dashboard. Works offline
  against the trust file. Paired with a new `--trust-path` flag on
  the `trust` subcommand so multi-daemon operators can target the
  right file.
- **Trust-state column in `ironmesh trust list`** output. Surfaces
  the v0.8.5 enum (pending / trusted / blocked) which was previously
  only visible via the dashboard's PENDING TRUST subpanel.
- **Dashboard PEERS table shows trust gate state.** `trust_gate_state`
  now flows through `/api/state` and renders in the main peers table
  as `… PENDING-PROMOTE` or `⛔ BLOCKED` alongside the existing
  `✓ TOFU-PINNED` / `✗ MISMATCH` labels.
- **Queue and gate counters in `/api/mesh_stats` and `/metrics`.**
  Four new observability fields: `gate_enabled`,
  `pending_trust_evicted`, `pending_trust_dropped`,
  `messages_received_blocked`. Fixes a latent bug where the v0.8.5
  trust-queue eviction counter shared a name with the pre-existing
  offline-queue counter — each queue now has its own counter set.
- **Better trust-integrity error message.** When the HMAC integrity
  check fails at load time (the v0.8.4 multi-daemon collision
  pattern), the CRITICAL log now includes the stored-vs-expected
  MAC prefix, the file path, and an explicit pointer to
  `--trust-path`. The previous message was the generic "file may be
  tampered" which misled operators chasing a non-existent compromise.
- **`ironmesh doctor` subcommand.** One-shot diagnostic that checks
  identity key file, trust store MAC plus peer counts, SQLite schema
  version, pending-trust queue depth, gate environment variables,
  port availability, and audit chain integrity. Exit code non-zero
  on any failing check.

### Security hardening

- **Constant-time GUI token comparison.** Previously compared with
  `==` at both the `?token=` query-param and `Authorization: Bearer`
  header paths. A LAN attacker could have recovered the token
  character-by-character via response-latency timing on the `/ws`
  upgrade. Now uses `hmac.compare_digest`.
- **Atomic trust-file write.** `TrustStore._save` previously wrote
  directly with `open(path, "w") + json.dump`. SIGKILL or power loss
  mid-write would leave the file truncated, and operators would lose
  every pinned peer on restart. Now writes to `path.tmp` → `fsync`
  → `os.replace` — atomic on POSIX and same-drive NTFS.
- **Strict `Frame.from_dict` type validation.** Previously accepted
  malformed inputs like `{"type": 123}` (integer) and crashed deep
  in the dispatch path with a confusing error. Now validates `type`,
  `msg_id`, `source`, `destination`, and `sequence` fields at the
  deserialization boundary with clear error messages.
- **MCP tool resource caps.** Every MCP tool that accepts caller
  input now has defensive bounds so a malicious MCP client can't
  exhaust daemon resources:
  - `ironmesh_request_service`: `timeout` clamped to [1, 300]
    seconds; `prompt` capped at 1 MB.
  - `ironmesh_send_message` and `ironmesh_broadcast`: `payload`
    capped at 16 MB. Broadcast per-peer fan-out timeout clamped to
    [1, 60] seconds.
  - `ironmesh_subscribe_events`: `limit` clamped to [1, 1000];
    `cursor` must be non-negative; `kinds` filter capped at 64
    entries.
- **TypeScript channel atomic persistence.** `PluginState.save` in
  `@wiztheagent/openclaw-ironmesh-channel` now calls `fsync` before
  the atomic rename. Without it, a power-loss window between rename
  and disk-flush could leave the new filename pointing at partial
  inode contents. Same class of fix as the Python trust-file atomic
  write above.
- **Framework adapter error-path sanitization.**
  `adapters/langchain_adapter.py` and `adapters/autogen_adapter.py`
  previously returned raw `str(e)` to the LLM's tool-result context
  on exception. File paths, config details, and stack-trace fragments
  could leak into the LLM's context window where a prompt-injection
  probe could exfiltrate them. Now returns only the exception class
  name plus a generic category ("send failed"); full trace logs
  server-side via `logger.exception`.
- **Federation targeted forwarding.**
  `FederationGateway._forward_handler` previously forwarded each
  cross-mesh message to **every** peer on the destination mesh if
  any peer there advertised a policy-allowed capability. An
  attacker on the destination mesh could harvest cross-mesh traffic
  simply by being online, without advertising the matched
  capability. Fixed to iterate destination peers and forward only
  to those whose own advertised capabilities intersect with the
  allow policy. Peers that advertise nothing never receive
  cross-mesh traffic.
- **MCP stdio EOF no longer leaves zombie daemons.** When an MCP
  host closed stdio, the MCP server's `serve()` loop returned
  cleanly but the embedded daemon's long-running tasks (heartbeat,
  cleanup, reconnect, discovery, capability announce, mDNS
  zeroconf, WebSocket server) kept non-daemon threads alive. The
  process survived for 20+ seconds — sometimes indefinitely —
  turning every host disconnect into a zombie daemon holding port
  and DB. Fixed: after `serve()` returns, `main()` now calls
  `daemon.shutdown()` with a 3 s cap and then `os._exit(0)` to kill
  any surviving non-daemon threads. Stdio MCP has no meaningful
  work after host disconnect. Verified exit within 3 s.
- **Audit-log bombing rate-limit.** `MSG_GATED_DROP` audit events
  are now rate-limited to one per peer per second. Without this
  cap, a blocked peer sending 1000 MSGs/sec grew the HMAC audit
  chain at ~200 KB/sec, rotating older forensic entries out of the
  5-archive retention window within ~4 minutes — an attacker could
  flood the log after misbehavior to push their earlier actions
  out of the retained audit tail. The daemon metrics counter
  (`pending_trust_dropped`) still increments every drop, so the
  operator sees the volume in `/api/mesh_stats` even when
  individual events are throttled.
- **Passphrase-file hardening.** `--passphrase-file` and
  `IRONMESH_PASSPHRASE_FILE` now route through
  `_read_passphrase_file_safe`, which:
  - Refuses to read non-regular files (blocks symlinks to
    `/dev/urandom` that would hang on read)
  - Caps reads at 4096 bytes (prevents memory exhaustion from a
    huge file that was pointed at by accident)
  - Rejects empty files with a clear error
  - Warns on world- or group-readable mode on POSIX
  - Validates UTF-8

### MCP host env passthrough

`python -m ironmesh_mcp` now honors `IRONMESH_REQUIRE_MSG_PROMOTION`,
`IRONMESH_PENDING_QUEUE_CAP`, and `IRONMESH_TRUST_PATH` so MCP hosts
(Claude Desktop, Claude Code) can opt their embedded daemon into the
gate via config block.

### Documentation additions

- `SECURITY.md` gained a "Storage-at-rest properties" section
  documenting that SQLite WAL/SHM inherit payload ciphertext (so
  backup leaks don't expose message bodies) and a "Reticulum (LoRa)
  transport caveats" section for operators who enable `--reticulum`.
- `SECURITY.md` gained a "TLS and peer authentication" section that
  explicitly documents the design choice to let TOFU and Ed25519
  authenticate peers while TLS is used only for line-level
  confidentiality.
- `docs/OPERATOR_TRUST_RUNBOOK.md` gained three new sections:
  "Running multiple daemons on one host (`--trust-path`)", "Audit
  events you can grep for", and "`ironmesh doctor` diagnostic".

## Validation

Every feature was exercised end-to-end on a real 3-node LAN mesh
(laptop, Raspberry Pi, NAS) with real Ollama-backed llm_bridge
peers — no synthetic localhost daemons:

| Check | Result |
|---|---|
| Full unit suite | 656 passed, 1 xpassed |
| Adversarial security review | findings fixed (see Security hardening) |
| Cross-version handshake (v0.8.5.2 daemon ↔ v0.8.4 peers) | all 3 peers verified=true |
| Malformed frame fuzz (11 payloads) | daemon survived all, rejected cleanly |
| SIGKILL and restart recovery | trust file intact, SQLite integrity=ok, peers re-handshaken <1s |
| Trust file deletion mid-run | daemon survived, file recreated on next trust op |
| Concurrent promote/block race | final state consistent, both operations in audit trail |
| End-to-end gate drop (live-peer block → llm response → drop) | `MSG_GATED_DROP` fired for real Ollama response, counter incremented |
| 5-minute soak with mixed traffic | no unexpected warnings or errors |

## Migration

Drop-in upgrade from v0.8.5. No schema migration (still v3). No
behavior change unless you explicitly opt into features:

```bash
pip install --upgrade ironmesh          # or: pip install ironmesh==0.8.5.2
docker pull wiztheagent/ironmesh:0.8.5.2
```

## What's not in this release

Same deferrals as v0.8.5 — still on the v0.8.6+ roadmap:

- Default-on flip for `--require-message-promotion`
- `source_signature` relay gate verification
- Multi-peer channel routing
- OpenClaw setup wizard
- Offline replay (needs `get_queued_since` RPC)
- Streaming partial replies
- npm publish of `@wiztheagent/ironmesh-client`

The npm publish of `@wiztheagent/openclaw-ironmesh-channel@0.1.0`
may happen inside this patch window if live OpenClaw-integration
testing stays clean.

## Compatibility

- Wire protocol: unchanged from v0.8.x (`ironmesh/0.3` minimum)
- Trust store format: unchanged
- SQLite schema: v3 (unchanged from v0.8.5)
- MCP tools: 21 (unchanged from v0.8.5 — three v0.8.5 tools got
  additional audit-log coverage)
- Dashboard `/ws` actions: unchanged
- Python API: `BridgeDaemon.__init__` unchanged; `TrustStore.pin_peer`
  unchanged; `trust set-state` is a new CLI subcommand with no Python
  API impact
