# IronMesh v0.8.5.2 — Release Notes

## Headline

Patch release on top of v0.8.5. Operator polish for the pending-trust
message gate + three security hardening fixes found by a deep
pre-submission audit.

No protocol changes. Every v0.8.x peer stays interoperable. Default
behavior is unchanged — upgrading a daemon touches no live state.

## Highlights

### Operator polish (6 items)

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
- **Queue + gate counters in `/api/mesh_stats` + `/metrics`.** Four
  new observability fields: `gate_enabled`, `pending_trust_evicted`,
  `pending_trust_dropped`, `messages_received_blocked`. Fixes a
  latent bug where my v0.8.5 trust-queue eviction clobbered the
  pre-existing offline-queue counter of the same name — each queue
  now has its own counter set.
- **Better trust-integrity error message.** When the HMAC integrity
  check fails at load time (the v0.8.4 multi-daemon collision
  pattern), the CRITICAL log now includes the stored-vs-expected
  MAC prefix + the file path + an explicit pointer to `--trust-path`.
  Previous message was the generic "file may be tampered" which
  misled operators chasing a non-existent compromise.
- **`ironmesh doctor` subcommand.** One-shot diagnostic that checks
  identity key file, trust store MAC + peer counts, SQLite schema
  version, pending-trust queue depth, gate environment variables,
  port availability, and audit chain integrity. Exit code non-zero
  on any failing check. Tested green on live production state (7/7).

### Security fixes (3 items from pre-submission audit)

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

### MCP host env passthrough

Carry-over from v0.8.5 that only shipped fully in v0.8.5.2 after
env-var bug fixes: `python -m ironmesh_mcp` now honors
`IRONMESH_REQUIRE_MSG_PROMOTION`, `IRONMESH_PENDING_QUEUE_CAP`, and
`IRONMESH_TRUST_PATH` so MCP hosts (Claude Desktop, Claude Code) can
opt their embedded daemon into the gate via config block.

## Hackathon-grade validation

Every feature was exercised end-to-end on a **real 3-node LAN mesh**
(a laptop, a Raspberry Pi, and a NAS) with real Ollama-backed
llm_bridge peers — no synthetic localhost daemons, per the
operator's explicit direction:

| Check | Result |
|---|---|
| Full unit suite | 656 passed, 1 xpassed |
| Deep adversarial security audit | 3 findings fixed, 1 false positive |
| Cross-version handshake (v0.8.5.2 daemon ↔ v0.8.4 peers) | all 3 peers verified=true |
| Malformed frame fuzz (11 payloads) | daemon survived all, rejected cleanly |
| SIGKILL + restart recovery | trust file intact, SQLite integrity=ok, peers re-handshaken <1s |
| Trust file deletion mid-run | daemon survived, file recreated on next trust op |
| Concurrent promote/block race | final state consistent, both operations in audit trail |
| Real-mesh end-to-end (live-peer block → llm response → drop) | `MSG_GATED_DROP` fired for real Ollama response, counter incremented |
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

## Verification gates (before tag)

1. `scripts/release-smoke.sh` — wheel packaging + installable smoke
2. `npm test` in `clients/ts-channel/` (29 tests)
3. Full pytest matrix on tag push (12 jobs incl macOS)
4. `ironmesh doctor` green on the test node
5. Public-facing scrub
