# IronMesh v0.8.4 — Deep Audit Report

**Date:** 2026-04-17
**Scope:** Every commit since `v0.8.3` (19 commits, ~6,100 lines added across 42 files).
**Method:** Three parallel deep-dive agents (MCP bridge, TypeScript client, docs/CHANGELOG cross-check) plus a foreground functional smoke covering CLI, MCP stdio, both test suites, type-check, and version consistency. Findings synthesized below by severity.

## TL;DR

- Code works. Python 603+1 tests pass in ~60 s; TS 38 tests pass in ~9 s including a live e2e against a real Python daemon.
- **Six straggler bugs were fixed inline during the audit** (version-bump completion + the SERVER_INFO hardcode + the canonicalJson unicode bug). All listed below.
- **Two CRITICAL bugs identified but not fixed**, both bounded in scope: a thread-safety race in the MCP server's peer-dict iteration and a wrong-key signature verification in the TS client when receiving relayed mesh frames.
- **One HIGH security gap** (correlation-id not keyed by peer node_id) and **one HIGH protocol-port hazard** (sequence not reset on TS-client reconnect).
- **Top expansion ideas:** five more MCP tools that would obviously help OpenClaw agents (advertise_capability, withdraw_capability, reply_to_request, get_my_identity, pending_requests).

## What was fixed inline during the audit

| # | File | Issue | Fix |
|---|---|---|---|
| F1 | `README.md` line 11 | "v0.8.3 — pre-1.0" + "582 tests" | → "v0.8.4 — pre-1.0" + "603 tests" |
| F2 | `README.md` line 144 + 547–548 | `wiztheagent/ironmesh:0.8.3`, "Latest: v0.8.3" | → 0.8.4 throughout |
| F3 | `README.md` line 276 | "OpenClaw bridge (NEW in v0.9.0)" | → "v0.8.4" |
| F4 | `README.md` line 504 | "v0.8.3 (current)" with stale section | New "v0.8.4 (current)" paragraph; v0.8.3 demoted |
| F5 | `Dockerfile` lines 4 + 8 | `ironmesh:0.8.3` | → 0.8.4 |
| F6 | `docker-compose.yml` lines 14 + 38 | `ironmesh:0.8.3` | → 0.8.4 |
| F7 | `bridge.py` line 497 | dashboard pill `v0.8.3 · PRE-1.0` | → v0.8.4 |
| F8 | `docs/OPENCLAW_MCP_SETUP.md` lines 16, 84, 100, 127 | "v0.9.0" / "≥ 0.9.0" / "0.9.0" | → "v0.8.4" |
| F9 | `docs/OPENCLAW_MCP_SETUP.md` lines 19–22 | False claim that MCP attaches to a running daemon | Rewritten to describe actual embedded-only behavior + caveat |
| F10 | `ironmesh_mcp/server.py` line 76 | `SERVER_INFO = {"version": "0.8.4"}` hardcoded | Reads `ironmesh.__version__` dynamically |
| F11 | `clients/ts/src/crypto.ts` `canonicalJson` | Non-ASCII names produced different bytes than Python's `ensure_ascii=True` default → HELLO sig would fail | Post-process to `\uXXXX`-escape every codepoint ≥ 0x80; verified parity for `"Zoë"` and `"🔐"` |

After F11 the TS suite is 38 tests (was 37), both unicode parity assertions green.

## Confirmed working

| Check | Result |
|---|---|
| `python -m pytest tests/` | 603 passed + 1 xpassed in ~60 s |
| `cd clients/ts && npx vitest run` | 38 passed in 9.4 s (incl 6.8 s live e2e vs real `BridgeDaemon`) |
| `cd clients/ts && npx tsc --noEmit` | 0 errors |
| `ironmesh --help` (installed CLI) | Lists 8 subcommands |
| `python -m ironmesh --help` | Works (was added in commit `4fd23f0`) |
| `python -m ironmesh_mcp` stdio handshake | Returns 13 tools, `serverInfo.version = "0.8.4"` |
| Version consistency across `pyproject.toml`, `__init__.py`, MCP `SERVER_INFO`, README, CHANGELOG, Dockerfile, docker-compose, bridge.py dashboard | All `0.8.4` after F1–F11 |

## Outstanding — CRITICAL

### C1. MCP server thread safety on peer dict iteration
**File:** `ironmesh_mcp/server.py`, multiple sites (`tool_list_peers`, `tool_send_message` name-lookup, `_resolve_target`).
**Problem:** the daemon's asyncio loop thread mutates `daemon.peers` on every connect/disconnect, while MCP tool handlers iterate it on the stdio reader thread without locking. `tool_broadcast` already uses `list(self.daemon.peers.items())` defensively; the others don't. Under live traffic on a multi-peer mesh, a `RuntimeError: dictionary changed size during iteration` is plausible.
**Suggested fix:** wrap every `self.daemon.peers.items()` / `.get()` in `list(...)` or marshal through `run_coroutine_threadsafe`.
**Effort:** ~10 lines.

### C2. TS client drops relayed binary frames as "outer signature failed"
**File:** `clients/ts/src/client.ts:321-334`.
**Problem:** outer Ed25519 verification uses `peerIdentityPublic` (the daemon we handshook with), but the daemon signs binary frames with its **hop-authentication** key — when relaying a frame from another node, the outer sig is the relayer's identity, not the originator's. Direct daemon→client (1-hop) happens to match. The moment a relay is involved, every signed frame raises and gets dropped.
**Suggested fix:** treat outer-sig failure as a soft warning rather than dropping the frame, or look up the immediate-hop key. Inner end-to-end source signature (when present) remains the authoritative trust signal.
**Effort:** ~5 lines + a test.

## Outstanding — HIGH

### H1. Correlation-id not keyed by peer
**File:** `ironmesh_mcp/server.py:186-194`.
**Problem:** `tool_request_service` keys the response slot by `correlation_id` only. Any peer with knowledge of the cid can reply and steal the response. The wire convention is documented in `OPENCLAW_MCP_SETUP.md:128-143` so anyone who reads it can spoof. UUID4 collision risk is negligible; adversarial echo isn't.
**Suggested fix:** store `expected_peer = node_id` in the slot; in `_on_bus_event`, drop responses where `peer_id != slot.expected_peer`.
**Effort:** ~3 lines.

### H2. TS client doesn't reset sequence on reconnect
**File:** `clients/ts/src/client.ts:81`, `connect()`.
**Problem:** `state.sequence` is initialized to `0n` in the constructor and never reset. On reconnect, the new session keeps incrementing from where the previous one ended. Doesn't necessarily break replay-guard semantics, but mismatches the daemon's expectation that each session starts at sequence 1, and stains forward secrecy minorly.
**Suggested fix:** `this.state.sequence = 0n;` at the top of `connect()`.
**Effort:** 1 line.

### H3. TS client has no real exponential backoff
**File:** `clients/ts/src/client.ts:398-403` and `clients/ts/src/types.ts:17`.
**Problem:** `types.ts` advertises "Doubles up to 30s cap" but `_scheduleReconnect` does a single fixed `setTimeout(opts.reconnectInitialDelayMs)`. On a daemon outage, all clients reconnect every 500 ms forever → thundering herd. Type doc lies.
**Suggested fix:** track `reconnectAttempt`; compute `min(initial * 2**attempt, 30000)` with ±20% jitter; reset on successful connect.
**Effort:** ~15 lines + tests.

## Outstanding — MEDIUM

| # | File | Issue |
|---|---|---|
| M1 | `ironmesh_mcp/server.py:300` | `tool_get_mesh_stats` on a non-started daemon returns a misleading partial snapshot — should error explicitly |
| M2 | `ironmesh_mcp/server.py:546-559` | `tool_broadcast` serializes with `fut.result(timeout=10)` per peer — N×10s worst case under load. Should use `asyncio.gather` |
| M3 | `ironmesh_mcp/server.py:587` | `tool_subscribe_events` cursor > high-water-mark falls back to itself, leaving client out of sync. Should clamp to high_water_mark |
| M4 | `ironmesh_mcp/server.py:375` | `tool_get_audit_log` `open(log_path)` lacks `encoding="utf-8"` — Windows `cp1252` can corrupt non-ASCII fields |
| M5 | `clients/ts/src/client.ts:317-342` | `_handleIncoming` accepts frames with `sequence == 0` — no client-side replay guard. Daemon rejects, but a malicious peer can flood us with seq=0 |
| M6 | `clients/ts/src/client.ts:228` | `Date.now() / 1000` float timestamp — sub-millisecond precision differs from Python's `time.time()`. Fine for replay-guard windows but worth a comment |
| M7 | `clients/ts/src/client.ts:271` | `Set as Set<Listener<E>> as never` cast hides type unsafety. Practically OK; consider a typed helper |

## Outstanding — Test gaps

These behaviors are not currently covered. Most are specific reproducers for the issues above.

**Python (`tests/test_mcp.py`):**
- Correlation-id collision / cross-peer spoof (would catch H1)
- Broadcast partial failure where some peers succeed and one times out
- Cursor > high_water_mark behavior (M3)
- `kinds` filter with multiple prefixes
- JSON-RPC error envelope when a tool handler raises
- `get_mesh_stats` on a non-started daemon (M1)
- Large payload (>1 MB) round-trip
- One real-daemon end-to-end smoke (currently 100% in-memory fixture)

**TypeScript (`clients/ts/tests/`):**
- Wrong-passphrase `PASSPHRASE_REJECTED` mid-stage 1
- Bad peer HELLO signature
- Reconnect after disconnect (would catch H2 + H3)
- Large payload (>1 MB)
- Parallel `sendMessage` calls (race on `state.sequence`)
- Mesh-relayed frame with non-peer source (would catch C2)
- Frame with `seq=0` from peer (would catch M5)
- Outer-sig present but invalid (currently emits error, never tested)

## Expansion — five MCP tools that would obviously help OpenClaw agents

1. **`ironmesh_advertise_capability(capability, ttl?)`** — currently the only way to change advertisements is restart the daemon. Trivial wrapper around `daemon.advertise_capability()`.
2. **`ironmesh_withdraw_capability(capability)`** — symmetric.
3. **`ironmesh_reply_to_request(correlation_id, body)`** — first-class responder helper so OpenClaw agents don't have to manually JSON-wrap a response. Right now responders must read the inbound `MSG`, parse JSON, extract `correlation_id`, build a reply envelope, send it. A one-call helper removes the footgun.
4. **`ironmesh_get_my_identity()`** — return own `node_id`, name, advertised caps. Trivial.
5. **`ironmesh_pending_requests()`** — observability into the in-flight `_pending` table.

## Process notes

- The `SESSION_REPORT_2026-04-17.md` at the repo root is a session artifact, not release documentation. Recommend deleting before tagging v0.8.4 or moving to a `docs/sessions/` folder.
- The OpenClaw integration plan lives at `C:\Users\jonha\.kingpi-secure\ironmesh\IronMesh_OpenClaw_Integration_ImplementationPlan.md` (out of tree) and still targets v0.9.0 for "full integration done". Since v0.8.4 ships only Path A + functional TS client, that plan target is still correct — Path B (channel plugin) gets v0.9.0.
- Manual A.9 from the plan (verify the new MCP server against the live OpenClaw gateway on `gatekeeper`) has not been run yet — recommended before tagging.

## Bottom line

The v0.8.4 work is substantively complete and tested. The 11 inline fixes close the obvious version-bump stragglers and the unicode hazard. The two CRITICAL items have known small fixes; neither is a regression from v0.8.3 (C1 has been latent the whole time; C2 is new code in this update). My recommendation: fix C1, C2, H1 before tagging — three small surgical changes — and treat the rest as v0.8.5 follow-up.
