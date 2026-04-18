# IronMesh v0.8.4 — Release Notes

**Tag:** `v0.8.4` · **Release date:** 2026-04-18

Incremental release on top of [v0.8.3](RELEASE_NOTES_v0.8.3.md). Lands
the expanded MCP surface that makes IronMesh a first-class substrate
for cross-agent collaboration, introduces a functional TypeScript
client library, and closes out a deep audit with twelve targeted
fixes. No protocol changes — every v0.8.x peer stays on the mesh.

## Highlights

- **18 MCP tools** (up from 8). Any MCP host — OpenClaw, Claude
  Desktop, Claude Code — now gets first-class mesh discovery, REQ/RESP
  request routing, broadcast, capability advertise/withdraw, and
  in-flight observability. See [`docs/OPENCLAW_MCP_SETUP.md`](OPENCLAW_MCP_SETUP.md).
- **TypeScript client library** (`@wiztheagent/ironmesh-client@0.1.0-alpha.2`)
  at [`clients/ts/`](../clients/ts/) — full wire-protocol port,
  live end-to-end tested against a real Python `BridgeDaemon`.
- **Python 3.10 compatibility bug fixed** at root. `concurrent.futures.TimeoutError`
  vs `builtins.TimeoutError` class split on 3.10 is documented in
  [`docs/BUG-PY310-TIMEOUTERROR-CLASS-SPLIT.md`](BUG-PY310-TIMEOUTERROR-CLASS-SPLIT.md).
- **Full audit** of every commit since v0.8.3 — 12 fixes landed,
  written up in [`docs/AUDIT_v0.8.4.md`](AUDIT_v0.8.4.md).

## What's new

### Expanded MCP surface (10 new tools, 18 total)

IronMesh's MCP server (`ironmesh-mcp`) is the shortest path to making
the mesh available to any agent that speaks the Model Context
Protocol. v0.8.4 takes the surface from 8 tools to 18, grouped three
ways:

**Core** (unchanged since v0.8.1):

- `ironmesh_list_peers` · `ironmesh_send_message` · `ironmesh_get_mesh_stats`
- `ironmesh_get_peer_stats` · `ironmesh_list_messages` · `ironmesh_get_audit_log`
- `ironmesh_trust_list` · `ironmesh_revoke_peer`

**Cross-agent collaboration** (new in v0.8.4):

- `ironmesh_discover_capabilities` — fnmatch glob across the mesh
  (`llm:*`, `role:assistant`, `tool:filesystem`, …)
- `ironmesh_get_peer_capabilities` — full capability set for one peer
- `ironmesh_request_service` — REQ/RESP with correlation-id + timeout
- `ironmesh_broadcast` — send to every online peer, returns
  `{sent_to, failed}` lists (uses `asyncio.gather` so one slow peer
  doesn't serialize the whole call)
- `ironmesh_subscribe_events` — cursor-based event poll with clamping
  for desynced clients

**Agent introspection + responder helpers** (new in v0.8.4):

- `ironmesh_advertise_capability` — declare a new capability without
  restarting the daemon
- `ironmesh_withdraw_capability` — symmetric
- `ironmesh_get_my_identity` — own `node_id`, name, advertised caps,
  running state
- `ironmesh_pending_requests` — observability into in-flight REQ/RESP
  correlation slots
- `ironmesh_reply_to_request` — first-class responder that wraps the
  correlation-id JSON envelope

Setup walkthrough: [`docs/OPENCLAW_MCP_SETUP.md`](OPENCLAW_MCP_SETUP.md).
SOUL.md snippet for OpenClaw agents: [`examples/openclaw/soul_mesh_snippet.md`](../examples/openclaw/soul_mesh_snippet.md).

### TypeScript client — functional alpha

`@wiztheagent/ironmesh-client@0.1.0-alpha.2` in [`clients/ts/`](../clients/ts/)
implements the full IronMesh wire protocol:

- **3-stage handshake** — passphrase challenge (HMAC-SHA256) + mutual
  auth, ephemeral Curve25519 ECDH, signed HELLO with channel binding
- **Binary frame v4** — matches `protocol.py` exactly, verified against
  Python-generated golden vectors
- **Encryption** — NaCl SecretBox (XSalsa20-Poly1305), Ed25519 inner +
  outer signatures, attached-form sig parity with Python's `nacl.sign`
- **WebSocket transport** with reconnect (real exponential backoff,
  ±20% jitter, 30 s cap)
- **Typed event API** — connect / disconnect / message / peerConnect /
  peerDisconnect / error

51 vitest tests including a live e2e that spawns a real Python
`BridgeDaemon` subprocess and exchanges a binary-frame MSG round-trip
(~6 s). Parallel-send and 256 KiB-payload e2e coverage included.
TypeScript strict mode, `tsc --noEmit` clean.

Package is published-ready but not yet on npm — reserved for the
`v0.9.0` cut when the OpenClaw Channel Plugin also ships. Install
from the GitHub repo or use as a workspace dependency until then.

### Fixes

Twelve audit-driven fixes (all with regression tests):

- **Python 3.10 `TimeoutError` class split** (`agent.py:276`, `bridge.py:1810`)
  — PEP 616 unified `concurrent.futures.TimeoutError` with
  `builtins.TimeoutError` in 3.11. On 3.10 they're distinct classes,
  so `except TimeoutError` missed the timeout raised by
  `fut.result(timeout=5)`. Full RCA at
  [`docs/BUG-PY310-TIMEOUTERROR-CLASS-SPLIT.md`](BUG-PY310-TIMEOUTERROR-CLASS-SPLIT.md).
- **MCP server peer-dict thread safety** — `daemon.peers` iterations
  now snapshot via `list(...)`. Previous code could crash with
  `RuntimeError: dictionary changed size during iteration` under
  concurrent peer connect/disconnect.
- **TS client no longer drops mesh-relayed binary frames** — outer-sig
  mismatch on relayed frames (where the signer is the relayer, not
  the originator) is now a soft warning, not a drop. Inner end-to-end
  source signature remains the originator's trust anchor.
- **MCP correlation-id slots peer-keyed** — `ironmesh_request_service`
  now records the addressed peer; cross-peer echo is rejected and
  logged as `request_service:cross_peer_echo`.
- **TS client resets `state.sequence` on each `connect()`** — each
  session gets its own sequence space.
- **TS client real exponential backoff with jitter** — fixed 500 ms
  delay replaced with `min(initial × 2^attempt, 30000)` ± 20% jitter,
  reset on success.
- **`tool_get_mesh_stats` errors on a non-started daemon** — was
  returning a misleading partial snapshot.
- **`tool_broadcast` parallelized via `asyncio.gather`** — one slow
  peer no longer blocks `N × 10 s`.
- **`tool_subscribe_events` clamps `cursor > high_water_mark`** —
  desynced clients stay alive.
- **`tool_get_audit_log` opens with `encoding="utf-8"`** — Windows
  cp1252 default would corrupt non-ASCII audit fields.
- **TS `canonicalJson` ASCII-escapes non-BMP chars** — matches
  Python's `json.dumps(ensure_ascii=True)` default. Without this, an
  agent named `Zoë` or carrying an emoji in a HELLO would fail
  signature verification.
- **CI stability** — `scripts/ci-pytest.sh` wrapper handles a
  long-standing atexit hang on hosted runners where pytest reports
  all tests passing but the interpreter doesn't terminate. Unit +
  integration jobs now use the wrapper.

## Compatibility

- **Wire protocol:** unchanged. Any v0.8.x peer (and many v0.7.x
  peers) stays on the mesh.
- **Python:** supports 3.10, 3.11, 3.12, 3.13. Validated on Ubuntu,
  Windows, and macOS.
- **MCP protocol version:** `2024-11-05` (unchanged).

## Artifacts

- **PyPI:** `pip install ironmesh` (add `[rns]` for Reticulum / LoRa).
- **Docker Hub:** `docker pull wiztheagent/ironmesh:0.8.4` (also
  `:latest`). Non-root UID 1000.
- **GitHub Release:** wheel + sdist attached.
- **TypeScript client:** not yet on npm — use the GitHub repo or
  workspace reference; see [`clients/ts/README.md`](../clients/ts/README.md).

## Verification before release

- Full Python suite: **625 passed + 1 xpassed** in ~55 s
- TypeScript suite: **51 passed** in ~17 s (incl 4 live e2e)
- `scripts/release-smoke.sh`: **PASS** (wheel + sdist built, 13
  critical paths verified, 24 modules import from fresh-venv install)
- CI on `main`: all 8 test jobs + integration job green
- `npm audit`: 0 vulnerabilities
- Dependabot alerts: 0 open

## Known limitations

- Manual verification against a live OpenClaw gateway (A.9 in the
  original integration plan) is recommended before heavy production
  use but hasn't been run as part of this release cycle.
- OpenClaw **Channel Plugin** (Path B of the integration plan) is
  not in v0.8.4; reserved for v0.9.0. The TS client is the
  foundation for that work.
- CI atexit hang root cause is still open — the wrapper makes it
  non-fatal but the underlying leak (likely `pytest-asyncio` auto
  mode + `pytest-cov` combiner holding a non-daemon thread) is
  unfixed. Tracker item for v0.8.5.

---

_Full changelog:_ [`CHANGELOG.md`](../CHANGELOG.md)
_Audit report:_ [`docs/AUDIT_v0.8.4.md`](AUDIT_v0.8.4.md)
