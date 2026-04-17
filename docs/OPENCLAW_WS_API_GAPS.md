# IronMesh ↔ OpenClaw — WebSocket API Gap Analysis

**Audience:** developers building the OpenClaw Channel Plugin (Path B
of the integration plan) or any other native client that needs to
speak the full IronMesh mesh protocol from outside Python.

**Conclusion up front:** Path B requires **one new WebSocket endpoint**
on the daemon (`/ws-plugin`) and **one new RPC** (`get_queued_since`).
Total daemon-side LOC estimate: ~120 (well under the spike's 200-LOC
rejection threshold, so Path B is GO).

This document is the M0 spike deliverable referenced by
`IronMesh_OpenClaw_Integration_ImplementationPlan.md` §1.3.

## Current state of the daemon's WebSocket surface

`bridge.py` currently exposes:

| Endpoint | Auth | Purpose | Used by |
|---|---|---|---|
| `/ws` | GUI token in `?token=` or `Authorization: Bearer` | JSON envelope (state pushes, send-message commands) | The operator console (GUI_HTML) |

Findings from grepping `bridge.py`:

- The GUI token (`self._gui_token`) is a single-tenant secret printed at
  daemon startup. Any holder gets full read access to mesh state and
  can issue send-message commands on behalf of the daemon's identity.
- The `/ws` JSON envelope is dashboard-shaped (`{type: "state_update",
  data: {...}}` etc.) — it is *not* the mesh wire protocol. A native
  client would have to translate twice.
- Capabilities flow into the GUI envelope (after the v0.8.3 fix to
  `_build_full_state`) — so a Channel Plugin reading `/ws` could
  technically see them, but it would be paying for the dashboard's
  serialization shape it doesn't want.

## Gaps for Path B

### G1. No plugin-scoped endpoint

A channel plugin running in OpenClaw's process should not share the GUI
token. Different threat model: a malicious browser tab on the operator
desktop could pull the GUI token from the URL bar and gain mesh-write
access; that token shouldn't unlock plugin operations. Recommendation:

**New endpoint `/ws-plugin`** with its own auth token (`plugin_token`
or per-plugin tokens). The plugin endpoint speaks the **mesh protocol
directly** — binary frames over WebSocket, same as the daemon-to-daemon
WS transport. This is what `clients/ts/` is being built against.

LOC impact: ~50-80 in `bridge.py` (new aiohttp route + token check +
hand-off to the existing mesh-protocol stack).

### G2. No "fetch queued messages since timestamp" RPC

D3 (offline replay) requires that when a channel plugin restarts, it
can ask the daemon: "give me everything destined for me from peer X
that arrived after my `last_seen_ts`." Today the plugin would have to
either:

- Read `data.db` SQLite directly (couples plugin to schema)
- Subscribe to live events and miss anything that arrived while it was
  off (defeats the point)

Recommendation: **new mesh-protocol message type or RPC**
`QUEUE_FETCH_SINCE { peer_id?, since_ts, limit }` returning a stream of
queued frames. Best implemented as an RPC on the new `/ws-plugin`
endpoint rather than a new mesh MessageType (those propagate; this is
local-only).

LOC impact: ~60 in `bridge.py` (route handler + DB query + frame
serialization). Could re-use `_db.get_messages(...)` which already
takes `since_ts`.

### G3. Capability propagation timing

The plugin needs to know peer capabilities at the moment of receiving
the first message from a new peer (D6 — TOFU pending state needs to
display "this peer offers: llm:hermes3, role:assistant" so the user
can make an informed Trust/Block call). Currently:

- Capabilities propagate via `CAPABILITY_ANNOUNCE` mesh broadcasts
  *after* HELLO completes. There can be a few-hundred-ms gap between
  "first MSG received" and "capabilities arrive."

Recommendation: **bundle capabilities into the HELLO payload** so they
arrive atomically with identity. This is a wire-protocol change — bumps
the frame minor version. Defer to v0.10 if we don't want to break
back-compat in v0.9; for now, the plugin can show "(capabilities
loading…)" for the first second.

LOC impact: ~20 in `protocol.py` (extend HELLO codec) — but pushes
*both* sides of the mesh to upgrade. Recommend deferring.

### G4. No dedicated event stream for plugin

`/ws` pushes `state_update` (every 2s) and `message_event` (real-time).
For a plugin that just wants "tell me when a message arrives" or "tell
me when a peer comes online," subscribing to the GUI WS with its 2s
polling tick is wasteful. Also, the dashboard envelope doesn't include
the raw mesh frame — only a redacted JSON view.

Recommendation: the new `/ws-plugin` endpoint pushes raw mesh frames
*inbound* for messages addressed to the plugin's identity. The plugin
emits *outbound* frames for messages it wants to send. No separate
event stream needed — the wire protocol already has typed frames for
each event.

This is the cleanest design and what the plan assumed.

### G5. mDNS discovery from outside the daemon

The plugin doesn't run mDNS itself — it inherits the daemon's
discovered peer set. This is fine. The daemon already maintains
`self.peers` dict and announces changes via `_hooks` (`on_peer_connect`,
`on_peer_disconnect`). The plugin endpoint relays these as mesh frames
(`PEER_CONNECT`, `PEER_DISCONNECT`) so the plugin's local peer view
mirrors the daemon's.

No new code needed beyond G1.

## Summary table

| Gap | New code | New protocol | Recommendation |
|---|---|---|---|
| G1: plugin endpoint | ~50-80 LOC | No | **DO** in v0.9 |
| G2: queue-since RPC | ~60 LOC | No (local RPC) | **DO** in v0.9 |
| G3: HELLO + capabilities atomic | ~20 LOC | Yes (frame bump) | DEFER to v0.10 |
| G4: event stream | (covered by G1) | No | Implicit in G1 |
| G5: mDNS relay | 0 LOC | No | Already works |

**Total v0.9 daemon LOC for Path B: ~120.**

This is well below the spike's 200-LOC ceiling above which we'd pause
and redesign. **Path B is feasible without a major protocol rework.**
Proceed to M2/M3 once M1 (this PR) is shipped and bake-tested.

## Open questions (for next session)

- Should the new `/ws-plugin` endpoint require pinning of plugin
  identity? (i.e. plugin-side keypair separate from daemon keypair)
  Probably yes for production; not for v0.9.0 alpha.
- Is the `plugin_token` stored alongside the GUI token or in its own
  file? Suggest `~/.ironmesh/plugin_tokens.json` keyed by plugin name,
  with rotation support.
- For D5 REQ/RESP, the MCP path (Path A, M1) uses correlation-id over
  MSG. The plugin path (Path B) could keep that convention or get a
  first-class REQ/RESP MessageType. Decision deferred to M3 design
  pass — keep parity with M1 unless a concrete need surfaces.
