# Pending-Trust Message Gate — Architecture (v0.8.5)

## Why

IronMesh's wire-level TOFU pinning (since v0.6) protects against MITM
attacks: every peer's identity key is pinned on first sight, and a key
change disconnects them as a possible attacker. But TOFU does not stop
a brand-new peer from immediately sending arbitrary messages into your
agents the moment they appear on the mesh.

For a single-operator hobby setup that's fine — the operator knows who
should be on the mesh. For a deployment where IronMesh feeds an
LLM agent (e.g. an OpenClaw channel), a chatty new peer can push
prompts into your agent before you've decided whether you trust them.
The pending-trust gate closes that gap by holding new peers' messages
in a queue until an operator promotes the peer to `trusted`.

## Design choice: opt-in, default off

Three options were on the table for the v0.8.5 default:

- **A: Opt-in flag, default off.** No behavior change on upgrade.
- **B: Opt-out flag, default on.** Security-positive, breaks existing
  Go / Python client deployments that rely on auto-trust.
- **C: Default off when no channel-plugin client is connected, on
  otherwise.** Best UX, hidden state controls security.

Option **A** was chosen. A breaking security change deserves its own release
window with explicit operator opt-in feedback before the default
flips. v0.9.0 is the natural place to revisit. C was rejected because
operators can't reason about a security policy whose state is
implicit — "why are messages being queued?" must always have a
predictable answer.

## Where the gate lives

```
Wire      bridge.py                                    Clients
─────────────────────────────────────────────────────────────────
MSG ───→  decrypt + verify
          dispatch_message()
            ├── control frame? → handle, return
            ├── e2e_payload?   → unseal
            ├── _gate_inbound_msg() ◀── trust_state lookup
            │     ├── deliver  → store_message + bus.publish ────→ /ws clients
            │     ├── queue    → pending_trust_messages table
            │     └── drop     → metrics counter only
            └── (post-deliver hooks)
```

The gate is a single decision point inside `_dispatch_message`. It runs
**after** the control-plane filters (REKEY / ROUTE_* / CAPABILITY_* /
REVOCATION) and **before** the message is stored or published. Control
frames are never gated — the protocol depends on them flowing.

## State model

### Trust states (per peer, persisted in `known_peers.json`)

| State    | Behavior                                    | How to enter                |
|----------|---------------------------------------------|------------------------------|
| `trusted`| MSGs deliver normally                       | Operator promote, or default-on-pin when gate is off |
| `pending`| MSGs queue (cap 100/peer FIFO eviction)     | Default on first sight when gate is on               |
| `blocked`| MSGs dropped silently, queue discarded      | Operator block                                       |

Pre-v0.8.5 stores have no `trust_state` field on their peer records.
Read defaults to `trusted` so existing operators see no behavior
change on upgrade.

### Pending message queue (per peer, persisted in SQLite v3)

```sql
CREATE TABLE pending_trust_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_node_id TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    msg_type TEXT NOT NULL,
    payload BLOB,
    priority TEXT DEFAULT 'NORMAL',
    queued_at REAL NOT NULL,
    UNIQUE(source_node_id, msg_id)
);
CREATE INDEX idx_pending_trust_source
ON pending_trust_messages(source_node_id, queued_at);
```

Cap is per-peer (default 100, configurable via
`--pending-trust-queue-cap`). On overflow the oldest message is
evicted and `pending_evicted` counter is incremented. The
`UNIQUE(source, msg_id)` constraint makes duplicate inbound (same
wire MSG arriving twice) idempotent.

Payload encryption-at-rest follows the existing `_encrypt_payload`
storage-key flow — the queue inherits the same protection as the
`messages` and `pending_messages` tables.

## Originator vs. immediate peer

The gate judges trust against `peer_id` — the wire-authenticated peer
whose identity key signed the frame. We deliberately do **not** key on
`frame.source`: that field is unauthenticated metadata on both the
JSON and binary paths (the peer's signature covers the encrypted
payload, not the source field in the envelope). A pending peer could
otherwise forge `source = self.node_id` and bypass the gate via the
self-loopback exemption.

For relayed messages, this means the gate evaluates the **relay**'s
trust state, not the original source. A trusted relay can deliver
messages from a pending peer. This is a known limitation of v0.8.5;
v0.9.0 may add `source_signature` verification so relays gate on the
originator. For deployments where this matters (multi-hop topologies
with mixed trust), prefer direct connections over relays for now.

Self-loopback (`peer_id == self.node_id`) bypasses the gate as a
defensive measure; in practice daemons don't connect to themselves
over the wire, so this branch is dormant.

## Operator surfaces

Three equivalent paths into the gate's promote / block / list API,
all backed by the same daemon methods:

1. **Dashboard** at `http://<daemon>:<port>/?token=<gui_token>` —
   "PENDING TRUST" panel under PEERS, with `PROMOTE` and `BLOCK`
   buttons per peer. `gate on` / `gate off` indicator. Auto-refreshes
   on every `pending_trust` event from the daemon.
2. **MCP tools** (intended for agent-driven operation):
   - `ironmesh_list_pending_trust` — `{gate_enabled, pending: [...]}`
   - `ironmesh_trust_peer` — `{peer}` → `{ok, drained}`
   - `ironmesh_block_peer` — `{peer, confirm: true}` → `{ok, discarded}`
3. **`/ws` actions** for any token-authenticated GUI client:
   - `{action: "list_pending_trust"}` → `pending_trust_list` event
   - `{action: "promote_peer", target_node_id}` → `promote_ack`
   - `{action: "block_peer", target_node_id}` → `block_ack`

## Block vs. revoke

| Operation | Scope        | Wire effect                 | Who notices               |
|-----------|--------------|-----------------------------|---------------------------|
| `block_peer` | local-only | none — peer keeps connecting | only this daemon          |
| `revoke_peer` (existing) | mesh-wide | signed REVOCATION control frame propagates to every connected peer; their daemons drop the pin | every daemon on the mesh  |

Use `block` when you want to silence one peer at one daemon. Use
`revoke` when you want every operator on the mesh to drop trust in
this peer (compromised key, stolen identity, abuse).

## Promote semantics

`promote_pending_peer(node_id)` does three things atomically:

1. Flip the peer's `trust_state` to `trusted` in the trust store
2. Drain the peer's `pending_trust_messages` queue in arrival order
3. Re-publish each drained message back through the normal inbound
   path: `_db.store_message(...)` + `bus.publish(...)`. Downstream
   subscribers (GUI feed, MCP `subscribe_events`, OpenClaw channel
   plugin) see the messages as if they had arrived just now.

Subsequent inbound from this peer takes the `trusted` short path —
no queueing.

Idempotent on already-trusted peers (returns `drained: 0`).

## Failure modes

If `TrustStore` fails to open (corrupted file, permissions, missing
keypair), the gate fails **closed** — drops all gated traffic with an
error log. A broken trust store is a security event; better to refuse
delivery than silently downgrade. The non-gated path (control frames,
self-loopback) is unaffected, so the daemon stays manageable.

## What the gate does NOT do

- **Does not encrypt the queue beyond `_encrypt_payload`** — same
  protection as message history.
- **Does not survive removal of the trust store** — if you delete
  `~/.ironmesh/known_peers.json` and reconnect a pending peer, that
  peer is re-pinned from scratch (fresh `pending` state, queue is
  empty because msg_ids of the deleted history were never seen).
- **Does not propagate to other daemons** — block is local. Only
  REVOCATION (via `broadcast_revocation`) crosses the mesh.
- **Does not gate the control plane** — KEY_ROTATE, REKEY_*,
  ROUTE_ANNOUNCE, CAPABILITY_ANNOUNCE always pass.
- **Does not cap total queue size across peers** — only per-peer.
  100 pending peers each queueing 100 messages = 10000 rows. SQLite
  handles this fine, but operators should not ignore the dashboard
  forever.

## Why daemon-side, not channel-plugin-side

The first iteration of v0.8.5 implemented the gate inside the
TypeScript channel plugin (in-memory queue inside the OpenClaw
process). That meant:

- Trust state lived in two places (TS plugin + daemon trust store)
- Gate state was lost on OpenClaw restart
- Other clients (Go client, Python CLI, future clients) got no benefit
- MCP tools couldn't reach the TS in-memory state without IPC

Moving the gate into the daemon collapsed all of those: one source of
truth, persistent state, every client benefits, MCP tools talk to the
daemon they were already talking to. The TS channel plugin is now
trust-agnostic — it just receives whatever the daemon delivered.

## Test coverage

`tests/test_trust_gate.py` (34 tests):

- TrustStore state machine (10): enum, defaults, pre-v0.8.5 read,
  filter-by-state
- Pending queue (7): admit, idempotent dedup, cap eviction, drain
  order, discard, summary, payload round-trip
- Schema migration (1): live v2 → v3 with data preserved
- MCP tools (5): registration, `confirm` enforcement, peer arg,
  hex-vs-name resolution
- End-to-end gate (11): off-bypass, trusted/pending/blocked actions,
  control frame skip, self-bypass, promote drain order, block
  discard, list shape, concurrent inbound serialization
