# Operator Runbook — Pending-Trust Message Gate (v0.8.5)

A practical guide to running with the new opt-in trust gate enabled.

## TL;DR

```bash
# Enable gating on the daemon (default off)
ironmesh run --passphrase "$PASSPHRASE" --gui --require-message-promotion

# Or via environment
export IRONMESH_REQUIRE_MSG_PROMOTION=true
ironmesh run --passphrase "$PASSPHRASE" --gui
```

When the gate is on, MSGs from any peer pinned for the first time
queue at the daemon until you promote them. Promote via dashboard
button, MCP tool, or CLI.

## Table of contents

1. [Should I enable the gate?](#should-i-enable-the-gate)
2. [Enabling it](#enabling-it)
3. [Inspecting pending peers](#inspecting-pending-peers)
4. [Promoting a peer](#promoting-a-peer)
5. [Blocking a peer](#blocking-a-peer)
6. [Block vs. revoke](#block-vs-revoke)
7. [Tuning the queue cap](#tuning-the-queue-cap)
8. [Troubleshooting](#troubleshooting)
9. [What changes for existing operators on upgrade](#what-changes-for-existing-operators-on-upgrade)

## Should I enable the gate?

| Deployment shape | Recommendation |
|------------------|----------------|
| Two-machine personal mesh, you trust everyone | Off (default). Gate adds friction without security benefit. |
| Daemon feeds an LLM agent (OpenClaw channel, MCP tool) | **On.** Without it, any new peer can push prompts into your agent. |
| Public / semi-public mesh where membership changes | **On.** Forces explicit per-peer admission. |
| Production deployment with audit requirements | **On.** Pending events land in the audit log. |

## Enabling it

CLI flag (preferred for explicit deployments):

```bash
ironmesh run --passphrase "$PASSPHRASE" --gui --require-message-promotion
```

Environment variable (preferred for systemd / docker):

```bash
IRONMESH_REQUIRE_MSG_PROMOTION=true ironmesh run --passphrase "$PASSPHRASE" --gui
```

Docker compose:

```yaml
environment:
  - IRONMESH_PASSPHRASE=...
  - IRONMESH_REQUIRE_MSG_PROMOTION=true
```

The daemon logs the gate state at startup; check the dashboard's
`gate on` / `gate off` indicator under PENDING TRUST to confirm.

## Inspecting pending peers

### Dashboard

`http://<daemon-host>:<port>/?token=<gui-token>` → PEERS panel →
PENDING TRUST subpanel. Each row shows:

- 12-char prefix of the peer's node_id (hover for full)
- Short fingerprint (first 4 / last 4 hex chars)
- Queued message count
- First-seen timestamp
- `PROMOTE` / `BLOCK` buttons

The queued count updates live as the peer keeps sending; the panel
refreshes whenever the daemon emits a `pending_trust` event.

### MCP

```jsonc
// Request
{"name": "ironmesh_list_pending_trust", "arguments": {}}

// Response
{
  "gate_enabled": true,
  "pending": [
    {
      "node_id": "abcdef0123...",
      "fingerprint": "abcd...wxyz",
      "queued_count": 7,
      "oldest_queued_at": 1734567890.123,
      "newest_queued_at": 1734567920.456,
      "first_seen": 1734567880.0,
      "last_seen": 1734567920.456
    }
  ]
}
```

`gate_enabled: false` means the daemon is running with the gate off —
the `pending` list will normally be empty in that case.

### CLI (existing — no new command needed)

```bash
ironmesh trust list
```

The existing trust list shows pinned peers; under v0.8.5 each peer
also carries a `trust_state` field. Look for `pending` entries.

## Promoting a peer

A promotion does three things:

1. Flips the peer's trust state to `trusted`
2. Drains every queued message from that peer back through the
   normal inbound path, in arrival order
3. From this point forward, MSGs from the peer deliver immediately

### Dashboard

Click `PROMOTE` next to the peer.

### MCP

```jsonc
{"name": "ironmesh_trust_peer", "arguments": {"peer": "alice"}}

// Response
{"ok": true, "node_id": "abcdef0123...", "drained": 7}
```

The `peer` arg accepts an agent name (resolved against currently-
connected peers) or a 32-hex node_id verbatim.

## Blocking a peer

A block does two things:

1. Discards every queued message from that peer
2. Silently drops every future MSG from that peer (counter increments;
   peer is not notified)

### Dashboard

Click `BLOCK`. A confirmation dialog appears.

### MCP

```jsonc
{"name": "ironmesh_block_peer", "arguments": {"peer": "spammer", "confirm": true}}

// Response
{"ok": true, "node_id": "abcdef0123...", "discarded": 5}
```

`confirm: true` is required to guard against accidental clicks.

## Block vs. revoke

| You want to…                                       | Use         |
|----------------------------------------------------|-------------|
| Stop one noisy peer at this daemon, quietly        | `block_peer` |
| Tell every operator on the mesh "this key is compromised" | `revoke_peer` (signed, broadcasts a REVOCATION control frame) |

Block is reversible (`set_trust_state(node_id, "trusted")` via
`promote_peer`). Revoke removes the TOFU pin entirely — the next
connection from that node_id is treated as a new (pending) peer.

## Tuning the queue cap

The default per-peer queue cap is 100 messages with FIFO eviction
(oldest dropped on overflow). Override:

```bash
ironmesh run ... --pending-trust-queue-cap 500
```

Or env: `IRONMESH_PENDING_QUEUE_CAP=500`.

Raise it if your peers are bursty and you don't promote often.
Lower it if you want a tight upper bound on storage. Set to 0 to
disable the cap (not recommended — a chatty pending peer can fill
your DB). Eviction count is exposed as `pending_evicted` in
`/api/mesh_stats`.

## Troubleshooting

### "I enabled the gate but messages still flow from <peer>"

That peer is already in the trust store with `trust_state == "trusted"`.
Existing pinned peers default to `trusted` (backwards-compat). To
quarantine an existing peer, use the MCP `ironmesh_block_peer` or
edit its `trust_state` directly:

```python
# from a Python REPL on the daemon host
from ironmesh.trust import TrustStore
from ironmesh.keys import load_keys
keys = load_keys("~/.ironmesh/keys.json", passphrase="...")
ts = TrustStore(agent_key=keys.ed25519_secret[:32])
ts.set_trust_state("<node_id>", "pending")
```

### "Promote returned `error: peer not in trust store`"

The peer disconnected and was pruned, or the trust store was reset.
Reconnect the peer; it will be re-pinned (in `pending` state if the
gate is on).

### "I see `pending_evicted > 0` in stats"

A pending peer's queue exceeded the cap and the oldest messages were
dropped. Either promote/block the peer faster or raise
`--pending-trust-queue-cap`.

### "Dashboard says `gate off` but I started with --require-message-promotion"

Check the daemon logs for argparse errors. Confirm the running
process has the flag with `ps -ef | grep ironmesh` or check the
`require_message_promotion` field in `/api/state`.

### "After daemon restart, pending peers are still pending but their queues are empty"

Expected — the trust state is persisted (`known_peers.json`) but the
queue is also persisted (SQLite WAL), so this should not happen. If
you wiped the DB but kept the trust file, you'll see this. The peer
needs to send again (or you can promote with no drain).

## What changes for existing operators on upgrade

**Nothing**, unless you opt in. Specifically:

- All pre-v0.8.5 pinned peers read as `trusted` (no retroactive gating)
- The flag is off by default
- The new MCP tools are present but inert when the flag is off
- The new dashboard panel shows `gate off` and "no peers awaiting
  promotion" when the flag is off
- The SQLite schema migrates from v2 to v3 in-place; your existing
  message + peer history is preserved

The flag is the single switch.
