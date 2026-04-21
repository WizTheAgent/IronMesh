# Trust Binding in IronMesh

Threat model and implementation of the trust-binding features in
IronMesh v0.8.5.6. This doc covers:

- **What is bound to what** in the trust store as of v0.8.5.6
- **The gap each feature closes**
- **Operator-visible surface** (CLI, MCP, dashboard, audit log)
- **What's deliberately still open** and slated for v0.9 wire extensions
  (see [`TRUST_BINDING_WIRE_v0.9.md`](TRUST_BINDING_WIRE_v0.9.md))

## Background

Before v0.8.5.6, IronMesh's pending-trust gate bound one thing:

```
peer_identity  →  trust_state ∈ {pending, trusted, blocked}
```

`peer_identity` is the TOFU-pinned Ed25519 fingerprint. That fingerprint
survives reconnects and key rotations (by design — it IS the identity
root of trust). Good.

But an authenticated peer can advertise different capabilities across
reconnects. A peer promoted to `trusted` while advertising `role:ops`
can reconnect advertising `role:admin` and reach the trusted-peer
code paths with its elevated privilege set. The gate doesn't notice —
its binding is identity-only.

This is the "authenticated but over-privileged after reconnect" hole.

## v0.8.5.6 — capability-set binding

The trust store's per-peer record gains a `capability_hash` field:

```json
{
  "<node_id>": {
    "fingerprint": "<ed25519-fingerprint-hex>",
    "trust_state": "trusted",
    "first_seen": "2026-04-18T...",
    "capability_hash": "<sha256-hex-of-canonical-capabilities>",
    "cap_first_observed": "2026-04-20T..."
  }
}
```

`capability_hash` is SHA-256 over a canonical serialization of the
peer's advertised capability set. The canonical form is:

1. Capabilities are `str` tokens (e.g. `llm:llama3.2`, `role:ops`,
   `tool:http-get`).
2. Serialize by sorting lexicographically, joining with `\n`, and
   UTF-8 encoding.
3. Hash with SHA-256, hex-encode.

Stable against:
- Capability list reordering (sort cancels)
- Trailing whitespace (stripped)
- Case — preserved; `role:ops` and `role:OPS` are distinct by design,
  since capability matching is case-sensitive.

### Gate behavior after v0.8.5.6

On handshake completion:

1. Compute `observed_hash = canonical_cap_hash(peer_declared_caps)`.
2. Look up the peer's stored `capability_hash`:
   - **Empty** (first observation ever, or migrated from a pre-
     v0.8.5.6 trust file) → store `observed_hash` as the peer's
     baseline. Log an `INFO` with the hash prefix. No gate action.
   - **Matches** → peer's trust state is honored as-is. Normal flow.
   - **Differs** → peer's effective trust state is demoted to
     `pending-cap-change`. All inbound messages queue at the daemon
     until an operator re-promotes. An audit event fires:

```
PEER_CAP_SET_CHANGED
  node_id: <peer>
  old_hash: <prev>
  new_hash: <observed>
  added: [list of new capabilities]
  removed: [list of capabilities no longer advertised]
  trust_state_effective: pending-cap-change
```

### Migration (upgrading from v0.8.5.5 or earlier)

Existing `known_peers.json` files don't have the `capability_hash`
field. On first load after upgrade, entries without the field get
`capability_hash: null`. The next successful handshake with each peer
sets the hash (treating this as "first observation"). This is
deliberate TOFU-for-capabilities, matching the existing TOFU-for-
identity pattern.

No operator action is required to upgrade. Security improvement
engages from the next capability change forward.

## v0.8.5.6 — cross-transport replay detection

IronMesh runs multiple transports simultaneously (WebSocket, Reticulum
/ LoRa). DedupCache ensures a duplicate frame arriving via a second
transport is silently dropped — the effect is already prevented. But
the *signal* is lost: operators can't distinguish a benign retry from
an active replay attempt spanning both transports.

As of v0.8.5.6, when DedupCache detects a duplicate that:

1. Matches a prior frame's canonical dedup key (source + sequence +
   MAC), AND
2. Arrived via a **different** transport than the original,

an audit event fires before the drop:

```
MSG_REPLAY_CROSS_TRANSPORT
  peer: <node_id>
  sequence: <N>
  original_transport: ws | rns | mesh
  replay_transport: ws | rns | mesh
  time_delta_ms: <int>
```

The event is HMAC-chained with the rest of the audit log. Operators
can tail it with `jq` for live detection:

```bash
tail -F ~/.ironmesh/audit.log | jq 'select(.event == "MSG_REPLAY_CROSS_TRANSPORT")'
```

A Prometheus counter is also exposed:

```
ironmesh_replay_cross_transport_total{peer, original_transport, replay_transport}
```

### Why detect if we're already protected?

The *effect* of a replay is prevented by DedupCache. The *act* of
replay is a signal:

- **Active MITM** — attacker is recording frames on one transport and
  replaying them on another, hoping for a race with DedupCache
- **Misconfigured relay** — a peer incorrectly forwards the same
  frame over two transports
- **Loop in the mesh topology** — rare, but possible with improper
  federation config

Silent drop hides all three. The audit event + Prometheus counter
surface them.

## Operator surface

### CLI

```bash
# List peers whose capability set changed since last promotion
ironmesh trust list-cap-pending

# Re-promote a peer after reviewing the cap diff
ironmesh trust cap-promote <node_id>

# Re-promote everyone currently in pending-cap-change (scripted deploys)
ironmesh trust cap-promote --all

# See the cap diff that triggered a pending-cap-change
ironmesh trust cap-diff <node_id>
```

### MCP

New tool on the MCP server:

- `ironmesh_pending_cap_changes` — returns the list of peers in
  `pending-cap-change` with their old/new capability sets, suitable
  for an LLM agent to review and act on.

### Dashboard

The PEERS table gains a `cap` column with one of:

- `✓` — capability hash matches the stored value (normal)
- `new` — first observation (no stored hash; TOFU baseline)
- `⚠` — hash changed; peer is in `pending-cap-change`. Row is
  highlighted yellow; clicking opens a diff dialog.

## What's deliberately still open (queued for v0.9)

The reviewer's original questions pointed at two more gaps not
closed by v0.8.5.6:

1. **Transcript hashes for message-history integrity.** Binding the
   pair of peers to an agreed message transcript so a MITM that
   selectively drops or injects frames leaves a visible signal.
2. **Reconnect session-continuity challenge.** Proving that the
   peer reconnecting *after* a disconnect observed the same
   transcript as before — not just the same identity + capability
   set.

Both require wire-protocol extensions (new frame fields, HELLO
negotiation). Shipping them in a patch release would risk mixed-
version mesh instability. They are fully designed in
[`TRUST_BINDING_WIRE_v0.9.md`](TRUST_BINDING_WIRE_v0.9.md) and slated
for v0.9 as opt-in-first, then default-on in v0.9.1 or v1.0.

## Threat model summary

| Threat | v0.8.5.5 and earlier | v0.8.5.6 | v0.9 (planned) |
|---|---|---|---|
| Impersonation via forged Ed25519 key | blocked (TOFU pin) | same | same |
| Over-privilege after reconnect w/ changed caps | **unnoticed** | **detected + re-gated** | same |
| Replay within same transport | blocked (ReplayGuard + DedupCache) | same | same |
| Cross-transport replay | **silently prevented, no signal** | **prevented + audit event** | same |
| MITM selective drop / reorder | no detection | no detection | **transcript hash mismatch** |
| Resumed session without observing prior history | no detection | no detection | **continuity challenge** |

## See also

- [`TRUST_BINDING_WIRE_v0.9.md`](TRUST_BINDING_WIRE_v0.9.md) — design
  for the wire-level extensions queued for v0.9
- [`SECURITY.md`](../SECURITY.md) — overall threat model + hardening
  recommendations
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — formal threat model (will be
  updated for v0.8.5.6)
- [`OPERATOR_TRUST_RUNBOOK.md`](OPERATOR_TRUST_RUNBOOK.md) — operator
  playbook for the pending-trust gate
