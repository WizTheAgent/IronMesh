# Migrating to v0.9 — pending-trust default-on

**Status:** v0.9 is in planning. This doc describes what will change
and how to prepare while still on v0.8.x.

## TL;DR

The pending-trust message gate has been opt-in since v0.8.5. **It
becomes the default in v0.9.** New TOFU peers will land in a per-peer
queue at the daemon and require operator promotion (via dashboard,
MCP, CLI, or `/ws`) before their messages are dispatched to local
subscribers.

If you want the legacy "trust on first message" behavior in v0.9 and
later, you will need to pass `--no-message-promotion` (or set
`IRONMESH_NO_MESSAGE_PROMOTION=true`). Default behavior on a fresh
v0.9 install will be default-deny.

## Why this is changing

Default-deny is the security posture v1.0 will commit to. The
pending-trust gate is the mechanism. Shipping it as opt-in for the
entire v0.8.x series gave operators time to evaluate it on real
deployments without forcing the change. v0.9 makes the safer default
the default.

## How to prepare while you're still on v0.8.x

If you have a deployment running v0.8.5+ today:

### Option 1 — opt in now and stay opted in

Recommended. Get used to the new behavior on your timeline instead of
the day v0.9 ships.

```bash
# Either via env var
export IRONMESH_REQUIRE_MSG_PROMOTION=true

# Or via CLI flag at every start
ironmesh run --require-message-promotion --name <agent> ...
```

When the gate is active, you will see startup output like:

```
[trust-gate] pending-trust message gate is ENABLED
[trust-gate] new peers will queue messages until promoted
```

Promote / block peers via:

```bash
# From the dashboard: PEERS table → row → Promote / Block buttons
# From MCP:
#   ironmesh_trust_peer  (promote, drain queue)
#   ironmesh_block_peer  (block, discard queue)
# From the offline CLI:
ironmesh trust set-state <node_id> trusted
ironmesh trust set-state <node_id> blocked
```

See [`OPERATOR_TRUST_RUNBOOK.md`](../OPERATOR_TRUST_RUNBOOK.md) for
the full operator guide.

### Option 2 — keep current behavior, plan to flip the flag

If your deployment is sensitive to the change (e.g. you have automation
that depends on instant-trust behavior), keep running with the gate
disabled and audit every script / handler that processes inbound
messages from new peers. When v0.9 ships, you have two paths:

1. **Take the new default.** Ensure your operator workflow can promote
   peers in a timely manner. Set up dashboard / MCP / CLI access on
   every node that runs `ironmesh`.
2. **Pin the legacy behavior** with `--no-message-promotion` (or
   `IRONMESH_NO_MESSAGE_PROMOTION=true`). The flag will exist in v0.9
   so existing automations don't break unannounced. The flag will emit
   its own deprecation warning at startup, just like the current
   "pending-trust opt-in disabled" warning does in v0.8.5.3.

The legacy flag is intended as a transition aid, not a long-term
operating mode. Plan to migrate to default-deny eventually.

## What does NOT change

- **Wire protocol.** v0.9 peers and v0.8.x peers stay interoperable.
  The gate is enforced at the receiving daemon; senders see no
  difference.
- **Existing pinned peers.** Peers already pinned in your trust store
  are unaffected. The gate only intercepts messages from newly-pinned
  peers (those completing TOFU for the first time after the gate is
  enabled).
- **Already-promoted peers.** If you promote a peer under the v0.8.x
  opt-in gate, that promotion persists into v0.9. You don't need to
  re-promote on upgrade.
- **Audit log shape.** The four HMAC-chained gate event types added in
  v0.8.5.2 (`MSG_GATED_QUEUE`, `MSG_GATED_DROP`, `PEER_PROMOTED`,
  `PEER_BLOCKED`) keep the same names and semantics in v0.9.

## Failure modes to expect

When the gate is on, the most common operator-visible behaviors are:

- **"My new peer connected but I'm not getting messages."** Expected.
  The peer is pending. Promote it via dashboard / MCP / CLI. Check
  `ironmesh trust list` — pending peers show up with that state.
- **Queue depth growing.** Expected for any peer left pending. The
  per-peer queue cap is configurable; once exceeded, oldest messages
  are evicted (`MSG_GATED_DROP` event, surfaced in
  `/api/mesh_stats.gate_dropped` and the `pending_trust_dropped`
  Prometheus counter). Promote or block decisively.
- **Tests / CI breaks because automation depends on first-message
  delivery.** Expected. Pre-pin peers in your CI fixtures (write
  directly to the trust store before starting the daemon), or run the
  gate disabled in CI specifically.

## Timeline

- **v0.8.5** (2026-04-19, shipped) — gate ships as opt-in
- **v0.8.5.2** (2026-04-19, shipped) — operator polish, audit
  events, offline CLI, doctor diagnostic
- **v0.8.5.3** (2026-04-19, shipped) — startup deprecation warning
  when gate is opt-in disabled
- **v0.9** (planning) — gate becomes default; `--no-message-promotion`
  legacy escape hatch lands

This doc will be updated when v0.9 ships with concrete migration
walkthroughs against the released behavior.

## Questions / edge cases

If your deployment has a pattern that doesn't fit the above (e.g.
fully-automated mesh with no human operator, frequent peer rotation,
multi-tenant trust boundaries), open an issue at
https://github.com/WizTheAgent/IronMesh/issues — your case helps shape
the v0.9 ergonomics before they're locked in.
