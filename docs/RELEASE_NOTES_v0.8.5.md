# IronMesh v0.8.5 — Release Notes (DRAFT)

> **Status:** draft. Contents will be finalized at tag time. Items
> below describe everything currently on `main` since v0.8.4.

## Headline

Two themes:

1. **Pending-trust message gate** — opt-in default-deny mode for new
   peers. Holds messages from any newly-pinned peer in a per-peer
   queue until an operator promotes them. Closes the "any new TOFU
   peer can immediately push messages into your agents" gap that has
   existed since the wire-level TOFU pinning landed in v0.6.
2. **OpenClaw channel plugin (alpha)** — IronMesh peers as a chat
   surface in OpenClaw, complementing the v0.8.4 MCP bridge.

No wire-protocol changes. Every v0.8.x peer stays interoperable.

## Highlights

### Pending-trust gate

- New CLI flag `--require-message-promotion` (env
  `IRONMESH_REQUIRE_MSG_PROMOTION=true`). **Default off** — upgrading
  changes nothing for existing operators. Opt in when you want
  default-deny on new peers.
- New per-peer trust state (`pending` / `trusted` / `blocked`)
  persisted in `known_peers.json`. Pre-v0.8.5 stores read missing
  field as `trusted` so existing peers are not retroactively gated.
- New SQLite schema (v3) with `pending_trust_messages` table, default
  100/peer cap, FIFO eviction. Migrates automatically from v2.
- Three new MCP tools (`ironmesh_list_pending_trust`,
  `ironmesh_trust_peer`, `ironmesh_block_peer`) — tool count 18 → 21.
- New "PENDING TRUST" dashboard panel under PEERS with `PROMOTE` /
  `BLOCK` action buttons.
- Operator runbook: [`docs/OPERATOR_TRUST_RUNBOOK.md`](OPERATOR_TRUST_RUNBOOK.md)
- Architecture doc: [`docs/TRUST_GATE_ARCHITECTURE.md`](TRUST_GATE_ARCHITECTURE.md)

### OpenClaw channel plugin

- New package `@wiztheagent/openclaw-ironmesh-channel@0.1.0-alpha.4`
  at `clients/ts-channel/`. OpenClaw agents send and receive messages
  over IronMesh as a chat channel.
- Implements: `id`, `meta`, `capabilities`, `config`,
  `lifecycle.start/stop`, `outbound.send`, `messaging.subscribe`,
  `directory.self/listPeers/listPeersLive`, `status.describe`.
- TOFU peer-mapper + persistence (`~/.openclaw/ironmesh-channel/`)
  survives gateway restart.
- Setup walkthrough: [`docs/OPENCLAW_CHANNEL_SETUP.md`](OPENCLAW_CHANNEL_SETUP.md)

### Tests

- 34 new tests in `tests/test_trust_gate.py` covering state machine,
  queue admit + cap eviction + drain order, schema migration, MCP tool
  dispatch, end-to-end gate behavior, concurrent inbound serialization
- 15 vitest tests for the channel plugin (unchanged from alpha.2)

## Migration

```bash
# Just install the new version. Default behavior is unchanged.
pip install --upgrade ironmesh
docker pull wiztheagent/ironmesh:0.8.5
```

Schema migration runs automatically on first start. Trust store stays
backwards-compatible.

To enable the new gate:

```bash
ironmesh run --passphrase "$PASSPHRASE" --gui --require-message-promotion
```

See the runbook for inspection / promote / block workflows.

## What's not in this release

Deferred to v0.8.6+:

- npm publish of `@wiztheagent/openclaw-ironmesh-channel` (install
  from source for v0.8.5; publish at v0.8.6 once we've shaken out
  integration friction with one or two real users)
- npm publish of `@wiztheagent/ironmesh-client`
- Multi-peer channel routing
- Setup wizard for the channel plugin
- Offline replay (cache missed messages, drain on reconnect)
- Streaming partial replies
- Group / room support
- Default-on flip for the trust gate (planned for v0.9.0 after one
  release of operator opt-in feedback)

## Verification gates

Before tagging:

1. `scripts/release-smoke.sh` — wheel packaging + installable smoke
2. Full pytest matrix on tag push (12 jobs)
3. `npm test` in `clients/ts-channel/` (15 tests)
4. Manual: dashboard pending-peers panel exercised against a live
   2-daemon mesh (one daemon with gate on, one peer pinned in
   pending state, promote drains queue)
5. Public-facing scrub via `git grep` for internal jargon

## Compatibility

- Wire protocol: unchanged from v0.8.x (`ironmesh/0.3` minimum)
- Trust store format: backwards-compatible (new optional field)
- SQLite schema: v3, auto-migrates from v2; v2 still readable until
  the migration runs (one-way after that)
- MCP tools: 18 → 21, none removed
- Dashboard `/ws` actions: 3 added (`list_pending_trust`,
  `promote_peer`, `block_peer`), none removed
- Python API: `BridgeDaemon.__init__` adds two optional kwargs
  (`require_message_promotion`, `pending_trust_queue_cap`); existing
  callers unaffected. `TrustStore.pin_peer` adds an optional
  `trust_state` kwarg with a backwards-compatible default.
