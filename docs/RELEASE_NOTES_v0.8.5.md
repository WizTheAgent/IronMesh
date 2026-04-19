# IronMesh v0.8.5 — Release Notes

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

- New package `@wiztheagent/openclaw-ironmesh-channel@0.1.0`
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
- 29 vitest tests for the channel plugin (plugin shape + adapter wiring + configSchema validation)

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
  from source for v0.8.5; publish at v0.8.6 once integration friction
  has been shaken out with one or two real users)
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
3. `npm test` in `clients/ts-channel/` (29 tests)
4. Public-facing scrub via `git grep` for internal jargon

### Already completed against a live 3-node mesh

End-to-end validation against a real LAN topology — three hosts of
mixed architecture (a laptop, a Raspberry Pi, and a NAS) — all
running stock `ironmesh run` daemons with a shared mesh passphrase:

| Test | Result |
|------|--------|
| 3-node mesh handshake | All three peers pinned each other; audit log shows continuous `ROUTE_LEARNED` at cost=1 |
| Bidirectional MSGs across all 6 directions | All 6 paths succeeded (each pair both directions, plus a direct Pi↔NAS path that does not route through the laptop) |
| Sustained load: 50 parallel MSGs from one node to another | 50/50 sent, 0 errors, 0 dupes, ~1k msgs/sec sustained throughput |
| v0.8.5 gate against the real mesh (5 MSGs to a daemon with `--require-message-promotion`) | All 5 queued in `pending_trust_messages`; 0 reached message history pre-promote |
| Operator promote via `/ws promote_peer` | `ok=true, drained=5`; all 5 MSGs landed in history in arrival order; trust state flipped pending → trusted |
| Operator block via `/ws block_peer` | `ok=true`; trust state flipped pending → blocked |
| MCP tools end-to-end via stdio JSON-RPC | All 21 tools registered; `ironmesh_list_pending_trust` reports `gate_enabled=true`; `trust_peer` / `block_peer` arg validation enforced |
| Dashboard PENDING TRUST panel + auto-refresh | Verified manually in browser; promote/block buttons drive `/ws` actions; events refresh the panel |

### Real-world bug surfaced + fixed during validation

Multi-daemon trust file collision in **v0.8.4** (live in production
deployments now): when two daemons on one host both default to
`~/.ironmesh/known_peers.json` with different keypairs, each save
invalidates the other's HMAC. Trust store silently resets to empty,
peers re-pin on every reconnect (observed every 20–30s on a host
running `ironmesh run` alongside another ironmesh-derived process).
Hit it five times across the three test nodes during this validation
pass. **v0.8.5 fixes it** via the new `--trust-path` CLI flag +
`BridgeDaemon(trust_path=...)` kwarg, threaded through Agent and the
integration test fixture.

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
