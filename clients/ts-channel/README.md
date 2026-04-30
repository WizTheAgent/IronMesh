# @wiztheagent/openclaw-ironmesh-channel

OpenClaw channel plugin for IronMesh. Lets OpenClaw agents send and
receive messages over the IronMesh peer-to-peer mesh — end-to-end
encrypted, no cloud, your network only.

> **Status:** `0.2.0` — published to npm. Ships with IronMesh
> v0.9.x; forward-compatible across v1.0 per
> [`STABILITY_PROMISE.md`](../../docs/STABILITY_PROMISE.md).
> Implements the lifecycle / outbound / messaging / directory /
> status / config surfaces of the OpenClaw `ChannelPlugin` contract,
> plus a bundled-entry helper that wires the package into OpenClaw's
> loader without glue code. Trust gating is daemon-authoritative
> (since v0.8.5): pending peers' messages queue at the IronMesh
> daemon (not the channel plugin) and operators promote via the
> dashboard or MCP tools — see
> [`docs/OPERATOR_TRUST_RUNBOOK.md`](../../docs/OPERATOR_TRUST_RUNBOOK.md).
> Install: `npm install @wiztheagent/openclaw-ironmesh`.

## What it does

For an OpenClaw agent, IronMesh peers become a channel: the agent can
receive inbound messages from other peers and send replies back, the
same way it interacts with Telegram, Slack, or Matrix channels. The
underlying transport is the encrypted IronMesh wire protocol via the
[`@wiztheagent/ironmesh-client`](../ts/) TypeScript client.

## What's NOT in alpha

- **Setup wizard** — accounts must be configured by hand
- **Group / multi-peer rooms** — DMs only
- **Offline replay** — messages received while OpenClaw was off are
  not surfaced when it comes back up
- **Streaming partial replies**

These remain on the v0.8.6+ roadmap.

## Install

Until 1.0 ships to npm, install from the workspace path:

```bash
npm install file:./clients/ts-channel
```

The package depends on `@wiztheagent/ironmesh-client` (sibling
workspace package — `file:../ts`). Build it once before installing:

```bash
cd clients/ts && npm install && npx tsc
cd ../ts-channel && npm install && npx tsc
```

## Use

### Recommended: bundled entry helper

The fastest path is the bundled entry helper — operators add one
section to `openclaw.json` and one import to their plugin loader, and
the channel just works:

```ts
// In your OpenClaw plugin loader entry file:
import { defineIronMeshChannelEntry }
  from "@wiztheagent/openclaw-ironmesh-channel/entry";

export default await defineIronMeshChannelEntry();
```

```jsonc
// openclaw.json
{
  "channels": {
    "ironmesh": {
      "default": {
        "url": "ws://127.0.0.1:8765",
        "passphrase": "your-mesh-wide-passphrase",
        "name": "my-agent"
      }
    }
  }
}
```

The helper dynamic-imports OpenClaw's `defineBundledChannelEntry` (a
peer dep), wires the channel plugin in with the standard
`channels.ironmesh.<accountId>` config layout, and exposes the channel
to OpenClaw's runtime. The exported `ChannelConfigSchema` is also
surfaced so OpenClaw's `mcp set` / setup tooling can validate the
config block.

### Manual wiring (advanced)

If your OpenClaw config tree puts the IronMesh section somewhere
non-standard, build the plugin yourself:

```ts
import { ironMeshChannelPlugin } from "@wiztheagent/openclaw-ironmesh-channel";

const plugin = ironMeshChannelPlugin({
  listAccountIds: (cfg: any) => Object.keys(cfg?.channels?.ironmesh ?? {}),
  resolveAccount: (cfg: any, accountId) => {
    const a = cfg.channels.ironmesh[accountId ?? "default"];
    return {
      accountId: accountId ?? "default",
      url: a.url,                 // e.g. ws://127.0.0.1:8765
      passphrase: a.passphrase,   // 12+ chars, mesh-wide
      name: a.name,               // agent name advertised on HELLO
    };
  },
});

// Hand `plugin` to OpenClaw's bundled-channel entry helper.
```

When the lifecycle starts, the plugin opens a WebSocket to the
configured IronMesh daemon and runs the full handshake (passphrase
challenge + ECDH + signed HELLO). Inbound `MSG` frames are forwarded
to any subscriber; outbound `text` payloads are sent as `MSG` frames
to the handshake peer.

### Trust gating (operators)

When the IronMesh daemon runs with `--require-message-promotion`
(v0.8.5+), MSGs from peers in `trust_state="pending"` queue at the
daemon until an operator promotes them. The channel plugin sees
nothing from pending peers — only fully-trusted peers' MSGs reach the
subscriber callback. Operators promote/block via:

- The daemon dashboard's PENDING TRUST panel
- The MCP tools `ironmesh_list_pending_trust`, `ironmesh_trust_peer`,
  `ironmesh_block_peer`

See [`docs/OPERATOR_TRUST_RUNBOOK.md`](../../docs/OPERATOR_TRUST_RUNBOOK.md)
for the full workflow.

## Adapter coverage

| OpenClaw `ChannelPlugin` adapter | This package | Notes |
|---|---|---|
| `id` | ✅ `"ironmesh"` | |
| `meta` | ✅ | label, blurb, docs link |
| `capabilities` | ✅ | outbound + inbound + DMs only |
| `config.listAccountIds` / `resolveAccount` | ✅ | delegated to caller |
| `lifecycle.start` / `.stop` | ✅ | open / close WS, load / save state |
| `outbound.send` | ✅ | sends a single `MSG` |
| `messaging.subscribe` | ✅ | inbound `MSG` → callback (refreshes peer last-seen) |
| `directory.self` / `listPeers` / `listPeersLive` | ✅ | peers appear as OpenClaw contacts; persists across restart |
| `status.describe` | ✅ | `linked` / `not linked` + peer node_id |
| Bundled entry helper | ✅ | `defineIronMeshChannelEntry()` — dynamic-imports `openclaw` peer dep |
| `configSchema` | ✅ | `ChannelConfigSchema` + `validateChannelConfig` for setup tooling |
| Trust gating | ✅ | Daemon-side (v0.8.5 `--require-message-promotion`); operator UI in daemon dashboard |
| `setup` / `setupWizard` | ❌ | manual config only |
| `security`, `pairing`, `groups`, `mentions` | ❌ | |
| `resolver`, `actions` | ❌ | |
| `streaming`, `threading`, `agentPrompt` | ❌ | |
| `secrets`, `allowlist`, `doctor` | ❌ | |
| `auth`, `commands`, `elevated`, `heartbeat` | ❌ | |

## Tests

```bash
npm test
```

29 unit tests:

- **plugin** (15) — shape, adapter wiring, connection caching,
  outbound success + error paths, inbound MSG routing, non-MSG
  filtering, directory adapter, status reporter
- **config-schema** (14) — validation accept/reject, account
  resolution, schema descriptor

End-to-end against a real OpenClaw gateway is verified manually as
part of the v0.8.5 release process. Wire-level cross-host messaging
between IronMesh daemons is covered by
[`tests/integration/test_trust_gate_e2e.py`](../../tests/integration/test_trust_gate_e2e.py).

## License

MIT.
