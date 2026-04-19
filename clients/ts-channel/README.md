# @wiztheagent/openclaw-ironmesh-channel

OpenClaw channel plugin for IronMesh. Lets OpenClaw agents send and
receive messages over the IronMesh peer-to-peer mesh — end-to-end
encrypted, no cloud, your network only.

> **Status:** alpha (`0.1.0-alpha.1`). Implements the minimum
> ChannelPlugin surface (lifecycle / outbound / messaging / status /
> config). No setup wizard, no security adapter, no group support, no
> directory adapter, no streaming, no threading. Use it to evaluate
> the design and surface friction; production-grade adapters come in
> a later release.

## What it does

For an OpenClaw agent, IronMesh peers become a channel: the agent can
receive inbound messages from other peers and send replies back, the
same way it interacts with Telegram, Slack, or Matrix channels. The
underlying transport is the encrypted IronMesh wire protocol via the
[`@wiztheagent/ironmesh-client`](../ts/) TypeScript client.

## What's NOT in alpha

- **Setup wizard** — accounts must be configured by hand
- **Group / multi-peer rooms** — DMs only
- **TOFU pending-trust UI** — peers are auto-pinned on first sight
  with `trust: "pending"`; an operator-approval flow that gates
  delivery on `trust: "trusted"` is not wired yet
- **Offline replay** — messages received while OpenClaw was off are
  not surfaced when it comes back up
- **Streaming partial replies**

These are all on the roadmap for the v0.9.0 cut.

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

Register the plugin with OpenClaw via your application's plugin entry:

```ts
import { ironMeshChannelPlugin } from "@wiztheagent/openclaw-ironmesh-channel";

const plugin = ironMeshChannelPlugin({
  // Pull a per-account record out of OpenClaw's loaded config tree.
  // The shape of cfg depends on how you've laid out openclaw.json —
  // here we assume `channels.ironmesh.<accountId>`.
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
challenge + ECDH + signed HELLO). Inbound `MSG` frames are forwarded to
any subscriber; outbound `text` payloads are sent as `MSG` frames to
the handshake peer.

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

12 unit tests covering plugin shape, adapter wiring, connection
caching, outbound success + error paths, inbound MSG routing,
non-MSG filtering, and the status reporter. The end-to-end
"plugin against a real OpenClaw gateway" test is the next milestone
once we have setup-wizard automation.

## License

MIT.
