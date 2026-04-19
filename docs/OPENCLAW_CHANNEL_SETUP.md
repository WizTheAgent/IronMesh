# OpenClaw + IronMesh — Channel Plugin Setup

The IronMesh **channel plugin** lets an OpenClaw agent treat mesh
peers as a chat channel: incoming peer messages arrive as inbound
chat, outbound replies go back over the encrypted mesh. This is
distinct from the **MCP bridge** (see
[`OPENCLAW_MCP_SETUP.md`](OPENCLAW_MCP_SETUP.md)), which exposes mesh
operations as agent tools rather than a chat surface. You can run
both at the same time.

> **Status:** alpha (`@wiztheagent/openclaw-ironmesh-channel@0.1.0-alpha.1`).
> Single-peer DMs only, no setup wizard, no directory adapter, no
> TOFU prompt UI. See the package's
> [`clients/ts-channel/README.md`](../clients/ts-channel/README.md)
> for the full adapter-coverage matrix.

## When to use the channel plugin vs the MCP bridge

| Scenario | Use |
|---|---|
| Agent wants to *receive* a message from a mesh peer and reply | **channel plugin** |
| Agent wants to *query* the mesh ("who's online?", "send X to peer Y") | **MCP bridge** |
| Both | install both — they don't conflict |

The MCP bridge is best when mesh interactions are agent-initiated
(tool calls). The channel plugin is best when the peer initiates
(unsolicited message that the agent should respond to).

## Prerequisites

- OpenClaw 2026.3 or later (`openclaw --version`)
- An IronMesh daemon running on the host (`ironmesh run` or via
  systemd) and reachable on its WebSocket port
- Your IronMesh passphrase available somewhere your OpenClaw
  application can read it
- Node.js ≥ 18

## Install

Until 1.0 ships to npm, build from source:

```bash
git clone https://github.com/WizTheAgent/IronMesh
cd IronMesh

# Build the underlying TypeScript client first.
( cd clients/ts && npm install && npx tsc )

# Build the channel plugin.
( cd clients/ts-channel && npm install && npx tsc )
```

You now have `clients/ts-channel/dist/index.js` ready to register
with OpenClaw.

## Wire it into OpenClaw

The channel plugin is constructed by your application — OpenClaw
itself doesn't auto-discover npm packages as channels. The recipe:

```ts
import { ironMeshChannelPlugin } from "@wiztheagent/openclaw-ironmesh-channel";
import { defineBundledChannelEntry } from "openclaw/plugin-sdk/core";

const plugin = ironMeshChannelPlugin({
  listAccountIds: (cfg: any) =>
    Object.keys(cfg?.channels?.ironmesh ?? {}),
  resolveAccount: (cfg: any, accountId) => {
    const a = cfg.channels.ironmesh[accountId ?? "default"];
    return {
      accountId: accountId ?? "default",
      url: a.url,
      passphrase: a.passphrase,
      name: a.name,
    };
  },
});

export default defineBundledChannelEntry({
  id: "ironmesh",
  name: "IronMesh",
  description: "Local-first encrypted mesh as an OpenClaw channel",
  importMetaUrl: import.meta.url,
  plugin: { specifier: "./plugin.js" },
  configSchema: {
    /* declare the shape of channels.ironmesh.<accountId> here */
  },
});
```

## Configuring an account

In `~/.openclaw/openclaw.json`:

```json
{
  "channels": {
    "ironmesh": {
      "default": {
        "url": "ws://127.0.0.1:8765",
        "passphrase": "your-mesh-passphrase",
        "name": "openclaw-thegatekeeper"
      }
    }
  }
}
```

Restart OpenClaw. On first inbound MSG from a peer, the plugin will
deliver it to your agent's inbound channel. Replies go back to the
handshake peer.

## What's not in the alpha

These are tracked for the v0.9.0 cut:

- **Setup wizard** — `openclaw channel setup ironmesh` flow
- **Directory adapter** — peers appear in OpenClaw's contact list
- **TOFU pending-trust UI** — first message from an unknown peer
  prompts the operator before delivering
- **Multi-peer rooms** — broadcast to a subset, group conversations
- **Offline replay** — messages received while OpenClaw is off get
  replayed on next start
- **Streaming partial replies** — for long LLM outputs, partial frames

Until then, every account corresponds to one mesh handshake peer; if
you want to talk to multiple peers, configure multiple accounts.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `failed to connect: ECONNREFUSED` | daemon isn't listening on the configured `url` | start `ironmesh run` first |
| Connect succeeds, no messages | inbound subscriber wasn't registered before peer sent | restart OpenClaw — `messaging.subscribe` re-registers on lifecycle.start |
| `passphrase rejected by server` | passphrase mismatch with the daemon | verify both sides use the same value |
| Outbound `ok: false, error: not connected` | lifecycle.start hasn't run yet | wait for OpenClaw to call lifecycle.start (it does this automatically on first send) |
