# @wiztheagent/ironmesh-client

TypeScript / Node.js client for the IronMesh agent-to-agent mesh
protocol. Connects, handshakes, and exchanges messages with an
IronMesh daemon over WebSocket.

> **Status:** alpha scaffold. The wire protocol (handshake, binary
> frame v4, encryption) is **not yet implemented** — the public type
> surface is in place so consumers can start building against the
> stable API while the implementation lands. Tracker: M2 of the
> IronMesh × OpenClaw integration plan.

## Why this exists

Two consumers benefit from a TS client:

1. **OpenClaw Channel Plugin** (M3) — the long-form integration that
   makes IronMesh peers appear as native OpenClaw contacts in the
   chat UI. Needs a real WS client in TS.
2. **Browser dashboards / Node.js agents** — anyone wanting to drive
   an IronMesh mesh from outside Python.

Breaking it out as a first-class library means the next consumer
doesn't re-pay the cost.

## Install (when published)

```bash
npm install @wiztheagent/ironmesh-client
```

Until 0.1.0 ships to npm, depend directly on the workspace path or
install from the GitHub repo.

## Planned API

```ts
import { IronMeshClient } from "@wiztheagent/ironmesh-client";

const client = new IronMeshClient({
  url: "ws://127.0.0.1:8765/ws-plugin",
  passphrase: process.env.IRONMESH_PASSPHRASE!,
  name: "openclaw-thegatekeeper",
  capabilities: ["openclaw:2026.4", "role:assistant"],
});

client.on("peerConnect", (peer) => console.log("up:", peer.agentName));
client.on("message", (msg) => console.log("from", msg.fromNodeId, msg.payload));

await client.connect();
await client.sendMessage("kingpi", "hello", { priority: "NORMAL" });
```

## Implementation order

| Stage | Module | Notes |
|---|---|---|
| 1 | `frame.ts` | Binary frame v4 — port from `protocol.py`'s FrameV4 |
| 2 | `handshake.ts` (HMAC) | Passphrase challenge — smallest crypto surface |
| 3 | `handshake.ts` (ECDH) | Curve25519 via `tweetnacl.box` + `scalarMult` |
| 4 | `handshake.ts` (HELLO) | Signed identity exchange (`tweetnacl.sign`) + TOFU |
| 5 | `client.ts` | Reconnect with exponential backoff |
| 6 | `tests/` | Live-daemon integration job in CI (Ubuntu only — Node.js ecosystem) |
| 7 | `tests/vectors/` | Cross-impl golden binary frame vectors (Python ↔ TS) |

The biggest risk is wire-protocol drift between this client and
`protocol.py`. Mitigation: shared golden-binary-frame vectors checked
into `tests/vectors/` — both implementations parse identical bytes.

## Daemon-side requirement

The current `bridge.py` exposes a single WebSocket at `/ws` that's
GUI-token-scoped. For the channel plugin we need a plugin-scoped
endpoint (likely `/ws-plugin`) that accepts a longer-lived token and
speaks the full mesh protocol, not the dashboard JSON envelope.
That's tracked under the M0 spike's "WebSocket-API gaps" deliverable
in the plan doc.

## Development

```bash
cd clients/ts
npm install
npm run build       # tsc -> dist/
npm test            # vitest
```

## License

MIT — same as the rest of IronMesh.
