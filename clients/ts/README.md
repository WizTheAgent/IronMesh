# @wiztheagent/ironmesh-client

TypeScript / Node.js client for the IronMesh agent-to-agent mesh
protocol. Connects, handshakes, and exchanges messages with an
IronMesh daemon over WebSocket.

> **Status:** functional alpha (`0.1.0-alpha.2`). The full wire
> protocol — 3-stage passphrase + ECDH + signed-HELLO handshake,
> binary frame v4, SecretBox + Ed25519 — is implemented and
> end-to-end tested against a live Python `BridgeDaemon`. Reconnect
> with backoff is wired. Not yet on npm; use as a workspace
> dependency or install from the GitHub repo until 1.0.

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

## What's implemented

| Module | Status | Notes |
|---|---|---|
| `frame.ts` | ✅ done | Binary frame v4 encode/decode + SHA-256 msg-id hash. Round-trips a 64-byte payload through encode→decode in unit tests. |
| `crypto.ts` | ✅ done | `nacl.box.before` for ECDH (NOT raw `scalarMult` — see below), HMAC-SHA256 passphrase proof, NaCl SecretBox seal/open, Ed25519 attached + detached sign/verify, canonical JSON. |
| `handshake.ts` | ✅ done | 3-stage handshake: passphrase challenge with mutual auth, ephemeral X25519 ECDH, signed HELLO with channel-binding. |
| `client.ts` | ✅ done | WebSocket connect, post-handshake message loop, binary frame send/receive, reconnect with backoff, typed event API. |
| Live e2e test | ✅ green | Spawns real Python daemon, exchanges MSG round-trip in ~6 s. |
| Golden vector tests | partial | Frame round-trip + Python-computed HMAC/SHA-256 fixtures pinned in `tests/crypto.test.ts`. Larger fixture set TODO. |
| TOFU pin file | TODO | `pinFile` option recognized but not yet enforced. |
| npm publish | TODO | Reserve `@wiztheagent/ironmesh-client` and publish 0.1.0. |

## Gotcha: NaCl shared-key derivation, not raw X25519

The biggest interop landmine — and the bug that delayed e2e by an
hour: Python's `nacl.public.Box(my_priv, their_pub).shared_key()` does
**X25519 scalarmult followed by HSalsa20 with a zero nonce** (NaCl's
`crypto_box_beforenm`). Raw `tweetnacl.scalarMult` returns only the
scalarmult result and produces a **different** key. Use
`nacl.box.before(theirPub, myPriv)` to match the daemon. This is why
`ecdh()` in `crypto.ts` calls `box.before` rather than `scalarMult`.

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
