# ACP integration — operator setup

The `ironmesh-acp` adapter speaks **Agent Client Protocol (ACP) v1**
(conformance profile `acp-core-v1@0.3.0`) over stdio. Any
ACP-compatible client — `acpx`, `codex`, `claude`, `droid`, and
others — can prompt a remote IronMesh peer as if it were a local
coding agent.

## Prerequisites

- IronMesh `>=0.9.0` installed (`pip install ironmesh` or
  `pipx install ironmesh`)
- An IronMesh daemon running on this host and reachable on its
  WebSocket port
- The mesh-wide passphrase available in an env var or file

## 1. Spawn the adapter

Direct CLI run:

```bash
export IRONMESH_PASSPHRASE="$(cat ~/.ironmesh/passphrase)"
ironmesh-acp \
    --name acp-agent \
    --port 18768 \
    --peer 127.0.0.1:8765 \
    --default-peer <peer-node-id-32-hex>
```

Or via your ACP client's adapter config. For `acpx`:

```bash
acpx --agent 'ironmesh-acp --peer 127.0.0.1:8765 \
    --default-peer 60a9cca12a98c5ffffe39fdbb6fcbd61' \
    "Summarize what's on the mesh right now."
```

## 2. CLI flags

| Flag | Default | Purpose |
|---|---|---|
| `--name <name>` | `acp-agent` | Mesh agent name advertised on `HELLO` |
| `--port <int>` | `8768` | WebSocket port the embedded daemon binds |
| `--bind <addr>` | `127.0.0.1` | WebSocket bind interface |
| `--peer host:port[,…]` | (none) | Manual peer bootstrap (repeatable) |
| `--default-peer <node-id>` | (none) | 32-hex node id used when `session/new` omits `meta.peer` |
| `--passphrase-env <var>` | `IRONMESH_PASSPHRASE` | Env var holding the mesh passphrase |
| `--passphrase-file <path>` | (none) | File containing the mesh passphrase |
| `--state-dir <path>` | `~/.ironmesh-acp` | Where the embedded daemon stores keys/audit/store |
| `--allow-plaintext-ws` | true | Allow `ws://` (no TLS) |
| `--open-discovery` | false | Disable mDNS allowlist gate |

The default `--state-dir` differs from the production
`~/.ironmesh` so the ACP adapter has its own identity, audit log,
and trust store. Sharing state with a production daemon would mean
the two compete for the same keys + audit chain.

## 3. Wire format reference

ACP v1 frames are JSON-RPC 2.0 over newline-delimited JSON on
stdio. One line in, one line (or several notifications) out.

### `initialize`

Request:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "initialize",
  "params": { "protocolVersion": "0.3.0" } }
```

Response (server advertises capabilities + conformance profile):

```json
{ "jsonrpc": "2.0", "id": 1, "result": {
    "protocolVersion": "0.3.0",
    "conformanceProfile": "acp-core-v1@0.3.0",
    "serverInfo": { "name": "ironmesh-acp", "version": "0.9.2" },
    "capabilities": {
      "session": { "new": true, "prompt": true, "cancel": true }
    } } }
```

### `session/new`

Bind a session to a specific mesh peer:

```json
{ "jsonrpc": "2.0", "id": 2, "method": "session/new",
  "params": { "meta": { "peer": "60a9cca12a98c5ffffe39fdbb6fcbd61" } } }
```

If `meta.peer` is omitted, `--default-peer` is used. Without
either, returns `-32602 invalid params`.

### `session/prompt`

```json
{ "jsonrpc": "2.0", "id": 3, "method": "session/prompt",
  "params": {
    "sessionId": "<uuid from session/new>",
    "prompt": [{ "type": "text", "text": "Summarize the IronMesh README." }]
  } }
```

The server emits one or more `session/update` notifications and
then a final response with `stopReason ∈ {end_turn, completed, cancelled}`.

### `session/update` (notification)

Three update types:

```json
{ "jsonrpc": "2.0", "method": "session/update", "params": {
    "sessionId": "<sid>", "type": "thinking",
    "preview": "Summarize the IronMesh README." } }

{ "jsonrpc": "2.0", "method": "session/update", "params": {
    "sessionId": "<sid>", "type": "agent_message_chunk",
    "content": { "type": "text", "text": "<reply text>" } } }

{ "jsonrpc": "2.0", "method": "session/update", "params": {
    "sessionId": "<sid>", "type": "stop", "stopReason": "end_turn" } }
```

### `session/cancel`

```json
{ "jsonrpc": "2.0", "id": 4, "method": "session/cancel",
  "params": { "sessionId": "<sid>" } }
```

The server acknowledges and emits a terminal `session/update` with
`stopReason: "cancelled"`.

## 4. Reply routing

Two paths, tried in order:

1. **Correlation match** — if the peer sends back a JSON envelope
   `{"correlation_id": "<ours>", "body": "..."}` (the same convention
   `ironmesh_request_service` uses), the reply is delivered precisely
   to the matching prompt. Use this when you control both ends.

2. **First-inbound fallback** — if the peer replies with plain text
   or any other JSON, the first such MSG from the target peer is
   delivered to the oldest pending prompt. This lets the adapter
   interoperate with simple peer agents (the bundled
   `examples/llm_bridge.py`, community agents) that don't implement
   the correlation convention. With multiple concurrent prompts to
   the same peer, fallback can cross replies — pin to one prompt
   per peer, or implement correlation on the peer side.

## 5. Trust model

- The adapter trusts the local daemon URL it dials (and any peer
  that daemon allows through).
- Bearer-token auth is **not** required for stdio — the spawning
  client process owns the adapter, so the trust boundary is the
  client itself. Run the adapter inside a sandbox if the client is
  untrusted.
- The embedded daemon does TOFU pinning on the local handshake
  peer; key changes surface as a warning on next connect.

## 6. Troubleshooting

`no peer specified — pass meta.peer in session/new or start the
server with --default-peer` — every session needs a target peer.
Either configure `--default-peer` at startup or include
`meta.peer` in every `session/new`.

`peer 'xxx' is not a 32-hex node id` — the target must be a
32-character lowercase-hex node id. Discover node ids via
`cat ~/.ironmesh/capabilities.json | jq '.body | fromjson | .remote'`
or via the MCP tool `ironmesh_list_peers`.

`completed (timeout)` instead of `end_turn` — the peer didn't
reply within `IRONMESH_ACP_TIMEOUT` (default 120 s). Bump the
env var, or check that the peer agent is reachable and processing
prompts (`ironmesh trust list` on the peer to confirm the adapter
is trusted).

mDNS `NonUniqueNameException` — another process holds the same
mDNS slot. Pick a distinct `--name` or stop the conflicting
process.

## See also

- [`OPENCLAW_CHANNEL_SETUP.md`](OPENCLAW_CHANNEL_SETUP.md) — chat-channel
  surface for OpenClaw agents.
- [`OPENCLAW_MCP_SETUP.md`](OPENCLAW_MCP_SETUP.md) — MCP bridge.
- [`A2A_INTEGRATION.md`](A2A_INTEGRATION.md) — Agent-to-Agent HTTP
  gateway.
- ACP spec: <https://agentclientprotocol.com>
