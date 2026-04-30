# A2A integration — operator setup

The `ironmesh-a2a` gateway exposes the local IronMesh node as an
**Agent-to-Agent (A2A) v0.3.0 peer** over HTTP. External A2A-aware
services can address the mesh natively — discover the peer's skills
via its `AgentCard`, then send prompts via JSON-RPC or the raw
envelope inbox.

## Prerequisites

- IronMesh `>=0.9.0` installed (`pip install ironmesh` or
  `pipx install ironmesh`)
- An IronMesh daemon running on this host and reachable on its
  WebSocket port
- The mesh-wide passphrase available in an env var or file
- A bearer token chosen by the operator (32+ chars recommended;
  generated with `openssl rand -base64 24`)

## 1. Spawn the gateway

```bash
export IRONMESH_PASSPHRASE="$(cat ~/.ironmesh/passphrase)"
export IRONMESH_A2A_TOKEN="$(openssl rand -base64 24)"

ironmesh-a2a \
    --name a2a-agent \
    --mesh-port 18769 \
    --http-port 18800 \
    --peer 127.0.0.1:8765 \
    --public-url https://your.host.example.com \
    --token "$IRONMESH_A2A_TOKEN"
```

Behind a reverse proxy that terminates TLS, point `--public-url`
at the public HTTPS URL. Behind a load balancer, scale by running
multiple instances each with its own `--mesh-port` and
`--http-port`.

For local development only, `--no-token` disables the bearer-token
check entirely. Do not ship without `--token`.

## 2. CLI flags

| Flag | Default | Purpose |
|---|---|---|
| `--name <name>` | `a2a-agent` | Mesh agent name advertised on `HELLO` |
| `--mesh-port <int>` | `8769` | Embedded daemon's WebSocket port |
| `--http-port <int>` | `18800` | A2A HTTP gateway bind port |
| `--http-bind <addr>` | `127.0.0.1` | HTTP bind interface |
| `--public-url <url>` | `http://<bind>:<port>` | URL the AgentCard advertises |
| `--gateway-id <id>` | embedded daemon's node id | Identifier in envelopes |
| `--token <token>` | (env `IRONMESH_A2A_TOKEN`) | Bearer token clients must present |
| `--no-token` | false | Disable bearer-token check (DEV ONLY) |
| `--peer host:port[,…]` | (none) | Manual mesh peer bootstrap (repeatable) |
| `--passphrase-env <var>` | `IRONMESH_PASSPHRASE` | Env var holding the mesh passphrase |
| `--passphrase-file <path>` | (none) | File containing the mesh passphrase |
| `--state-dir <path>` | `~/.ironmesh-a2a` | Embedded daemon's state files |
| `--max-request-bytes <int>` | `2097152` | Max inbound HTTP body size (2 MiB) |
| `--allow-plaintext-ws` | true | Allow `ws://` mesh transport |

## 3. Endpoints

### `GET /.well-known/agent-card.json`

Public AgentCard. No auth required (clients use it to learn the
auth scheme + URLs).

```json
{
  "protocolVersion": "0.3.0",
  "version": "0.9.2",
  "name": "ironmesh-a2a",
  "description": "IronMesh node exposed as an A2A peer",
  "url": "https://your.host.example.com/a2a/jsonrpc",
  "skills": [
    { "id": "chat", "name": "chat",
      "description": "Encrypted DM bridge to a mesh peer" }
  ],
  "capabilities": {
    "streaming": false, "pushNotifications": false,
    "stateTransitionHistory": false
  },
  "securitySchemes": { "bearer": { "type": "http", "scheme": "bearer" } },
  "security": [{ "bearer": [] }],
  "supportsAuthenticatedExtendedCard": false,
  "defaultInputModes": ["text"],
  "defaultOutputModes": ["text"],
  "additionalInterfaces": [
    { "url": "https://your.host.example.com/a2a/jsonrpc",   "transport": "JSONRPC" },
    { "url": "https://your.host.example.com/a2a/v1/inbox",  "transport": "HTTP+JSON" }
  ]
}
```

### `POST /a2a/jsonrpc`

JSON-RPC 2.0 entry. Currently the only supported method is
`message/send`:

Request:

```bash
curl -X POST https://your.host.example.com/a2a/jsonrpc \
    -H "Authorization: Bearer $IRONMESH_A2A_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "jsonrpc": "2.0", "id": 1, "method": "message/send",
      "params": {
        "destination": "60a9cca12a98c5ffffe39fdbb6fcbd61",
        "text": "Summarize the IronMesh README.",
        "ttl_seconds": 60
      }
    }'
```

Response (success):

```json
{ "jsonrpc": "2.0", "id": 1, "result": {
    "reply": "<the peer's reply text>", "elapsed_ms": 4521 } }
```

Errors:

| Code   | Meaning |
|--------|---------|
| -32602 | Invalid params (missing destination, malformed text, …) |
| -32010 | Authentication failed (bad/missing bearer) |
| -32011 | Replay detected (duplicate nonce — reserved for future HMAC auth) |
| -32012 | Hop limit exceeded (`route_path` already traversed too many gateways) |
| -32013 | No reply within `ttl_seconds` |
| -32014 | Mesh peer unreachable |

`message.parts` (A2A v0.3.0 multipart) is supported as an alternative
to `text`:

```json
"params": {
  "destination": "<node-id>",
  "message": { "parts": [{ "kind": "text", "text": "Hello" }] }
}
```

### `POST /a2a/v1/inbox`

Raw envelope dispatch matching the third-party
`openclaw-a2a-gateway` shape. Useful when speaking gateway-to-gateway
without going through JSON-RPC framing.

Inbound envelope:

```json
{
  "protocol_version": "a2a/v1",
  "message_id": "<uuid>",
  "source": { "gateway_id": "<sender-id>" },
  "destination": "<peer-node-id>",
  "message_type": "command",
  "timestamp": 1714867200,
  "ttl_seconds": 60,
  "route_path": [],
  "hop_count": 0,
  "payload": { "text": "Hello" }
}
```

Response (success — full response envelope):

```json
{
  "protocol_version": "a2a/v1",
  "message_id": "<new-uuid>",
  "correlation_id": "<original message_id>",
  "source": { "gateway_id": "<this-gateway-id>" },
  "destination": "<sender-id>",
  "message_type": "response",
  "timestamp": 1714867204,
  "route_path": ["<sender-id>", "<this-gateway-id>"],
  "hop_count": 1,
  "payload": { "text": "<reply>", "elapsed_ms": 4521 }
}
```

Response (rejected — ack envelope with reason):

```json
{ "protocol_version": "a2a/v1", "message_id": "<uuid>",
  "correlation_id": "<original>",
  "source": { "gateway_id": "<this>" }, "message_type": "ack",
  "status": "rejected", "reason": "loop detected" }
```

### `GET /healthz`

Cheap liveness probe. Returns `{"ok": true, "version": "..."}`. No
auth required.

## 4. Anti-loop + hop limit

Every inbound envelope appends this gateway's `gateway_id` to
`route_path`. If the gateway id is already present, the envelope is
rejected with `loop detected`. `hop_count` is incremented on
relay; the default cap is 8 hops (config knob in the source —
adjust if you operate a deep cross-gateway federation).

## 5. Bearer-token auth (v0.9.0)

The single token is set at startup via `--token` or
`IRONMESH_A2A_TOKEN`. The AgentCard advertises `bearer` as the
security scheme. Clients send `Authorization: Bearer <token>` on
every authenticated request; bad/missing tokens return
`HTTP 401`.

Per-peer HMAC-SHA256 authentication derived from the existing
ECDH session keys (matching the third-party `openclaw-a2a-gateway`
pattern, with `X-A2A-Signature`, `X-A2A-Timestamp`, `X-A2A-Nonce`,
`X-A2A-Source-Gateway` headers + a `NonceCache` for replay
protection) is on the post-v0.9.2 roadmap. Track in
[`docs/ROADMAP_TO_1.0.md`](ROADMAP_TO_1.0.md).

## 6. Reply routing

Same two-path strategy as the ACP adapter:

1. **Correlation match** — preferred. The gateway sends MSGs with a
   JSON envelope `{"correlation_id": "<uuid>", "body": "..."}` and
   resolves the matching JSON-RPC request when the peer echoes the
   correlation id back. Use this for precise multi-prompt routing.
2. **First-inbound fallback** — for peers that don't implement the
   correlation convention (the bundled `examples/llm_bridge.py`,
   community agents), the first inbound MSG from the target peer
   wakes the oldest pending request for that peer.

## 7. Trust model

- **The bearer token is the entire auth boundary in v0.9.0.** Treat
  it as a long-lived secret; rotate it by restarting the gateway
  with a new value.
- The gateway's mesh identity (`gateway_id`) is the embedded
  daemon's IronMesh node id by default. Override with
  `--gateway-id` if you want a stable identifier across daemon key
  rotations.
- The default `--state-dir` of `~/.ironmesh-a2a` keeps the
  gateway's keys, audit log, and trust store separate from a
  co-resident production `ironmesh` daemon.
- HTTP body size is capped (`--max-request-bytes`) to prevent
  trivial DoS via giant payloads.

## 8. Troubleshooting

`HTTP 401 unauthorized — bearer token required` — `Authorization`
header missing or doesn't match the configured token.

`"-32014 mesh peer unreachable"` — the daemon couldn't dispatch
to the destination node id. Check `ironmesh trust list` and the
peer's online status.

`"-32013 no reply from … within Ns"` — the peer received the MSG
but didn't reply within `ttl_seconds`. Bump the TTL, or check
that the peer agent is processing prompts.

`"loop detected"` — the envelope's `route_path` already contains
this gateway's id. Cycle in the federation — investigate
upstream routing.

mDNS `NonUniqueNameException` — another process holds the same
mDNS slot. Pick a distinct `--name`.

## See also

- [`OPENCLAW_CHANNEL_SETUP.md`](OPENCLAW_CHANNEL_SETUP.md)
- [`OPENCLAW_MCP_SETUP.md`](OPENCLAW_MCP_SETUP.md)
- [`ACP_INTEGRATION.md`](ACP_INTEGRATION.md)
- A2A spec: <https://github.com/google-a2a/A2A>
