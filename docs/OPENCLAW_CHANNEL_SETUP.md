# OpenClaw + IronMesh — Channel Plugin Setup

The IronMesh **channel plugin** lets an OpenClaw agent treat mesh
peers as a chat channel: incoming peer messages arrive as inbound
chat, outbound replies go back over the encrypted mesh. This is
distinct from the **MCP bridge** (see
[`OPENCLAW_MCP_SETUP.md`](OPENCLAW_MCP_SETUP.md)), which exposes mesh
operations as agent tools rather than a chat surface. Both can run
side-by-side.

> **Status:** `@wiztheagent/openclaw-ironmesh@0.2.0`. Multi-peer
> mesh routing is supported; the channel can address any peer the
> local daemon knows about. See `Limitations` near the end of this
> document for what's not yet in the package.

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

- OpenClaw `>=2026.3` (`openclaw --version`)
- IronMesh `>=0.8.5.9` daemon running on this host and reachable on
  its WebSocket port
- IronMesh mesh-wide passphrase (≥12 characters) accessible by the
  OpenClaw process — typically `~/.ironmesh/passphrase`
- Node.js `>=18` (OpenClaw already requires this)

## 1. Install the plugin

The plugin ships as an npm tarball. Download the release artifact (or
build from source per the README) and install through OpenClaw's
plugin manager:

```bash
openclaw plugins install ./wiztheagent-openclaw-ironmesh-0.2.0.tgz
```

Expected output:

```
Extracting wiztheagent-openclaw-ironmesh-0.2.0.tgz…
Installing to ~/.openclaw/extensions/ironmesh…
Installing plugin dependencies…
[plugins] registering channel plugin id=ironmesh
[plugins] channel registration complete
Installed plugin: ironmesh
Restart the gateway to load plugins.
```

Add the plugin to OpenClaw's allow-list so it auto-loads at gateway
startup:

```bash
openclaw config set 'plugins.allow' '["ironmesh"]'
```

If `plugins.allow` already contains other entries, edit the JSON
array in `~/.openclaw/openclaw.json` to append `"ironmesh"` rather
than overwriting.

### Build from source (alternative)

```bash
git clone https://github.com/WizTheAgent/IronMesh
cd IronMesh
( cd clients/ts && npm install && npm run build )
( cd clients/ts-channel && npm install && npm pack )
openclaw plugins install ./clients/ts-channel/wiztheagent-openclaw-ironmesh-0.2.0.tgz
```

## 2. Configure the channel account

The plugin reads its account configuration from
`plugins.entries.ironmesh.config`. Set the three fields:

```bash
openclaw config set 'plugins.entries.ironmesh.config.url' \
    'ws://127.0.0.1:8765'
openclaw config set 'plugins.entries.ironmesh.config.passphrase' \
    "$(cat ~/.ironmesh/passphrase)"
openclaw config set 'plugins.entries.ironmesh.config.name' \
    'openclaw-agent'
```

Field reference:

| Field        | Type     | Description                                             |
|--------------|----------|---------------------------------------------------------|
| `url`        | `string` | WebSocket URL of the IronMesh daemon (`ws://host:port`).|
| `passphrase` | `string` | Mesh-wide shared passphrase (≥12 characters).           |
| `name`       | `string` | Agent name advertised to peers on `HELLO`.              |

The plugin does TOFU on first contact: the local daemon's identity
key is pinned in OpenClaw's plugin state on first successful
handshake. A subsequent fingerprint mismatch surfaces as a warning so
the operator can investigate before continuing.

## 3. Restart the gateway

```bash
systemctl --user restart openclaw-gateway.service
# or, if not under systemd:
openclaw gateway stop
openclaw gateway --port 18789
```

Confirm the channel is registered:

```bash
openclaw channels list
```

The output should include a row similar to:

```
- IronMesh default (openclaw-agent): connected
```

## 4. Send a test message

```bash
openclaw message send --channel ironmesh \
    --target <peer-node-id-32-hex> \
    --message "hello from openclaw"
```

Valid `--target` formats:

- `<32-hex>` — peer's IronMesh node id (preferred; stable across
  rename and key rotation).
- `mesh:<32-hex>` — explicit prefix (equivalent to the above).
- `<agent-name>` — loose name; resolved by the daemon against the
  current peer set (may be ambiguous if multiple peers share a name).

Successful send:

```
[plugins] [ironmesh-channel] account=default connected to ws://127.0.0.1:8765 (peer=<...>)
✅ Sent. Message ID: <uuid>
```

The IronMesh daemon's mesh router relays the message to the target
peer if it is not the directly-connected peer. The destination peer's
agent processes the message and may reply; the reply lands on the
sending OpenClaw agent's inbound channel through the same plugin.

## 5. Discover what's on the mesh

The local daemon advertises capabilities via gossip. To see what
other peers expose, read the persisted `capabilities.json`:

```bash
cat ~/.ironmesh/capabilities.json | jq '.body | fromjson'
```

Example body:

```json
{
  "local": ["llm:llama3", "role:assistant"],
  "my_node_id": "60a9cca12a98c5ffffe39fdbb6fcbd61",
  "remote": {
    "65939b76915e7028565ebdd5dbd23303": ["llm:hermes3:3b", "role:translator"],
    "75fcb2579f9c87f857ec4f82a1540de0": ["llm:qwen-opus-tools:latest"]
  }
}
```

(Node ids in the example are illustrative.)

Use the discovered node ids as `--target` values for cross-peer
messaging. For richer discovery (capability glob matches, peer
metadata, RTT, queue depth), use the MCP bridge — see
[`OPENCLAW_MCP_SETUP.md`](OPENCLAW_MCP_SETUP.md).

## 6. Trust model

The channel plugin trusts the local daemon (the URL it dials).
Pre-shared assumptions:

- The mesh-wide passphrase matches what the daemon expects (the
  daemon validates it during the first handshake; mismatch yields
  `AUTH_FAIL` and the plugin surfaces a warning).
- The local daemon enforces its own pending-trust gate
  (`IRONMESH_REQUIRE_MSG_PROMOTION=1`) when the operator wants to
  approve new peers manually. Configure that on the daemon side; the
  channel plugin defers to whatever the daemon allows through. See
  [`OPERATOR_TRUST_RUNBOOK.md`](OPERATOR_TRUST_RUNBOOK.md).
- Plugins run in-process inside the OpenClaw gateway. Installing
  this channel grants the same trust as installing any other Node
  package globally. Review the source before installing in
  high-assurance environments.

## 7. Limitations (v0.2.0)

- **Reply path requires a persistent gateway plugin.** When the
  channel is loaded by the OpenClaw gateway (the normal mode of
  operation), the connection stays open for the gateway's lifetime
  and replies flow back live. When messages are sent through the
  one-shot `openclaw message send` CLI, the plugin process exits
  after the send completes, and any reply lands queued at the daemon
  until the gateway plugin reconnects.
- **No setup wizard yet.** Configuration is via `openclaw config set`
  rather than an interactive flow.
- **No directory adapter / contact list UI.** Peer discovery is via
  the persisted `capabilities.json` file or the MCP bridge.
- **No streaming partials.** Long LLM replies are delivered as a
  single message after the daemon has the full response.

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Outbound not configured for channel: ironmesh` | gateway hasn't been restarted since `plugins.allow` changed | restart the gateway and retry |
| `Unknown target "..." for IronMesh.` | `--target` did not match any accepted form | pass the explicit 32-hex node id, `mesh:<node-id>`, or a known agent name |
| `failed to connect: ECONNREFUSED` | daemon isn't listening on the configured `url` | start `ironmesh run` first; confirm `ss -tlnp` shows the port |
| Connect succeeds, no inbound messages | daemon's pending-trust gate has the OpenClaw agent queued | promote with `ironmesh trust promote <node-id>` (or the equivalent MCP tool) |
| `mDNS registration failed (NonUniqueNameException)` | another process holds the same mDNS slot | stop the conflicting process or use a distinct `name` field |
| `Capability file failed HMAC verification` | daemon was started with a different identity key than the one that wrote `capabilities.json` | confirm `IRONMESH_KEYS_PATH` matches the daemon's actual keys file |

## See also

- [`PROTOCOL.md`](PROTOCOL.md) — IronMesh wire-protocol reference.
- [`QUICKSTART.md`](QUICKSTART.md) — daemon setup if you don't have
  one running.
- [`CAPABILITIES.md`](CAPABILITIES.md) — capability advertisement,
  discovery, and trust binding.
- [`OPENCLAW_MCP_SETUP.md`](OPENCLAW_MCP_SETUP.md) — MCP bridge
  installation (complementary to this channel plugin).
- `clients/ts/README.md` — the underlying WebSocket client library
  the plugin uses internally.
