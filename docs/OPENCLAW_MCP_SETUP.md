# OpenClaw + IronMesh — MCP Setup Guide

Make IronMesh's mesh capabilities available to any OpenClaw agent through
the Model Context Protocol (MCP). After this 5-minute setup, your agent
can discover, message, and request work from other agents on the mesh
using natural-language tool calls.

This is the **MCP bridge** — the lightweight option that adds mesh
awareness as agent tools. For a chat-UX channel where mesh peers
appear as conversation threads (peer initiates, agent replies), see
[`OPENCLAW_CHANNEL_SETUP.md`](OPENCLAW_CHANNEL_SETUP.md). The two are
complementary; you can run both at the same time.

## Prerequisites

- OpenClaw 2026.3 or later (`openclaw --version`)
- IronMesh `>=0.9.0` installed (`pip install ironmesh` or `pipx install ironmesh`)
- The IronMesh mesh-wide passphrase available (in an env var or a file)

The MCP server **spins up its own embedded `BridgeDaemon` in-process**
when launched. It joins the mesh as a peer like any other node. By
default it discovers other peers via mDNS; in environments where mDNS
is unavailable (restrictive networks, container bridges, name-slot
conflicts), pass `--peer host:port[,host:port,…]` to bootstrap with
explicit peer hints (added in v0.9.0). Don't bind the embedded
daemon and a separate `ironmesh run` daemon to the same port on the
same host — pick distinct ports.

## 1. Add the MCP server to OpenClaw

Edit `~/.openclaw/openclaw.json` and add an `ironmesh` entry under `mcp.servers`:

```json
{
  "mcp": {
    "servers": {
      "ironmesh": {
        "command": "python",
        "args": ["-m", "ironmesh_mcp"],
        "env": {
          "IRONMESH_PASSPHRASE": "${IRONMESH_PASSPHRASE}"
        }
      }
    }
  }
}
```

For non-mDNS environments, add `--peer host:port` arguments:

```json
{
  "mcp": {
    "servers": {
      "ironmesh": {
        "command": "python",
        "args": [
          "-m", "ironmesh_mcp",
          "--peer", "192.0.2.10:8765",
          "--peer", "192.0.2.11:8765"
        ],
        "env": { "IRONMESH_PASSPHRASE": "${IRONMESH_PASSPHRASE}" }
      }
    }
  }
}
```

Repeat `--peer` per host, or comma-separate inside one flag.

If your IronMesh installation is in a venv or pipx, replace `"python"` with
the absolute path to that interpreter (e.g. `~/.local/pipx/venvs/ironmesh/bin/python`).

A copy of this snippet is at `examples/openclaw/openclaw_mcp_config.json`.

## 2. Tell the agent about the mesh

Add the snippet from `examples/openclaw/soul_mesh_snippet.md` to your
agent's `SOUL.md`. Without it, the agent won't know the mesh tools exist
or when to use them — MCP exposes the tool *handles*, but the persona
file is what teaches the agent the *judgment* about when to reach for them.

## 3. Restart OpenClaw

```bash
systemctl --user restart openclaw-gateway   # if using systemd unit
# or just restart your `openclaw run` process
```

OpenClaw will spawn the MCP server as a child process on first tool call.

## 4. Verify

Ask your agent:

> List the peers currently online on the mesh.

It should call `ironmesh_list_peers` and report node IDs, agent names,
RTT, and message counters. If you have other agents running, they
should appear here.

Try a discovery query:

> Is there an LLM-capable peer on the mesh I could ask?

The agent should call `ironmesh_discover_capabilities` with `pattern: "llm:*"`.

## Tool reference

The `ironmesh` MCP server exposes 25 tools as of v0.9.5. The first
sections below cover the eight core operations and the five
agent-collaboration tools added for cross-agent workflows. Later
sections document the agent-introspection helpers, the pending-trust
operator tools (added with the v0.8.5 trust gate), and the
capability-binding tools (added with the v0.8.5.6 trust-binding
feature).

### Core tools

| Tool | Purpose |
|---|---|
| `ironmesh_list_peers` | Enumerate connected + known peers with live metrics |
| `ironmesh_send_message` | Fire-and-forget MSG to a peer by name or node_id |
| `ironmesh_get_mesh_stats` | Full mesh snapshot (uptime, lifetime p50/p90/p99) |
| `ironmesh_get_peer_stats` | Drill into one peer (RTT, retries, rekey, bytes) |
| `ironmesh_list_messages` | Query the local encrypted message store |
| `ironmesh_get_audit_log` | Tail the tamper-evident HMAC-chained audit log |
| `ironmesh_trust_list` | List pinned (TOFU) and revoked peers |
| `ironmesh_revoke_peer` | Revoke a peer (requires confirm=true) |

### Agent-collaboration tools (new in v0.8.4)

| Tool | Purpose |
|---|---|
| `ironmesh_discover_capabilities` | Glob-match capabilities across the mesh (e.g. `llm:*`, `role:assistant`) |
| `ironmesh_get_peer_capabilities` | Query one peer's advertised capability set |
| `ironmesh_request_service` | REQ/RESP — send a prompt and block for the matching reply (correlation-id) |
| `ironmesh_broadcast` | Send to every online peer (with `sent_to` / `failed` lists) |
| `ironmesh_subscribe_events` | Cursor-based poll of peer + message events |

### Agent-introspection + responder tools (new in v0.8.4)

These five rounded out the MCP surface based on the v0.8.4 audit of
what an OpenClaw agent actually needs in practice. Total tool count
is now 18.

| Tool | Purpose |
|---|---|
| `ironmesh_advertise_capability` | Declare a new local capability (`namespace:name`) without restarting the daemon |
| `ironmesh_withdraw_capability` | Stop advertising a previously-announced local capability |
| `ironmesh_get_my_identity` | Return our own `node_id`, name, advertised caps, running state — self-introspection |
| `ironmesh_pending_requests` | List in-flight `ironmesh_request_service` correlation slots — observability |
| `ironmesh_reply_to_request` | First-class REQ/RESP responder — wraps the correlation-id JSON envelope so the agent doesn't build one manually |

## Capabilities your agent should advertise

Capabilities are short `namespace:name` strings other agents discover via
glob match. Common conventions:

- `openclaw:<version>` — that you're an OpenClaw agent (recommended)
- `llm:<model_id>` — the LLM you're backed by (e.g. `llm:hermes3:3b`)
- `role:<purpose>` — the agent's primary role from your SOUL.md
- `tool:<name>` — any tool capability you can offer over the mesh

Set them at daemon start time via `--capability` flags or by calling
`daemon.advertise_capability("...")` from a startup hook. Other peers
discover them through `ironmesh_discover_capabilities`.

## REQ/RESP wire format

`ironmesh_request_service` uses an MSG-with-correlation-id pattern (no new
MessageType added in v0.8.4). On the wire:

```
Request payload  (UTF-8 JSON):
  {"correlation_id": "<32-hex uuid>", "body": "<your prompt>"}

Response payload (UTF-8 JSON):
  {"correlation_id": "<same uuid>", "body": "<the reply>"}
```

The peer side is responsible for round-tripping the `correlation_id`. If
you're the responder, parse incoming MSG payloads, look for the field, and
echo it back in your reply. Without it, the requester's `subscribe_events`
buffer captures your message but the blocking call never wakes.

This convention is forward-compatible with a future first-class `REQ`/`RESP`
MessageType in IronMesh v0.10+.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ERROR: set --passphrase-file or IRONMESH_PASSPHRASE` | env var not visible to the MCP server | OpenClaw spawns child processes with a clean env — pass the passphrase explicitly under `env` in the MCP server config |
| `ironmesh_list_peers` returns `[]` despite peers being online | the embedded daemon hasn't done discovery yet | wait 10–30 s after start, or add `--open-discovery` to `args` to broadcast on first launch |
| `request_service` always times out | the peer isn't echoing back the `correlation_id` | confirm peer-side handler is parsing the JSON envelope and including the same `correlation_id` in its reply payload |
| `Capability registry not available` | daemon was started before its own capability subsystem was wired in | restart the daemon; this is fixed in 0.8.3+ |
| Tool call latency >5 s | the embedded daemon is racing to start mDNS in the same process | run `ironmesh run` separately (long-lived); attach-to-existing-daemon mode is on the v0.9.1+ roadmap |

## Running alongside an existing IronMesh daemon

A common deployment has a long-lived `ironmesh run` daemon already
serving the host on port 8765. The MCP server spawns its **own**
embedded `BridgeDaemon` (it does not attach to a running one), so
configure it on a non-conflicting port and a distinct agent name to
avoid two processes claiming the same identity:

```json
{
  "mcp": {
    "servers": {
      "ironmesh-mesh": {
        "command": "/path/to/python",
        "args": [
          "-m", "ironmesh_mcp",
          "--name", "mcp-<host>",
          "--port", "8767",
          "--passphrase-file", "/home/<user>/.ironmesh/passphrase",
          "--open-discovery"
        ]
      }
    }
  }
}
```

The MCP-spawned daemon and the long-lived daemon will discover each
other via mDNS (when `--open-discovery` is set on both) and appear as
two separate peers on the mesh — each with its own identity key. That
is the right behavior: the MCP server's view of the mesh is what the
host's MCP tools call against, distinct from the long-lived daemon's
operator-facing dashboard.

## Operational notes

- The MCP server is **stdio**-only — it reads JSON-RPC frames from stdin and
  writes responses to stdout. Logs go to stderr. OpenClaw handles all of
  this transparently when the server is registered as above.
- The daemon spun up by `python -m ironmesh_mcp` listens on `127.0.0.1:8767`
  by default. Override with `--bind` and `--port` if you have a conflict.
- The daemon shares the same SQLite store IronMesh uses elsewhere
  (`~/.ironmesh/data.db`). Multiple processes pointed at the same DB can
  corrupt it — keep one daemon per host.
