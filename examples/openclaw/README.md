# OpenClaw integration recipes

Files here walk through wiring IronMesh into the [OpenClaw](https://openclaw.io) 2026.3.x agent stack.

## Files

| File | What it is |
|---|---|
| [`openclaw_mcp_config.json`](openclaw_mcp_config.json) | Drop-in MCP config block — paste into your OpenClaw MCP host config to expose the 25 IronMesh MCP tools to your OpenClaw agents. |
| [`soul_mesh_snippet.md`](soul_mesh_snippet.md) | A "soul" snippet (OpenClaw's persona / system-prompt format) that gives an OpenClaw agent the context it needs to use IronMesh well — when to broadcast, when to point-to-point, how to handle pending-trust replies. |

## Two integration paths

OpenClaw 2026.3.x has two ways to use IronMesh, and they solve different problems. Pick based on what you're building:

1. **MCP server** — exposes the IronMesh daemon as a set of 25 MCP tools the agent can call. Best for *the agent uses the mesh as a tool*: "send this message to bob", "find peers that advertise `llm:*`", "check the audit log". Setup: [`docs/OPENCLAW_MCP_SETUP.md`](../../docs/OPENCLAW_MCP_SETUP.md). The JSON config in this directory plugs into that.
2. **Channel plugin** — `@wiztheagent/openclaw-ironmesh` on npm, a TypeScript ChannelPlugin that makes IronMesh peers appear as native OpenClaw contacts in the chat UI. Best for *peers are first-class chat contacts*: a remote IronMesh peer shows up alongside Slack / Telegram contacts, the agent can DM them, replies route back automatically. Setup: [`docs/OPENCLAW_CHANNEL_SETUP.md`](../../docs/OPENCLAW_CHANNEL_SETUP.md).

You can run both at once. They share the underlying daemon and are independent integration surfaces.

## When you pick MCP

Paste `openclaw_mcp_config.json` into your OpenClaw MCP host config (or merge with an existing one). The 25 tools cover:

- **Core**: `list_peers`, `send_message`, `get_mesh_stats`, `list_messages`, `get_audit_log`, `get_peer_stats`, `trust_list`, `revoke_peer`
- **Cross-agent collaboration**: `discover_capabilities`, `get_peer_capabilities`, `request_service`, `broadcast`, `subscribe_events`
- **Self-introspection**: `advertise_capability`, `withdraw_capability`, `get_my_identity`, `pending_requests`, `reply_to_request`
- **Pending-trust gate** (since v0.8.5): `list_pending_trust`, plus the existing trust-state tools

Full per-tool reference: [`docs/OPENCLAW_MCP_SETUP.md §Tool reference`](../../docs/OPENCLAW_MCP_SETUP.md).

## When you pick the channel plugin

`npm install @wiztheagent/openclaw-ironmesh` then follow the loader-config recipe in [`docs/OPENCLAW_CHANNEL_SETUP.md`](../../docs/OPENCLAW_CHANNEL_SETUP.md). The plugin handles the lifecycle, outbound, messaging, directory, status, and config surfaces of the OpenClaw `ChannelPlugin` contract; you don't write any glue code.

## Soul snippet

[`soul_mesh_snippet.md`](soul_mesh_snippet.md) is **optional**. OpenClaw soul files give the agent a persona, but you don't need a custom soul to use either integration above — they work with stock OpenClaw agents. The snippet is here for operators who want the agent to default to certain mesh-aware behaviours (broadcast-on-uncertainty, point-to-point on direct addressing, etc.).
