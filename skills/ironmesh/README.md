# IronMesh skills for agents

A set of Claude Code–style skills that let an AI agent observe and
operate an IronMesh node. Drop this folder into your agent's skills
directory (or symlink it) and the skills listed below become available
as slash commands.

## Included skills

| Skill | What it does |
|---|---|
| [`ironmesh-status`](ironmesh-status/SKILL.md) | Prints mesh health: uptime, active peers, message lifetime p50/p90/p99, queue pressure |
| [`ironmesh-peers`](ironmesh-peers/SKILL.md) | Per-peer table (RTT, retries, bytes sent/received, rekey count) |
| [`ironmesh-send`](ironmesh-send/SKILL.md) | Send a MSG to a named peer; optionally wait for ACK |
| [`ironmesh-audit`](ironmesh-audit/SKILL.md) | Tail the tamper-evident audit log for security events |
| [`ironmesh-trust`](ironmesh-trust/SKILL.md) | List pinned peers, show revocation state, and (with confirm) revoke a peer |

## Trust model

These skills are **trusted** in the sense that they execute shell
commands against the local IronMesh daemon's `/api/mesh_stats`,
`ironmesh` CLI, and audit log. They do **not** send unsolicited
messages, expose secrets, or reach outside the host.

Before enabling an agent to use these skills:

1. Confirm the agent has network access to `127.0.0.1:8766` (the default
   GUI/metrics port) OR shell access to the node running the daemon.
2. Set `IRONMESH_GUI_TOKEN` in the agent's environment — this token is
   printed at daemon startup (see `scripts/startup-capture.sh`).
3. `ironmesh-send` and `ironmesh-trust revoke` have side effects and
   should be granted deliberately.

## Alternative: MCP server

If your agent speaks the Model Context Protocol (Claude Desktop,
Claude Code MCP clients), you can skip the shell-based skills entirely
and use [`ironmesh_mcp`](../../ironmesh_mcp/) instead. Add to your
client config:

```json
{
  "mcpServers": {
    "ironmesh": {
      "command": "python",
      "args": ["-m", "ironmesh_mcp"],
      "env": {"IRONMESH_PASSPHRASE": "your-passphrase"}
    }
  }
}
```

The MCP server exposes the same operations as typed JSON-RPC tools.

## Install

```bash
# As Claude Code skills (per-project)
ln -s "$(pwd)/skills/ironmesh" .claude/skills/ironmesh

# Or system-wide
cp -r skills/ironmesh ~/.claude/skills/
```

After install, `/ironmesh-status` etc. will be available to the agent.
