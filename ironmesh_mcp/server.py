#!/usr/bin/env python3
"""IronMesh MCP server — exposes IronMesh as MCP tools.

Protocol: Model Context Protocol (stdio transport by default).
Client: any MCP host (Claude Desktop, Claude Code, VS Code MCP).

Tools exposed:
    ironmesh_list_peers         — enumerate connected + known peers with live metrics
    ironmesh_send_message       — send a MSG to a named peer (by agent name or node_id)
    ironmesh_get_mesh_stats     — full /api/mesh_stats snapshot (lifetime, bytes, retries)
    ironmesh_list_messages      — query the local message store, optionally filtered by peer
    ironmesh_get_audit_log      — read the tamper-evident audit log tail
    ironmesh_get_peer_stats     — drill into one peer's latency/retries/rekey history
    ironmesh_trust_list         — list pinned and revoked peers
    ironmesh_revoke_peer        — revoke a peer (requires confirm parameter)

Transport: spawns a local ``ironmesh run`` daemon if one isn't already running,
then attaches as a read/write client via the IronMesh programmatic API. The
MCP server itself doesn't require a network — it talks to the local daemon
over its bus and database.

Run standalone::

    python -m ironmesh_mcp

Or register with Claude Desktop by adding to ``claude_desktop_config.json``::

    {
      "mcpServers": {
        "ironmesh": {
          "command": "python",
          "args": ["-m", "ironmesh_mcp"],
          "env": {"IRONMESH_PASSPHRASE": "your-passphrase"}
        }
      }
    }

Rationale: MCP is the shortest path to making IronMesh a first-class agent
substrate. Any agent that speaks MCP can now send A2A messages over the
local-first mesh without wrapping the IronMesh CLI or parsing its JSON logs.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ironmesh.bridge import BridgeDaemon  # noqa: E402

log = logging.getLogger("ironmesh.mcp")


# --------------------------------------------------------------------------
# MCP wire protocol — implemented inline to avoid a hard dependency on the
# mcp SDK (which may not be installed). If the user has ``mcp`` available,
# they can swap in the SDK's Server/Tool wrappers; the tool functions below
# are SDK-agnostic.
# --------------------------------------------------------------------------

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "ironmesh", "version": "0.8.0"}


def _read_frame(stream) -> Optional[dict]:
    """Read a single JSON-RPC request from the MCP host (stdio, line-delimited)."""
    line = stream.readline()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError as e:
        log.warning("bad JSON-RPC frame: %s", e)
        return None


def _write_frame(stream, obj: dict) -> None:
    stream.write(json.dumps(obj, default=str) + "\n")
    stream.flush()


# --------------------------------------------------------------------------
# Tool handlers
# --------------------------------------------------------------------------


class IronMeshMCP:
    """The MCP server state machine + tool implementations."""

    def __init__(self, daemon: BridgeDaemon, loop: asyncio.AbstractEventLoop):
        self.daemon = daemon
        self.loop = loop

    # --- tool: list_peers ---------------------------------------------------

    def tool_list_peers(self, args: dict) -> list[dict]:
        """Return all currently tracked peers with live metrics."""
        out = []
        for pid, p in self.daemon.peers.items():
            out.append({
                "node_id": pid,
                "name": getattr(p, "agent_name", None),
                "address": p.address,
                "online": bool(p.is_online),
                "status": p.status.value if hasattr(p.status, "value") else str(p.status),
                "rtt_ms": p.latency_ms,
                "messages_sent": p.messages_sent,
                "messages_received": p.messages_received,
                "bytes_sent_total": getattr(p, "bytes_sent_total", 0),
                "bytes_received_total": getattr(p, "bytes_received_total", 0),
                "retries_total": getattr(p, "retries_total", 0),
                "session_rekey_count": getattr(p, "session_rekey_count", 0),
                "last_seen": p.last_seen,
                "offline_since": getattr(p, "offline_since", None),
            })
        return out

    # --- tool: send_message --------------------------------------------------

    def tool_send_message(self, args: dict) -> dict:
        """Send a MSG to a peer by name or node_id.

        Args:
            target: agent name or node_id (32-hex)
            payload: string (UTF-8 encoded) or base64 for binary
            priority: "CRITICAL" | "HIGH" | "NORMAL" (default) | "LOW"
            msg_type: defaults to "MSG"
        """
        target = args.get("target")
        payload = args.get("payload", "")
        priority = args.get("priority", "NORMAL")
        msg_type = args.get("msg_type", "MSG")

        if not target:
            return {"error": "target required (agent name or node_id)"}

        # Resolve name → node_id
        target_node = target
        if len(target) != 32 or not all(c in "0123456789abcdef" for c in target):
            # Treat as name — search peers
            for pid, p in self.daemon.peers.items():
                if getattr(p, "agent_name", None) == target:
                    target_node = pid
                    break
            else:
                return {"error": f"peer '{target}' not found. Known: "
                                 f"{[getattr(p, 'agent_name', pid[:12]) for pid, p in self.daemon.peers.items()]}"}

        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)

        fut = asyncio.run_coroutine_threadsafe(
            self.daemon.send_message(target_node, msg_type, payload_bytes, priority),
            self.loop,
        )
        try:
            msg_id = fut.result(timeout=10)
        except Exception as e:
            return {"error": f"send failed: {e}"}
        return {
            "ok": True,
            "msg_id": msg_id,
            "target_node_id": target_node,
            "priority": priority,
        }

    # --- tool: get_mesh_stats -----------------------------------------------

    def tool_get_mesh_stats(self, args: dict) -> dict:
        return self.daemon._build_mesh_stats()

    # --- tool: get_peer_stats -----------------------------------------------

    def tool_get_peer_stats(self, args: dict) -> dict:
        pid = args.get("node_id") or args.get("target")
        if not pid:
            return {"error": "node_id required"}
        # Allow name lookup
        if len(pid) != 32:
            for peer_id, p in self.daemon.peers.items():
                if getattr(p, "agent_name", None) == pid:
                    pid = peer_id
                    break
        p = self.daemon.peers.get(pid)
        if p is None:
            return {"error": f"unknown peer {pid}"}
        return {
            "node_id": pid,
            "name": getattr(p, "agent_name", None),
            "online": bool(p.is_online),
            "rtt_ms": p.latency_ms,
            "messages_sent": p.messages_sent,
            "messages_received": p.messages_received,
            "bytes_sent_total": getattr(p, "bytes_sent_total", 0),
            "bytes_received_total": getattr(p, "bytes_received_total", 0),
            "retries_total": getattr(p, "retries_total", 0),
            "retries_by_reason": dict(getattr(p, "retries_by_reason", {})),
            "session_rekey_count": getattr(p, "session_rekey_count", 0),
            "last_seen": p.last_seen,
            "offline_since": getattr(p, "offline_since", None),
            "connected_at": p.connected_at,
            "transport": getattr(p, "transport_type", "websocket"),
            "verified": p.verified,
        }

    # --- tool: list_messages ------------------------------------------------

    def tool_list_messages(self, args: dict) -> list[dict]:
        """Query the local message store."""
        peer = args.get("peer")
        limit = int(args.get("limit", 20))
        fut = asyncio.run_coroutine_threadsafe(
            self.daemon._db.get_messages(peer_id=peer, limit=limit),
            self.loop,
        )
        try:
            rows = fut.result(timeout=5)
        except Exception as e:
            return [{"error": str(e)}]
        out = []
        for r in rows:
            out.append({
                "msg_id": r.get("msg_id"),
                "source": r.get("source"),
                "source_display": r.get("source_display"),
                "destination": r.get("destination"),
                "msg_type": r.get("msg_type"),
                "timestamp": r.get("timestamp"),
                "direction": r.get("direction"),
                "priority": r.get("priority"),
                "size": len(r.get("payload") or b""),
            })
        return out

    # --- tool: get_audit_log ------------------------------------------------

    def tool_get_audit_log(self, args: dict) -> list[dict]:
        limit = int(args.get("limit", 50))
        if not self.daemon._audit:
            return [{"error": "audit log not enabled on this daemon"}]
        log_path = getattr(self.daemon._audit, "path", None)
        if not log_path or not os.path.exists(log_path):
            return []
        entries = []
        with open(log_path) as f:
            lines = f.readlines()[-limit:]
        for line in lines:
            try:
                entries.append(json.loads(line))
            except Exception:
                entries.append({"raw": line.strip()})
        return entries

    # --- tool: trust_list ---------------------------------------------------

    def tool_trust_list(self, args: dict) -> dict:
        """List pinned + revoked peers from the trust store."""
        try:
            from ironmesh.trust import TrustStore
            if not self.daemon._keypair:
                return {"error": "daemon keypair not loaded"}
            mac_key = self.daemon._keypair.ed25519_secret[:32]
            store = TrustStore(agent_key=mac_key)
            return {
                "pinned": dict(store._peers),
                "revoked": dict(getattr(store, "_revoked", {})),
            }
        except Exception as e:
            return {"error": f"trust list failed: {e}"}

    # --- tool: revoke_peer --------------------------------------------------

    def tool_revoke_peer(self, args: dict) -> dict:
        """Revoke a peer — requires confirm=True to guard against accidents."""
        peer = args.get("peer")
        if not peer:
            return {"error": "peer name required"}
        if not args.get("confirm"):
            return {"error": "set confirm=true to execute; this is destructive"}
        try:
            from ironmesh.trust import TrustStore
            mac_key = self.daemon._keypair.ed25519_secret[:32]
            store = TrustStore(agent_key=mac_key)
            store.revoke_peer(peer)
            return {"ok": True, "revoked": peer}
        except Exception as e:
            return {"error": f"revoke failed: {e}"}


# --------------------------------------------------------------------------
# Tool registry — MCP "tools/list" + "tools/call" routing
# --------------------------------------------------------------------------

TOOL_SPECS = [
    {
        "name": "ironmesh_list_peers",
        "description": "Enumerate connected and known peers on the mesh with live metrics (RTT, retries, bytes).",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "ironmesh_send_message",
        "description": "Send an application message (MSG) to another peer by agent name or 32-hex node_id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "agent name or 32-hex node_id"},
                "payload": {"type": "string", "description": "UTF-8 text payload"},
                "priority": {"type": "string", "enum": ["CRITICAL", "HIGH", "NORMAL", "LOW"], "default": "NORMAL"},
                "msg_type": {"type": "string", "default": "MSG"},
            },
            "required": ["target", "payload"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ironmesh_get_mesh_stats",
        "description": "Full mesh snapshot — uptime, active peers, message lifetime p50/p90/p99, per-peer counters.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "ironmesh_get_peer_stats",
        "description": "Detailed metrics for one peer: RTT, bytes, retries by reason, session rekeys, last-seen.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "ironmesh_list_messages",
        "description": "Query the local encrypted message store (history of sent/received messages).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "peer": {"type": "string", "description": "filter by peer node_id (optional)"},
                "limit": {"type": "integer", "default": 20},
            },
        },
    },
    {
        "name": "ironmesh_get_audit_log",
        "description": "Tail the tamper-evident HMAC-chained audit log (security events).",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 50}},
        },
    },
    {
        "name": "ironmesh_trust_list",
        "description": "List pinned peer identities (TOFU) and any revoked peers.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "ironmesh_revoke_peer",
        "description": "Revoke a peer by name. Prevents future connections from its identity key. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "peer": {"type": "string"},
                "confirm": {"type": "boolean", "default": False},
            },
            "required": ["peer"],
        },
    },
]


def _dispatch(mcp: IronMeshMCP, tool: str, args: dict) -> Any:
    handler_name = "tool_" + tool.replace("ironmesh_", "")
    fn = getattr(mcp, handler_name, None)
    if fn is None:
        return {"error": f"unknown tool: {tool}"}
    return fn(args or {})


# --------------------------------------------------------------------------
# JSON-RPC 2.0 loop (stdio transport — the MCP default)
# --------------------------------------------------------------------------


def serve(daemon: BridgeDaemon, loop: asyncio.AbstractEventLoop,
          stdin=None, stdout=None) -> None:
    """Run the MCP server loop on stdio until EOF."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    mcp = IronMeshMCP(daemon, loop)

    log.info("IronMesh MCP server ready (stdio transport)")
    while True:
        msg = _read_frame(stdin)
        if msg is None:
            break

        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "serverInfo": SERVER_INFO,
                    "capabilities": {"tools": {}},
                }
            elif method == "notifications/initialized":
                # one-way, no response
                continue
            elif method == "tools/list":
                result = {"tools": TOOL_SPECS}
            elif method == "tools/call":
                tool = params.get("name", "")
                args = params.get("arguments", {})
                content = _dispatch(mcp, tool, args)
                # MCP expects content as a list of content blocks
                result = {"content": [{
                    "type": "text",
                    "text": json.dumps(content, indent=2, default=str),
                }]}
            elif method == "ping":
                result = {}
            else:
                _write_frame(stdout, {
                    "jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                })
                continue
        except Exception as e:
            log.exception("error handling %s", method)
            _write_frame(stdout, {
                "jsonrpc": "2.0", "id": mid,
                "error": {"code": -32000, "message": str(e)},
            })
            continue

        if mid is not None:  # notification requests have no id
            _write_frame(stdout, {"jsonrpc": "2.0", "id": mid, "result": result})


def main() -> int:
    """CLI entry point — spin up an embedded BridgeDaemon then serve MCP on stdio."""
    import argparse
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s [%(name)s] %(message)s")

    p = argparse.ArgumentParser()
    p.add_argument("--name", default="mcp-agent")
    p.add_argument("--port", type=int, default=8767)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--passphrase-env", default="IRONMESH_PASSPHRASE")
    p.add_argument("--passphrase-file", default=None)
    p.add_argument("--open-discovery", action="store_true")
    p.add_argument("--allow-plaintext-ws", action="store_true", default=True)
    args = p.parse_args()

    passphrase = None
    if args.passphrase_file:
        with open(os.path.expanduser(args.passphrase_file)) as f:
            passphrase = f.read().strip()
    else:
        passphrase = os.environ.get(args.passphrase_env)
    if not passphrase:
        print(f"ERROR: set --passphrase-file or {args.passphrase_env}", file=sys.stderr)
        return 2

    daemon = BridgeDaemon(
        name=args.name, port=args.port, bind_address=args.bind,
        passphrase=passphrase,
        open_discovery=args.open_discovery,
        allow_plaintext_ws=args.allow_plaintext_ws,
    )
    loop = daemon.run(background=True)
    threading.Thread(target=loop.run_forever, name="mcp-loop",
                     daemon=True).start()
    time.sleep(0.5)

    try:
        serve(daemon, loop)
    except KeyboardInterrupt:
        pass
    loop.call_soon_threadsafe(loop.stop)
    return 0


if __name__ == "__main__":
    sys.exit(main())
