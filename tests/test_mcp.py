"""Tests for the IronMesh MCP server (stdio JSON-RPC protocol)."""

import asyncio
import io
import json
import threading
import time

import pytest
import pytest_asyncio

from ironmesh.bridge import BridgeDaemon
from ironmesh.protocol import PeerState
from ironmesh_mcp.server import (
    IronMeshMCP,
    TOOL_SPECS,
    _dispatch,
    serve,
    PROTOCOL_VERSION,
    SERVER_INFO,
)


STRONG_PASSPHRASE = "mcp-test-passphrase-ok"


@pytest.fixture
def daemon(tmp_path):
    """A non-started BridgeDaemon — enough for tool dispatch tests that
    don't need live networking. The MCP tools query local state + the
    message store, which is exercised here without opening sockets."""
    d = BridgeDaemon(name="mcp-test", passphrase=STRONG_PASSPHRASE,
                     db_path=str(tmp_path / "mcp.db"))
    return d


@pytest.fixture
def loop():
    """Background asyncio loop thread — matches how the MCP entrypoint uses it."""
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    yield loop
    loop.call_soon_threadsafe(loop.stop)
    t.join(timeout=2)
    loop.close()


class TestToolRegistry:
    def test_every_tool_has_required_fields(self):
        for spec in TOOL_SPECS:
            assert "name" in spec
            assert spec["name"].startswith("ironmesh_")
            assert "description" in spec
            assert "inputSchema" in spec
            assert spec["inputSchema"]["type"] == "object"

    def test_tool_names_match_handlers(self, daemon, loop):
        """Every declared tool has an implementation in IronMeshMCP."""
        mcp = IronMeshMCP(daemon, loop)
        for spec in TOOL_SPECS:
            handler = getattr(mcp, "tool_" + spec["name"].replace("ironmesh_", ""), None)
            assert handler is not None, f"missing handler for {spec['name']}"
            assert callable(handler)


class TestListPeers:
    def test_empty_when_no_peers(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        assert mcp.tool_list_peers({}) == []

    def test_reports_peer_metrics(self, daemon, loop):
        ps = PeerState(node_id="abc123", address="10.0.0.1:8765")
        ps.transition(PeerState.Status.ONLINE)
        ps.bytes_sent_total = 1000
        ps.bytes_received_total = 2500
        ps.retries_total = 3
        ps.messages_sent = 5
        ps.messages_received = 8
        daemon.peers["abc123"] = ps

        mcp = IronMeshMCP(daemon, loop)
        peers = mcp.tool_list_peers({})
        assert len(peers) == 1
        p = peers[0]
        assert p["node_id"] == "abc123"
        assert p["online"] is True
        assert p["bytes_sent_total"] == 1000
        assert p["bytes_received_total"] == 2500
        assert p["retries_total"] == 3


class TestSendMessage:
    def test_missing_target(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        result = mcp.tool_send_message({"payload": "hi"})
        assert "error" in result

    def test_unknown_peer_returns_error_with_suggestions(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        result = mcp.tool_send_message({"target": "ghost", "payload": "hi"})
        assert "error" in result
        assert "not found" in result["error"]


class TestMeshStats:
    def test_schema_shape(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        stats = mcp.tool_get_mesh_stats({})
        for key in ("node_id", "name", "active_peers", "total_peers",
                    "message_lifetime", "peers"):
            assert key in stats


class TestAuditLog:
    def test_returns_error_when_audit_disabled(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        daemon._audit = None
        out = mcp.tool_get_audit_log({})
        assert out and "error" in out[0]


class TestRevokePeer:
    def test_requires_confirm(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        result = mcp.tool_revoke_peer({"peer": "target"})
        assert "error" in result
        assert "confirm" in result["error"]

    def test_requires_peer_name(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        result = mcp.tool_revoke_peer({"confirm": True})
        assert "error" in result


class TestDispatch:
    def test_unknown_tool(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        result = _dispatch(mcp, "ironmesh_nonexistent", {})
        assert "error" in result
        assert "unknown tool" in result["error"]


class TestJSONRPCLoop:
    """Drive the full stdio JSON-RPC loop with in-memory streams."""

    def _run(self, daemon, loop, requests: list[dict]) -> list[dict]:
        stdin = io.StringIO(
            "\n".join(json.dumps(r) for r in requests) + "\n"
        )
        stdout = io.StringIO()
        serve(daemon, loop, stdin=stdin, stdout=stdout)
        out = []
        for line in stdout.getvalue().splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def test_initialize(self, daemon, loop):
        responses = self._run(daemon, loop, [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        ])
        assert len(responses) == 1
        assert responses[0]["id"] == 1
        assert responses[0]["result"]["protocolVersion"] == PROTOCOL_VERSION
        assert responses[0]["result"]["serverInfo"] == SERVER_INFO
        assert "tools" in responses[0]["result"]["capabilities"]

    def test_tools_list(self, daemon, loop):
        responses = self._run(daemon, loop, [
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ])
        assert len(responses) == 1
        tools = responses[0]["result"]["tools"]
        assert len(tools) == len(TOOL_SPECS)
        names = {t["name"] for t in tools}
        assert "ironmesh_list_peers" in names
        assert "ironmesh_send_message" in names

    def test_tools_call_list_peers(self, daemon, loop):
        responses = self._run(daemon, loop, [
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "ironmesh_list_peers", "arguments": {}}},
        ])
        assert len(responses) == 1
        content = responses[0]["result"]["content"]
        assert content[0]["type"] == "text"
        # Payload is a JSON array of peers; empty daemon has none
        assert json.loads(content[0]["text"]) == []

    def test_unknown_method(self, daemon, loop):
        responses = self._run(daemon, loop, [
            {"jsonrpc": "2.0", "id": 4, "method": "nonsense"},
        ])
        assert responses[0]["error"]["code"] == -32601

    def test_notifications_have_no_response(self, daemon, loop):
        """Notifications (no id) must not generate a response."""
        responses = self._run(daemon, loop, [
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 5, "method": "ping"},
        ])
        assert len(responses) == 1  # only the ping got a reply
        assert responses[0]["id"] == 5
