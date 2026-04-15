"""Tests for IronMesh GUI dashboard (bridge.py GUI additions)."""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ironmesh.bridge import BridgeDaemon, GUI_HTML, Metrics
from ironmesh.protocol import PeerState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_daemon(**kwargs) -> BridgeDaemon:
    """Create a BridgeDaemon with sensible test defaults (no network)."""
    defaults = {
        "name": "test-agent",
        "passphrase": "test-secret-phrase",
        "port": 18765,
        "gui": True,
    }
    defaults.update(kwargs)
    return BridgeDaemon(**defaults)


# ---------------------------------------------------------------------------
# GUI_HTML constant
# ---------------------------------------------------------------------------

class TestGUIHTML:
    def test_html_is_string(self):
        assert isinstance(GUI_HTML, str)

    def test_html_has_doctype(self):
        assert GUI_HTML.strip().startswith("<!DOCTYPE html>")

    def test_html_has_closing_tags(self):
        assert "</html>" in GUI_HTML
        assert "</head>" in GUI_HTML
        assert "</body>" in GUI_HTML

    def test_html_has_title(self):
        assert "<title>IronMesh Dashboard</title>" in GUI_HTML

    def test_html_has_ws_connection(self):
        assert "/ws" in GUI_HTML

    def test_html_has_metrics_elements(self):
        assert "m-uptime" in GUI_HTML
        assert "m-peers" in GUI_HTML
        assert "m-sent" in GUI_HTML
        assert "m-recv" in GUI_HTML

    def test_html_has_send_form(self):
        assert "send-peer" in GUI_HTML
        assert "send-payload" in GUI_HTML
        assert "send-btn" in GUI_HTML

    def test_html_has_peer_table(self):
        assert "peer-table" in GUI_HTML

    def test_html_has_feed(self):
        assert 'id="feed"' in GUI_HTML


# ---------------------------------------------------------------------------
# BridgeDaemon GUI init
# ---------------------------------------------------------------------------

class TestGUIInit:
    def test_gui_enabled_by_default(self):
        d = _make_daemon()
        assert d._gui_enabled is True
        assert isinstance(d._gui_clients, set)
        assert len(d._gui_clients) == 0

    def test_gui_disabled(self):
        d = _make_daemon(gui=False)
        assert d._gui_enabled is False

    def test_gui_server_initially_none(self):
        d = _make_daemon()
        assert d._gui_server is None


# ---------------------------------------------------------------------------
# _build_metrics_dict
# ---------------------------------------------------------------------------

class TestBuildMetricsDict:
    def test_returns_dict(self):
        d = _make_daemon()
        m = d._build_metrics_dict()
        assert isinstance(m, dict)

    def test_has_standard_metrics_keys(self):
        d = _make_daemon()
        m = d._build_metrics_dict()
        for key in [
            "uptime_seconds", "messages_sent", "messages_received",
            "bytes_sent", "bytes_received", "handshake_successes",
            "handshake_failures", "connections_total", "rate_limits_triggered",
            "active_peers", "total_peers",
        ]:
            assert key in m, f"Missing key: {key}"

    def test_active_peers_count(self):
        d = _make_daemon()
        p1 = PeerState("peer-1")
        p1.transition(PeerState.Status.ONLINE)
        p2 = PeerState("peer-2")  # offline
        d.peers["peer-1"] = p1
        d.peers["peer-2"] = p2
        m = d._build_metrics_dict()
        assert m["active_peers"] == 1
        assert m["total_peers"] == 2

    def test_reflects_metrics_values(self):
        d = _make_daemon()
        d.metrics.messages_sent = 42
        d.metrics.bytes_received = 9999
        m = d._build_metrics_dict()
        assert m["messages_sent"] == 42
        assert m["bytes_received"] == 9999


# ---------------------------------------------------------------------------
# _build_full_state
# ---------------------------------------------------------------------------

class TestBuildFullState:
    def test_returns_dict(self):
        d = _make_daemon()
        s = d._build_full_state()
        assert isinstance(s, dict)

    def test_has_required_keys(self):
        d = _make_daemon()
        s = d._build_full_state()
        for key in ["node_id", "name", "port", "metrics", "peers", "history"]:
            assert key in s, f"Missing key: {key}"

    def test_name_and_port(self):
        d = _make_daemon(name="wiz", port=9000)
        s = d._build_full_state()
        assert s["name"] == "wiz"
        assert s["port"] == 9000

    def test_peers_is_list(self):
        d = _make_daemon()
        s = d._build_full_state()
        assert isinstance(s["peers"], list)

    def test_peers_serialized(self):
        d = _make_daemon()
        p = PeerState("node-abc", address="1.2.3.4:8765")
        p.transition(PeerState.Status.ONLINE)
        d.peers["node-abc"] = p
        s = d._build_full_state()
        assert len(s["peers"]) == 1
        assert s["peers"][0]["node_id"] == "node-abc"
        assert s["peers"][0]["status"] == "online"

    def test_history_is_list(self):
        d = _make_daemon()
        s = d._build_full_state()
        assert isinstance(s["history"], list)

    def test_metrics_nested(self):
        d = _make_daemon()
        s = d._build_full_state()
        assert "uptime_seconds" in s["metrics"]
        assert "active_peers" in s["metrics"]


# ---------------------------------------------------------------------------
# _gui_process_request routing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGUIProcessRequest:

    async def _route(self, daemon, path, with_token=False):
        """Simulate a process_request call with a given path."""
        request = MagicMock()
        if with_token:
            request.path = f"{path}?token={daemon._gui_token}" if "?" not in path else path
        else:
            request.path = path
        request.headers = {}
        connection = MagicMock()
        return await daemon._gui_process_request(connection, request)

    async def test_root_returns_html(self):
        d = _make_daemon()
        resp = await self._route(d, "/")
        assert resp is not None
        assert resp.status_code == 200
        assert b"IronMesh Dashboard" in resp.body

    async def test_index_html_returns_html(self):
        d = _make_daemon()
        resp = await self._route(d, "/index.html")
        assert resp is not None
        assert resp.status_code == 200

    async def test_metrics_returns_prometheus_by_default(self):
        """v0.4: /metrics now returns Prometheus exposition format by default."""
        d = _make_daemon()
        resp = await self._route(d, "/metrics", with_token=True)
        assert resp is not None
        assert resp.status_code == 200
        body_text = resp.body.decode()
        assert "ironmesh_uptime_seconds" in body_text
        assert "ironmesh_active_peers" in body_text
        assert "# HELP" in body_text
        assert "# TYPE" in body_text

    async def test_metrics_returns_json_with_format_query(self):
        """JSON format remains available via ?format=json."""
        d = _make_daemon()
        resp = await self._route(
            d, f"/metrics?format=json&token={d._gui_token}",
        )
        assert resp is not None
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert "uptime_seconds" in data
        assert "active_peers" in data

    async def test_api_state_returns_json(self):
        d = _make_daemon()
        resp = await self._route(d, "/api/state", with_token=True)
        assert resp is not None
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert "node_id" in data
        assert "peers" in data

    async def test_api_mesh_stats_schema(self):
        """v0.7.2: /api/mesh_stats has a stable schema for harness polling."""
        d = _make_daemon()
        resp = await self._route(d, "/api/mesh_stats", with_token=True)
        assert resp is not None
        assert resp.status_code == 200
        data = json.loads(resp.body)
        # Top-level fields
        for key in ("node_id", "name", "ts", "uptime_seconds",
                    "active_peers", "total_peers", "message_lifetime", "peers"):
            assert key in data, f"mesh_stats missing {key}"
        # Lifetime summary has stable shape even when empty
        lt = data["message_lifetime"]
        assert "count" in lt and "sum" in lt and "p50" in lt
        # peers is a list (empty ok)
        assert isinstance(data["peers"], list)

    async def test_api_mesh_stats_requires_token(self):
        d = _make_daemon()
        resp = await self._route(d, "/api/mesh_stats", with_token=False)
        assert resp is not None
        assert resp.status_code == 401

    async def test_api_mesh_stats_per_peer_fields(self):
        """Per-peer records expose retry + goodput counters from v0.7.2."""
        from ironmesh.protocol import PeerState
        d = _make_daemon()
        ps = PeerState(node_id="abc123", address="10.0.0.1:8765")
        ps.transition(PeerState.Status.ONLINE)
        ps.bytes_sent_total = 4096
        ps.bytes_received_total = 2048
        ps.record_retry("direct_send_failed")
        ps.record_retry("direct_send_failed")
        d.peers["abc123"] = ps

        resp = await self._route(d, "/api/mesh_stats", with_token=True)
        data = json.loads(resp.body)
        assert data["active_peers"] == 1
        peer = data["peers"][0]
        assert peer["node_id"] == "abc123"
        assert peer["online"] is True
        assert peer["bytes_sent_total"] == 4096
        assert peer["bytes_received_total"] == 2048
        assert peer["retries_total"] == 2
        assert peer["retries_by_reason"]["direct_send_failed"] == 2

    async def test_ws_returns_none(self):
        d = _make_daemon()
        resp = await self._route(d, "/ws", with_token=True)
        assert resp is None  # Allow WebSocket upgrade

    async def test_unknown_returns_404(self):
        d = _make_daemon()
        resp = await self._route(d, "/nonexistent")
        assert resp is not None
        assert resp.status_code == 404

    async def test_metrics_backward_compat(self):
        """Metrics endpoint returns same data shape via ?format=json (v0.4)."""
        d = _make_daemon()
        d.metrics.messages_sent = 5
        d.metrics.handshake_successes = 2
        resp = await self._route(
            d, f"/metrics?format=json&token={d._gui_token}",
        )
        data = json.loads(resp.body)
        assert data["messages_sent"] == 5
        assert data["handshake_successes"] == 2


# ---------------------------------------------------------------------------
# _handle_gui_command
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHandleGUICommand:

    async def test_refresh_sends_snapshot(self):
        d = _make_daemon()
        ws = AsyncMock()
        await d._handle_gui_command({"action": "refresh"}, ws)
        ws.send.assert_called_once()
        msg = json.loads(ws.send.call_args[0][0])
        assert msg["type"] == "snapshot"
        assert "data" in msg

    async def test_send_message_missing_to_node(self):
        d = _make_daemon()
        ws = AsyncMock()
        await d._handle_gui_command({"action": "send_message", "payload": "hi"}, ws)
        msg = json.loads(ws.send.call_args[0][0])
        assert msg["type"] == "send_error"
        assert "to_node" in msg["error"]

    async def test_unknown_action(self):
        d = _make_daemon()
        ws = AsyncMock()
        await d._handle_gui_command({"action": "nonexistent"}, ws)
        msg = json.loads(ws.send.call_args[0][0])
        assert msg["type"] == "send_error"
        assert "Unknown action" in msg["error"]


# ---------------------------------------------------------------------------
# _gui_broadcast
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGUIBroadcast:

    async def test_broadcast_to_empty(self):
        d = _make_daemon()
        await d._gui_broadcast({"type": "test"})  # Should not raise

    async def test_broadcast_to_clients(self):
        d = _make_daemon()
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        d._gui_clients = {ws1, ws2}
        await d._gui_broadcast({"type": "test", "value": 42})
        ws1.send.assert_called_once()
        ws2.send.assert_called_once()
        msg1 = json.loads(ws1.send.call_args[0][0])
        assert msg1["type"] == "test"

    async def test_broadcast_removes_dead_clients(self):
        d = _make_daemon()
        ws_dead = AsyncMock()
        ws_dead.send.side_effect = Exception("closed")
        ws_alive = AsyncMock()
        d._gui_clients = {ws_dead, ws_alive}
        await d._gui_broadcast({"type": "ping"})
        assert ws_dead not in d._gui_clients
        assert ws_alive in d._gui_clients
