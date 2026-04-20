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
    def test_schema_shape_when_daemon_running(self, daemon, loop):
        # Force the M1 gate to pass — flip the running flag without
        # actually opening sockets, then verify the existing snapshot
        # schema is unchanged.
        daemon._running = True
        try:
            mcp = IronMeshMCP(daemon, loop)
            stats = mcp.tool_get_mesh_stats({})
            for key in ("node_id", "name", "active_peers", "total_peers",
                        "message_lifetime", "peers"):
                assert key in stats
        finally:
            daemon._running = False


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


# ---------------------------------------------------------------------------
# M1 / OpenClaw bridge tools
# ---------------------------------------------------------------------------

from ironmesh.capabilities import CapabilityRegistry  # noqa: E402


def _attach_registry(daemon):
    """Daemon doesn't instantiate _capabilities until _start(); inject one
    so the new MCP tools have something to talk to in unit tests."""
    daemon._capabilities = CapabilityRegistry(my_node_id=daemon.node_id)
    return daemon._capabilities


def _add_peer(daemon, node_id, name, online=True, caps=None):
    ps = PeerState(node_id=node_id, address="10.0.0.1:8765")
    ps.agent_name = name
    if online:
        ps.transition(PeerState.Status.ONLINE)
    daemon.peers[node_id] = ps
    if caps and getattr(daemon, "_capabilities", None) is not None:
        daemon._capabilities.learn_remote(node_id, caps)
    return ps


class TestDiscoverCapabilities:
    def test_glob_matches_remote_caps(self, daemon, loop):
        _attach_registry(daemon)
        _add_peer(daemon, "a" * 32, "alice", caps=["llm:llama3", "role:assistant"])
        _add_peer(daemon, "b" * 32, "bob", caps=["llm:hermes3", "tool:fs"])
        mcp = IronMeshMCP(daemon, loop)
        rows = mcp.tool_discover_capabilities({"pattern": "llm:*"})
        caps = sorted(r["capability"] for r in rows)
        assert caps == ["llm:hermes3", "llm:llama3"]
        # Names propagate
        assert {r["agent_name"] for r in rows} == {"alice", "bob"}

    def test_empty_when_registry_empty(self, daemon, loop):
        _attach_registry(daemon)
        mcp = IronMeshMCP(daemon, loop)
        assert mcp.tool_discover_capabilities({"pattern": "*"}) == []

    def test_default_pattern_returns_everything(self, daemon, loop):
        _attach_registry(daemon)
        _add_peer(daemon, "c" * 32, "x", caps=["a", "b"])
        mcp = IronMeshMCP(daemon, loop)
        rows = mcp.tool_discover_capabilities({})
        assert len(rows) == 2

    def test_no_registry_does_not_crash(self, daemon, loop):
        # Pre-_start daemons have no _capabilities — must not raise.
        daemon._capabilities = None
        mcp = IronMeshMCP(daemon, loop)
        assert mcp.tool_discover_capabilities({"pattern": "*"}) == []


class TestGetPeerCapabilities:
    def test_known_peer_by_name(self, daemon, loop):
        _attach_registry(daemon)
        _add_peer(daemon, "d" * 32, "alice", caps=["llm:llama3", "role:assistant"])
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_get_peer_capabilities({"target": "alice"})
        assert out["node_id"] == "d" * 32
        assert out["capabilities"] == ["llm:llama3", "role:assistant"]

    def test_known_peer_by_node_id(self, daemon, loop):
        _attach_registry(daemon)
        _add_peer(daemon, "e" * 32, "x", caps=["cap1"])
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_get_peer_capabilities({"target": "e" * 32})
        assert out["capabilities"] == ["cap1"]

    def test_unknown_peer(self, daemon, loop):
        _attach_registry(daemon)
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_get_peer_capabilities({"target": "ghost"})
        assert "error" in out

    def test_missing_target(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        assert "error" in mcp.tool_get_peer_capabilities({})


class TestRequestService:
    def test_unknown_peer(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_request_service({"target": "ghost", "prompt": "hi"})
        assert "error" in out

    def test_offline_peer(self, daemon, loop):
        _add_peer(daemon, "f" * 32, "alice", online=False)
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_request_service({"target": "alice", "prompt": "hi"})
        assert "error" in out and "online" in out["error"]

    def test_missing_prompt(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_request_service({"target": "x"})
        assert "error" in out

    def test_correlation_id_routes_response(self, daemon, loop, monkeypatch):
        """End-to-end: send_message returns; bus event with matching cid
        wakes the waiter and the body is returned."""
        _add_peer(daemon, "g" * 32, "alice")
        mcp = IronMeshMCP(daemon, loop)

        captured = {}
        async def fake_send(node_id, msg_type, payload, priority):
            captured["payload"] = payload
            envelope = json.loads(payload.decode())
            # Simulate the peer replying through the bus on a different thread
            def _reply():
                time.sleep(0.05)
                daemon.bus.publish("MSG", {
                    "peer_id": node_id,
                    "msg_id": "reply-1",
                    "payload": json.dumps({
                        "correlation_id": envelope["correlation_id"],
                        "body": "pong",
                    }).encode("utf-8"),
                })
            threading.Thread(target=_reply, daemon=True).start()
            return "msg-id-1"
        monkeypatch.setattr(daemon, "send_message", fake_send)

        out = mcp.tool_request_service({"target": "alice", "prompt": "ping",
                                         "timeout": 5})
        assert out.get("ok") is True
        assert out["response"] == "pong"

    def test_timeout_returns_timeout_marker(self, daemon, loop, monkeypatch):
        _add_peer(daemon, "h" * 32, "alice")
        mcp = IronMeshMCP(daemon, loop)
        async def fake_send(*a, **k):
            return "msg-id-2"
        monkeypatch.setattr(daemon, "send_message", fake_send)
        out = mcp.tool_request_service({"target": "alice", "prompt": "x",
                                         "timeout": 0.2})
        assert out.get("timeout") is True


class TestBroadcast:
    def test_skips_offline_and_self(self, daemon, loop, monkeypatch):
        _add_peer(daemon, "i" * 32, "online_a")
        _add_peer(daemon, "j" * 32, "online_b")
        _add_peer(daemon, "k" * 32, "off", online=False)
        # Self
        _add_peer(daemon, daemon.node_id, "me")

        sent = []
        async def fake_send(node_id, *a, **k):
            sent.append(node_id)
            return f"mid-{node_id[:4]}"
        monkeypatch.setattr(daemon, "send_message", fake_send)

        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_broadcast({"payload": "hello"})
        assert sorted(out["sent_to"]) == sorted(["i" * 32, "j" * 32])
        assert out["count"] == 2
        assert out["failed"] == []

    def test_records_failures(self, daemon, loop, monkeypatch):
        _add_peer(daemon, "l" * 32, "p")
        async def fake_send(*a, **k):
            raise RuntimeError("boom")
        monkeypatch.setattr(daemon, "send_message", fake_send)
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_broadcast({"payload": "x"})
        assert out["sent_to"] == []
        assert out["failed"] and out["failed"][0]["error"] == "boom"

    def test_missing_payload(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        assert "error" in mcp.tool_broadcast({})


class TestSubscribeEvents:
    def test_cursor_advances(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        # No events yet
        out0 = mcp.tool_subscribe_events({})
        assert out0["events"] == []
        assert out0["next_cursor"] == 0

        # Synthesize a couple bus events
        daemon.bus.publish("MSG", {"peer_id": "pa", "msg_id": "m1", "payload": b"x"})
        daemon.bus.publish("MSG", {"peer_id": "pb", "msg_id": "m2", "payload": b"y"})
        out1 = mcp.tool_subscribe_events({})
        assert len(out1["events"]) == 2
        cursor = out1["next_cursor"]
        # Subsequent poll with that cursor returns nothing
        out2 = mcp.tool_subscribe_events({"cursor": cursor})
        assert out2["events"] == []
        # New event after cursor shows up
        daemon.bus.publish("MSG", {"peer_id": "pc", "msg_id": "m3", "payload": b"z"})
        out3 = mcp.tool_subscribe_events({"cursor": cursor})
        assert len(out3["events"]) == 1

    def test_buffer_evicts_oldest(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop, event_buffer_size=5)
        for i in range(10):
            daemon.bus.publish("MSG", {"peer_id": f"p{i}", "msg_id": f"m{i}", "payload": b""})
        out = mcp.tool_subscribe_events({"limit": 100})
        assert len(out["events"]) == 5
        # Oldest seq retained should be 6 (we pushed 10, kept the last 5)
        seqs = [e["seq"] for e in out["events"]]
        assert seqs == [6, 7, 8, 9, 10]

    def test_kinds_filter(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        daemon.bus.publish("MSG", {"peer_id": "p", "msg_id": "m", "payload": b""})
        daemon.bus.publish("PING", {"peer_id": "p", "msg_id": "n", "payload": b""})
        out = mcp.tool_subscribe_events({"kinds": ["msg:MSG"]})
        kinds = {e["kind"] for e in out["events"]}
        assert kinds == {"msg:MSG"}

    def test_correlation_id_response_does_not_fail_parsing(self, daemon, loop):
        """The bus listener decodes JSON envelopes for correlation routing.
        Plain-bytes payloads must not crash that path."""
        mcp = IronMeshMCP(daemon, loop)  # noqa: F841
        # Non-JSON, non-decodable bytes
        daemon.bus.publish("MSG", {"peer_id": "p", "msg_id": "m",
                                    "payload": b"\xff\xfe\x00\x01"})
        # Plain text that's not JSON
        daemon.bus.publish("MSG", {"peer_id": "p", "msg_id": "m2",
                                    "payload": b"hello"})
        # Should still record both as events (no exception)
        out = mcp.tool_subscribe_events({})
        assert len(out["events"]) == 2


class TestGroup4StandaloneGaps:
    """Behaviors documented in docs/AUDIT_v0.8.4.md as untested but
    worth coverage independent of any specific fix."""

    def test_large_payload_round_trips_through_send_message(self, daemon, loop, monkeypatch):
        # 1 MiB payload — exercises the encode + send path without a
        # real socket. Confirms no truncation / no crash on the size.
        _add_peer(daemon, "a" * 32, "alice")
        captured = {}
        async def fake_send(node_id, msg_type, payload, priority):
            captured["size"] = len(payload)
            return "msg-1"
        monkeypatch.setattr(daemon, "send_message", fake_send)
        mcp = IronMeshMCP(daemon, loop)
        big = "x" * (1024 * 1024)  # 1 MiB
        out = mcp.tool_send_message({"target": "alice", "payload": big})
        assert out.get("ok") is True
        assert captured["size"] == 1024 * 1024

    def test_jsonrpc_error_envelope_shape_on_handler_exception(self, daemon, loop, monkeypatch):
        # The serve() loop wraps every tools/call in try/except and
        # emits a JSON-RPC error envelope (code -32000) when the
        # handler raises. Force the path explicitly.
        from ironmesh_mcp.server import serve, _dispatch as orig_dispatch  # noqa: F401

        def boom(*_a, **_k):
            raise RuntimeError("synthetic handler failure")

        # Monkeypatch _dispatch at import-site to force a raise
        import ironmesh_mcp.server as srv
        monkeypatch.setattr(srv, "_dispatch", boom)

        stdin = io.StringIO(json.dumps({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "ironmesh_list_peers", "arguments": {}},
        }) + "\n")
        stdout = io.StringIO()
        serve(daemon, loop, stdin=stdin, stdout=stdout)
        responses = [json.loads(l) for l in stdout.getvalue().splitlines() if l.strip()]
        assert len(responses) == 1
        r = responses[0]
        assert r["id"] == 9
        assert "error" in r
        assert r["error"]["code"] == -32000
        assert "synthetic handler failure" in r["error"]["message"]

    def test_kinds_filter_with_multiple_prefixes(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        daemon.bus.publish("MSG", {"peer_id": "p", "msg_id": "m1", "payload": b""})
        daemon.bus.publish("PING", {"peer_id": "p", "msg_id": "m2", "payload": b""})
        daemon.bus.publish("ACK", {"peer_id": "p", "msg_id": "m3", "payload": b""})
        out = mcp.tool_subscribe_events({"kinds": ["msg:MSG", "msg:ACK"]})
        kinds = sorted(e["kind"] for e in out["events"])
        assert kinds == ["msg:ACK", "msg:MSG"]

    def test_broadcast_partial_failure_with_mixed_outcomes(self, daemon, loop, monkeypatch):
        # Three peers — one succeeds, one raises sync, one raises async.
        _add_peer(daemon, "a" * 32, "alice")
        _add_peer(daemon, "b" * 32, "bob")
        _add_peer(daemon, "c" * 32, "carol")
        sent = []
        async def fake_send(node_id, *a, **k):
            if node_id == "b" * 32:
                raise RuntimeError("bob is down")
            if node_id == "c" * 32:
                raise ValueError("carol channel closed")
            sent.append(node_id)
            return f"mid-{node_id[:4]}"
        monkeypatch.setattr(daemon, "send_message", fake_send)
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_broadcast({"payload": "hi"})
        assert out["sent_to"] == ["a" * 32]
        assert {f["node_id"] for f in out["failed"]} == {"b" * 32, "c" * 32}
        assert out["count"] == 1


class TestNewToolSpecs:
    def test_new_tools_registered(self):
        names = {s["name"] for s in TOOL_SPECS}
        for n in ("ironmesh_discover_capabilities", "ironmesh_get_peer_capabilities",
                  "ironmesh_request_service", "ironmesh_broadcast",
                  "ironmesh_subscribe_events"):
            assert n in names, f"{n} missing from TOOL_SPECS"

    def test_total_tool_count(self):
        # 8 core + 5 cross-agent + 5 self-introspection + 3 pending-trust = 21
        assert len(TOOL_SPECS) == 21

    def test_pending_trust_tools_registered(self):
        names = {s["name"] for s in TOOL_SPECS}
        for n in (
            "ironmesh_list_pending_trust",
            "ironmesh_trust_peer",
            "ironmesh_block_peer",
        ):
            assert n in names, f"{n} missing from TOOL_SPECS"

    def test_audit_expansion_tools_registered(self):
        names = {s["name"] for s in TOOL_SPECS}
        for n in (
            "ironmesh_advertise_capability",
            "ironmesh_withdraw_capability",
            "ironmesh_get_my_identity",
            "ironmesh_pending_requests",
            "ironmesh_reply_to_request",
        ):
            assert n in names, f"{n} missing from TOOL_SPECS"


class TestAdvertiseCapability:
    def test_advertise_then_withdraw(self, daemon, loop):
        _attach_registry(daemon)
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_advertise_capability({"capability": "llm:test"})
        assert out["ok"] is True
        assert "llm:test" in out["local_capabilities"]
        # Withdraw
        out2 = mcp.tool_withdraw_capability({"capability": "llm:test"})
        assert out2["ok"] is True
        assert "llm:test" not in out2["local_capabilities"]

    def test_advertise_missing_capability(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_advertise_capability({})
        assert "error" in out

    def test_advertise_empty_string(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_advertise_capability({"capability": ""})
        assert "error" in out

    def test_withdraw_no_registry(self, daemon, loop):
        daemon._capabilities = None
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_withdraw_capability({"capability": "x"})
        assert "error" in out


class TestGetMyIdentity:
    def test_returns_node_id_name_capabilities(self, daemon, loop):
        _attach_registry(daemon)
        mcp = IronMeshMCP(daemon, loop)
        mcp.tool_advertise_capability({"capability": "role:test"})
        out = mcp.tool_get_my_identity({})
        assert out["node_id"] == daemon.node_id
        assert out["name"] == daemon.name
        assert "role:test" in out["capabilities"]
        assert out["running"] is False  # fixture daemon isn't started


class TestPendingRequests:
    def test_empty_when_none_inflight(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        assert mcp.tool_pending_requests({}) == []

    def test_lists_inflight_request_with_expected_peer(self, daemon, loop, monkeypatch):
        _add_peer(daemon, "z" * 32, "zoe")
        mcp = IronMeshMCP(daemon, loop)

        # Use a real concurrent.futures.Future-style fake that lets us
        # observe pending state mid-call. We synthesize the slot
        # directly to avoid having to spin up the full request_service
        # flow with a long timeout.
        slot = {"event": threading.Event(), "response": None,
                "from": None, "expected_peer": "z" * 32}
        with mcp._pending_lock:
            mcp._pending["abc123"] = slot
        try:
            out = mcp.tool_pending_requests({})
            assert len(out) == 1
            assert out[0]["correlation_id"] == "abc123"
            assert out[0]["expected_peer"] == "z" * 32
            assert out[0]["waiting"] is True
        finally:
            with mcp._pending_lock:
                mcp._pending.pop("abc123", None)


class TestReplyToRequest:
    def test_sends_correlation_envelope(self, daemon, loop, monkeypatch):
        _add_peer(daemon, "y" * 32, "yan")
        captured = {}
        async def fake_send(node_id, msg_type, payload, priority):
            captured["node_id"] = node_id
            captured["payload"] = json.loads(payload.decode())
            return "msg-r1"
        monkeypatch.setattr(daemon, "send_message", fake_send)
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_reply_to_request({
            "target": "yan",
            "correlation_id": "abc-1",
            "body": "the answer is 42",
        })
        assert out["ok"] is True
        assert captured["node_id"] == "y" * 32
        assert captured["payload"] == {"correlation_id": "abc-1", "body": "the answer is 42"}

    def test_missing_args(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        for args in [{}, {"target": "x"}, {"target": "x", "correlation_id": "y"}]:
            assert "error" in mcp.tool_reply_to_request(args)

    def test_unknown_peer(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_reply_to_request({
            "target": "ghost", "correlation_id": "x", "body": "y",
        })
        assert "error" in out

    def test_offline_peer(self, daemon, loop):
        _add_peer(daemon, "f" * 32, "fred", online=False)
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_reply_to_request({
            "target": "fred", "correlation_id": "x", "body": "y",
        })
        assert "error" in out


# ---------------------------------------------------------------------------
# Audit Group 1 — safety fixes (v0.8.4 audit)
# ---------------------------------------------------------------------------

class TestC1PeerDictThreadSafety:
    """C1: tool_list_peers / tool_send_message / _resolve_target must
    snapshot daemon.peers before iterating, otherwise concurrent
    connect/disconnect on the daemon's loop thread raises
    `RuntimeError: dictionary changed size during iteration`."""

    def test_list_peers_under_concurrent_mutation(self, daemon, loop):
        import time as _t
        mcp = IronMeshMCP(daemon, loop)
        # Seed
        for i in range(20):
            _add_peer(daemon, format(i, "032x"), f"p{i}")

        stop = threading.Event()
        errors: list[Exception] = []

        def mutate():
            i = 100
            while not stop.is_set():
                pid = format(i, "032x")
                _add_peer(daemon, pid, f"churn{i}")
                _t.sleep(0.0001)
                daemon.peers.pop(pid, None)
                i += 1

        def reader():
            try:
                for _ in range(500):
                    mcp.tool_list_peers({})
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        m = threading.Thread(target=mutate, daemon=True)
        r = threading.Thread(target=reader, daemon=True)
        m.start(); r.start()
        r.join(timeout=10)
        stop.set()
        m.join(timeout=2)
        assert not errors, f"tool_list_peers raised under concurrent mutation: {errors[:3]}"

    def test_resolve_target_under_concurrent_mutation(self, daemon, loop):
        import time as _t
        mcp = IronMeshMCP(daemon, loop)
        _add_peer(daemon, "a" * 32, "alice")

        stop = threading.Event()
        errors: list[Exception] = []

        def mutate():
            i = 200
            while not stop.is_set():
                pid = format(i, "032x")
                _add_peer(daemon, pid, f"churn{i}")
                _t.sleep(0.0001)
                daemon.peers.pop(pid, None)
                i += 1

        def reader():
            try:
                for _ in range(500):
                    assert mcp._resolve_target("alice") == "a" * 32
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        m = threading.Thread(target=mutate, daemon=True)
        r = threading.Thread(target=reader, daemon=True)
        m.start(); r.start()
        r.join(timeout=10)
        stop.set()
        m.join(timeout=2)
        assert not errors, f"_resolve_target raised under concurrent mutation: {errors[:3]}"


class TestM1MeshStatsRequiresStartedDaemon:
    def test_get_mesh_stats_errors_on_not_started(self, daemon, loop):
        # Daemon fixture is non-started by design.
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_get_mesh_stats({})
        assert "error" in out
        assert "not running" in out["error"]


class TestM3SubscribeEventsCursorClamp:
    def test_cursor_above_high_water_mark_is_clamped(self, daemon, loop):
        mcp = IronMeshMCP(daemon, loop)
        # Push a couple events
        daemon.bus.publish("MSG", {"peer_id": "p", "msg_id": "m1", "payload": b""})
        daemon.bus.publish("MSG", {"peer_id": "p", "msg_id": "m2", "payload": b""})
        # high_water_mark is now 2; ask for events past 99999
        out = mcp.tool_subscribe_events({"cursor": 99_999})
        assert out["cursor_clamped"] is True
        assert out["events"] == []
        # Subsequent poll picks up new events from the high-water mark
        daemon.bus.publish("MSG", {"peer_id": "p", "msg_id": "m3", "payload": b""})
        out2 = mcp.tool_subscribe_events({"cursor": out["next_cursor"]})
        assert len(out2["events"]) == 1


class TestH1CorrelationIdPeerKeyed:
    """H1: only the addressed peer may close out a request_service slot.
    Without this, any peer that knows the correlation_id can steal the
    response slot."""

    def test_cross_peer_echo_does_not_unblock_caller(self, daemon, loop, monkeypatch):
        # Two online peers; we send to "alice" but "mallory" tries to echo
        _add_peer(daemon, "a" * 32, "alice")
        _add_peer(daemon, "m" * 32, "mallory")

        captured = {}
        async def fake_send(node_id, msg_type, payload, priority):
            captured["sent_to"] = node_id
            envelope = json.loads(payload.decode())
            captured["cid"] = envelope["correlation_id"]
            # mallory tries to steal the slot by echoing the cid
            def _spoof():
                time.sleep(0.05)
                daemon.bus.publish("MSG", {
                    "peer_id": "m" * 32,  # NOT the addressed peer
                    "msg_id": "spoof-1",
                    "payload": json.dumps({
                        "correlation_id": captured["cid"],
                        "body": "stolen",
                    }).encode("utf-8"),
                })
            threading.Thread(target=_spoof, daemon=True).start()
            return "msg-id-1"

        monkeypatch.setattr(daemon, "send_message", fake_send)
        mcp = IronMeshMCP(daemon, loop)

        # With the timeout short, if the spoof had succeeded we'd see
        # `ok: True, response: "stolen"`. With the fix, the spoof is
        # filtered and the call times out.
        out = mcp.tool_request_service({"target": "alice", "prompt": "hi",
                                         "timeout": 0.5})
        assert out.get("timeout") is True
        # Cross-peer echo recorded as observability event
        events = mcp.tool_subscribe_events({})["events"]
        kinds = [e["kind"] for e in events]
        assert "request_service:cross_peer_echo" in kinds

    def test_correct_peer_response_still_resolves(self, daemon, loop, monkeypatch):
        # Sanity check that H1 didn't break the happy path
        _add_peer(daemon, "a" * 32, "alice")

        async def fake_send(node_id, msg_type, payload, priority):
            envelope = json.loads(payload.decode())
            def _reply():
                time.sleep(0.05)
                daemon.bus.publish("MSG", {
                    "peer_id": node_id,  # the addressed peer
                    "msg_id": "reply-1",
                    "payload": json.dumps({
                        "correlation_id": envelope["correlation_id"],
                        "body": "pong",
                    }).encode("utf-8"),
                })
            threading.Thread(target=_reply, daemon=True).start()
            return "msg-id-1"

        monkeypatch.setattr(daemon, "send_message", fake_send)
        mcp = IronMeshMCP(daemon, loop)
        out = mcp.tool_request_service({"target": "alice", "prompt": "hi",
                                         "timeout": 5})
        assert out.get("ok") is True
        assert out["response"] == "pong"
