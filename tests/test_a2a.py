"""Tests for the A2A HTTP gateway (Agent-to-Agent v0.3.0).

Protocol-level tests against a stub daemon. The full mesh-side
dispatch is covered by manual release-smoke.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest

from ironmesh_a2a.server import (
    A2A_PROTOCOL_VERSION,
    A2A_DEFAULT_MAX_HOPS,
    A2AGateway,
    A2AError,
    _extract_text_part,
    _looks_like_node_id,
    _ack,
    _response_envelope,
)


VALID_NODE = "60a9cca12a98c5ffffe39fdbb6fcbd61"


class _FakeBus:
    def __init__(self):
        self.subscribers = {}

    def subscribe(self, topic, cb):
        self.subscribers.setdefault(topic, []).append(cb)

    def unsubscribe(self, topic, cb):
        try:
            self.subscribers[topic].remove(cb)
        except (KeyError, ValueError):
            pass

    def publish(self, topic, msg_data):
        for cb in list(self.subscribers.get(topic, [])):
            cb(msg_data)


class _FakeDaemon:
    def __init__(self):
        self.bus = _FakeBus()
        self.sent = []

    async def send_message(self, to_node, msg_type, payload, priority="NORMAL"):
        self.sent.append((to_node, msg_type, payload, priority))
        return "fake-msg-id"


@pytest.fixture
def loop():
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, name="test-a2a-loop", daemon=True)
    t.start()
    yield loop
    loop.call_soon_threadsafe(loop.stop)
    t.join(timeout=2)


@pytest.fixture
def gateway(loop):
    daemon = _FakeDaemon()
    gw = A2AGateway(
        daemon=daemon,
        loop=loop,
        gateway_id=VALID_NODE,
        token="test-token",
        public_url="http://127.0.0.1:18800",
    )
    return gw, daemon


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_extract_text_part_finds_first_text():
    assert _extract_text_part([{"kind": "text", "text": "hello"}]) == "hello"
    assert _extract_text_part(
        [{"kind": "image"}, {"kind": "text", "text": "hi"}],
    ) == "hi"


def test_extract_text_part_returns_none_when_no_text():
    assert _extract_text_part([{"kind": "image"}]) is None
    assert _extract_text_part([]) is None
    assert _extract_text_part("not-a-list") is None


def test_looks_like_node_id_basic():
    assert _looks_like_node_id(VALID_NODE)
    assert not _looks_like_node_id(VALID_NODE[:-1])


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_auth_required_when_token_set(gateway):
    gw, _ = gateway
    assert gw.auth_ok("Bearer test-token") is True
    assert gw.auth_ok("Bearer wrong-token") is False
    assert gw.auth_ok(None) is False
    assert gw.auth_ok("") is False
    assert gw.auth_ok("Basic dGVzdA==") is False


def test_auth_disabled_when_no_token(loop):
    daemon = _FakeDaemon()
    gw = A2AGateway(daemon=daemon, loop=loop, gateway_id=VALID_NODE,
                    token=None, public_url="http://127.0.0.1:18800")
    assert gw.auth_ok(None) is True
    assert gw.auth_ok("Bearer anything") is True


# ---------------------------------------------------------------------------
# AgentCard
# ---------------------------------------------------------------------------


def test_agent_card_structure(gateway):
    gw, _ = gateway
    card = gw.agent_card()
    assert card["protocolVersion"] == A2A_PROTOCOL_VERSION
    assert card["name"] == "ironmesh-a2a"
    assert card["url"] == "http://127.0.0.1:18800/a2a/jsonrpc"
    assert "bearer" in card["securitySchemes"]
    assert card["security"] == [{"bearer": []}]
    assert any(s["id"] == "chat" for s in card["skills"])
    transports = [iface["transport"] for iface in card["additionalInterfaces"]]
    assert "JSONRPC" in transports
    assert "HTTP+JSON" in transports


def test_agent_card_no_auth_section_when_token_disabled(loop):
    daemon = _FakeDaemon()
    gw = A2AGateway(daemon=daemon, loop=loop, gateway_id=VALID_NODE,
                    token=None, public_url="http://127.0.0.1:18800")
    card = gw.agent_card()
    assert card["securitySchemes"] == {}
    assert card["security"] == []


# ---------------------------------------------------------------------------
# Anti-loop / hop limit
# ---------------------------------------------------------------------------


def test_append_route_appends_self_when_not_in_path(gateway):
    gw, _ = gateway
    new_route, is_loop = gw.append_route(["other-gateway"])
    assert is_loop is False
    assert new_route == ["other-gateway", VALID_NODE]


def test_append_route_detects_loop_when_self_already_in_path(gateway):
    gw, _ = gateway
    new_route, is_loop = gw.append_route(["other-gateway", VALID_NODE])
    assert is_loop is True
    # When loop detected, route is left unchanged.
    assert new_route == ["other-gateway", VALID_NODE]


def test_max_hops_constant_is_reasonable():
    assert A2A_DEFAULT_MAX_HOPS >= 4
    assert A2A_DEFAULT_MAX_HOPS <= 32


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------


def test_ack_envelope_carries_correlation_and_status(gateway):
    gw, _ = gateway
    env = {"message_id": "src-msg-1"}
    ack = _ack(env, gw, "accepted", None)
    assert ack["protocol_version"] == "a2a/v1"
    assert ack["correlation_id"] == "src-msg-1"
    assert ack["message_type"] == "ack"
    assert ack["status"] == "accepted"
    assert ack["source"]["gateway_id"] == VALID_NODE


def test_response_envelope_increments_hop_count(gateway):
    gw, _ = gateway
    env = {"message_id": "src-1", "source": {"gateway_id": "other"}, "hop_count": 3}
    resp = _response_envelope(env, gw, {"reply": "hi", "elapsed_ms": 12}, ["a", "b"])
    assert resp["hop_count"] == 4
    assert resp["destination"] == "other"
    assert resp["payload"]["text"] == "hi"
    assert resp["payload"]["elapsed_ms"] == 12
    assert resp["route_path"] == ["a", "b"]


# ---------------------------------------------------------------------------
# message/send dispatch (with the fake daemon's bus echoing the reply)
# ---------------------------------------------------------------------------


def test_dispatch_message_send_round_trip(gateway):
    gw, daemon = gateway

    # Echo replies on the bus when a MSG is dispatched.
    def auto_reply(to_node, msg_type, payload, priority):
        envelope = json.loads(payload)
        gw._on_inbound_msg({
            "peer_id": VALID_NODE,
            "msg_id": "reply",
            "type": "MSG",
            "payload": json.dumps(
                {"correlation_id": envelope["correlation_id"], "body": "echo: " + envelope["body"]},
            ).encode("utf-8"),
        })

    original_send = daemon.send_message

    async def wrapped_send(to_node, msg_type, payload, priority="NORMAL"):
        result = await original_send(to_node, msg_type, payload, priority)
        # Schedule the echo on the loop thread so the future lookup races
        # with the dispatch completing.
        threading.Timer(
            0.01,
            auto_reply, args=(to_node, msg_type, payload, priority),
        ).start()
        return result

    daemon.send_message = wrapped_send

    result = gw.dispatch_message_send(VALID_NODE, "ping", ttl_seconds=5.0)
    assert result["reply"] == "echo: ping"
    assert isinstance(result["elapsed_ms"], int)


def test_dispatch_invalid_destination_raises(gateway):
    gw, _ = gateway
    with pytest.raises(A2AError) as exc_info:
        gw.dispatch_message_send("not-a-node-id", "ping", ttl_seconds=1.0)
    assert "not a 32-hex node id" in str(exc_info.value)


def test_dispatch_timeout_when_no_reply(gateway):
    gw, _ = gateway
    t0 = time.time()
    with pytest.raises(A2AError) as exc_info:
        gw.dispatch_message_send(VALID_NODE, "ping", ttl_seconds=1.0)
    assert "no reply" in str(exc_info.value).lower()
    assert time.time() - t0 < 4.0  # should respect ttl
