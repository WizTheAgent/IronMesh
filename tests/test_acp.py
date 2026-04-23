"""Tests for the ACP stdio adapter (Agent Client Protocol bridge).

Protocol-level tests use a stub ``daemon`` (no real mesh) so the test
loop can run on any host. The full live-mesh round-trip is exercised
in the manual ``release-smoke`` checklist.
"""

from __future__ import annotations

import asyncio
import json
import threading

import pytest

from ironmesh_acp.server import (
    ACPServer,
    ACP_PROTOCOL_VERSION,
    ACP_CONFORMANCE_PROFILE,
    JSONRPC_INVALID_PARAMS,
    ACP_UNKNOWN_SESSION,
    _ParamError,
    _UnknownSession,
    _content_text,
    _looks_like_node_id,
)


VALID_NODE = "60a9cca12a98c5ffffe39fdbb6fcbd61"


class _FakeBus:
    """Stub of the daemon's pub/sub bus.

    Captures subscribe/unsubscribe so the test can simulate inbound
    MSGs landing on the daemon and check that the gateway routes them
    back as session/update notifications via the future the gateway
    registered.
    """

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
        self.sent = []  # list of (peer_node_id, msg_type, payload, priority)

    async def send_message(self, to_node, msg_type, payload, priority="NORMAL"):
        self.sent.append((to_node, msg_type, payload, priority))
        return "fake-msg-id"


@pytest.fixture
def loop():
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, name="test-loop", daemon=True)
    t.start()
    yield loop
    loop.call_soon_threadsafe(loop.stop)
    t.join(timeout=2)


@pytest.fixture
def gateway(loop):
    daemon = _FakeDaemon()
    server = ACPServer(daemon, loop, default_peer=None)
    return server, daemon


# ---------------------------------------------------------------------------
# Helper-function tests
# ---------------------------------------------------------------------------


def test_content_text_text_block():
    assert _content_text([{"type": "text", "text": "hello"}]) == "hello"


def test_content_text_concatenates_multiple_text_blocks():
    blocks = [
        {"type": "text", "text": "hello "},
        {"type": "text", "text": "world"},
    ]
    assert _content_text(blocks) == "hello world"


def test_content_text_ignores_non_text_blocks():
    blocks = [
        {"type": "text", "text": "the "},
        {"type": "image", "url": "https://example.com/x.png"},
        {"type": "text", "text": "answer"},
    ]
    assert _content_text(blocks) == "the answer"


def test_content_text_empty_or_invalid_returns_none():
    assert _content_text([]) is None
    assert _content_text(None) is None
    assert _content_text("not a list") is None
    assert _content_text([{"type": "image"}]) is None


def test_looks_like_node_id_accepts_lower_and_upper():
    assert _looks_like_node_id(VALID_NODE)
    assert _looks_like_node_id(VALID_NODE.upper())


def test_looks_like_node_id_rejects_wrong_length_or_non_hex():
    assert not _looks_like_node_id(VALID_NODE[:-1])
    assert not _looks_like_node_id(VALID_NODE + "ff")
    assert not _looks_like_node_id("zzzzzzzz" + VALID_NODE[8:])
    assert not _looks_like_node_id("")


# ---------------------------------------------------------------------------
# Protocol-level tests
# ---------------------------------------------------------------------------


def test_initialize_returns_protocol_version_and_capabilities(gateway, loop):
    server, _ = gateway
    fut = asyncio.run_coroutine_threadsafe(server.handle_initialize({}), loop)
    result = fut.result(timeout=2)
    assert result["protocolVersion"] == ACP_PROTOCOL_VERSION
    assert result["conformanceProfile"] == ACP_CONFORMANCE_PROFILE
    assert "capabilities" in result
    assert result["capabilities"]["session"]["prompt"] is True


def test_session_new_requires_a_peer(gateway, loop):
    server, _ = gateway
    fut = asyncio.run_coroutine_threadsafe(
        server.handle_session_new({"meta": {}}), loop,
    )
    with pytest.raises(_ParamError, match="no peer specified"):
        fut.result(timeout=2)


def test_session_new_rejects_non_hex_peer(gateway, loop):
    server, _ = gateway
    fut = asyncio.run_coroutine_threadsafe(
        server.handle_session_new({"meta": {"peer": "not-a-node-id"}}), loop,
    )
    with pytest.raises(_ParamError, match="not a 32-hex node id"):
        fut.result(timeout=2)


def test_session_new_creates_session_with_lowercased_peer(gateway, loop):
    server, _ = gateway
    fut = asyncio.run_coroutine_threadsafe(
        server.handle_session_new({"meta": {"peer": VALID_NODE.upper()}}), loop,
    )
    result = fut.result(timeout=2)
    assert result["peer"] == VALID_NODE
    assert result["sessionId"] in server.sessions
    assert server.sessions[result["sessionId"]].peer_node_id == VALID_NODE


def test_default_peer_is_used_when_meta_omits(loop):
    daemon = _FakeDaemon()
    server = ACPServer(daemon, loop, default_peer=VALID_NODE)
    fut = asyncio.run_coroutine_threadsafe(
        server.handle_session_new({}), loop,
    )
    result = fut.result(timeout=2)
    assert result["peer"] == VALID_NODE


def test_session_cancel_unknown_id_raises(gateway, loop):
    server, _ = gateway
    fut = asyncio.run_coroutine_threadsafe(
        server.handle_session_cancel({"sessionId": "nope"}), loop,
    )
    with pytest.raises(_UnknownSession):
        fut.result(timeout=2)


def test_session_prompt_validates_content_blocks(gateway, loop):
    server, _ = gateway
    new_fut = asyncio.run_coroutine_threadsafe(
        server.handle_session_new({"meta": {"peer": VALID_NODE}}), loop,
    )
    sid = new_fut.result(timeout=2)["sessionId"]

    async def noop_notify(_frame):
        return None

    fut = asyncio.run_coroutine_threadsafe(
        server.handle_session_prompt(
            {"sessionId": sid, "prompt": []}, noop_notify,
        ),
        loop,
    )
    with pytest.raises(_ParamError, match="content-blocks"):
        fut.result(timeout=2)


def test_session_prompt_dispatches_msg_then_resolves_on_correlated_reply(gateway, loop):
    server, daemon = gateway
    new_fut = asyncio.run_coroutine_threadsafe(
        server.handle_session_new({"meta": {"peer": VALID_NODE}}), loop,
    )
    sid = new_fut.result(timeout=2)["sessionId"]

    notifications = []

    async def collect_notify(frame):
        notifications.append(frame)

    prompt_fut = asyncio.run_coroutine_threadsafe(
        server.handle_session_prompt(
            {"sessionId": sid,
             "prompt": [{"type": "text", "text": "hello"}]},
            collect_notify,
        ),
        loop,
    )

    # Wait for the dispatch to enqueue.
    deadline = asyncio.run_coroutine_threadsafe(
        asyncio.sleep(0.5), loop,
    )
    deadline.result()
    assert len(daemon.sent) == 1
    to_node, msg_type, payload, priority = daemon.sent[0]
    assert to_node == VALID_NODE
    assert msg_type == "MSG"
    assert priority == "NORMAL"

    envelope = json.loads(payload)
    assert envelope["body"] == "hello"
    correlation_id = envelope["correlation_id"]

    # Simulate the peer's reply landing on the daemon's bus.
    reply_payload = json.dumps(
        {"correlation_id": correlation_id, "body": "ack: hello"},
    ).encode("utf-8")
    daemon.bus.publish(
        "MSG",
        {"peer_id": VALID_NODE, "msg_id": "reply-id",
         "type": "MSG", "payload": reply_payload},
    )

    result = prompt_fut.result(timeout=5)
    assert result["stopReason"] == "end_turn"
    # We get at least the "thinking" preview, the agent_message_chunk, and
    # the terminal "stop" notification.
    types = [n["params"]["type"] for n in notifications]
    assert "thinking" in types
    assert "agent_message_chunk" in types
    assert types[-1] == "stop"
    chunks = [
        n["params"]["content"]["text"]
        for n in notifications
        if n["params"]["type"] == "agent_message_chunk"
    ]
    assert chunks == ["ack: hello"]
