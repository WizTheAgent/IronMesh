"""Tests for the v0.9.2 NAT relay rendezvous server."""
import asyncio
import json

import pytest
import websockets

from ironmesh.nat_relay import (
    MAX_FORWARDS_PER_MINUTE,
    MAX_REGISTERED_PEERS,
    RelayRegistry,
    RelayServer,
)


class TestRelayRegistry:
    def test_register_and_lookup(self):
        r = RelayRegistry()
        assert r.register("n1", object()) is True
        assert r.lookup("n1") is not None
        assert r.lookup("unknown") is None

    def test_register_replaces_stale_socket(self):
        r = RelayRegistry()
        old = object()
        new = object()
        r.register("n1", old)
        r.register("n1", new)
        assert r.lookup("n1") is new

    def test_note_forward_enforces_cap(self):
        r = RelayRegistry()
        r.register("n1", object())
        for _ in range(MAX_FORWARDS_PER_MINUTE):
            assert r.note_forward("n1") is True
        # The next one trips the cap
        assert r.note_forward("n1") is False

    def test_deregister_clears_state(self):
        r = RelayRegistry()
        r.register("n1", object())
        r.note_forward("n1")
        r.deregister("n1")
        assert r.lookup("n1") is None
        assert "n1" not in r._forward_counts

    def test_registry_full_refuses_new_peer(self):
        r = RelayRegistry()
        # Pretend the registry is already at cap
        for i in range(MAX_REGISTERED_PEERS):
            r._sockets[f"n{i}"] = object()
        # Existing peer re-register is allowed (replaces)
        assert r.register("n0", object()) is True
        # Brand-new peer is refused
        assert r.register("new", object()) is False


# ---------------------------------------------------------------------------
# End-to-end: spin up the real relay, register two clients, forward a frame.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_end_to_end_forward_between_two_clients(unused_tcp_port):
    server = RelayServer(bind="127.0.0.1", port=unused_tcp_port)
    serve_task = asyncio.create_task(server.serve())
    try:
        await asyncio.sleep(0.3)  # let the server bind

        a = await websockets.connect(f"ws://127.0.0.1:{unused_tcp_port}")
        b = await websockets.connect(f"ws://127.0.0.1:{unused_tcp_port}")

        await a.send(json.dumps({"type": "REGISTER", "node_id": "alice"}))
        ack = json.loads(await a.recv())
        assert ack["type"] == "REGISTER_ACK"
        assert ack["node_id"] == "alice"

        await b.send(json.dumps({"type": "REGISTER", "node_id": "bob"}))
        ack = json.loads(await b.recv())
        assert ack["type"] == "REGISTER_ACK"
        assert ack["node_id"] == "bob"

        await a.send(json.dumps({
            "type": "FORWARD",
            "to": "bob",
            "payload": "aGVsbG8=",  # "hello" base64
        }))
        received = json.loads(await b.recv())
        assert received["type"] == "FORWARD"
        assert received["from"] == "alice"
        assert received["payload"] == "aGVsbG8="

        await a.close()
        await b.close()
    finally:
        serve_task.cancel()
        try:
            await serve_task
        except (asyncio.CancelledError, Exception):
            pass


@pytest.mark.asyncio
async def test_forward_to_unknown_peer_returns_unreachable(unused_tcp_port):
    server = RelayServer(bind="127.0.0.1", port=unused_tcp_port)
    serve_task = asyncio.create_task(server.serve())
    try:
        await asyncio.sleep(0.3)
        client = await websockets.connect(f"ws://127.0.0.1:{unused_tcp_port}")
        await client.send(json.dumps({"type": "REGISTER", "node_id": "alice"}))
        await client.recv()  # REGISTER_ACK

        await client.send(json.dumps({
            "type": "FORWARD",
            "to": "nobody",
            "payload": "x",
        }))
        resp = json.loads(await client.recv())
        assert resp["type"] == "FORWARD_UNREACHABLE"
        assert resp["to"] == "nobody"

        await client.close()
    finally:
        serve_task.cancel()
        try:
            await serve_task
        except (asyncio.CancelledError, Exception):
            pass


@pytest.mark.asyncio
async def test_forward_with_non_string_payload_rejected(unused_tcp_port):
    """v0.9.2 hardening: payload must be a string, never null/list/dict."""
    server = RelayServer(bind="127.0.0.1", port=unused_tcp_port)
    serve_task = asyncio.create_task(server.serve())
    try:
        await asyncio.sleep(0.3)
        client = await websockets.connect(f"ws://127.0.0.1:{unused_tcp_port}")
        await client.send(json.dumps({"type": "REGISTER", "node_id": "alice"}))
        await client.recv()  # REGISTER_ACK

        # Try a non-string payload (None, list, dict)
        for bad_payload in (None, [1, 2, 3], {"k": "v"}, 42):
            await client.send(json.dumps({
                "type": "FORWARD",
                "to": "anyone",
                "payload": bad_payload,
            }))
            resp = json.loads(await client.recv())
            assert resp["type"] == "REJECTED", (
                f"non-string payload {bad_payload!r} should be rejected, "
                f"got {resp}"
            )
            # After REJECTED the server closes; need a fresh connection.
            try: await client.close()
            except Exception: pass
            client = await websockets.connect(
                f"ws://127.0.0.1:{unused_tcp_port}")
            await client.send(json.dumps({"type": "REGISTER", "node_id": "alice"}))
            await client.recv()
        try: await client.close()
        except Exception: pass
    finally:
        serve_task.cancel()
        try: await serve_task
        except (asyncio.CancelledError, Exception): pass


@pytest.mark.asyncio
async def test_forward_with_empty_dst_rejected(unused_tcp_port):
    """v0.9.2 hardening: 'to' must be non-empty string."""
    server = RelayServer(bind="127.0.0.1", port=unused_tcp_port)
    serve_task = asyncio.create_task(server.serve())
    try:
        await asyncio.sleep(0.3)
        client = await websockets.connect(f"ws://127.0.0.1:{unused_tcp_port}")
        await client.send(json.dumps({"type": "REGISTER", "node_id": "alice"}))
        await client.recv()
        await client.send(json.dumps({
            "type": "FORWARD", "to": "", "payload": "x",
        }))
        resp = json.loads(await client.recv())
        assert resp["type"] == "REJECTED"
        assert "non-empty 'to'" in resp["reason"]
    finally:
        serve_task.cancel()
        try: await serve_task
        except (asyncio.CancelledError, Exception): pass


@pytest.mark.asyncio
async def test_forward_before_register_rejected(unused_tcp_port):
    server = RelayServer(bind="127.0.0.1", port=unused_tcp_port)
    serve_task = asyncio.create_task(server.serve())
    try:
        await asyncio.sleep(0.3)
        client = await websockets.connect(f"ws://127.0.0.1:{unused_tcp_port}")
        await client.send(json.dumps({
            "type": "FORWARD",
            "to": "bob",
            "payload": "x",
        }))
        resp = json.loads(await client.recv())
        assert resp["type"] == "REJECTED"
        assert "REGISTER" in resp["reason"]
    finally:
        serve_task.cancel()
        try:
            await serve_task
        except (asyncio.CancelledError, Exception):
            pass
