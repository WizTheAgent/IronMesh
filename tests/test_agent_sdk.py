"""Tests for the high-level Agent SDK (ironmesh.agent)."""

import asyncio
import os
import threading
import time

import pytest

from ironmesh.agent import Agent
from ironmesh.protocol import PeerState


STRONG_PASS = "test-agent-sdk-passphrase-ok"


class TestAgentInit:
    def test_creates_with_passphrase(self):
        a = Agent("test", port=19001, passphrase=STRONG_PASS)
        assert a.name == "test"
        assert a.daemon is not None
        assert a.daemon.port == 19001

    def test_reads_passphrase_from_env(self, monkeypatch):
        monkeypatch.setenv("IRONMESH_PASSPHRASE", STRONG_PASS)
        a = Agent("test-env", port=19002)
        assert a.daemon.passphrase == STRONG_PASS

    def test_custom_passphrase_env(self, monkeypatch):
        monkeypatch.setenv("MY_PASS", STRONG_PASS)
        a = Agent("test-custom", port=19003, passphrase_env="MY_PASS")
        assert a.daemon.passphrase == STRONG_PASS

    def test_raises_without_passphrase(self, monkeypatch):
        monkeypatch.delenv("IRONMESH_PASSPHRASE", raising=False)
        with pytest.raises(ValueError, match="Passphrase required"):
            Agent("test-fail", port=19004)

    def test_extra_daemon_kwargs(self):
        a = Agent("test-extra", port=19005, passphrase=STRONG_PASS,
                   max_hops=3, rekey_interval=600.0)
        assert a.daemon is not None


class TestDecorators:
    def test_on_message_registers_handler(self):
        a = Agent("deco-test", port=19010, passphrase=STRONG_PASS)
        calls = []

        @a.on_message()
        def handler(peer_id, payload):
            calls.append((peer_id, payload))

        assert "MSG" in a._handlers
        assert len(a._handlers["MSG"]) == 1

    def test_on_message_custom_type(self):
        a = Agent("deco-custom", port=19011, passphrase=STRONG_PASS)

        @a.on_message("REQ")
        def handler(peer_id, payload):
            pass

        assert "REQ" in a._handlers
        assert "MSG" not in a._handlers

    def test_on_event_raw(self):
        a = Agent("deco-raw", port=19012, passphrase=STRONG_PASS)

        @a.on("CUSTOM_EVENT")
        def handler(data):
            pass

        assert "CUSTOM_EVENT" in a._handlers

    def test_multiple_handlers_same_type(self):
        a = Agent("deco-multi", port=19013, passphrase=STRONG_PASS)

        @a.on_message()
        def first(peer_id, payload):
            pass

        @a.on_message()
        def second(peer_id, payload):
            pass

        assert len(a._handlers["MSG"]) == 2

    def test_decorator_returns_original_function(self):
        a = Agent("deco-ret", port=19014, passphrase=STRONG_PASS)

        @a.on_message()
        def handler(peer_id, payload):
            return "original"

        assert handler("x", b"y") == "original"


class TestPeers:
    def test_peers_empty_when_no_connections(self):
        a = Agent("peers-test", port=19020, passphrase=STRONG_PASS)
        assert a.peers == []

    def test_peers_returns_online_only(self):
        a = Agent("peers-filter", port=19021, passphrase=STRONG_PASS)
        online = PeerState(node_id="aaa", address="10.0.0.1:8765")
        online.transition(PeerState.Status.ONLINE)
        online.latency_ms = 12.5
        offline = PeerState(node_id="bbb", address="10.0.0.2:8765")
        a.daemon.peers["aaa"] = online
        a.daemon.peers["bbb"] = offline

        peers = a.peers
        assert len(peers) == 1
        assert peers[0]["node_id"] == "aaa"
        assert peers[0]["rtt_ms"] == 12.5

    def test_peer_by_name(self):
        a = Agent("peers-name", port=19022, passphrase=STRONG_PASS)
        ps = PeerState(node_id="ccc", address="10.0.0.3:8765")
        ps.transition(PeerState.Status.ONLINE)
        ps.agent_name = "alice"
        a.daemon.peers["ccc"] = ps

        found = a.peer_by_name("alice")
        assert found is not None
        assert found["node_id"] == "ccc"
        assert a.peer_by_name("nonexistent") is None

    def test_node_id_before_run(self):
        a = Agent("node-id", port=19023, passphrase=STRONG_PASS)
        # Before run(), node_id is either None or a placeholder like 'uninitialized'
        assert a.node_id is None or a.node_id == "uninitialized"


class TestResolvePeer:
    def test_passthrough_hex_node_id(self):
        a = Agent("resolve", port=19030, passphrase=STRONG_PASS)
        assert a._resolve_peer("abcdef0123456789abcdef0123456789") == "abcdef0123456789abcdef0123456789"

    def test_resolves_name_to_node_id(self):
        a = Agent("resolve-name", port=19031, passphrase=STRONG_PASS)
        ps = PeerState(node_id="ddd111ddd222ddd333ddd444ddd55566", address="10.0.0.4:8765")
        ps.transition(PeerState.Status.ONLINE)
        ps.agent_name = "target-agent"
        a.daemon.peers["ddd111ddd222ddd333ddd444ddd55566"] = ps

        assert a._resolve_peer("target-agent") == "ddd111ddd222ddd333ddd444ddd55566"

    def test_raises_on_unknown_name(self):
        a = Agent("resolve-fail", port=19032, passphrase=STRONG_PASS)
        with pytest.raises(ValueError, match="not found"):
            a._resolve_peer("ghost-agent")


class TestSendSync:
    def test_raises_if_not_running(self):
        a = Agent("send-norun", port=19040, passphrase=STRONG_PASS)
        with pytest.raises(RuntimeError, match="not running"):
            a.send_sync("anyone", "hello")


class TestReply:
    def test_reply_noop_if_not_running(self):
        a = Agent("reply-norun", port=19041, passphrase=STRONG_PASS)
        a.reply("peer1", "hello")


class TestWireHandlers:
    def test_wire_handlers_subscribes_to_bus(self):
        a = Agent("wire-test", port=19050, passphrase=STRONG_PASS)
        calls = []

        @a.on_message()
        def handler(peer_id, payload):
            calls.append((peer_id, payload))

        # Manually wire (normally done by run())
        a._wire_handlers()

        # Simulate bus publish
        a.daemon.bus.publish("MSG", {"peer_id": "sender1", "payload": b"hello"})

        assert len(calls) == 1
        assert calls[0] == ("sender1", b"hello")

    def test_handler_exception_doesnt_crash(self):
        a = Agent("wire-crash", port=19051, passphrase=STRONG_PASS)

        @a.on_message()
        def bad_handler(peer_id, payload):
            raise ValueError("intentional test error")

        a._wire_handlers()
        a.daemon.bus.publish("MSG", {"peer_id": "x", "payload": b"y"})

    def test_raw_event_handler(self):
        a = Agent("wire-raw", port=19052, passphrase=STRONG_PASS)
        events = []

        @a.on("CUSTOM")
        def handler(data):
            events.append(data)

        a._wire_handlers()
        a.daemon.bus.publish("CUSTOM", {"key": "value"})
        assert len(events) == 1


class TestStop:
    def test_stop_is_idempotent(self):
        a = Agent("stop-idem", port=19060, passphrase=STRONG_PASS)
        a.stop()
        a.stop()
