"""Tests for the v0.9.1 unified-transport selection layer.

Covers ``BridgeDaemon.send_to_name`` and ``BridgeDaemon.unified_peers``:
the two daemon methods that back ``Agent.send_to`` / ``Agent.unified_peers``
and serve as the single transport-selection point for the OpenClaw,
ACP, and A2A surfaces.

These tests stub the daemon's transport methods directly — they verify
the *routing decision* (which tier fires for which input) rather than
the underlying send paths, which have their own coverage.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

class FakePeerState:
    """Minimal stand-in for ``ironmesh.protocol.PeerState``."""
    def __init__(self, *, is_online=True, agent_name=None,
                 transport_type="websocket", latency_ms=42.0,
                 rns_dest_hash=None, rns_hops=None,
                 rns_estimated_rtt_ms=None, rns_estimated_bps=None):
        self.is_online = is_online
        self.agent_name = agent_name
        self.transport_type = transport_type
        self.latency_ms = latency_ms
        self.rns_dest_hash = rns_dest_hash
        self.rns_hops = rns_hops
        self.rns_estimated_rtt_ms = rns_estimated_rtt_ms
        self.rns_estimated_bps = rns_estimated_bps


def _make_daemon():
    """Build a daemon stub with just the v0.9.1 unified-transport bits.

    Binds the real methods from BridgeDaemon onto a bare object to
    exercise the actual code, not a mock — while skipping the heavy
    daemon init.
    """
    from ironmesh.bridge import BridgeDaemon
    daemon = MagicMock()
    daemon.peers = {}
    daemon._rns_discovered = {}
    daemon._reticulum = None
    daemon._lxmf = None
    daemon._known_rns_hashes = {}
    daemon.send_message = AsyncMock(return_value="msg-id-stub")
    daemon._connect_and_track_rns = AsyncMock(return_value=None)
    # Bind the real implementations from BridgeDaemon
    daemon._find_online_peer_by_name = (
        BridgeDaemon._find_online_peer_by_name.__get__(daemon)
    )
    daemon._find_rns_discovered_by_name = (
        BridgeDaemon._find_rns_discovered_by_name.__get__(daemon)
    )
    daemon._looks_like_lxmf_hash = BridgeDaemon._looks_like_lxmf_hash
    daemon.unified_peers = BridgeDaemon.unified_peers.__get__(daemon)
    daemon.send_to_name = BridgeDaemon.send_to_name.__get__(daemon)
    return daemon


# ---------------------------------------------------------------------------
# unified_peers()
# ---------------------------------------------------------------------------

class TestUnifiedPeers:
    def test_online_ws_peer_appears_with_websocket_transport(self):
        daemon = _make_daemon()
        daemon.peers = {
            "node-1": FakePeerState(agent_name="alice",
                                     transport_type="websocket",
                                     latency_ms=12.0)
        }
        peers = daemon.unified_peers()
        assert len(peers) == 1
        assert peers[0]["name"] == "alice"
        assert peers[0]["transport"] == "websocket"
        assert peers[0]["reachable_via"] == ["websocket"]
        assert peers[0]["estimated_rtt_ms"] == 12.0

    def test_online_rns_peer_uses_rns_metrics(self):
        daemon = _make_daemon()
        daemon.peers = {
            "node-2": FakePeerState(
                agent_name="bob", transport_type="rns",
                rns_dest_hash="abcdef", rns_hops=3,
                rns_estimated_rtt_ms=180.0, rns_estimated_bps=3120.0,
            )
        }
        peers = daemon.unified_peers()
        assert peers[0]["transport"] == "rns"
        assert peers[0]["rns_dest_hash"] == "abcdef"
        assert peers[0]["rns_hops"] == 3
        assert peers[0]["estimated_rtt_ms"] == 180.0
        assert peers[0]["estimated_bps"] == 3120.0

    def test_announce_only_peer_appears_with_rns_announce_tier(self):
        daemon = _make_daemon()
        daemon._rns_discovered = {
            "hash-x": {
                "dest_hash": "hash-x",
                "name": "carol",
                "node_id": "node-carol",
                "hops": 5,
            }
        }
        peers = daemon.unified_peers()
        assert len(peers) == 1
        assert peers[0]["name"] == "carol"
        assert peers[0]["reachable_via"] == ["rns_announce"]
        assert peers[0]["transport"] is None
        assert peers[0]["rns_hops"] == 5

    def test_peer_seen_via_both_paths_merges_reachable_via(self):
        daemon = _make_daemon()
        daemon.peers = {
            "node-3": FakePeerState(agent_name="dave",
                                     transport_type="websocket")
        }
        daemon._rns_discovered = {
            "hash-d": {
                "dest_hash": "hash-d",
                "name": "dave",
                "node_id": "node-3",
                "hops": 2,
            }
        }
        peers = daemon.unified_peers()
        assert len(peers) == 1
        assert set(peers[0]["reachable_via"]) == {"websocket", "rns_announce"}

    def test_offline_peer_excluded(self):
        daemon = _make_daemon()
        daemon.peers = {
            "node-4": FakePeerState(is_online=False, agent_name="eve")
        }
        peers = daemon.unified_peers()
        assert peers == []


# ---------------------------------------------------------------------------
# send_to_name() tier chain
# ---------------------------------------------------------------------------

class TestSendToNameTierChain:
    @pytest.mark.asyncio
    async def test_tier1_existing_online_peer(self):
        daemon = _make_daemon()
        daemon.peers = {
            "node-1": FakePeerState(agent_name="alice",
                                     transport_type="websocket")
        }
        result = await daemon.send_to_name("alice", b"hello")
        assert result["tier"] == 1
        assert result["transport"] == "websocket"
        assert result["target"] == "node-1"
        daemon.send_message.assert_awaited_once_with(
            "node-1", "MSG", b"hello", "NORMAL",
        )

    @pytest.mark.asyncio
    async def test_tier1_string_payload_encoded_to_utf8(self):
        daemon = _make_daemon()
        daemon.peers = {
            "node-1": FakePeerState(agent_name="alice")
        }
        await daemon.send_to_name("alice", "hello unicode ✓")
        sent_payload = daemon.send_message.call_args.args[2]
        assert sent_payload == "hello unicode ✓".encode("utf-8")

    @pytest.mark.asyncio
    async def test_tier2_auto_link_for_announce_only_peer(self, monkeypatch):
        # The real send_to_name spawns the connect as a background task
        # and polls self.peers for the peer to come online — accommodates
        # _do_client_handshake's permanent message loop. Simulate that by
        # mutating self.peers from the connect task's body.
        daemon = _make_daemon()
        daemon._rns_discovered = {
            "hash-b": {
                "dest_hash": "hash-b",
                "name": "bob",
                "node_id": "node-bob",
                "hops": 4,
            }
        }
        daemon._reticulum = MagicMock()
        async def _fake_connect(dest_hash):
            # Simulate the handshake completing by populating self.peers
            await asyncio.sleep(0.05)
            daemon.peers["node-bob"] = FakePeerState(
                is_online=True, agent_name="bob", transport_type="rns",
            )
            # Emulate session_key being set (real handshake assigns this)
            daemon.peers["node-bob"].session_key = b"x" * 32
            return "node-bob"
        daemon._connect_and_track_rns = AsyncMock(side_effect=_fake_connect)
        result = await daemon.send_to_name("bob", b"hello bob")
        assert result["tier"] == 2
        assert result["transport"] == "rns"
        assert result["target"] == "node-bob"
        daemon._connect_and_track_rns.assert_awaited_once_with("hash-b")
        daemon.send_message.assert_awaited_once_with(
            "node-bob", "MSG", b"hello bob", "NORMAL",
        )

    @pytest.mark.asyncio
    async def test_tier2_skipped_when_reticulum_off(self):
        daemon = _make_daemon()
        daemon._rns_discovered = {
            "hash-c": {"dest_hash": "hash-c", "name": "carol",
                       "node_id": "node-carol"}
        }
        # _reticulum stays None — tier 2 must skip
        with pytest.raises(ValueError, match="No reachable transport"):
            await daemon.send_to_name("carol", b"x")
        daemon._connect_and_track_rns.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_tier2_timeout_when_handshake_never_completes(self, monkeypatch):
        # If the auto-Link task never produces an online peer within
        # the poll deadline, send_to_name raises ValueError rather
        # than hanging indefinitely. The code shorten the deadline by
        # patching time.monotonic so the test stays fast.
        daemon = _make_daemon()
        daemon._rns_discovered = {
            "hash-d": {"dest_hash": "hash-d", "name": "dave",
                       "node_id": "node-dave"}
        }
        daemon._reticulum = MagicMock()
        # Connect task that never populates peers
        async def _stuck_connect(dest_hash):
            await asyncio.sleep(60)
            return None
        daemon._connect_and_track_rns = AsyncMock(side_effect=_stuck_connect)
        # Patch the time used in the poll loop to a fixed clock that
        # marches forward fast.
        from ironmesh import bridge as bridge_mod
        real_monotonic = bridge_mod.time.monotonic
        clock = [real_monotonic()]
        def _fast(): clock[0] += 5.0; return clock[0]
        monkeypatch.setattr(bridge_mod.time, "monotonic", _fast)
        with pytest.raises(ValueError):
            await daemon.send_to_name("dave", b"x")
        daemon.send_message.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_tier3_lxmf_when_name_is_dest_hash(self):
        daemon = _make_daemon()
        daemon._lxmf = MagicMock()
        daemon._lxmf.send_lxmf_to = AsyncMock(return_value=True)
        # 32-byte hex hash → looks like LXMF
        dest = "ab" * 32
        result = await daemon.send_to_name(dest, "hi via lxmf")
        assert result["tier"] == 3
        assert result["transport"] == "lxmf"
        assert result["target"] == dest
        daemon._lxmf.send_lxmf_to.assert_awaited_once_with(dest, "hi via lxmf")

    @pytest.mark.asyncio
    async def test_tier3_lxmf_skipped_when_listener_off(self):
        daemon = _make_daemon()
        daemon._lxmf = None
        dest = "ab" * 32
        with pytest.raises(ValueError):
            await daemon.send_to_name(dest, "x")

    @pytest.mark.asyncio
    async def test_no_tiers_match_raises_descriptive_error(self):
        daemon = _make_daemon()
        with pytest.raises(ValueError, match="No reachable transport"):
            await daemon.send_to_name("ghost", b"")

    @pytest.mark.asyncio
    async def test_priority_threaded_through_to_send_message(self):
        daemon = _make_daemon()
        daemon.peers = {"n": FakePeerState(agent_name="a")}
        await daemon.send_to_name("a", b"x", priority="HIGH")
        assert daemon.send_message.call_args.args[3] == "HIGH"


# ---------------------------------------------------------------------------
# Helper: _looks_like_lxmf_hash heuristic
# ---------------------------------------------------------------------------

class TestLxmfHashHeuristic:
    def test_64_char_hex_is_lxmf_hash(self):
        from ironmesh.bridge import BridgeDaemon
        assert BridgeDaemon._looks_like_lxmf_hash("ab" * 32) is True

    def test_32_char_hex_is_lxmf_hash(self):
        from ironmesh.bridge import BridgeDaemon
        assert BridgeDaemon._looks_like_lxmf_hash("ab" * 16) is True

    def test_colon_separators_tolerated(self):
        from ironmesh.bridge import BridgeDaemon
        h = ":".join(["ab"] * 16)
        assert BridgeDaemon._looks_like_lxmf_hash(h) is True

    def test_non_hex_rejected(self):
        from ironmesh.bridge import BridgeDaemon
        assert BridgeDaemon._looks_like_lxmf_hash("ghijkl" * 6) is False

    def test_short_string_rejected(self):
        from ironmesh.bridge import BridgeDaemon
        assert BridgeDaemon._looks_like_lxmf_hash("abc") is False

    def test_non_string_rejected(self):
        from ironmesh.bridge import BridgeDaemon
        assert BridgeDaemon._looks_like_lxmf_hash(None) is False
        assert BridgeDaemon._looks_like_lxmf_hash(123) is False
