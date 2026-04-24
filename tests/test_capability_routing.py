"""Tests for v0.9.2 chunk E — capability-aware routing.

Covers `BridgeDaemon.send_to_capability(pattern, payload, strategy=…)`:
the resolver picks one (or many) peers advertising a matching
capability and dispatches via the unified-transport layer that backs
`send_to_name`.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest


class _FakePeerState:
    def __init__(self, *, online=True, name=None, latency_ms=None):
        self.is_online = online
        self.agent_name = name
        self.latency_ms = latency_ms


def _make_daemon(*, my_node="node-self"):
    """Build a daemon stub with the v0.9.2 capability-routing methods bound."""
    from ironmesh.bridge import BridgeDaemon
    daemon = MagicMock()
    daemon.peers = {}
    daemon.node_id = my_node
    daemon._capabilities = MagicMock()
    daemon.send_to_name = AsyncMock()
    # Bind the actual implementations
    daemon._capability_candidates = (
        BridgeDaemon._capability_candidates.__get__(daemon)
    )
    daemon._rank_candidates = (
        BridgeDaemon._rank_candidates.__get__(daemon)
    )
    daemon.send_to_capability = (
        BridgeDaemon.send_to_capability.__get__(daemon)
    )
    return daemon


# ---------------------------------------------------------------------------
# Candidate resolution
# ---------------------------------------------------------------------------

class TestCapabilityCandidates:
    def test_no_registry_returns_empty(self):
        daemon = _make_daemon()
        daemon._capabilities = None
        assert daemon._capability_candidates("llm:*") == []

    def test_self_node_filtered_out(self):
        daemon = _make_daemon(my_node="self-x")
        daemon._capabilities.find = MagicMock(return_value=[
            ("self-x", "llm:llama3"),
            ("peer-a", "llm:llama3"),
            ("peer-b", "llm:mistral"),
        ])
        out = daemon._capability_candidates("llm:*")
        names = [n for n, _ in out]
        assert "self-x" not in names
        assert names == ["peer-a", "peer-b"]


# ---------------------------------------------------------------------------
# Strategy ranking
# ---------------------------------------------------------------------------

class TestRanking:
    def test_first_prefers_online_with_lowest_rtt(self):
        daemon = _make_daemon()
        daemon.peers = {
            "p-slow": _FakePeerState(online=True, latency_ms=200.0),
            "p-fast": _FakePeerState(online=True, latency_ms=20.0),
            "p-off":  _FakePeerState(online=False),
        }
        candidates = [("p-slow", "x"), ("p-off", "x"), ("p-fast", "x")]
        ranked = daemon._rank_candidates(candidates, "first")
        ordered_ids = [n for n, _ in ranked]
        # Online peers come first; among them, lowest RTT first
        assert ordered_ids[0] == "p-fast"
        assert ordered_ids[1] == "p-slow"
        assert ordered_ids[2] == "p-off"

    def test_random_returns_all_in_some_order(self):
        daemon = _make_daemon()
        candidates = [("a", "x"), ("b", "x"), ("c", "x")]
        ranked = daemon._rank_candidates(candidates, "random")
        assert sorted(n for n, _ in ranked) == ["a", "b", "c"]

    def test_all_returns_input_unchanged(self):
        daemon = _make_daemon()
        candidates = [("a", "x"), ("b", "x")]
        assert daemon._rank_candidates(candidates, "all") == candidates


# ---------------------------------------------------------------------------
# send_to_capability dispatch
# ---------------------------------------------------------------------------

class TestSendToCapability:
    @pytest.mark.asyncio
    async def test_no_match_raises(self):
        daemon = _make_daemon()
        daemon._capabilities.find = MagicMock(return_value=[])
        with pytest.raises(ValueError, match="No peer advertises"):
            await daemon.send_to_capability("llm:none", b"x")

    @pytest.mark.asyncio
    async def test_first_strategy_dispatches_to_best_match(self):
        daemon = _make_daemon()
        daemon._capabilities.find = MagicMock(return_value=[
            ("p-fast", "llm:chat"),
            ("p-slow", "llm:chat"),
        ])
        daemon.peers = {
            "p-fast": _FakePeerState(online=True, latency_ms=10.0,
                                       name="fast-bot"),
            "p-slow": _FakePeerState(online=True, latency_ms=200.0,
                                       name="slow-bot"),
        }
        daemon.send_to_name.return_value = {
            "transport": "websocket", "target": "p-fast",
            "msg_id": "mid-1", "tier": 1,
        }
        result = await daemon.send_to_capability("llm:*", b"hi")
        # First call must go to the fast peer's name
        first_call_target = daemon.send_to_name.call_args.args[0]
        assert first_call_target == "fast-bot"
        assert result["capability"] == "llm:chat"
        assert result["strategy"] == "first"

    @pytest.mark.asyncio
    async def test_first_falls_through_on_failure(self):
        daemon = _make_daemon()
        daemon._capabilities.find = MagicMock(return_value=[
            ("p-broken", "tool:echo"),
            ("p-good",   "tool:echo"),
        ])
        daemon.peers = {
            "p-broken": _FakePeerState(online=True, latency_ms=10.0,
                                         name="broken"),
            "p-good":   _FakePeerState(online=True, latency_ms=20.0,
                                         name="good"),
        }
        # First call (broken) raises; second call (good) succeeds
        side = [
            ValueError("simulated unreachable"),
            {"transport": "rns", "target": "p-good",
             "msg_id": "ok", "tier": 2},
        ]
        daemon.send_to_name.side_effect = side
        result = await daemon.send_to_capability("tool:*", b"hi")
        assert result["target"] == "p-good"
        assert daemon.send_to_name.await_count == 2

    @pytest.mark.asyncio
    async def test_first_raises_if_all_candidates_fail(self):
        daemon = _make_daemon()
        daemon._capabilities.find = MagicMock(return_value=[
            ("p1", "x"), ("p2", "x"),
        ])
        daemon.peers = {
            "p1": _FakePeerState(online=True, name="a"),
            "p2": _FakePeerState(online=True, name="b"),
        }
        daemon.send_to_name.side_effect = ValueError("unreachable")
        with pytest.raises(ValueError, match="No reachable peer"):
            await daemon.send_to_capability("x", b"hi")

    @pytest.mark.asyncio
    async def test_all_strategy_fans_out(self):
        daemon = _make_daemon()
        daemon._capabilities.find = MagicMock(return_value=[
            ("p1", "llm:chat"),
            ("p2", "llm:chat"),
            ("p3", "llm:chat"),
        ])
        daemon.peers = {
            "p1": _FakePeerState(online=True, name="a"),
            "p2": _FakePeerState(online=True, name="b"),
            "p3": _FakePeerState(online=True, name="c"),
        }
        daemon.send_to_name.return_value = {
            "transport": "websocket", "target": "x",
            "msg_id": "id", "tier": 1,
        }
        result = await daemon.send_to_capability("llm:*", b"hi", strategy="all")
        assert result["transport"] == "fanout"
        assert result["total"] == 3
        assert result["success"] == 3
        assert daemon.send_to_name.await_count == 3

    @pytest.mark.asyncio
    async def test_all_strategy_records_per_target_failures(self):
        daemon = _make_daemon()
        daemon._capabilities.find = MagicMock(return_value=[
            ("p1", "x"), ("p2", "x"),
        ])
        daemon.peers = {
            "p1": _FakePeerState(online=True, name="a"),
            "p2": _FakePeerState(online=True, name="b"),
        }
        daemon.send_to_name.side_effect = [
            {"transport": "websocket", "target": "p1",
             "msg_id": "id", "tier": 1},
            ValueError("p2 down"),
        ]
        result = await daemon.send_to_capability("x", b"hi", strategy="all")
        assert result["transport"] == "fanout"
        assert result["success"] == 1
        assert result["total"] == 2
        # Per-target results include the error string for p2
        errs = [r for r in result["results"] if "error" in r]
        assert len(errs) == 1

    @pytest.mark.asyncio
    async def test_all_raises_if_every_candidate_fails(self):
        daemon = _make_daemon()
        daemon._capabilities.find = MagicMock(return_value=[
            ("p1", "x"), ("p2", "x"),
        ])
        daemon.peers = {
            "p1": _FakePeerState(online=True, name="a"),
            "p2": _FakePeerState(online=True, name="b"),
        }
        daemon.send_to_name.side_effect = ValueError("all dead")
        with pytest.raises(ValueError, match="All .* candidates"):
            await daemon.send_to_capability("x", b"hi", strategy="all")
