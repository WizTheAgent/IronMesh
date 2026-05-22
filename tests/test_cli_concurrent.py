"""Tests for `ironmesh.cli_concurrent`.

Covers: parallel speedup vs serial baseline, per-peer error
isolation, batch timeout, ordering options, summary helpers.
"""

from __future__ import annotations

import time

import pytest

from ironmesh import cli_concurrent as cc
from ironmesh.cli_concurrent import PeerResult, fan_out, partition, summarize_timings


# ---- correctness: each peer gets its own result -------------------

def test_each_peer_in_results():
    peers = ["a", "b", "c", "d"]
    results = fan_out(lambda p: p.upper(), peers, max_workers=4)
    assert len(results) == 4
    seen = {r.peer for r in results}
    assert seen == {"a", "b", "c", "d"}
    assert all(r.ok for r in results)
    assert {r.value for r in results} == {"A", "B", "C", "D"}


def test_preserve_order():
    peers = ["a", "b", "c", "d"]
    # Reverse-sleep so completion order would otherwise be d, c, b, a.
    sleeps = {"a": 0.04, "b": 0.03, "c": 0.02, "d": 0.01}
    def fn(p):
        time.sleep(sleeps[p])
        return p
    results = fan_out(fn, peers, max_workers=4, preserve_order=True)
    assert [r.peer for r in results] == ["a", "b", "c", "d"]


def test_completion_order_default():
    peers = ["slow", "fast"]
    sleeps = {"slow": 0.1, "fast": 0.01}
    def fn(p):
        time.sleep(sleeps[p])
        return p
    results = fan_out(fn, peers, max_workers=2)
    # Default returns in completion order — fast peer first.
    assert results[0].peer == "fast"
    assert results[1].peer == "slow"


# ---- parallel speedup ---------------------------------------------

def test_parallel_speedup_vs_serial():
    """5 peers each sleeping 100ms should finish near 100ms in
    parallel, not 500ms."""
    peers = list(range(5))
    def fn(p):
        time.sleep(0.1)
        return p

    t0 = time.monotonic()
    results = fan_out(fn, peers, max_workers=5)
    elapsed_parallel = time.monotonic() - t0

    assert len(results) == 5
    assert all(r.ok for r in results)
    # Serial would be ~500ms; parallel with 5 workers finishes much
    # sooner. The 0.4s budget is a sanity check that fan_out is
    # actually parallel, not a perf SLO — cloud CI runners under
    # load have been observed to spend 250ms+ on the ThreadPool
    # scheduling itself even with negligible per-task work.
    assert elapsed_parallel < 0.4, (
        f"parallel fan-out took {elapsed_parallel:.3f}s, expected <0.4s"
    )


# ---- per-peer error isolation -------------------------------------

def test_one_peer_failure_does_not_kill_batch():
    def fn(p):
        if p == "bad":
            raise RuntimeError("simulated peer error")
        return f"ok:{p}"

    peers = ["a", "bad", "c"]
    results = fan_out(fn, peers, max_workers=3, preserve_order=True)
    assert results[0].ok is True
    assert results[0].value == "ok:a"
    assert results[1].ok is False
    assert results[1].error == "simulated peer error"
    assert results[2].ok is True
    assert results[2].value == "ok:c"


# ---- batch timeout -------------------------------------------------

def test_total_timeout_marks_pending_as_batch_timeout():
    def fn(p):
        time.sleep(p)  # peer 0 returns immediately, peer 1 is slow
        return p

    peers = [0.001, 5.0]  # second peer takes 5s
    results = fan_out(fn, peers, max_workers=2, total_timeout_s=0.2,
                      preserve_order=True)
    assert len(results) == 2
    assert results[0].ok is True
    assert results[1].ok is False
    assert results[1].error == "batch_timeout"


# ---- empty input ---------------------------------------------------

def test_empty_peers_returns_empty():
    assert fan_out(lambda p: p, []) == []


# ---- elapsed_ms is populated --------------------------------------

def test_elapsed_ms_set():
    def fn(p):
        time.sleep(0.05)
        return p
    results = fan_out(fn, ["x"], max_workers=1)
    assert len(results) == 1
    # Lower bound tolerates clock-resolution rounding (Windows
    # time.sleep can return ~3 ms early under default 15.6 ms timer
    # granularity). The test's intent is "elapsed_ms is populated and
    # roughly matches sleep duration", not "elapsed_ms >= sleep exactly".
    assert results[0].elapsed_ms >= 40.0
    # Sanity upper bound — 0.05s plus thread overhead, < 500ms
    assert results[0].elapsed_ms < 500.0


# ---- partition + summarize ----------------------------------------

def test_partition():
    results = [
        PeerResult(peer="a", ok=True, value=1),
        PeerResult(peer="b", ok=False, error="boom"),
        PeerResult(peer="c", ok=True, value=3),
    ]
    ok, failed = partition(results)
    assert [r.peer for r in ok] == ["a", "c"]
    assert [r.peer for r in failed] == ["b"]


def test_summarize_timings():
    results = [
        PeerResult(peer=i, ok=True, elapsed_ms=float(i * 10))
        for i in range(1, 11)
    ]
    s = summarize_timings(results)
    assert s["count"] == 10
    assert s["min_ms"] == 10.0
    assert s["max_ms"] == 100.0
    assert s["p50_ms"] == 50.0  # median
    assert s["mean_ms"] == 55.0


def test_summarize_timings_empty():
    assert summarize_timings([]) == {"count": 0}
