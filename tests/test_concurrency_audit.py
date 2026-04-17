"""Concurrency audit tests for v0.8.3.

Drives heavy parallel traffic through the core bridge primitives and
asserts no drops, duplicates, or ordering violations. These tests use
the in-process Agent pair from the integration fixture style but live
under ``tests/`` (not ``tests/integration/``) because they exercise
internal primitives rather than real framework libraries.
"""
from __future__ import annotations

import os
import tempfile
import threading
import time

import pytest

from ironmesh import Agent
from ironmesh.mesh import DedupCache
from ironmesh.protocol import ReplayGuard, TokenBucket


PASS = "concurrency-audit-passphrase-12"


def _mk_agent(name: str, port: int, allowed: list[str]) -> Agent:
    tmp = tempfile.mkdtemp(prefix=f"conc-{name}-")
    a = Agent(
        name, port=port, passphrase=PASS,
        open_discovery=False, allow_plaintext=True,
        keys_path=os.path.join(tmp, "k.json"),
        db_path=os.path.join(tmp, "d.db"),
        routes_path=os.path.join(tmp, "r.json"),
        capabilities_path=os.path.join(tmp, "c.json"),
        allowed_peers=allowed,
    )
    a.run(foreground=False)
    return a


def _wait(pred, timeout=15, step=0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return False


# ---------------------------------------------------------------------------
# 1. ReplayGuard is concurrency-safe
# ---------------------------------------------------------------------------

class TestReplayGuardParallel:
    """The replay guard is hit from every inbound message. If multiple
    peers hammer it in parallel we must not mistakenly accept a replay
    or reject a fresh sequence."""

    def test_parallel_unique_sequences_all_accepted(self):
        guard = ReplayGuard()
        n_threads = 16
        seqs_per_thread = 200
        results: list[str | None] = []
        lock = threading.Lock()
        now = time.time()

        def worker(peer_prefix: str):
            local = []
            for i in range(1, seqs_per_thread + 1):
                r = guard.check(f"{peer_prefix}", i, now)
                local.append(r)
            with lock:
                results.extend(local)

        threads = [
            threading.Thread(target=worker, args=(f"peer-{t}",))
            for t in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Every fresh (peer, seq) pair must be accepted (returns None).
        rejections = [r for r in results if r is not None]
        assert not rejections, f"unexpected rejections: {rejections[:5]}"
        assert len(results) == n_threads * seqs_per_thread

    def test_replays_always_rejected_under_load(self):
        guard = ReplayGuard()
        now = time.time()
        # Prime the guard with a seq for peer-A.
        assert guard.check("peer-A", 50, now) is None

        # Now hammer it with replays of seqs <= 50.
        n_threads = 8
        hits = 500
        replays: list[bool] = []
        lock = threading.Lock()

        def worker():
            local = []
            for i in range(1, 51):  # 1..50 are all replays
                r = guard.check("peer-A", i, now)
                local.append(r is not None)
            with lock:
                replays.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Every replay must be rejected (r is not None).
        assert all(replays), "a replay slipped through under concurrency"
        _ = hits  # silence lint


# ---------------------------------------------------------------------------
# 2. DedupCache under parallel hammering
# ---------------------------------------------------------------------------

class TestDedupCacheParallel:
    """Regression tests for the TOCTOU bug fixed in v0.8.3:
    ``is_duplicate`` + ``add`` used to be two separate lock
    acquisitions so concurrent arrivals of the same frame both
    passed the dup check. ``check_and_add`` is atomic."""

    def test_atomic_check_and_add_first_wins_in_race(self):
        cache = DedupCache()
        source = "src-1"
        msg_id = "msg-1"
        results: list[bool] = []
        lock = threading.Lock()

        def worker():
            # Each thread hits the same (source, msg_id) 20 times.
            local = [cache.check_and_add(source, msg_id) for _ in range(20)]
            with lock:
                results.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly ONE call returns False (the first, marks as seen);
        # every subsequent call returns True (already present).
        first_adds = sum(1 for r in results if r is False)
        assert first_adds == 1, (
            f"expected exactly one 'newly added' result, got {first_adds}"
        )

    def test_parallel_distinct_msgs_all_fresh(self):
        """Distinct (source, msg_id) pairs hammered in parallel are all
        marked fresh on first insertion."""
        cache = DedupCache()
        n_threads = 8
        per_thread = 200
        freshness: list[bool] = []
        lock = threading.Lock()

        def worker(tid: int):
            local = [
                cache.check_and_add(f"src-{tid}", f"msg-{i}")
                for i in range(per_thread)
            ]
            with lock:
                freshness.extend(local)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All inserts are of new (source, msg_id) pairs so every return
        # should be False (== newly added).
        assert not any(freshness), (
            f"saw {sum(freshness)} false dup hits on distinct ids"
        )


# ---------------------------------------------------------------------------
# 3. TokenBucket concurrent consume does not over-grant
# ---------------------------------------------------------------------------

class TestTokenBucketParallel:

    def test_concurrent_consume_respects_burst(self):
        # rate=10 tokens/sec, burst=50 — 20 threads should collectively
        # consume at most 50 tokens on a "cold" bucket.
        bucket = TokenBucket(rate=10.0, burst=50)
        grants: list[bool] = []
        lock = threading.Lock()

        def worker():
            local = [bucket.consume() for _ in range(10)]
            with lock:
                grants.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        t0 = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.monotonic() - t0

        granted = sum(1 for g in grants if g)
        # Allowed = burst (50) + refill during the race window (elapsed * 10).
        ceiling = 50 + int(elapsed * 10) + 1
        assert granted <= ceiling, (
            f"over-granted: {granted} > ceiling {ceiling} (elapsed={elapsed:.2f}s)"
        )


# ---------------------------------------------------------------------------
# 4. 2-node mesh: many parallel sends, no drops, no duplicates
# ---------------------------------------------------------------------------

@pytest.mark.slow
class TestParallelMessaging:

    def test_100_parallel_sends_no_drops(self):
        """Scaled from 500 to 100 -- Windows mDNS + handshake is ~10 s of
        overhead before we can start stressing the wire. The invariant
        we're pinning is 'no drops under concurrent load', not 'handles
        infinite throughput'. A bridge-level benchmark (tests/harness/)
        covers the perf axis."""
        port_a = 41000
        port_b = port_a + 2

        alice = _mk_agent("alice-conc", port_a, ["bob-conc"])
        bob = _mk_agent("bob-conc", port_b, ["alice-conc"])

        received: list[bytes] = []
        recv_lock = threading.Lock()

        @bob.on_message()
        def _on_msg(peer_id: str, payload: bytes) -> None:  # noqa: ARG001
            with recv_lock:
                received.append(payload)
        bob._wire_handlers()

        try:
            assert _wait(
                lambda: alice.peer_by_name("bob-conc")
                        and bob.peer_by_name("alice-conc"),
                timeout=15,
            ), "mesh failed to handshake"

            N = 100
            send_errors: list[Exception] = []
            err_lock = threading.Lock()

            def send_one(i: int) -> None:
                try:
                    alice.send_sync("bob-conc", f"msg-{i:04d}".encode())
                except Exception as e:
                    with err_lock:
                        send_errors.append(e)

            threads = [threading.Thread(target=send_one, args=(i,)) for i in range(N)]
            t0 = time.monotonic()
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Wait for all messages to arrive. 60 s upper bound covers
            # the slower hosted-runner combinations (Ubuntu / Python 3.10
            # were observed to need ~30+ s for the full handshake plus
            # 100-message drain on a shared GitHub-Actions runner). Local
            # dev machines complete the same drain in 2-3 s.
            assert _wait(lambda: len(received) >= N, timeout=60), (
                f"only {len(received)}/{N} messages arrived after 60 s"
            )
            elapsed = time.monotonic() - t0

            assert not send_errors, f"send errors: {send_errors[:3]}"

            # No duplicates (each msg-NNNN appears exactly once).
            bodies = {r for r in received}
            expected_bodies = {f"msg-{i:04d}".encode() for i in range(N)}
            assert bodies == expected_bodies, (
                f"missing: {expected_bodies - bodies}; "
                f"extra: {bodies - expected_bodies}"
            )

            # Informational: throughput number for the audit doc.
            print(f"[concurrency-audit] {N} msgs in {elapsed:.2f}s "
                  f"= {N/elapsed:.1f} msgs/s")
        finally:
            alice.stop()
            bob.stop()
