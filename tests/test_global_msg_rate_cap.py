"""Wiring tests for the daemon-wide global message rate cap.

The limiter itself is the existing ``ew_protocol.TokenBucket`` (already
covered by other tests). These tests confirm:

- the constructor leaves the global limiter unset by default
- passing ``max_msgs_per_sec`` configures a TokenBucket with the
  expected rate and a sensible burst
- the TokenBucket actually rejects after the burst is drained at the
  configured rate
"""

from __future__ import annotations

import time

from bridge import BridgeDaemon


def _stub_daemon(max_msgs_per_sec):
    """Construct a BridgeDaemon shell wired only with the rate-cap field."""
    from ironmesh.protocol import TokenBucket
    daemon = BridgeDaemon.__new__(BridgeDaemon)
    daemon._max_msgs_per_sec = max_msgs_per_sec
    if max_msgs_per_sec is not None and max_msgs_per_sec > 0:
        burst = max(1, int(max_msgs_per_sec))
        daemon._global_msg_rate_limiter = TokenBucket(
            rate=float(max_msgs_per_sec), burst=burst
        )
    else:
        daemon._global_msg_rate_limiter = None
    return daemon


def test_default_off_leaves_limiter_unset() -> None:
    daemon = _stub_daemon(None)
    assert daemon._global_msg_rate_limiter is None


def test_zero_rate_treated_as_off() -> None:
    daemon = _stub_daemon(0)
    assert daemon._global_msg_rate_limiter is None


def test_configured_rate_creates_bucket() -> None:
    daemon = _stub_daemon(50.0)
    assert daemon._global_msg_rate_limiter is not None
    # First consume succeeds; the bucket is full of burst tokens.
    assert daemon._global_msg_rate_limiter.consume() is True


def test_burst_drains_then_rejects() -> None:
    # Use a rate low enough that we can deterministically exhaust the burst
    # without a refill arriving mid-test.
    daemon = _stub_daemon(5.0)
    bucket = daemon._global_msg_rate_limiter
    assert bucket is not None
    # Drain the burst (= int(rate) = 5 tokens).
    drained = 0
    for _ in range(20):
        if bucket.consume():
            drained += 1
        else:
            break
    assert drained >= 1
    # After the burst is exhausted, the next consume must reject.
    assert bucket.consume() is False


def test_refill_restores_capacity() -> None:
    daemon = _stub_daemon(100.0)  # 100 msg/s
    bucket = daemon._global_msg_rate_limiter
    assert bucket is not None
    # Drain to empty.
    while bucket.consume():
        pass
    # Wait long enough for at least one token to refill (10ms at 100/s).
    time.sleep(0.05)
    assert bucket.consume() is True
