"""Concurrent peer fan-out helper for IronMesh CLI commands.

The v0.9.4 CLI ergonomics bundle (`docs/ROADMAP.md`) calls out
serial peer iteration as the dominant tail-latency contributor for
`status` / `ping` / `broadcast` / `health`. A single unreachable
peer stalls the whole command for its full timeout.

This module provides `fan_out`: pass a callable + a list of peers;
get back a list of `PeerResult` records, computed in parallel by a
bounded `ThreadPoolExecutor`. Total wall time becomes roughly the
slowest single peer, not the sum.

Why threads (not asyncio):

- Most CLI integrations are sync (HTTP libraries, raw socket
  reads, shell-out to mesh tooling). Threads compose with sync
  callables without forcing every caller to learn `await`.
- For the 8-32 peer scale this targets, the GIL + thread-overhead
  trade is fine — these calls are I/O-bound, not CPU-bound.
- Asyncio version can be added later without changing the public
  shape if a CLI command genuinely benefits.

Failure mode: each peer's call is wrapped in `try/except`. An
exception becomes `PeerResult(error=...)` rather than crashing the
whole fan-out. Per-peer timeout is supported via the underlying
callable; this module doesn't impose its own deadline beyond the
optional `total_timeout` kill-switch.
"""

from __future__ import annotations

import concurrent.futures
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence


@dataclass
class PeerResult:
    """One peer's outcome from a fan-out batch."""
    peer: Any                          # whatever was passed in
    ok: bool                           # True iff the call returned without raising
    value: Any = None                  # the call's return value (if ok)
    error: Optional[str] = None        # str(exception) (if not ok)
    elapsed_ms: float = 0.0            # wall-time for this peer's call
    metadata: dict[str, Any] = field(default_factory=dict)


def fan_out(
    fn: Callable[[Any], Any],
    peers: Sequence[Any],
    *,
    max_workers: int = 8,
    total_timeout_s: Optional[float] = None,
    preserve_order: bool = False,
) -> list[PeerResult]:
    """Run `fn(peer)` for each peer in parallel.

    Args:
        fn: callable taking one peer, returning anything. Exceptions
            from `fn` are captured per-peer; they don't kill the
            batch.
        peers: list of peer specifiers. Whatever your `fn` expects.
        max_workers: cap on parallel threads. Default 8 — enough for
            the typical 5-20 peer mesh; bound on file-descriptor
            and connection-pool pressure.
        total_timeout_s: optional kill-switch for the whole batch.
            Peers still pending when this fires get
            `PeerResult(ok=False, error="batch_timeout")`.
        preserve_order: if True, results are returned in the order
            of `peers`. If False (default), in completion order —
            handy when you want to print as results arrive.

    Returns:
        List of `PeerResult` (length == len(peers)).
    """
    if not peers:
        return []
    n = len(peers)
    workers = max(1, min(max_workers, n))

    results_by_peer: dict[int, PeerResult] = {}
    completion_order: list[int] = []

    def _run_one(idx: int, peer: Any) -> PeerResult:
        t0 = time.monotonic()
        try:
            value = fn(peer)
            elapsed = (time.monotonic() - t0) * 1000.0
            return PeerResult(peer=peer, ok=True, value=value,
                              elapsed_ms=elapsed)
        except Exception as e:
            elapsed = (time.monotonic() - t0) * 1000.0
            return PeerResult(peer=peer, ok=False, error=str(e),
                              elapsed_ms=elapsed)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="ironmesh-fanout",
    ) as pool:
        future_to_idx = {
            pool.submit(_run_one, i, p): i for i, p in enumerate(peers)
        }
        try:
            for fut in concurrent.futures.as_completed(
                future_to_idx, timeout=total_timeout_s
            ):
                idx = future_to_idx[fut]
                results_by_peer[idx] = fut.result()
                completion_order.append(idx)
        except concurrent.futures.TimeoutError:
            # Stamp any still-pending futures as batch_timeout.
            for fut, idx in future_to_idx.items():
                if idx in results_by_peer:
                    continue
                fut.cancel()
                results_by_peer[idx] = PeerResult(
                    peer=peers[idx], ok=False,
                    error="batch_timeout",
                    elapsed_ms=(total_timeout_s or 0) * 1000.0,
                )

    if preserve_order:
        return [results_by_peer[i] for i in range(n)]
    return [results_by_peer[i] for i in completion_order]


# ---- Convenience: split + summarize -------------------------------

def partition(results: Sequence[PeerResult]
              ) -> tuple[list[PeerResult], list[PeerResult]]:
    """Split a fan-out result list into (ok, failed)."""
    ok = [r for r in results if r.ok]
    failed = [r for r in results if not r.ok]
    return ok, failed


def summarize_timings(results: Sequence[PeerResult]) -> dict[str, float]:
    """Quick latency summary across a batch."""
    if not results:
        return {"count": 0}
    elapsed = [r.elapsed_ms for r in results]
    elapsed_sorted = sorted(elapsed)
    n = len(elapsed_sorted)

    def _pct(p: float) -> float:
        if n == 1:
            return elapsed_sorted[0]
        idx = max(0, min(n - 1, int(round((p / 100.0) * (n - 1)))))
        return elapsed_sorted[idx]

    return {
        "count": n,
        "min_ms": min(elapsed),
        "max_ms": max(elapsed),
        "p50_ms": _pct(50),
        "p95_ms": _pct(95),
        "mean_ms": sum(elapsed) / n,
    }
