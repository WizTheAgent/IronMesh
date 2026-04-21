"""Concurrent-operator-action stress harness.

Promoted from the v0.8.5.6 Phase 3 audit (ad-hoc inline script) into
a reusable tool. Spawns N threads racing `accept_capability_change`
against a shared TrustStore for M peers each in `pending-cap-change`.
Correctness criteria:

* exactly one thread per peer returns True (the "winner")
* no MAC corruption on the final trust file (it re-verifies cleanly)
* final on-disk baseline matches the pending set each peer had stashed

This is the regression script for B14 (silent concurrent-save
corruption on Windows) and B19 (missing thread-granularity on the
trust-file lock). Run it locally before any v0.8.x release or as a
nightly CI job to catch future regressions.

Usage:

    python scripts/stress_concurrent.py                 # default: 20x100
    python scripts/stress_concurrent.py --peers 50 --threads-per-peer 50
    python scripts/stress_concurrent.py --quick         # 5x20 smoke

Exit code: 0 on pass, 1 on any correctness failure.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import threading
import time

# Add repo root to path so the script runs from the scripts/ dir.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))


def run(peers: int, per_peer: int, verbose: bool = False) -> int:
    import logging
    if not verbose:
        # Silence expected loser-race save-refusal logs (ERROR level).
        # These are part of the correct behavior under contention, not
        # failures; the harness evaluates success at the aggregate level.
        logging.disable(logging.CRITICAL)

    from ironmesh.trust import TrustStore, canonical_capability_hash

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "known_peers.json")
        agent_key = b"\xfe" * 32

        # Seed: pin every peer and stash a pending cap change for each.
        setup = TrustStore(agent_key=agent_key, path=path)
        peer_ids = []
        for i in range(peers):
            nid = "p{:031x}".format(i)
            peer_ids.append(nid)
            setup.pin_peer(
                nid,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                trust_state="trusted",
            )
            setup.observe_capabilities(nid, [f"role:original-{i}"])
            setup.observe_capabilities(nid, [f"role:new-{i}"])
            setup.stash_pending_capability_change(nid, [f"role:new-{i}"])
            setup.set_trust_state(nid, "pending-cap-change")
        del setup

        total = peers * per_peer
        winners = {nid: 0 for nid in peer_ids}
        errors: list = []
        err_lock = threading.Lock()

        def promote(nid: str) -> None:
            try:
                store = TrustStore(agent_key=agent_key, path=path)
                ok = store.accept_capability_change(nid)
                if ok:
                    with err_lock:
                        winners[nid] += 1
            except Exception as e:
                with err_lock:
                    errors.append(repr(e))

        threads = [
            threading.Thread(target=promote, args=(nid,))
            for nid in peer_ids
            for _ in range(per_peer)
        ]
        start = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        elapsed = time.time() - start

        bad_winners = sum(1 for n in winners.values() if n != 1)
        verify = TrustStore(agent_key=agent_key, path=path)
        mac_ok = not verify._readonly_due_to_mac_failure

        final_correct = sum(
            1 for i, nid in enumerate(peer_ids)
            if verify.get_peer(nid).get("capability_hash")
               == canonical_capability_hash([f"role:new-{i}"])
        )

        print(f"stress: threads={total} runtime={elapsed:.2f}s  "
              f"errors={len(errors)}  "
              f"bad_winners={bad_winners}  "
              f"mac_ok={mac_ok}  "
              f"final_correct={final_correct}/{peers}")

        ok = (
            bad_winners == 0
            and len(errors) == 0
            and mac_ok
            and final_correct == peers
        )
        if not ok:
            if errors:
                print(f"  first error: {errors[0]}")
            if bad_winners:
                print("  peers with != 1 winner (first 3):")
                for nid, n in list(winners.items())[:3]:
                    if n != 1:
                        print(f"    {nid[:12]}: winners={n}")
        return 0 if ok else 1


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--peers", type=int, default=20,
                   help="Number of peers in pending-cap-change (default 20)")
    p.add_argument("--threads-per-peer", type=int, default=100,
                   help="Concurrent promote attempts per peer (default 100)")
    p.add_argument("--quick", action="store_true",
                   help="5 peers x 20 threads — smoke profile")
    p.add_argument("--verbose", action="store_true",
                   help="Show PROPTrustStore logging instead of suppressing")
    args = p.parse_args()

    if args.quick:
        return run(peers=5, per_peer=20, verbose=args.verbose)
    return run(peers=args.peers, per_peer=args.threads_per_peer,
               verbose=args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
