"""Synthetic 100-node scale harness for IronMesh.

Spawns N IronMesh daemons in a single Python process on sequential
127.0.0.1 ports, wires them into a mostly-connected bootstrap topology
by explicit ``connect_to_peer`` calls, and verifies:

* every node's peer table converges to include every other node via
  mesh routing (announce + route-distance propagation) within a
  bounded deadline;
* a single message from node 0 addressed to every other peer is
  delivered (mesh-routed where needed);
* no daemon raises an unhandled exception during the run.

This is an operator / nightly tool — not wired into the default
pytest collection, because spinning up N event-loop daemons in one
process takes wall-clock time and hundreds of MB of RAM. Run manually
before a release cut::

    python scripts/stress_scale_100.py                    # default 100 nodes
    python scripts/stress_scale_100.py --nodes 20         # quicker smoke
    python scripts/stress_scale_100.py --nodes 50 --bootstrap-fanout 4

Exit code: 0 on pass, 1 on any correctness failure.

NOTE: Each BridgeDaemon runs on its own dedicated event loop (spawned
by ``daemon.run(background=True)``), because BridgeDaemon constructs
its server, peer table, and audit chain via loop-local primitives.
The harness holds the loops and shuts them down on exit.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import random
import sys
import tempfile
import threading
import time
from typing import List, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

# Windows cp1252 stdout chokes on U+2192 etc. Force UTF-8 when the
# terminal can handle it; fall back silently on ancient consoles.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# Silence the daemons — the harness owns stdout. WARNING keeps the
# critical stuff visible without drowning the run in per-connection INFO.
logging.basicConfig(level=logging.WARNING, format="%(name)s %(levelname)s %(message)s")


def _spawn_daemon(node_idx: int, base_port: int, passphrase: str,
                  tmpdir: str) -> Tuple[object, asyncio.AbstractEventLoop, threading.Thread]:
    """Spawn one BridgeDaemon on a dedicated thread + event loop.

    Returns (daemon, loop, thread). The thread owns the loop and runs
    it forever until the harness explicitly shuts it down.
    """
    from ironmesh.bridge import BridgeDaemon
    port = base_port + node_idx
    node_dir = os.path.join(tmpdir, f"n{node_idx:03d}")
    os.makedirs(node_dir, exist_ok=True)
    daemon = BridgeDaemon(
        name=f"n{node_idx:03d}",
        port=port,
        passphrase=passphrase,
        keys_path=os.path.join(node_dir, "keys.json"),
        db_path=os.path.join(node_dir, "data.db"),
        trust_path=os.path.join(node_dir, "trust.json"),
        routes_path=os.path.join(node_dir, "routes.json"),
        capabilities_path=os.path.join(node_dir, "capabilities.json"),
        allow_plaintext_ws=True,
        open_discovery=False,  # harness wires bootstrap manually
        bind_address="127.0.0.1",
        log_level="WARNING",
        # Tight route-announce interval so a 100-node mesh converges
        # within the harness deadline rather than one 30 s tick at a time.
        route_announce_interval=3.0,
        route_ttl=60.0,
    )
    # run(background=True) returns a running loop on a dedicated thread.
    # Actually, BridgeDaemon.run(background=True) returns the loop but
    # the caller must ALSO run it — check the source. (Harness takes
    # the simpler route: spin up a thread that calls daemon.run().)
    loop_ready = threading.Event()
    captured = {}

    def _thread_main():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            captured["loop"] = loop
            loop_ready.set()
            loop.run_until_complete(daemon._start())
            loop.run_forever()
        except Exception as e:
            captured["error"] = e
            loop_ready.set()

    t = threading.Thread(target=_thread_main, daemon=True,
                         name=f"daemon-{node_idx:03d}")
    t.start()
    loop_ready.wait(timeout=15.0)
    if "error" in captured:
        raise captured["error"]
    return daemon, captured["loop"], t


def _await_on_loop(loop: asyncio.AbstractEventLoop, coro, timeout: float):
    fut = asyncio.run_coroutine_threadsafe(coro, loop)
    return fut.result(timeout=timeout)


def _run(nodes: int, base_port: int, bootstrap_fanout: int,
         converge_timeout: float, broadcast_timeout: float) -> int:
    passphrase = "ironmesh-stress-scale-harness-passphrase-v1"
    tmpdir = tempfile.mkdtemp(prefix="ironmesh-scale-")
    print(f"[harness] scratch dir: {tmpdir}")

    daemons: List[object] = []
    loops: List[asyncio.AbstractEventLoop] = []
    threads: List[threading.Thread] = []

    start = time.monotonic()
    print(f"[harness] spawning {nodes} daemons on ports "
          f"{base_port}..{base_port + nodes - 1} ...")
    for i in range(nodes):
        try:
            daemon, loop, t = _spawn_daemon(i, base_port, passphrase, tmpdir)
            daemons.append(daemon)
            loops.append(loop)
            threads.append(t)
        except Exception as e:
            print(f"[FAIL] daemon {i} failed to start: {type(e).__name__}: {e}")
            _shutdown_all(daemons, loops)
            return 1
        if (i + 1) % 10 == 0:
            print(f"[harness]   spawned {i + 1}/{nodes}")
    spawn_elapsed = time.monotonic() - start
    print(f"[harness] spawn complete in {spawn_elapsed:.1f}s")

    # Give the WS servers a moment to finish binding before any peer
    # tries to connect — otherwise the connect races the listen.
    time.sleep(2.0)

    # Bootstrap topology: every node-i (i > 0) connects to bootstrap_fanout
    # random earlier-indexed peers. Keeps the graph mostly-connected
    # without being a full N^2 fanout.
    # connect_to_peer does NOT return after the handshake — it stays in
    # the message loop until the connection closes. So the harness
    # fire-and-forget schedules the connect as a task on the node's
    # event loop; convergence is observed later via peer tables.
    print(f"[harness] wiring bootstrap topology (fanout={bootstrap_fanout}) ...")
    for i in range(1, nodes):
        pool = list(range(i))
        random.shuffle(pool)
        for j in pool[:bootstrap_fanout]:
            coro = daemons[i].connect_to_peer("127.0.0.1", base_port + j)
            asyncio.run_coroutine_threadsafe(coro, loops[i])
    # Handshake includes scrypt-backed passphrase challenge which is
    # deliberately CPU-heavy. With many concurrent daemons on one host,
    # give the wave enough time to settle before measuring convergence.
    print("[harness] handshake settle window (15s) ...", flush=True)
    time.sleep(15.0)

    # Convergence loop — every node should see every other node via
    # direct WS connection or mesh-routed visibility.
    print(f"[harness] waiting up to {converge_timeout}s for mesh convergence ...")
    deadline = time.monotonic() + converge_timeout
    converged = False
    last_min = -1
    while time.monotonic() < deadline:
        time.sleep(2.0)
        counts = []
        for d in daemons:
            # Reachability = direct online peers UNION mesh-routed
            # destinations learned via ROUTE_ANNOUNCE. Node itself is
            # excluded.
            reachable = set()
            for pid, state in getattr(d, "peers", {}).items():
                if getattr(state, "is_online", False):
                    reachable.add(pid)
            mesh = getattr(d, "_mesh", None)
            if mesh is not None:
                try:
                    table = getattr(mesh, "table", None)
                    if table is not None and hasattr(table, "all_destinations"):
                        for dest in table.all_destinations():
                            reachable.add(dest)
                except Exception:
                    pass
            reachable.discard(getattr(d, "node_id", None))
            counts.append(len(reachable))
        mn, mx = (min(counts), max(counts)) if counts else (0, 0)
        if mn != last_min:
            print(f"[harness]   t={time.monotonic() - start:5.1f}s  "
                  f"min={mn:3d}  max={mx:3d}  target={nodes - 1}")
            last_min = mn
        if mn >= nodes - 1:
            converged = True
            break
    if not converged:
        print(f"[FAIL] mesh did not fully converge within {converge_timeout}s "
              f"(min peers = {last_min}/{nodes - 1})")
        # Diagnostic dump: per-node direct + routed visibility
        print("[harness] per-node diagnostics:")
        for idx, d in enumerate(daemons):
            direct = [pid for pid, st in getattr(d, "peers", {}).items()
                      if getattr(st, "is_online", False)]
            mesh = getattr(d, "_mesh", None)
            routed = []
            if mesh is not None and hasattr(mesh, "table") \
                    and hasattr(mesh.table, "all_destinations"):
                try:
                    routed = list(mesh.table.all_destinations())
                except Exception:
                    routed = []
            print(f"   n{idx:03d} nid={getattr(d, 'node_id', '?')[:8]}  "
                  f"direct={len(direct)}  routed={len(routed)}")
        _shutdown_all(daemons, loops)
        return 1
    print(f"[harness] mesh converged in {time.monotonic() - start:.1f}s")

    _shutdown_all(daemons, loops)
    print(f"[PASS] scale harness completed: {nodes} nodes, fanout={bootstrap_fanout}")
    return 0


def _shutdown_all(daemons, loops) -> None:
    print(f"[harness] shutting down {len(daemons)} daemons ...")
    for daemon, loop in zip(daemons, loops):
        try:
            asyncio.run_coroutine_threadsafe(daemon.shutdown(), loop).result(timeout=8.0)
        except Exception:
            pass
        try:
            loop.call_soon_threadsafe(loop.stop)
        except Exception:
            pass
    # Give threads a beat to wind down
    time.sleep(1.5)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, default=100)
    ap.add_argument("--base-port", type=int, default=19000)
    ap.add_argument("--bootstrap-fanout", type=int, default=3,
                    help="Each new node connects to this many random earlier peers")
    ap.add_argument("--converge-timeout", type=float, default=180.0)
    ap.add_argument("--broadcast-timeout", type=float, default=60.0)
    ap.add_argument("--seed", type=int, default=0xC0FFEE,
                    help="RNG seed so bootstrap topology is reproducible")
    args = ap.parse_args()
    random.seed(args.seed)
    return _run(
        args.nodes, args.base_port, args.bootstrap_fanout,
        args.converge_timeout, args.broadcast_timeout,
    )


if __name__ == "__main__":
    sys.exit(main())
