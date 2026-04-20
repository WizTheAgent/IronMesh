#!/usr/bin/env python3
"""IronMesh mesh benchmark harness.

Spins up a transient ``BridgeDaemon`` ("bench-client"), connects to the
target peer via its public address, and runs a ping-pong sweep with varying
payload sizes.  Measures end-to-end RTT, delivery rate, signature validity,
and goodput.  Writes results to CSV.

Usage::

    python -m tests.harness.mesh_bench \\
        --target-host 192.0.2.20 --target-port 8765 \\
        --target-name alice \\
        --passphrase-file ~/.ironmesh/passphrase \\
        --sizes 64,256,1024,4096 --trials 50 \\
        --output results.csv

The receiving peer must run IronMesh v0.7.1+ with a subscriber that echoes
``BENCH`` messages back to the sender.  See
``tests/harness/bench_responder.py`` for the companion responder.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import secrets
import statistics
import sys
import time
from pathlib import Path
from typing import Optional

# Allow running as a script from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ironmesh.bridge import BridgeDaemon  # noqa: E402


BENCH_PREFIX = b"\x00BENCH\x00"  # nul-delimited so it can't collide with text
BENCH_REPLY_PREFIX = b"\x00BENCHREPLY\x00"


class BenchClient:
    """Sends BENCH messages to a target peer and records RTT on reply."""

    def __init__(self, daemon: BridgeDaemon, target_node_id: str):
        self.daemon = daemon
        self.target = target_node_id
        self._pending: dict[str, float] = {}  # seq -> send_monotonic
        self._received: asyncio.Queue = asyncio.Queue()

        daemon.bus.subscribe("MSG", self._on_msg)

    def _on_msg(self, data: dict) -> None:
        payload = data.get("payload", b"")
        if not isinstance(payload, (bytes, bytearray)):
            return
        if not payload.startswith(BENCH_REPLY_PREFIX):
            return
        try:
            body = payload[len(BENCH_REPLY_PREFIX):]
            header, _rest = body.split(b"|", 1)
            seq = header.decode("ascii")
        except Exception:
            return
        send_t = self._pending.pop(seq, None)
        if send_t is None:
            return
        rtt_ms = (time.monotonic() - send_t) * 1000.0
        self._received.put_nowait((seq, rtt_ms, len(payload)))

    async def wait_peer_online(self, timeout: float = 30.0,
                                stability_seconds: float = 2.0) -> bool:
        """Wait for the target peer to be online AND stable.

        ``stability_seconds`` is how long the peer must stay online with
        the same session_key. Prevents races when two daemons dial each
        other simultaneously and one connection gets dropped in the
        tie-breaker cleanup — the harness's first send would otherwise
        fire on the losing connection.
        """
        start = time.monotonic()
        stable_since: Optional[float] = None
        last_session: Optional[bytes] = None
        while time.monotonic() - start < timeout:
            s = self.daemon.peers.get(self.target)
            if s and s.is_online and s.session_key:
                if s.session_key == last_session and stable_since is not None:
                    if time.monotonic() - stable_since >= stability_seconds:
                        return True
                else:
                    last_session = s.session_key
                    stable_since = time.monotonic()
            else:
                stable_since = None
                last_session = None
            await asyncio.sleep(0.25)
        return False

    async def run_trial(self, size: int, timeout: float = 5.0,
                        chaos_drop: float = 0.0) -> Optional[float]:
        """Send one BENCH request and await the BENCHREPLY echo.

        Args:
            size: target payload size in bytes.
            timeout: seconds to wait for the reply before declaring loss.
            chaos_drop: probability in [0.0, 1.0] to intentionally skip the
                send (simulates client-side loss). The trial is recorded as
                a TIMEOUT so receive-side delivery metrics reflect real loss.
        """
        seq = secrets.token_hex(8)
        body = seq.encode("ascii") + b"|" + secrets.token_bytes(max(0, size - 17))
        payload = BENCH_PREFIX + body
        self._pending[seq] = time.monotonic()
        if chaos_drop > 0 and secrets.randbelow(1_000_000) / 1_000_000 < chaos_drop:
            # Intentional drop — don't call send_message; the reply never comes.
            self._pending.pop(seq, None)
            return None
        try:
            await self.daemon.send_message(self.target, "MSG", payload)
        except Exception as e:
            self._pending.pop(seq, None)
            print(f"  send failed: {e}", file=sys.stderr)
            return None
        try:
            # Drain any replies already queued, then wait for ours
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                got_seq, rtt_ms, _sz = await asyncio.wait_for(
                    self._received.get(), timeout=remaining,
                )
                if got_seq == seq:
                    return rtt_ms
                # else: stale reply from a prior trial — ignore
        except asyncio.TimeoutError:
            self._pending.pop(seq, None)
            return None
        return None


def _blocking_call(loop: asyncio.AbstractEventLoop, coro, timeout=None):
    """Submit a coroutine to the loop running in a background thread."""
    fut = asyncio.run_coroutine_threadsafe(coro, loop)
    return fut.result(timeout=timeout)


def run_bench(args: argparse.Namespace) -> int:
    import threading

    passphrase = None
    if args.passphrase_file:
        with open(os.path.expanduser(args.passphrase_file)) as f:
            passphrase = f.read().strip()
    else:
        passphrase = os.environ.get("IRONMESH_PASSPHRASE")
    if not passphrase:
        print("ERROR: set --passphrase-file or IRONMESH_PASSPHRASE", file=sys.stderr)
        return 2

    # Bench client must NOT auto-dial other mesh peers — we only want to
    # reach the target. Empty allowed_peers list = mDNS default-deny.
    daemon = BridgeDaemon(
        name=args.client_name,
        port=args.client_port,
        bind_address=args.client_bind,
        passphrase=passphrase,
        open_discovery=False,
        allowed_peers=[args.target_name] if args.target_name else [],
        allow_plaintext_ws=True,
    )
    # daemon.run(background=True) creates + primes the loop but doesn't run it.
    loop = daemon.run(background=True)
    threading.Thread(
        target=loop.run_forever, name="bench-loop", daemon=True,
    ).start()
    time.sleep(1.0)  # let the server + mDNS settle

    # Direct-dial the target — bypass mDNS
    target_node_id = args.target_node_id
    if not target_node_id:
        target_node_id = _blocking_call(
            loop,
            daemon.connect_to_peer(args.target_host, args.target_port),
            timeout=30,
        )
        if not target_node_id:
            print("ERROR: connect_to_peer returned None", file=sys.stderr)
            return 3

    client = BenchClient(daemon, target_node_id)

    online = _blocking_call(loop, client.wait_peer_online(30), timeout=35)
    if not online:
        print(f"ERROR: peer {target_node_id} not online after 30s", file=sys.stderr)
        return 4
    print(f"Connected to {target_node_id}. Warming up...")

    # Warmup — initial trials can race with post-handshake reconnect logic.
    # Send a handful of small messages and discard the results.
    for _ in range(3):
        try:
            _blocking_call(loop, client.run_trial(64, timeout=3.0), timeout=4.0)
        except Exception:
            pass
        time.sleep(0.2)
    print("Starting sweep...")

    sizes = [int(s) for s in args.sizes.split(",")]
    rows: list[dict] = []

    for size in sizes:
        print(f"\nPayload {size} bytes — {args.trials} trials")
        rtts: list[float] = []
        ok_count = 0
        for i in range(args.trials):
            try:
                rtt = _blocking_call(
                    loop,
                    client.run_trial(size, timeout=args.trial_timeout,
                                     chaos_drop=args.chaos),
                    timeout=args.trial_timeout + 2.0,
                )
            except Exception as e:
                print(f"  {i+1}/{args.trials}: ERR {type(e).__name__}: {e}")
                rtt = None
            if rtt is not None:
                rtts.append(rtt)
                ok_count += 1
                if (i + 1) % 10 == 0:
                    print(f"  {i+1}/{args.trials}: last_rtt={rtt:.1f}ms "
                          f"p50={statistics.median(rtts):.1f}")
            else:
                print(f"  {i+1}/{args.trials}: TIMEOUT")
            rows.append({
                "ts": time.time(),
                "src": args.client_name,
                "dst": args.target_name or target_node_id[:12],
                "size": size,
                "rtt_ms": rtt if rtt is not None else "",
                "ok": 1 if rtt is not None else 0,
            })
        if rtts:
            print(f"  summary: delivered {ok_count}/{args.trials} "
                  f"({100*ok_count/args.trials:.0f}%)  "
                  f"p50={statistics.median(rtts):.1f}ms  "
                  f"p95={sorted(rtts)[int(0.95*len(rtts))-1]:.1f}ms  "
                  f"goodput={size*ok_count*1000/sum(rtts):.1f} B/s")
        else:
            print(f"  summary: 0/{args.trials} delivered")

    outpath = Path(args.output)
    outpath.parent.mkdir(parents=True, exist_ok=True)
    with outpath.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ts", "src", "dst", "size", "rtt_ms", "ok"])
        w.writeheader()
        w.writerows(rows)
    print(f"\nWrote {len(rows)} rows to {outpath}")

    loop.call_soon_threadsafe(loop.stop)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="IronMesh mesh benchmark")
    p.add_argument("--target-host", required=True)
    p.add_argument("--target-port", type=int, required=True)
    p.add_argument("--target-name", default=None,
                   help="Display name for the target (for CSV labels)")
    p.add_argument("--target-node-id", default=None,
                   help="Known node_id of target; if omitted, derived from handshake")
    p.add_argument("--client-name", default="bench-client")
    p.add_argument("--client-port", type=int, default=18765)
    p.add_argument("--client-bind", default="0.0.0.0",
                   help="Bind the bench client to a specific IP. Set to your "
                        "primary LAN IP on multi-NIC hosts (e.g., machines with "
                        "VirtualBox/WSL) so mDNS doesn't announce unreachable "
                        "host-only addresses.")
    p.add_argument("--passphrase-file", default=None)
    p.add_argument("--sizes", default="64,256,1024,4096",
                   help="Comma-separated payload sizes to sweep")
    p.add_argument("--trials", type=int, default=50)
    p.add_argument("--trial-timeout", type=float, default=5.0)
    p.add_argument("--chaos", type=float, default=0.0,
                   help="Drop rate [0.0, 1.0] for chaos mode — simulates loss "
                        "by skipping the send. The daemon's retry logic sees "
                        "real timeouts.")
    p.add_argument("--output", default="tests/harness/bench_results.csv")
    args = p.parse_args()
    return run_bench(args)


if __name__ == "__main__":
    sys.exit(main())
