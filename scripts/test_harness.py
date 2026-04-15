#!/usr/bin/env python3
"""IronMesh Test Harness — payload sizing, latency, and loss measurement.

Connects to the local IronMesh bridge via the GUI WebSocket and runs
incremental payload tests against a target peer.  Outputs a CSV and
prints summary statistics including per-size min/max/avg/p95 latency
and success rate.

Usage:
    python scripts/test_harness.py \\
        --ws-url ws://127.0.0.1:8767/ws \\
        --token <gui_token> \\
        --peer <peer_node_id> \\
        --count 10 \\
        --output results.csv

The harness measures *bridge processing latency* (time from send to
send_ack).  For actual network RTT, check the peer's ``latency_ms``
field in the dashboard API (populated by heartbeat pings).
"""

import argparse
import asyncio
import csv
import json
import statistics
import sys
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional

try:
    import websockets
except ImportError:
    print("Error: websockets package required. Install with: pip install websockets")
    sys.exit(1)


@dataclass
class TestResult:
    size: int
    attempt: int
    latency_ms: float
    success: bool
    msg_id: str
    timestamp: float


class TestHarness:
    def __init__(self, ws_url: str, token: str, peer_id: str,
                 count: int = 10, sizes: Optional[List[int]] = None):
        self.ws_url = ws_url
        self.token = token
        self.peer_id = peer_id
        self.count = count
        self.sizes = sizes or [32, 64, 128, 256, 512, 1024, 2048, 4096]
        self.results: List[TestResult] = []
        self._ws = None
        self._peer_transport: str = "unknown"
        self._peer_rtt_ms: Optional[float] = None

    async def connect(self):
        """Connect to the GUI WebSocket and consume initial snapshot."""
        url = f"{self.ws_url}?token={self.token}"
        self._ws = await websockets.connect(url, open_timeout=10)
        raw = await asyncio.wait_for(self._ws.recv(), timeout=10)
        snapshot = json.loads(raw)
        if snapshot.get("type") == "snapshot":
            data = snapshot.get("data", {})
            for p in data.get("peers", []):
                if p.get("node_id") == self.peer_id:
                    self._peer_transport = p.get("transport_type", "unknown")
                    self._peer_rtt_ms = p.get("latency_ms")
                    break
        print(f"Connected. Peer transport: {self._peer_transport}, "
              f"RTT: {self._peer_rtt_ms:.1f} ms" if self._peer_rtt_ms else
              f"Connected. Peer transport: {self._peer_transport}, RTT: n/a")

    async def run_tests(self):
        """Run all payload size tests."""
        total = len(self.sizes) * self.count
        done = 0
        for size in self.sizes:
            print(f"\n--- {size} bytes ({self.count} messages) ---")
            for attempt in range(1, self.count + 1):
                result = await self._send_and_measure(size, attempt)
                self.results.append(result)
                done += 1
                status = "OK" if result.success else "FAIL"
                lat = f"{result.latency_ms:.1f}ms" if result.success else "timeout"
                print(f"  [{done}/{total}] {size}B #{attempt}: {status} {lat}")
                await asyncio.sleep(0.1)

    async def _send_and_measure(self, size: int, attempt: int) -> TestResult:
        """Send a single test message and wait for send_ack."""
        nonce = uuid.uuid4().hex[:16]
        padding = "X" * max(0, size - len(nonce))
        payload = nonce + padding

        send_time = time.monotonic()
        await self._ws.send(json.dumps({
            "action": "send_message",
            "to_node": self.peer_id,
            "msg_type": "MSG",
            "payload": payload,
        }))

        try:
            raw = await asyncio.wait_for(self._ws.recv(), timeout=15.0)
            resp = json.loads(raw)
            if resp.get("type") == "send_ack":
                latency_ms = (time.monotonic() - send_time) * 1000
                return TestResult(
                    size=size, attempt=attempt, latency_ms=latency_ms,
                    success=True, msg_id=resp.get("msg_id", ""),
                    timestamp=time.time(),
                )
            # Might get a state_update instead — try one more recv
            raw2 = await asyncio.wait_for(self._ws.recv(), timeout=5.0)
            resp2 = json.loads(raw2)
            if resp2.get("type") == "send_ack":
                latency_ms = (time.monotonic() - send_time) * 1000
                return TestResult(
                    size=size, attempt=attempt, latency_ms=latency_ms,
                    success=True, msg_id=resp2.get("msg_id", ""),
                    timestamp=time.time(),
                )
        except (asyncio.TimeoutError, Exception):
            pass

        return TestResult(
            size=size, attempt=attempt, latency_ms=-1,
            success=False, msg_id="", timestamp=time.time(),
        )

    def write_csv(self, path: str):
        """Write results to CSV."""
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["size", "attempt", "latency_ms", "success",
                             "transport_type", "timestamp", "msg_id"])
            for r in self.results:
                writer.writerow([r.size, r.attempt, r.latency_ms, r.success,
                                 self._peer_transport, r.timestamp, r.msg_id])
        print(f"\nCSV written to {path}")

    def print_summary(self):
        """Print per-size statistics."""
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Peer: {self.peer_id[:16]}...")
        print(f"Transport: {self._peer_transport}")
        if self._peer_rtt_ms is not None:
            print(f"Network RTT (heartbeat): {self._peer_rtt_ms:.1f} ms")
        print()
        print(f"{'Size':>6}  {'OK':>4}/{' N':>2}  {'Min':>8}  {'Avg':>8}  "
              f"{'P95':>8}  {'Max':>8}  {'Rate':>6}")
        print("-" * 60)

        for size in self.sizes:
            batch = [r for r in self.results if r.size == size]
            ok = [r for r in batch if r.success]
            n = len(batch)
            ok_count = len(ok)

            if ok:
                lats = sorted(r.latency_ms for r in ok)
                mn = lats[0]
                mx = lats[-1]
                avg = statistics.mean(lats)
                p95_idx = int(len(lats) * 0.95)
                p95 = lats[min(p95_idx, len(lats) - 1)]
                rate = f"{ok_count / n * 100:.0f}%"
                print(f"{size:>6}  {ok_count:>4}/{n:>2}  {mn:>7.1f}  {avg:>7.1f}  "
                      f"{p95:>7.1f}  {mx:>7.1f}  {rate:>6}")
            else:
                print(f"{size:>6}  {ok_count:>4}/{n:>2}  {'---':>8}  {'---':>8}  "
                      f"{'---':>8}  {'---':>8}  {'0%':>6}")

        total = len(self.results)
        total_ok = sum(1 for r in self.results if r.success)
        print("-" * 60)
        print(f"Total: {total_ok}/{total} messages delivered "
              f"({total_ok / total * 100:.0f}%)" if total else "No results")

    async def close(self):
        if self._ws:
            await self._ws.close()


async def main():
    parser = argparse.ArgumentParser(description="IronMesh Test Harness")
    parser.add_argument("--ws-url", required=True,
                        help="GUI WebSocket URL (e.g. ws://127.0.0.1:8767/ws)")
    parser.add_argument("--token", required=True, help="GUI authentication token")
    parser.add_argument("--peer", required=True, help="Target peer node_id")
    parser.add_argument("--count", type=int, default=10,
                        help="Messages per payload size (default: 10)")
    parser.add_argument("--sizes", default="32,64,128,256,512,1024,2048,4096",
                        help="Comma-separated payload sizes in bytes")
    parser.add_argument("--output", default="ironmesh_test_results.csv",
                        help="Output CSV path (default: ironmesh_test_results.csv)")
    args = parser.parse_args()

    sizes = [int(s.strip()) for s in args.sizes.split(",")]

    harness = TestHarness(
        ws_url=args.ws_url,
        token=args.token,
        peer_id=args.peer,
        count=args.count,
        sizes=sizes,
    )

    try:
        await harness.connect()
        await harness.run_tests()
        harness.write_csv(args.output)
        harness.print_summary()
    finally:
        await harness.close()


if __name__ == "__main__":
    asyncio.run(main())
