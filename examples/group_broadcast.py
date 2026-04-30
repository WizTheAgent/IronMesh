#!/usr/bin/env python3
"""Mesh-wide shared-secret broadcast (chunk B, v0.9.2+).

Two agents on the same mesh passphrase independently derive the same
HKDF-SHA256 group destination + symmetric key — no key exchange. One
agent calls ``broadcast_via_rns_group(payload)``; every peer that
also enabled ``rns_group_broadcast`` and shares the passphrase
receives the bytes via the ``on_group_broadcast`` hook.

Two-phase delivery handles both same-segment and cross-host cases:

    Phase 1: O(1) RNS GROUP packet on the local segment (every
             daemon sharing one rnsd or one LoRa medium hears it).
    Phase 2: O(N) IronMesh GROUP_BROADCAST fan-out over established
             connections to peers that advertised the ``group``
             feature. Receivers dedup on payload SHA-256 (60 s
             window, 10k entries) so a peer reachable via both
             phases handles the bytes exactly once.

Usage
-----
    export IRONMESH_PASSPHRASE='your-shared-passphrase-12-plus'

    # Terminal 1 (receiver)
    python examples/group_broadcast.py --role receiver --port 18890

    # Terminal 2 (sender)
    python examples/group_broadcast.py --role sender --port 18891

What you'll see
---------------
    [receiver] listening on 127.0.0.1:18890; waiting for broadcasts...
    [receiver] got broadcast (24 bytes): b'hello mesh from sender 1'
    [receiver] got broadcast (24 bytes): b'hello mesh from sender 2'
    [receiver] got broadcast (24 bytes): b'hello mesh from sender 3'

    [sender] broadcasting #1 ...  result={'local_segment': True,
                                          'fanout_sent': 1,
                                          'fanout_skipped': 0}
    [sender] broadcasting #2 ...  result={...}

Reference for: passphrase-derived group identity, two-phase delivery
result dict, on_group_broadcast hook signature.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

from ironmesh.agent import Agent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--role", required=True, choices=["sender", "receiver"])
    parser.add_argument("--port", type=int, required=True,
                        help="WebSocket port for this agent's local daemon")
    parser.add_argument("--passphrase", default=os.environ.get("IRONMESH_PASSPHRASE"),
                        help="Mesh passphrase (default: $IRONMESH_PASSPHRASE)")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--count", type=int, default=3,
                        help="Sender: how many broadcasts to fire (default: 3)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Sender: seconds between broadcasts (default: 2.0)")
    args = parser.parse_args()

    if not args.passphrase:
        sys.stderr.write(
            "Set IRONMESH_PASSPHRASE in the environment, or pass --passphrase. "
            "Both agents must use the SAME passphrase or they derive different "
            "group destinations and won't see each other's broadcasts.\n"
        )
        return 2

    agent = Agent(
        f"group-{args.role}",
        port=args.port,
        bind=args.bind,
        passphrase=args.passphrase,
        allow_plaintext=True,
        # Chunk B requires Reticulum + the group-broadcast feature.
        reticulum=True,
        rns_group_broadcast=True,
    )

    if args.role == "receiver":
        # The daemon calls this hook synchronously (or awaits it if
        # async) for every successfully-deduped inbound payload. Keep
        # it fast — slow handlers serialize the receive loop.
        def on_group_broadcast(payload: bytes) -> None:
            print(f"[receiver] got broadcast ({len(payload)} bytes): {payload!r}",
                  flush=True)
        agent.daemon.on_group_broadcast = on_group_broadcast

        agent.run(foreground=False)
        print(f"[receiver] listening on {args.bind}:{args.port}; "
              f"waiting for broadcasts... (Ctrl-C to stop)",
              flush=True)
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("\n[receiver] shutting down")
        finally:
            asyncio.run_coroutine_threadsafe(
                agent.daemon.shutdown(), agent._loop,
            ).result(timeout=5)
        return 0

    # role == "sender"
    agent.run(foreground=False)
    # Brief settling window so RNS announces propagate before we try
    # to enumerate Phase 2 fan-out targets.
    time.sleep(3.0)
    try:
        for i in range(1, args.count + 1):
            payload = f"hello mesh from sender {i}".encode("utf-8")
            result = agent.daemon.broadcast_via_rns_group(payload)
            print(f"[sender] broadcasting #{i} ...  result={result}",
                  flush=True)
            time.sleep(args.interval)
    finally:
        asyncio.run_coroutine_threadsafe(
            agent.daemon.shutdown(), agent._loop,
        ).result(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
