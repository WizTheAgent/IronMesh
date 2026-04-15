#!/usr/bin/env python3
"""Bench responder — echoes BENCH messages back to sender.

Attaches to a running ``BridgeDaemon``'s MessageBus.  When a MSG arrives
with the ``\\x00BENCH\\x00`` prefix, reply with the same seq tagged as
``\\x00BENCHREPLY\\x00``.  Used alongside ``mesh_bench.py``.

Run this on the target node BEFORE starting the benchmark from the client::

    python -m tests.harness.bench_responder \\
        --name responder --port 8764 \\
        --passphrase-file ~/.ironmesh/passphrase \\
        --open-discovery --allow-plaintext-ws

Or register the responder programmatically inside an existing daemon by
calling ``attach_responder(daemon)`` — see the helper below.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ironmesh.bridge import BridgeDaemon  # noqa: E402


BENCH_PREFIX = b"\x00BENCH\x00"
BENCH_REPLY_PREFIX = b"\x00BENCHREPLY\x00"


def attach_responder(daemon: BridgeDaemon, loop: asyncio.AbstractEventLoop) -> None:
    """Register the bench responder on an existing daemon's bus."""

    def _on_msg(data: dict) -> None:
        payload = data.get("payload", b"")
        peer_id = data.get("peer_id")
        if not peer_id or not isinstance(payload, (bytes, bytearray)):
            return
        if not payload.startswith(BENCH_PREFIX):
            return
        body = payload[len(BENCH_PREFIX):]
        reply = BENCH_REPLY_PREFIX + body
        asyncio.run_coroutine_threadsafe(
            daemon.send_message(peer_id, "MSG", reply), loop,
        )

    daemon.bus.subscribe("MSG", _on_msg)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--name", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--passphrase-file", default=None)
    p.add_argument("--open-discovery", action="store_true")
    p.add_argument("--allow-plaintext-ws", action="store_true")
    args = p.parse_args()

    passphrase = None
    if args.passphrase_file:
        with open(os.path.expanduser(args.passphrase_file)) as f:
            passphrase = f.read().strip()
    else:
        passphrase = os.environ.get("IRONMESH_PASSPHRASE")
    if not passphrase:
        print("ERROR: set --passphrase-file or IRONMESH_PASSPHRASE", file=sys.stderr)
        return 2

    daemon = BridgeDaemon(
        name=args.name, port=args.port, bind_address=args.bind,
        passphrase=passphrase,
        open_discovery=args.open_discovery,
        allow_plaintext_ws=args.allow_plaintext_ws,
    )
    loop = daemon.run(background=True)
    threading.Thread(target=loop.run_forever, name="responder-loop",
                     daemon=True).start()
    attach_responder(daemon, loop)

    print(f"Bench responder running as '{args.name}' on port {args.port}")
    print(f"Node ID: {daemon.node_id}")
    print("Ctrl-C to stop.")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass
    loop.call_soon_threadsafe(loop.stop)
    return 0


if __name__ == "__main__":
    sys.exit(main())
