"""Boot a minimal IronMesh daemon for e2e tests against the TS client.

Args (from env):
  PORT                — TCP port to listen on (default 49321)
  PASSPHRASE          — mesh passphrase (default 'e2e-overnight-passphrase-12345')
  NAME                — daemon agent name (default 'e2e-daemon')

Behaviour:
  - Echoes any inbound MSG back to the sender as type "ECHO" so the
    TS client can verify a full request/response loop.
  - Prints "READY <port>" to stdout once the WebSocket server is
    accepting connections — the harness blocks on that line.
  - Exits cleanly on SIGTERM or stdin EOF.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading
from pathlib import Path

# Make the in-tree package importable when this script is run directly
# (from clients/ts/tests/fixtures/) without a site-install.
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from ironmesh.bridge import BridgeDaemon  # noqa: E402


def main() -> int:
    port = int(os.environ.get("PORT", "49321"))
    passphrase = os.environ.get("PASSPHRASE", "e2e-overnight-passphrase-12345")
    name = os.environ.get("NAME", "e2e-daemon")

    daemon = BridgeDaemon(
        name=name,
        port=port,
        bind_address="127.0.0.1",
        passphrase=passphrase,
        # Disable mDNS — we don't need discovery for a single-peer e2e.
        open_discovery=False,
        allow_plaintext_ws=False,
        # Use an in-memory DB so test runs don't pollute ~/.ironmesh.
        db_path=":memory:",
    )

    # Echo handler — when an MSG arrives, reply with type "ECHO" and the same payload.
    def on_msg(data):
        from collections.abc import Mapping
        if not isinstance(data, Mapping):
            return
        peer_id = data.get("peer_id")
        payload = data.get("payload")
        if not peer_id or payload is None:
            return
        # send_message returns a coroutine; schedule on the daemon's loop
        try:
            asyncio.run_coroutine_threadsafe(
                daemon.send_message(peer_id, "ECHO", payload, "NORMAL"),
                daemon._loop,
            )
        except Exception as e:  # noqa: BLE001
            print(f"echo dispatch failed: {e}", file=sys.stderr)

    daemon.bus.subscribe("MSG", on_msg)

    loop = daemon.run(background=True)
    threading.Thread(target=loop.run_forever, name="e2e-daemon-loop",
                     daemon=True).start()

    # Tiny block until the WS server is bound.
    import time as _t
    for _ in range(100):
        if getattr(daemon, "_server", None) is not None:
            break
        _t.sleep(0.05)

    print(f"READY {port}", flush=True)

    # Block on stdin EOF — the test harness sends SIGTERM or closes
    # stdin to signal shutdown.
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    loop.call_soon_threadsafe(loop.stop)
    return 0


if __name__ == "__main__":
    sys.exit(main())
