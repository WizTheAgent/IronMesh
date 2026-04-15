#!/usr/bin/env python3
"""IronMesh basic chat example — two agents send messages to each other.

Usage:
  Machine A: python basic_chat.py --name alice --port 8765 --passphrase secret
  Machine B: python basic_chat.py --name bob   --port 8765 --passphrase secret

Both agents auto-discover via mDNS, authenticate, and establish an encrypted channel.
Type messages to send; received messages are printed automatically.
"""

import argparse
import asyncio
import sys
import threading

sys.path.insert(0, "..")

from ironmesh.bridge import BridgeDaemon


def main():
    parser = argparse.ArgumentParser(description="IronMesh basic chat")
    parser.add_argument("--name", required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--passphrase", default="empire")
    args = parser.parse_args()

    daemon = BridgeDaemon(
        name=args.name,
        port=args.port,
        passphrase=args.passphrase,
    )

    # Subscribe to incoming messages
    def on_message(data):
        peer = data.get("peer_id", "?")
        payload = data.get("payload", b"")
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="replace")
        print(f"\n[{peer}]: {payload}")
        print("> ", end="", flush=True)

    daemon.bus.subscribe("MSG", on_message)

    # Start daemon in background
    loop = daemon.run(background=True)
    print(f"Chat started as '{args.name}'. Waiting for peers...")
    print("Type a message and press Enter to send to all connected peers.")
    print("Type 'quit' to exit.\n")

    # Input loop
    try:
        while True:
            text = input("> ")
            if text.lower() in ("quit", "exit"):
                break
            if not text.strip():
                continue

            # Send to all online peers
            for peer_id, state in daemon.peers.items():
                if state.is_online:
                    asyncio.run_coroutine_threadsafe(
                        daemon.send_message(peer_id, "MSG", text.encode("utf-8")),
                        loop,
                    )
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        asyncio.run_coroutine_threadsafe(daemon.shutdown(), loop)
        loop.call_soon_threadsafe(loop.stop)
        print("\nChat ended.")


if __name__ == "__main__":
    main()
