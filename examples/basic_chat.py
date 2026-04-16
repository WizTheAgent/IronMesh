#!/usr/bin/env python3
"""IronMesh basic chat — two agents send messages to each other.

Usage:
  export IRONMESH_PASSPHRASE='your-shared-passphrase-12-plus'
  # Machine A:
  python basic_chat.py --name alice
  # Machine B (or another terminal with --port 8766):
  python basic_chat.py --name bob

Both agents auto-discover via mDNS, authenticate, and establish an encrypted channel.
Type messages to send; received messages are printed automatically.
"""

import argparse
import os
import sys

from ironmesh.agent import Agent


def main():
    p = argparse.ArgumentParser(description="IronMesh basic chat")
    p.add_argument("--name", required=True)
    p.add_argument("--port", type=int, default=8765)
    args = p.parse_args()

    passphrase = os.environ.get("IRONMESH_PASSPHRASE")
    if not passphrase:
        sys.exit("Set IRONMESH_PASSPHRASE env var (12+ chars) before running.")

    agent = Agent(args.name, port=args.port, passphrase=passphrase)

    @agent.on_message()
    def on_msg(peer_id, payload):
        print(f"\n[{peer_id[:12]}]: {payload.decode('utf-8', errors='replace')}")
        print("> ", end="", flush=True)

    loop = agent.run(foreground=False)
    print(f"Chat started as '{args.name}'. Waiting for peers...")
    print("Type a message and press Enter. 'quit' to exit.\n")

    try:
        while True:
            text = input("> ")
            if text.lower() in ("quit", "exit"):
                break
            if not text.strip():
                continue
            for peer in agent.peers:
                agent.reply(peer["node_id"], text)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        agent.stop()
        print("\nChat ended.")


if __name__ == "__main__":
    main()
