#!/usr/bin/env python3
"""Capability-aware routing — Agent.send_to_capability (chunk E, v0.9.2+).

Three roles share a passphrase. Two ``provider`` agents advertise the
same capability glob (e.g. ``echo:demo``); a ``client`` agent
discovers them via the capability registry and dispatches with one
of three strategies:

* ``--strategy first`` — pick the best-RTT online match, fall through
  on failure.
* ``--strategy random`` — load-distribute across capability-equivalent
  peers.
* ``--strategy all`` — fan out to every match in parallel.

The local node is never picked even if it also satisfies the
capability, so the client can safely advertise its own capabilities
without self-loop concerns.

Usage
-----
    export IRONMESH_PASSPHRASE='your-shared-passphrase-12-plus'

    # Terminal 1 (provider A)
    python examples/capability_routing.py --role provider \\
        --name provider-a --port 18890

    # Terminal 2 (provider B)
    python examples/capability_routing.py --role provider \\
        --name provider-b --port 18891

    # Terminal 3 (client)
    python examples/capability_routing.py --role client \\
        --name caller --port 18892 --strategy all

What you'll see
---------------
    [provider-a] advertising echo:demo on 127.0.0.1:18890
    [provider-a] echoing 'ping from caller'

    [provider-b] advertising echo:demo on 127.0.0.1:18891
    [provider-b] echoing 'ping from caller'

    [caller] dispatching with strategy=all ...
    [caller] result: {'transport': 'fanout', 'targets': [...]}

Reference for: capability advertisement on Agent init, on_message
handler, send_to_capability with each strategy, the dict shape
returned for first/random vs all.
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
    parser.add_argument("--role", required=True, choices=["provider", "client"])
    parser.add_argument("--name", required=True,
                        help="Agent name (e.g. provider-a, provider-b, caller)")
    parser.add_argument("--port", type=int, required=True,
                        help="WebSocket port for this agent's local daemon")
    parser.add_argument("--passphrase", default=os.environ.get("IRONMESH_PASSPHRASE"),
                        help="Mesh passphrase (default: $IRONMESH_PASSPHRASE)")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--capability", default="echo:demo",
                        help="Capability string providers advertise / client matches "
                             "(default: echo:demo)")
    parser.add_argument("--strategy", default="first",
                        choices=["first", "random", "all"],
                        help="Client dispatch strategy (default: first)")
    parser.add_argument("--message", default="ping from caller",
                        help="Client: payload to send (default: 'ping from caller')")
    parser.add_argument("--settle", type=float, default=4.0,
                        help="Client: seconds to wait for capability discovery "
                             "before dispatching (default: 4.0)")
    args = parser.parse_args()

    if not args.passphrase:
        sys.stderr.write(
            "Set IRONMESH_PASSPHRASE in the environment, or pass --passphrase.\n"
        )
        return 2

    # Providers advertise a capability on Agent init; client doesn't.
    capabilities = [args.capability] if args.role == "provider" else None

    agent = Agent(
        args.name,
        port=args.port,
        bind=args.bind,
        passphrase=args.passphrase,
        capabilities=capabilities,
        allow_plaintext=True,
    )

    if args.role == "provider":
        # Echo every inbound MSG back to its sender. Prints a line so
        # the operator sees which provider was picked by the client's
        # strategy.
        @agent.on_message()
        def handle(peer_id: str, payload: bytes) -> None:
            text = payload.decode("utf-8", errors="replace")
            print(f"[{args.name}] echoing {text!r}", flush=True)
            agent.reply(peer_id, b"ack: " + payload)

        agent.run(foreground=False)
        print(f"[{args.name}] advertising {args.capability} on "
              f"{args.bind}:{args.port}; waiting... (Ctrl-C to stop)",
              flush=True)
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            print(f"\n[{args.name}] shutting down")
        finally:
            asyncio.run_coroutine_threadsafe(
                agent.daemon.shutdown(), agent._loop,
            ).result(timeout=5)
        return 0

    # role == "client"
    agent.run(foreground=False)
    print(f"[{args.name}] settling {args.settle}s for capability discovery...",
          flush=True)
    time.sleep(args.settle)

    print(f"[{args.name}] dispatching with strategy={args.strategy} "
          f"capability={args.capability!r}", flush=True)
    try:
        result = agent.send_to_capability_sync(
            args.capability, args.message, strategy=args.strategy,
        )
        print(f"[{args.name}] result: {result}", flush=True)
    except ValueError as e:
        # Raised when no peer advertises the capability or every
        # reachable candidate fails. Surfaces as
        # ironmesh_capability_routes_no_match_total in metrics.
        print(f"[{args.name}] no match: {e}", flush=True)
        return 1
    finally:
        asyncio.run_coroutine_threadsafe(
            agent.daemon.shutdown(), agent._loop,
        ).result(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
