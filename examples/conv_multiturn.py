#!/usr/bin/env python3
"""Minimal multi-turn conversation over IronMesh using ConvEnvelope.

Two terminals, two roles. The pinger opens a bounded conversation
(default 4 turns) and exchanges scripted ping/pong messages with the
ponger. No LLM dependency — both sides are scripted — so this works as
a self-contained ConvEnvelope walkthrough you can run without any
external service.

Usage
-----
    export IRONMESH_PASSPHRASE='your-shared-passphrase-12-plus'

    # Terminal 1
    python examples/conv_multiturn.py --role ponger --port 18890

    # Terminal 2
    python examples/conv_multiturn.py --role pinger --port 18891 \\
        --partner ponger --turns 4

What you'll see
---------------
    [pinger] turn 1/4 -> ponger: 'ping 1'
    [ponger] received turn 1/4: 'ping 1'
    [ponger] turn 2/4 -> pinger: 'pong 1'
    [pinger] received turn 2/4: 'pong 1'
    ...
    [ponger] turn 4/4 -> pinger: 'pong 2 [END]'
    Conversation ended naturally after 4 turns.

Reference for: open a conversation, exchange bounded turns, recognize
end-of-conversation, no orphaned state.
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import uuid

from ironmesh import Agent, ConvEnvelope
from ironmesh.conversation import (
    KIND_END,
    KIND_PROMPT,
    is_terminal,
    make_reply,
)


def run_pinger(name: str, partner: str, port: int, turns: int,
               passphrase: str, discovery_timeout: float) -> int:
    agent = Agent(
        name, port=port, passphrase=passphrase,
        open_discovery=True, allow_plaintext=True,
    )
    done = threading.Event()
    conv_id = uuid.uuid4().hex[:12]

    @agent.on("CONV")
    def _on_conv(data):
        payload = data.get("payload", b"") or b""
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        try:
            env = ConvEnvelope.decode(payload)
        except ValueError:
            return
        if env.conv_id != conv_id:
            return
        print(f"[{name}] received turn {env.turn}/{env.max_turns}: "
              f"{env.body!r}")
        if is_terminal(env):
            print(f"Conversation ended naturally after {env.turn} turns.")
            done.set()

    agent.run(foreground=False)
    try:
        # Wait for the partner to come online via mDNS
        deadline = time.monotonic() + discovery_timeout
        while time.monotonic() < deadline:
            if agent.peer_by_name(partner):
                break
            time.sleep(0.25)
        else:
            print(f"[{name}] timed out waiting for {partner}",
                  file=sys.stderr)
            return 1

        envelope = ConvEnvelope(
            conv_id=conv_id,
            turn=1,
            max_turns=turns,
            kind=KIND_PROMPT,
            body="ping 1",
            from_role="pinger",
            to_role="ponger",
        )
        print(f"[{name}] turn 1/{turns} -> {partner}: {envelope.body!r}")
        agent.send_sync(partner, envelope.encode(), msg_type="CONV")

        # Wait for the conversation to end naturally or time out
        if not done.wait(timeout=30.0):
            print(f"[{name}] conversation timed out", file=sys.stderr)
            return 1
        return 0
    finally:
        agent.stop()


def run_ponger(name: str, port: int, passphrase: str) -> int:
    agent = Agent(
        name, port=port, passphrase=passphrase,
        open_discovery=True, allow_plaintext=True,
    )
    pong_count = {"n": 0}

    @agent.on("CONV")
    def _on_conv(data):
        peer_id = data.get("peer_id", "")
        payload = data.get("payload", b"") or b""
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        try:
            env = ConvEnvelope.decode(payload)
        except ValueError:
            return
        print(f"[{name}] received turn {env.turn}/{env.max_turns}: "
              f"{env.body!r}")
        if is_terminal(env):
            return

        pong_count["n"] += 1
        body = f"pong {pong_count['n']}"
        next_turn = env.turn + 1
        # Mark the final turn with [END] so the pinger sees natural termination
        if next_turn >= env.max_turns:
            body += " [END]"
            kind = KIND_END
        else:
            kind = KIND_PROMPT

        reply = make_reply(env, body=body, kind=kind)
        peer_name = next(
            (p.get("name") for p in agent.peers if p.get("node_id") == peer_id),
            peer_id[:12],
        )
        print(f"[{name}] turn {next_turn}/{env.max_turns} -> {peer_name}: "
              f"{reply.body!r}")
        agent.send_sync(peer_id, reply.encode(), msg_type="CONV")

    agent.run(foreground=False)
    print(f"[{name}] online on port {port}, waiting for a conversation...")
    try:
        # Block forever — the pinger drives the conversation
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0
    finally:
        agent.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True,
                        choices=["pinger", "ponger"],
                        help="Which side to run")
    parser.add_argument("--name", default=None,
                        help="Agent name (defaults to the role name)")
    parser.add_argument("--partner", default="ponger",
                        help="Partner agent name (pinger only, default: ponger)")
    parser.add_argument("--port", type=int, default=18890,
                        help="Port for this agent (default: 18890)")
    parser.add_argument("--turns", type=int, default=4,
                        help="Maximum turns in the conversation (default: 4)")
    parser.add_argument("--discovery-timeout", type=float, default=30.0,
                        help="Seconds to wait for partner discovery (default: 30)")
    args = parser.parse_args()

    passphrase = os.environ.get("IRONMESH_PASSPHRASE")
    if not passphrase:
        print("Set IRONMESH_PASSPHRASE in the environment "
              "(12+ characters).", file=sys.stderr)
        return 1
    if len(passphrase) < 12:
        print("IRONMESH_PASSPHRASE must be at least 12 characters.",
              file=sys.stderr)
        return 1

    name = args.name or args.role
    if args.role == "pinger":
        return run_pinger(name, args.partner, args.port, args.turns,
                          passphrase, args.discovery_timeout)
    else:
        return run_ponger(name, args.port, passphrase)


if __name__ == "__main__":
    sys.exit(main())
