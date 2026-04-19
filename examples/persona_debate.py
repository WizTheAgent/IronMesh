#!/usr/bin/env python3
"""Two persona-tagged LLM bridges debating a motion over IronMesh.

Discovers two peers that advertise different ``role:<persona>``
capabilities (e.g., ``role:assistant`` and ``role:devil``), seeds a
debate motion, and relays bounded turns between them. Each side
responds in character using its persona preset from
``ironmesh.roles``. Prints a clean debate transcript.

This is a focused complement to ``ai_to_ai_dialogue.py`` — same
underlying CONV envelope plumbing, but framed around persona contrast
instead of generic dialogue.

Prerequisites
-------------
Two ``llm_bridge.py`` instances running with different ``--role``
flags, both pointed at an LLM backend (Ollama or compatible). For
example, in two separate terminals:

    # Terminal 1 — the helpful assistant
    python examples/llm_bridge.py --name asst --role assistant \\
        --port 18801 --model llama3.2:3b

    # Terminal 2 — the devil's advocate
    python examples/llm_bridge.py --name devil --role devil \\
        --port 18802 --model llama3.2:3b

Then in a third terminal:

    export IRONMESH_PASSPHRASE='your-shared-passphrase-12-plus'
    python examples/persona_debate.py \\
        --persona-a assistant --persona-b devil \\
        --motion "Self-hosted AI is the only ethical path forward." \\
        --turns 6

Available personas (built into IronMesh):
    assistant, security-analyst, network-engineer, historian,
    coder, ops, devil

Pair them however you like — assistant vs devil for classic debate,
security-analyst vs ops for a real-world tradeoff discussion,
historian vs coder for perspective contrast.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import uuid

from ironmesh import Agent, ConvEnvelope
from ironmesh.conversation import KIND_END, KIND_ERROR, KIND_PROMPT


def find_peer_with_role(agent: Agent, role: str,
                        timeout: float) -> str | None:
    """Block up to `timeout` seconds for a peer advertising role:<role>."""
    deadline = time.monotonic() + timeout
    cap = f"role:{role}"
    while time.monotonic() < deadline:
        for node_id, advertised in agent.discover(cap):
            for peer in agent.peers:
                if peer.get("node_id") == node_id and peer.get("name"):
                    return peer["name"]
        time.sleep(0.5)
    return None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--persona-a", required=True,
                   help="First persona (e.g., assistant)")
    p.add_argument("--persona-b", required=True,
                   help="Second persona (e.g., devil)")
    p.add_argument("--motion", required=True,
                   help="Debate motion / seed prompt")
    p.add_argument("--turns", type=int, default=6,
                   help="Max debate turns (default: 6, three each side)")
    p.add_argument("--name", default="debate-moderator")
    p.add_argument("--port", type=int, default=18888)
    p.add_argument("--turn-timeout", type=float, default=120.0,
                   help="Seconds to wait per reply (default: 120)")
    p.add_argument("--discovery-timeout", type=float, default=60.0,
                   help="Seconds to wait for both personas (default: 60)")
    args = p.parse_args()

    if args.persona_a == args.persona_b:
        print("Pick two different personas — debate needs contrast.",
              file=sys.stderr)
        return 1

    passphrase = os.environ.get("IRONMESH_PASSPHRASE")
    if not passphrase:
        print("Set IRONMESH_PASSPHRASE in the environment "
              "(12+ characters).", file=sys.stderr)
        return 1

    agent = Agent(
        args.name, port=args.port, passphrase=passphrase,
        open_discovery=True, allow_plaintext=True,
    )

    inbox: list[tuple[str, ConvEnvelope]] = []

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
        inbox.append((peer_id, env))

    agent.run(foreground=False)

    try:
        print(f"[moderator] discovering role:{args.persona_a} "
              f"and role:{args.persona_b}...")
        peer_a = find_peer_with_role(agent, args.persona_a,
                                     args.discovery_timeout)
        peer_b = find_peer_with_role(agent, args.persona_b,
                                     args.discovery_timeout)
        if not peer_a:
            print(f"No peer advertising role:{args.persona_a} found.",
                  file=sys.stderr)
            return 1
        if not peer_b:
            print(f"No peer advertising role:{args.persona_b} found.",
                  file=sys.stderr)
            return 1
        print(f"[moderator] {args.persona_a} = {peer_a},  "
              f"{args.persona_b} = {peer_b}")

        conv_id = uuid.uuid4().hex[:12]
        print()
        print("=" * 70)
        print(f"DEBATE  (conv_id={conv_id}, max_turns={args.turns})")
        print(f"Motion: {args.motion}")
        print("=" * 70)
        print()

        # Seed the first persona with the motion
        seed = ConvEnvelope(
            conv_id=conv_id,
            turn=0,
            max_turns=args.turns,
            kind=KIND_PROMPT,
            body=args.motion,
            from_role="moderator",
            to_role=args.persona_a,
        )
        agent.send_sync(peer_a, seed.encode(), msg_type="CONV")

        current_target = peer_a
        next_target = peer_b
        current_persona = args.persona_a
        next_persona = args.persona_b
        cursor = 0
        transcript: list[tuple[str, str]] = []

        while True:
            deadline = time.monotonic() + args.turn_timeout
            env: ConvEnvelope | None = None
            speaker_name: str | None = None
            while time.monotonic() < deadline:
                if cursor < len(inbox):
                    peer_id, incoming = inbox[cursor]
                    cursor += 1
                    if incoming.conv_id != conv_id:
                        continue
                    for p in agent.peers:
                        if p.get("node_id") == peer_id:
                            speaker_name = p.get("name")
                            break
                    env = incoming
                    break
                time.sleep(0.1)

            if env is None:
                print(f"\n[moderator] no reply from {current_target} "
                      f"within {args.turn_timeout}s. Stopping.")
                break

            if env.kind == KIND_END:
                print(f"\n[{speaker_name}] ended debate: "
                      f"{env.end_reason or env.body}")
                break
            if env.kind == KIND_ERROR:
                print(f"\n[{speaker_name}] error: {env.body}")
                break

            transcript.append((current_persona, env.body))
            print(f"--- Turn {env.turn}  [{current_persona.upper()}] "
                  f"({speaker_name}) ---")
            print(env.body.strip())
            print()

            if env.turn >= args.turns:
                print(f"[moderator] turn limit reached ({args.turns}).")
                break

            # Relay to the other side
            current_target, next_target = next_target, current_target
            current_persona, next_persona = next_persona, current_persona
            relay = ConvEnvelope(
                conv_id=conv_id,
                turn=env.turn,
                max_turns=args.turns,
                kind=KIND_PROMPT,
                body=env.body,
                from_role=next_persona,
                to_role=current_persona,
            )
            agent.send_sync(current_target, relay.encode(), msg_type="CONV")

        print()
        print("=" * 70)
        print(f"Transcript: {len(transcript)} turn(s).  "
              f"conv_id={conv_id}")
        return 0
    finally:
        agent.stop()


if __name__ == "__main__":
    sys.exit(main())
