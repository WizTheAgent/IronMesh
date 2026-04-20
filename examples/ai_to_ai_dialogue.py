#!/usr/bin/env python3
"""Two AI agents having a bounded conversation, orchestrated over IronMesh.

Connects to the mesh, picks two peers that advertise ``llm:*`` capability
(or uses ``--peer-a`` / ``--peer-b`` if specified), kicks off a
conversation with a seed prompt, and relays each agent's reply to the
other until a configured turn cap is reached. Every relayed message
carries a ``[CONV:<id>:<turn>/<max>]`` header so the receiving LLM
bridge can enforce the cap and any AI reply is also tagged with the
``[LLM] `` prefix, preventing accidental re-triggering.

This is the reference pattern for "AI agents talk to each other
without the user babysitting, and without looping forever."

Usage
-----
    export IRONMESH_PASSPHRASE='your-shared-passphrase-12-plus'
    python examples/ai_to_ai_dialogue.py \\
        --peer-a alice --peer-b bob \\
        --seed "Debate whether a raspberry pi makes a good home server."  \\
        --turns 4

    # Or let it auto-pick from advertised capabilities:
    python examples/ai_to_ai_dialogue.py --seed "Pick a name for a pet cat."

The script exits after the turn cap is hit or a ``[END] `` frame is
received from one of the peers.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import uuid

from ironmesh import Agent, ConvEnvelope, Budget
from ironmesh.conversation import (
    KIND_END,
    KIND_ERROR,
    KIND_PROMPT,
)


def pick_llm_peers(agent: Agent) -> tuple[str, str] | None:
    """Find two peers that advertise any ``llm:*`` capability."""
    hits = agent.discover("llm:*")
    names: list[str] = []
    seen = set()
    for node_id, _cap in hits:
        if node_id in seen:
            continue
        seen.add(node_id)
        peer = next(
            (p for p in agent.peers if p["node_id"] == node_id),
            None,
        )
        if peer and peer.get("name"):
            names.append(peer["name"])
    if len(names) < 2:
        return None
    return names[0], names[1]


def main() -> None:
    p = argparse.ArgumentParser(description="Bounded AI-to-AI dialogue over IronMesh")
    p.add_argument("--name", default="dialogue-orchestrator",
                    help="Orchestrator agent name (default: dialogue-orchestrator)")
    p.add_argument("--port", type=int, default=19876,
                    help="Port for the orchestrator (default: 19876)")
    p.add_argument("--peer-a", default=None,
                    help="First LLM peer by name (auto-discover llm:* if omitted)")
    p.add_argument("--peer-b", default=None,
                    help="Second LLM peer by name (auto-discover llm:* if omitted)")
    p.add_argument("--seed", required=True,
                    help="Opening prompt sent to peer-a")
    p.add_argument("--turns", type=int, default=4,
                    help="Max conversation turns (default: 4). Each turn = one agent reply.")
    p.add_argument("--turn-timeout", type=float, default=120.0,
                    help="Seconds to wait for each reply before bailing (default: 120)")
    p.add_argument("--discovery-timeout", type=float, default=60.0,
                    help="Seconds to wait for both peers to come online (default: 60)")
    p.add_argument("--budget-seconds", type=float, default=None,
                    help="Per-conversation wall-clock budget (default: no limit)")
    p.add_argument("--budget-bytes", type=int, default=None,
                    help="Per-conversation total response-byte budget (default: no limit)")
    args = p.parse_args()

    passphrase = os.environ.get("IRONMESH_PASSPHRASE")
    if not passphrase:
        sys.exit("Set IRONMESH_PASSPHRASE env var (12+ chars) before running.")

    agent = Agent(
        args.name, port=args.port, passphrase=passphrase,
        open_discovery=True, allow_plaintext=True,
    )

    # Collect the latest inbound CONV envelope per peer.
    inbox: list[tuple[float, str, ConvEnvelope]] = []

    @agent.on("CONV")
    def _on_conv(data):
        peer_id = data.get("peer_id", "")
        payload = data.get("payload", b"") or b""
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        try:
            env = ConvEnvelope.decode(payload)
        except ValueError as e:
            print(f"[orchestrator] malformed CONV frame from {peer_id[:12]}: {e}",
                  file=sys.stderr, flush=True)
            return
        inbox.append((time.monotonic(), peer_id, env))

    agent.run(foreground=False)

    # Wait for the two LLM peers to come online. Print status every 5s so
    # the wait is observable.
    deadline = time.monotonic() + args.discovery_timeout
    peer_a = args.peer_a
    peer_b = args.peer_b
    last_status = 0.0
    while time.monotonic() < deadline:
        if peer_a and peer_b:
            a_online = agent.peer_by_name(peer_a)
            b_online = agent.peer_by_name(peer_b)
            if a_online and b_online:
                break
        else:
            picked = pick_llm_peers(agent)
            if picked:
                peer_a, peer_b = picked
                break
        now = time.monotonic()
        if now - last_status >= 5:
            last_status = now
            names = [p.get("name", "?") for p in agent.peers]
            remaining = deadline - now
            print(f"[discovery] {len(agent.peers)} peer(s) online: {names} "
                  f"(looking for {peer_a},{peer_b}; {remaining:.0f}s left)",
                  flush=True)
        time.sleep(0.5)
    else:
        print("timed out waiting for two LLM-capable peers on the mesh.",
              file=sys.stderr)
        agent.stop()
        sys.exit(1)

    print(f"Orchestrating: {peer_a} <-> {peer_b}  (max turns: {args.turns})")
    print(f"Seed: {args.seed}")
    print()

    conv_id = uuid.uuid4().hex[:12]
    transcript: list[tuple[str, str]] = []  # (speaker_name, text)
    budget = None
    if args.budget_seconds is not None or args.budget_bytes is not None:
        budget = Budget(
            max_seconds=args.budget_seconds,
            max_bytes=args.budget_bytes,
        )

    def send_prompt(to_name: str, body: str, turn: int,
                    to_role: str, from_role: str = "orchestrator") -> None:
        env = ConvEnvelope(
            conv_id=conv_id,
            turn=turn,
            max_turns=args.turns,
            kind=KIND_PROMPT,
            body=body,
            from_role=from_role,
            to_role=to_role,
            budget=budget,
        )
        agent.send_sync(to_name, env.encode(), msg_type="CONV")

    # Turn 0 (initial prompt) → peer_a. Peer_a's reply comes back as
    # turn 1; we relay it to peer_b still carrying turn 1; their reply
    # is turn 2; etc. until turn >= args.turns or [END] shows up.
    transcript.append(("ORCHESTRATOR", args.seed))
    current_target = peer_a
    next_target = peer_b
    send_prompt(current_target, args.seed, turn=0, to_role=current_target)

    inbox_cursor = 0
    while True:
        wait_deadline = time.monotonic() + args.turn_timeout
        env: ConvEnvelope | None = None
        speaker: str | None = None
        while time.monotonic() < wait_deadline:
            if inbox_cursor < len(inbox):
                _, peer_id, incoming = inbox[inbox_cursor]
                inbox_cursor += 1
                if incoming.conv_id != conv_id:
                    # Someone else's conversation; ignore.
                    continue
                for p in agent.peers:
                    if p["node_id"] == peer_id:
                        speaker = p.get("name")
                        break
                env = incoming
                break
            time.sleep(0.1)

        if env is None:
            print(f"\nNo reply from {current_target} within {args.turn_timeout}s. Stopping.")
            break

        if env.kind == KIND_END:
            print(f"\n{speaker} sent END: {env.end_reason or env.body}")
            break
        if env.kind == KIND_ERROR:
            print(f"\n{speaker} error: {env.body}")
            break

        transcript.append((speaker or "?", env.body))
        print(f"--- Turn {env.turn} ({speaker}) ---")
        print(env.body.strip())
        print()

        if env.turn >= args.turns:
            print(f"Reached turn limit ({args.turns}). Done.")
            break

        # Relay to the OTHER peer. We keep the same turn counter -- the
        # receiving bridge will bump it by one when it replies.
        current_target, next_target = next_target, current_target
        send_prompt(current_target, env.body, turn=env.turn,
                    to_role=current_target, from_role=speaker or "peer")

    print()
    print(f"Transcript: {len(transcript)} turn(s).  conv_id={conv_id}")
    agent.stop()


if __name__ == "__main__":
    main()
