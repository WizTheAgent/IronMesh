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
        --peer-a gatekeeper --peer-b kingpi \\
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
import re
import sys
import time
import uuid

from ironmesh import Agent

RESPONSE_PREFIX = b"[LLM] "
END_PREFIX = b"[END] "
ERROR_PREFIX = b"[LLM-ERR] "

_CONV_HEADER_RE = re.compile(
    r"^\[CONV:(?P<id>[A-Za-z0-9._-]+):(?P<turn>\d+)/(?P<max>\d+)\]\n",
)


def strip_header(text: str) -> tuple[str, int, int]:
    """Return (body, turn, max) from a conv-headered string (defaults if absent)."""
    m = _CONV_HEADER_RE.match(text)
    if not m:
        return text, 0, 0
    return text[m.end():], int(m.group("turn")), int(m.group("max"))


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
    p.add_argument("--discovery-timeout", type=float, default=20.0,
                    help="Seconds to wait for both peers to come online (default: 20)")
    args = p.parse_args()

    passphrase = os.environ.get("IRONMESH_PASSPHRASE")
    if not passphrase:
        sys.exit("Set IRONMESH_PASSPHRASE env var (12+ chars) before running.")

    agent = Agent(
        args.name, port=args.port, passphrase=passphrase,
        open_discovery=True, allow_plaintext=True,
    )

    # Collect the latest reply from each peer. Each entry is
    # (timestamp, peer_id, payload).
    inbox: list[tuple[float, str, bytes]] = []

    @agent.on_message()
    def _on_msg(peer_id: str, payload: bytes) -> None:
        inbox.append((time.monotonic(), peer_id, payload))

    agent.run(foreground=False)

    # Wait for the two LLM peers to come online.
    deadline = time.monotonic() + args.discovery_timeout
    peer_a = args.peer_a
    peer_b = args.peer_b
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

    def send_with_header(to_name: str, body: str, turn: int) -> None:
        header = f"[CONV:{conv_id}:{turn}/{args.turns}]\n"
        agent.send_sync(to_name, header + body)

    # Turn 0 (initial prompt) → peer_a. Peer_a's reply will come back
    # as turn 1; we then relay it to peer_b as turn 1; their reply is
    # turn 2; etc. until turn >= args.turns or [END] shows up.
    transcript.append(("ORCHESTRATOR", args.seed))
    current_target = peer_a
    next_target = peer_b
    send_with_header(current_target, args.seed, turn=0)

    # Wait for replies and shuttle them. We stop when either:
    #   - a peer sends [END]
    #   - the relayed-reply turn reaches args.turns
    #   - turn_timeout elapses with no reply
    inbox_cursor = 0
    while True:
        wait_deadline = time.monotonic() + args.turn_timeout
        reply: bytes | None = None
        speaker: str | None = None
        while time.monotonic() < wait_deadline:
            if inbox_cursor < len(inbox):
                _, peer_id, payload = inbox[inbox_cursor]
                inbox_cursor += 1
                # Find the speaker's name
                for p in agent.peers:
                    if p["node_id"] == peer_id:
                        speaker = p.get("name")
                        break
                reply = payload
                break
            time.sleep(0.1)

        if reply is None:
            print(f"\nNo reply from {current_target} within {args.turn_timeout}s. Stopping.")
            break

        if reply.startswith(END_PREFIX):
            reason = reply[len(END_PREFIX):].decode("utf-8", errors="replace")
            print(f"\n{speaker} sent [END]: {reason}")
            break
        if reply.startswith(ERROR_PREFIX):
            print(f"\n{speaker} error: {reply[len(ERROR_PREFIX):].decode(errors='replace')}")
            break
        if not reply.startswith(RESPONSE_PREFIX):
            # Unexpected -- just log and stop
            print(f"\nUnexpected payload from {speaker}: {reply[:60]!r}")
            break

        body_bytes = reply[len(RESPONSE_PREFIX):]
        body_text = body_bytes.decode("utf-8", errors="replace")
        body_clean, body_turn, body_max = strip_header(body_text)

        transcript.append((speaker or "?", body_clean))
        print(f"--- Turn {body_turn} ({speaker}) ---")
        print(body_clean.strip())
        print()

        if body_turn >= args.turns:
            print(f"Reached turn limit ({args.turns}). Done.")
            break

        # Relay to the other peer, passing the orchestrator's view
        # of the turn so the next bridge sees the same conv state.
        current_target, next_target = next_target, current_target
        send_with_header(current_target, body_clean, turn=body_turn)

    print()
    print(f"Transcript length: {len(transcript)} turn(s).  conv_id={conv_id}")
    agent.stop()


if __name__ == "__main__":
    main()
