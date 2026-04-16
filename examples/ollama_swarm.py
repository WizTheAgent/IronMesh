#!/usr/bin/env python3
"""Two Ollama agents talking to each other over IronMesh.

Run one node as the "thinker" (answers questions using a local model)
and one as the "asker" (prompts the thinker and prints the response).
Works on one machine (two ports) or two machines on the same LAN.

Prerequisites
-------------
    ollama serve &
    ollama pull llama3.2:3b          # any Ollama model you like
    pip install ironmesh

Running on one machine (two terminals)
--------------------------------------
    export IRONMESH_PASSPHRASE='shared-passphrase-12-plus'

    # Terminal 1 - the thinker
    python examples/ollama_swarm.py --role thinker --name thinker --port 8765

    # Terminal 2 - the asker
    python examples/ollama_swarm.py --role asker  --name asker  --port 8766 \\
        --target thinker --prompt "Explain mesh networking in one sentence."

The asker will print the thinker's reply once the model finishes
generating. Point the asker at a different machine by running with
``--target`` set to the thinker's ``--name`` on the LAN.

Notes
-----
- The asker and thinker authenticate, exchange ephemeral ECDH keys, and
  speak over an XSalsa20-Poly1305 encrypted channel. Ollama itself is
  plain HTTP on localhost; the *between-machines* hop is what IronMesh
  secures.
- The thinker advertises a capability string ``llm:<model>``. On a
  bigger mesh you can discover thinkers with
  ``agent.discover("llm:*")`` instead of hard-coding a ``--target``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

from ironmesh import Agent

OLLAMA_DEFAULT_URL = "http://127.0.0.1:11434"


def _query_ollama(base_url: str, model: str, prompt: str, timeout: int = 120) -> str:
    """Hit /api/generate on a local Ollama and return the completion."""
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/generate",
        data=json.dumps({"model": model, "prompt": prompt, "stream": False}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        return f"[ollama error: {e}]"
    return body.get("response", "").strip() or "[empty response]"


def run_thinker(args, passphrase: str) -> None:
    agent = Agent(
        args.name,
        port=args.port,
        passphrase=passphrase,
        open_discovery=True,
        allow_plaintext=True,
    )
    agent.advertise(f"llm:{args.model}")

    @agent.on_message()
    def on_prompt(peer_id: str, payload: bytes) -> None:
        prompt = payload.decode("utf-8", errors="replace")
        short = peer_id[:12]
        print(f"[{short}] prompt: {prompt!r}")
        answer = _query_ollama(args.ollama_url, args.model, prompt)
        print(f"[{short}] answer: {answer[:80]}{'...' if len(answer) > 80 else ''}")
        agent.reply(peer_id, answer.encode("utf-8"))

    print(f"Thinker '{args.name}' ready on port {args.port} with model '{args.model}'.")
    print("Waiting for prompts. Ctrl-C to stop.")
    agent.run()


def run_asker(args, passphrase: str) -> None:
    agent = Agent(
        args.name,
        port=args.port,
        passphrase=passphrase,
        open_discovery=True,
        allow_plaintext=True,
    )

    replies: list[str] = []

    @agent.on_message()
    def on_reply(peer_id: str, payload: bytes) -> None:
        replies.append(payload.decode("utf-8", errors="replace"))

    loop = agent.run(foreground=False)
    assert loop is not None

    # Wait until the target peer is online.
    deadline = time.monotonic() + args.discover_timeout
    target = None
    while time.monotonic() < deadline:
        peer = agent.peer_by_name(args.target)
        if peer:
            target = peer
            break
        time.sleep(0.5)

    if target is None:
        print(
            f"Could not find peer '{args.target}' within {args.discover_timeout}s. "
            "Check that the thinker is running and both nodes share a passphrase."
        )
        agent.stop()
        sys.exit(1)

    print(f"Found '{args.target}' at {target['node_id'][:12]}; sending prompt...")
    agent.send_sync(args.target, args.prompt)

    deadline = time.monotonic() + args.reply_timeout
    while time.monotonic() < deadline and not replies:
        time.sleep(0.2)

    if replies:
        print("\n--- reply from thinker ---")
        print(replies[0])
    else:
        print(f"No reply within {args.reply_timeout}s.")

    agent.stop()


def main() -> None:
    p = argparse.ArgumentParser(description="Ollama swarm over IronMesh")
    p.add_argument("--role", choices=("thinker", "asker"), required=True)
    p.add_argument("--name", required=True, help="Agent name on the mesh")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--model", default="llama3.2:3b", help="Ollama model (thinker only)")
    p.add_argument("--ollama-url", default=OLLAMA_DEFAULT_URL)
    p.add_argument("--target", help="Name of the thinker to query (asker only)")
    p.add_argument("--prompt", help="Prompt to send (asker only)")
    p.add_argument("--discover-timeout", type=float, default=30.0)
    p.add_argument("--reply-timeout", type=float, default=180.0)
    args = p.parse_args()

    passphrase = os.environ.get("IRONMESH_PASSPHRASE")
    if not passphrase:
        sys.exit("Set IRONMESH_PASSPHRASE env var (12+ chars) before running.")

    if args.role == "thinker":
        run_thinker(args, passphrase)
    else:
        if not args.target or not args.prompt:
            sys.exit("--target and --prompt are required for --role asker.")
        run_asker(args, passphrase)


if __name__ == "__main__":
    main()
