#!/usr/bin/env python3
"""IronMesh LLM bridge — turns a node into an encrypted LLM agent.

Receives MSG payloads from any peer, treats them as prompts, forwards
them to a local Ollama instance, and sends the response back.

Usage:
    python examples/llm_bridge.py \\
        --name wiz-llm --port 8766 \\
        --passphrase-file ~/.ironmesh/passphrase \\
        --ollama-url http://localhost:11434 \\
        --model llama3.2:3b

Prerequisites:
    - Ollama running locally (``ollama serve``)
    - Model pulled (``ollama pull llama3.2:3b``)
    - IronMesh installed (``pip install ironmesh``)

Loop prevention
---------------
Agent-to-agent dialogue needs bounded turn counts, otherwise two LLM
bridges that can both talk will ping-pong forever. Three protections
stack here:

1. Responses are tagged with the ``[LLM] `` prefix. This bridge
   ignores any incoming message that starts with ``[LLM] `` or
   ``[LLM-ERR] ``, so a reply landing in another LLM bridge's inbox
   doesn't re-trigger generation.
2. Optional conversation header on the prompt:
   ``[CONV:<id>:<turn>/<max>]\\n<prompt>``. The bridge parses it,
   increments the turn counter, and if ``turn >= max`` it sends back
   a ``[END] `` frame and stops. The orchestrator (e.g.
   ``examples/ai_to_ai_dialogue.py``) reads the turn from the
   reply's own conv header.
3. Per-conversation cooldown: the bridge will not respond to the same
   conv_id more than once every ``--conv-cooldown`` seconds (default 1s)
   to catch accidental self-replay loops.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ironmesh.agent import Agent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("llm_bridge")

RESPONSE_PREFIX = b"[LLM] "
ERROR_PREFIX = b"[LLM-ERR] "
END_PREFIX = b"[END] "

# Matches e.g. "[CONV:8f3c-...:2/5]\n" at the start of a prompt.
_CONV_HEADER_RE = re.compile(
    r"^\[CONV:(?P<id>[A-Za-z0-9._-]+):(?P<turn>\d+)/(?P<max>\d+)\]\n",
)


def _ollama_generate_sync(url: str, model: str, prompt: str,
                          system: str, timeout: float) -> str:
    body = json.dumps({
        "model": model, "prompt": prompt, "system": system, "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{url.rstrip('/')}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("response", "").strip()


async def query_ollama(url: str, model: str, prompt: str,
                       system: str, timeout: float = 30.0) -> str:
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                _ollama_generate_sync, url, model, prompt, system, timeout,
            ),
            timeout=timeout + 2,
        )
    except asyncio.TimeoutError:
        return "[LLM-ERR] Timeout"
    except urllib.error.URLError as e:
        return f"[LLM-ERR] Ollama unreachable: {e.reason}"
    except Exception as e:
        return f"[LLM-ERR] {type(e).__name__}: {e}"


def main():
    p = argparse.ArgumentParser(description="IronMesh Ollama LLM bridge")
    p.add_argument("--name", required=True)
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--passphrase-file", default=None)
    p.add_argument("--ollama-url", default="http://localhost:11434")
    p.add_argument("--model", default="llama3.2:3b")
    p.add_argument("--system-prompt",
                    default="You are a helpful assistant on an encrypted LoRa mesh. "
                            "Be concise — responses travel over low-bandwidth radio.")
    p.add_argument("--max-prompt-bytes", type=int, default=4096)
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--gui", action="store_true")
    p.add_argument("--reticulum", action="store_true")
    # Identity + trust: reuse the same keys that an existing
    # ``ironmesh run`` daemon uses, so TOFU pinning on other peers
    # doesn't break when you upgrade a normal node into an LLM bridge.
    p.add_argument("--keys-path", default=None,
                    help="Identity keys file to load (default: ~/.ironmesh/keys.json)")
    p.add_argument("--keys-passphrase", default=None,
                    help="Passphrase protecting the keys file, if any")
    p.add_argument("--allowed-peers", default=None,
                    help="Comma-separated list of peer names allowed to auto-connect via mDNS")
    p.add_argument("--conv-cooldown", type=float, default=1.0,
                    help="Seconds to wait before processing the same conv_id twice (default: 1.0)")
    args = p.parse_args()

    passphrase = None
    if args.passphrase_file:
        with open(os.path.expanduser(args.passphrase_file)) as f:
            passphrase = f.read().strip()

    extra = {}
    if args.keys_path:
        extra["keys_path"] = os.path.expanduser(args.keys_path)
    if args.keys_passphrase:
        extra["keys_passphrase"] = args.keys_passphrase
    if args.allowed_peers:
        extra["allowed_peers"] = [p.strip() for p in args.allowed_peers.split(",") if p.strip()]
        # When an allowlist is set the daemon's default-deny kicks in;
        # open_discovery=False pairs with that.
        extra["open_discovery"] = False

    agent = Agent(
        args.name, port=args.port, passphrase=passphrase,
        gui=args.gui, reticulum=args.reticulum,
        capabilities=[f"llm:{args.model}"],
        **extra,
    )

    stats = {"received": 0, "replied": 0, "errors": 0, "ended": 0, "cooldown_drops": 0}
    # conv_id -> last timestamp we processed it. Small bounded dict
    # (capped by _trim_conv_seen) so we don't leak memory on long runs.
    conv_seen: dict[str, float] = {}

    def _trim_conv_seen(max_entries: int = 1024) -> None:
        if len(conv_seen) > max_entries:
            # Drop the oldest half. Good enough; not a hot path.
            cutoff = sorted(conv_seen.values())[len(conv_seen) // 2]
            for k in [k for k, v in conv_seen.items() if v < cutoff]:
                conv_seen.pop(k, None)

    @agent.on_message()
    def on_prompt(peer_id, payload):
        # 1. Ignore our own protocol responses so two LLM bridges don't
        #    turn each other's replies into prompts.
        if (payload.startswith(RESPONSE_PREFIX)
                or payload.startswith(ERROR_PREFIX)
                or payload.startswith(END_PREFIX)):
            return
        if len(payload) > args.max_prompt_bytes:
            agent.reply(peer_id, ERROR_PREFIX + f"Prompt too large (max {args.max_prompt_bytes} bytes)".encode())
            return
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            return

        # 2. Parse the optional conversation header. Absent header
        #    = single-turn Q&A, no loop risk.
        conv_id: str | None = None
        turn: int = 0
        max_turns: int = 0
        m = _CONV_HEADER_RE.match(text)
        if m:
            conv_id = m.group("id")
            turn = int(m.group("turn"))
            max_turns = int(m.group("max"))
            prompt = text[m.end():]
        else:
            prompt = text

        # 3. Turn-limit check: if this is a CONV message and we've
        #    hit the cap, send [END] and don't call the model.
        if conv_id and turn >= max_turns:
            stats["ended"] += 1
            log.info("[%s] conv %s reached turn %d/%d — ending",
                     peer_id[:8], conv_id, turn, max_turns)
            agent.reply(peer_id, END_PREFIX + b"turn limit reached")
            return

        # 4. Cooldown: drop repeats of the same conv_id within the window.
        if conv_id:
            now = time.monotonic()
            prev = conv_seen.get(conv_id, 0.0)
            if now - prev < args.conv_cooldown:
                stats["cooldown_drops"] += 1
                log.info("[%s] conv %s dropped (cooldown, %.2fs < %.2fs)",
                         peer_id[:8], conv_id, now - prev, args.conv_cooldown)
                return
            conv_seen[conv_id] = now
            _trim_conv_seen()

        stats["received"] += 1
        log.info("[%s] prompt%s (%d chars): %s",
                 peer_id[:8],
                 f" [conv {conv_id} turn {turn}/{max_turns}]" if conv_id else "",
                 len(prompt),
                 prompt[:80] + ("..." if len(prompt) > 80 else ""))

        async def _respond():
            t0 = time.monotonic()
            response = await query_ollama(
                args.ollama_url, args.model, prompt,
                args.system_prompt, args.timeout,
            )
            elapsed = time.monotonic() - t0
            log.info("[%s] responded in %.1fs (%d chars)", peer_id[:8], elapsed, len(response))
            if response.startswith("[LLM-ERR]"):
                stats["errors"] += 1
                await agent.send(peer_id, response.encode())
                return
            stats["replied"] += 1
            # Pass the conversation header through with turn+1 so the
            # orchestrator (or the other LLM bridge) sees its own
            # position in the exchange.
            if conv_id:
                header = f"[CONV:{conv_id}:{turn + 1}/{max_turns}]\n"
                out = RESPONSE_PREFIX + (header + response).encode()
            else:
                out = RESPONSE_PREFIX + response.encode()
            await agent.send(peer_id, out)

        asyncio.run_coroutine_threadsafe(_respond(), agent._loop)

    loop = agent.run(foreground=False)

    print(f"\nLLM bridge '{args.name}' online (port {args.port})")
    print(f"Node ID: {agent.node_id}")
    print(f"Ollama:  {args.ollama_url}  model={args.model}")
    print(f"Capability: llm:{args.model}")
    print("\nWaiting for MSG prompts. Ctrl-C to stop.\n")

    try:
        while True:
            time.sleep(30)
            log.info("Stats: received=%d replied=%d ended=%d cooldown=%d errors=%d peers=%d",
                     stats["received"], stats["replied"], stats["ended"],
                     stats["cooldown_drops"], stats["errors"],
                     len(agent.peers))
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop()
        print("\nLLM bridge stopped.")


if __name__ == "__main__":
    main()
