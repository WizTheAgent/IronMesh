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
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
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

    stats = {"received": 0, "replied": 0, "errors": 0}

    @agent.on_message()
    def on_prompt(peer_id, payload):
        if payload.startswith(RESPONSE_PREFIX) or payload.startswith(ERROR_PREFIX):
            return
        if len(payload) > args.max_prompt_bytes:
            agent.reply(peer_id, ERROR_PREFIX + f"Prompt too large (max {args.max_prompt_bytes} bytes)".encode())
            return
        try:
            prompt = payload.decode("utf-8")
        except UnicodeDecodeError:
            return

        stats["received"] += 1
        log.info("[%s] prompt (%d chars): %s", peer_id[:8], len(prompt),
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
            else:
                stats["replied"] += 1
                await agent.send(peer_id, RESPONSE_PREFIX + response.encode())

        asyncio.run_coroutine_threadsafe(_respond(), agent._loop)

    loop = agent.run(foreground=False)

    print(f"\nLLM bridge '{args.name}' online (port {args.port})")
    print(f"Node ID: {agent.node_id}")
    print(f"Ollama:  {args.ollama_url}  model={args.model}")
    print(f"Capability: llm:{args.model}")
    print(f"\nWaiting for MSG prompts. Ctrl-C to stop.\n")

    try:
        while True:
            time.sleep(30)
            log.info("Stats: received=%d replied=%d errors=%d peers=%d",
                     stats["received"], stats["replied"], stats["errors"],
                     len(agent.peers))
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop()
        print("\nLLM bridge stopped.")


if __name__ == "__main__":
    main()
