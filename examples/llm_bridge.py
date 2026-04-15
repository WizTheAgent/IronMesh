#!/usr/bin/env python3
"""IronMesh LLM bridge — turns a node into an encrypted LLM agent.

Receives MSG payloads from any peer, treats them as prompts, forwards
them to a local Ollama instance, and sends the response back to the
original sender as a MSG.

This is the "killer app" demo for IronMesh: encrypted LLM agents that
work fully offline over LoRa, with no internet dependency.

Usage:
    python examples/llm_bridge.py \\
        --name wiz-llm --port 8766 \\
        --passphrase-file ~/.ironmesh/passphrase \\
        --ollama-url http://localhost:11434 \\
        --model llama3.2:3b \\
        --system-prompt "You are a helpful assistant on an encrypted LoRa mesh."

Prerequisites:
    - Ollama running locally (``ollama serve``)
    - Model pulled (``ollama pull llama3.2:3b``)
    - IronMesh installed (``pip install -e .`` from repo root)

Security notes:
    - The Ollama HTTP endpoint is trusted (usually localhost).
    - Responses are signed and encrypted by IronMesh like any other MSG.
    - The LLM sees plaintext prompts — if that's unacceptable, use a
      remote LLM with its own auth.
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
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ironmesh.bridge import BridgeDaemon

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("llm_bridge")

# Tag for our own responses so we don't loop on self-reply
RESPONSE_PREFIX = b"[LLM] "
ERROR_PREFIX = b"[LLM-ERR] "


def _ollama_generate_sync(url: str, model: str, prompt: str,
                          system: str, timeout: float) -> str:
    """Blocking call to Ollama. Intended for asyncio.to_thread()."""
    body = json.dumps({
        "model": model,
        "prompt": prompt,
        "system": system,
        "stream": False,
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
    """Async wrapper around Ollama /api/generate."""
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
    parser = argparse.ArgumentParser(description="IronMesh Ollama LLM bridge")
    parser.add_argument("--name", required=True, help="Bridge agent name")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--passphrase-file", default=None,
                        help="Path to a file containing the IronMesh passphrase")
    parser.add_argument("--passphrase-env", default="IRONMESH_PASSPHRASE",
                        help="Env var name holding the passphrase")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--model", default="llama3.2:3b")
    parser.add_argument("--system-prompt",
                        default="You are a helpful assistant on an encrypted LoRa mesh. "
                                "Be concise — responses travel over low-bandwidth radio.")
    parser.add_argument("--max-prompt-bytes", type=int, default=4096,
                        help="Reject prompts larger than this (default 4096)")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="LLM request timeout seconds")
    parser.add_argument("--open-discovery", action="store_true")
    parser.add_argument("--allow-plaintext-ws", action="store_true")
    parser.add_argument("--reticulum", action="store_true")
    parser.add_argument("--gui", action="store_true",
                        help="Enable the GUI dashboard on port+1")
    args = parser.parse_args()

    # Load passphrase
    passphrase = None
    if args.passphrase_file:
        with open(os.path.expanduser(args.passphrase_file)) as f:
            passphrase = f.read().strip()
    else:
        passphrase = os.environ.get(args.passphrase_env)
    if not passphrase:
        log.error("No passphrase: set --passphrase-file or %s env var",
                  args.passphrase_env)
        sys.exit(1)

    log.info("Connecting to Ollama at %s (model=%s)", args.ollama_url, args.model)

    daemon = BridgeDaemon(
        name=args.name,
        port=args.port,
        bind_address=args.bind,
        passphrase=passphrase,
        open_discovery=args.open_discovery,
        allow_plaintext_ws=args.allow_plaintext_ws,
        rns_enabled=args.reticulum,
        gui=args.gui,
    )

    # We need the daemon's loop to schedule async work from the bus callback
    loop_ref = {"loop": None}

    stats = {"received": 0, "replied": 0, "errors": 0}

    async def handle_prompt(peer_id: str, prompt: str):
        stats["received"] += 1
        log.info("[%s] prompt (%d chars): %s", peer_id[:8], len(prompt),
                 prompt[:80] + ("..." if len(prompt) > 80 else ""))
        t0 = time.monotonic()
        response = await query_ollama(
            args.ollama_url, args.model, prompt,
            args.system_prompt, args.timeout,
        )
        elapsed = time.monotonic() - t0
        log.info("[%s] responded in %.1fs (%d chars)",
                 peer_id[:8], elapsed, len(response))
        if response.startswith("[LLM-ERR]"):
            stats["errors"] += 1
            payload = response.encode("utf-8")
        else:
            stats["replied"] += 1
            payload = RESPONSE_PREFIX + response.encode("utf-8")
        try:
            await daemon.send_message(peer_id, "MSG", payload)
        except Exception as e:
            log.warning("Send failed to %s: %s", peer_id[:8], e)

    def on_message(data):
        loop = loop_ref["loop"]
        if loop is None:
            return
        peer_id = data.get("peer_id", "")
        payload = data.get("payload", b"")
        if not isinstance(payload, (bytes, bytearray)):
            return
        # Don't loop on our own responses or errors
        if payload.startswith(RESPONSE_PREFIX) or payload.startswith(ERROR_PREFIX):
            return
        if len(payload) > args.max_prompt_bytes:
            log.warning("Prompt from %s too large (%d bytes) — rejecting",
                        peer_id[:8], len(payload))
            asyncio.run_coroutine_threadsafe(
                daemon.send_message(
                    peer_id, "MSG",
                    ERROR_PREFIX + f"Prompt too large (max {args.max_prompt_bytes} bytes)".encode(),
                ),
                loop,
            )
            return
        try:
            prompt = payload.decode("utf-8")
        except UnicodeDecodeError:
            return
        asyncio.run_coroutine_threadsafe(
            handle_prompt(peer_id, prompt), loop,
        )

    daemon.bus.subscribe("MSG", on_message)

    loop = daemon.run(background=True)
    loop_ref["loop"] = loop

    print(f"\nLLM bridge '{args.name}' online on port {args.port}")
    print(f"Node ID: {daemon.node_id}")
    print(f"Ollama:  {args.ollama_url}  model={args.model}")
    print(f"\nWaiting for MSG prompts. Ctrl-C to stop.\n")

    try:
        while True:
            time.sleep(30)
            log.info("Stats: received=%d replied=%d errors=%d peers=%d",
                     stats["received"], stats["replied"], stats["errors"],
                     sum(1 for s in daemon.peers.values() if s.is_online))
    except KeyboardInterrupt:
        pass
    finally:
        try:
            asyncio.run_coroutine_threadsafe(daemon.shutdown(), loop).result(5)
        except Exception:
            pass
        loop.call_soon_threadsafe(loop.stop)
        print("\nLLM bridge stopped.")


if __name__ == "__main__":
    main()
