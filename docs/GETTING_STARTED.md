# Getting Started

This is the multi-node walkthrough — picks up where [QUICKSTART.md](QUICKSTART.md) leaves off and gets you to a real two-machine mesh you can talk to from Python.

If you haven't run the 60-second demo yet, do that first:

```bash
pip install ironmesh
ironmesh demo
```

When that prints `PASS`, your install works. The demo spawned two daemons in subprocesses on localhost, ran the handshake, exchanged a hello, and tore them down. No config files, no two machines, no credentials. Now we go further.

## What you'll have at the end

- Two machines running `ironmesh run` in the background, finding each other automatically over your LAN.
- Trust pinned (TOFU) so a third machine joining the LAN can't spoof either side.
- A Python script on either side that sends a signed + encrypted message to the other.
- A working understanding of how to add LoRa transport (Reticulum), an LLM bridge, or capability-based routing.

## 1. Install on both machines

```bash
pip install ironmesh
```

That's the base install. Two optional extras matter for most setups:

```bash
pip install 'ironmesh[rns]'        # Reticulum / LoRa transport
pip install 'ironmesh[keychain]'   # store the passphrase in your OS keychain
```

You can add the extras later. For now the base install is enough.

## 2. Run the interactive setup wizard

On each machine:

```bash
ironmesh setup
```

This is the first-run wizard. It asks four questions:

1. **Agent name** — defaults to your hostname. Anything human-readable. Has to be unique on the mesh.
2. **Daemon port** — defaults to `8765`. Change it if something else is using that port.
3. **Passphrase source** — one of:
   - A file at `~/.ironmesh/passphrase` (chmod 600). The wizard creates it.
   - The `IRONMESH_PASSPHRASE` env var (only set in your shell rc, not in `ps`-visible scripts).
   - Your OS keychain (requires `[keychain]` extra).
4. **Trust gate** — should incoming peers default to `pending` and require an explicit `ironmesh trust set-state ALLOWED`? Recommended. Off by default for first-run-friendliness; you can flip it later.

The passphrase MUST be identical on every machine in the mesh. It's the shared secret behind the handshake. 12+ characters; longer is better. Don't reuse a password you use anywhere else.

## 3. Start the daemon on each machine

On machine A:

```bash
ironmesh run
```

On machine B:

```bash
ironmesh run
```

Within 5–10 seconds the two should find each other via mDNS and complete the handshake. Each side prints something like:

```
[INFO] Peer 'alice' connected: <node_id_short> via websocket
```

If they don't find each other within ~30 seconds, run the diagnostic:

```bash
ironmesh doctor
```

It reports passphrase configured? port reachable? mDNS up? RNS configdir healthy? trust file readable? Each check has a remediation hint.

## 4. Pin the trust

After the first handshake, each side has the other in `pending` (or `ALLOWED` if you turned the trust gate off in setup). List them:

```bash
ironmesh trust list
```

If the trust gate is on, promote the peer:

```bash
ironmesh trust set-state <node_id_short> ALLOWED
```

The trust file is `~/.ironmesh/known_peers.json`. Pinning is **TOFU** (trust on first use): the first time you see a peer, you accept its public key. Future reconnects must use the same key or the peer is rejected. Capability changes are also tracked — a peer that suddenly advertises new capabilities goes to `pending-cap-change` for review (`ironmesh trust cap-diff <node_id>`).

## 5. Send a message from Python

Both machines now have a daemon running. Open a Python REPL on machine A:

```python
import asyncio
from ironmesh import Agent

async def main():
    me = Agent(
        name="alice",
        port=8765,                          # daemon's port
        # passphrase taken from IRONMESH_PASSPHRASE or ~/.ironmesh/passphrase
    )
    await me.start()

    # Wait for the resolver to see "bob" via mDNS
    await me.wait_for_peer("bob", timeout=10)

    # Send. The transport layer picks WebSocket / RNS / LXMF
    # automatically; you don't care which one was used.
    await me.send_to("bob", b"hello from alice")

    # Receive — register a handler before the message arrives.
    @me.on_message
    async def handler(msg):
        print(f"got: {msg.payload!r} from {msg.source}")

    await asyncio.sleep(5)        # let the reply land
    await me.stop()

asyncio.run(main())
```

On machine B, either run a mirror script or one of the [`examples/`](../examples/) scripts. The simplest is `basic_chat.py`.

That's the SDK. Three calls — `Agent(...)`, `await me.send_to(name, payload)`, `@me.on_message` — cover the 80% case.

## 6. Where to go next

You now have a working LAN mesh and a Python SDK that sends + receives. The next steps depend on what you're building:

- **Add a third + fourth machine.** Same recipe — `ironmesh setup`, `ironmesh run`. Discovery scales out via mDNS up to ~50 hosts on a flat LAN.
- **Bridge to a local LLM.** Walk through [`examples/llm_bridge.py`](../examples/llm_bridge.py). One agent owns the LLM, the others ask it questions over the mesh.
- **Cross WAN with NAT relay.** When two daemons can't reach each other's ports directly, run the bundled relay on a public host: `python -m ironmesh.nat_relay`. Both daemons configure `--nat-relay wss://your.relay/`. See [NAT_TRAVERSAL.md](NAT_TRAVERSAL.md).
- **Cross over LoRa.** Install `'ironmesh[rns]'` and start with [Reticulum guide](RETICULUM.md). Sub-second 64-byte probes at SF8/BW125 — measured, not estimated.
- **Capability-based routing instead of hardcoding peer names.** Read [CAPABILITIES.md](CAPABILITIES.md) and `examples/capability_routing.py`. `Agent.send_to_capability("llm:*", payload)` discovers + dispatches without you knowing which peer is online.
- **Group broadcast.** When you want every peer in the mesh to hear the same message: `me.broadcast_via_rns_group(payload)`. Two-phase delivery handles same-segment + cross-host. See `examples/group_broadcast.py`.
- **Production deploy.** Read [OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md). It covers systemd unit files, the audit-log retention story, what `ironmesh doctor` won't catch, and the locked surfaces in [STABILITY_PROMISE.md](STABILITY_PROMISE.md).
- **Integrate with MCP / OpenClaw / A2A / ACP.** Three separate guides — [OPENCLAW_MCP_SETUP.md](OPENCLAW_MCP_SETUP.md), [OPENCLAW_CHANNEL_SETUP.md](OPENCLAW_CHANNEL_SETUP.md), [A2A_INTEGRATION.md](A2A_INTEGRATION.md), [ACP_INTEGRATION.md](ACP_INTEGRATION.md). Pick the one matching your agent stack.

## When something goes wrong

Three things to try, in order:

1. `ironmesh doctor` — fastest signal on configuration / network / RNS health.
2. `ironmesh trust list` — confirm both sides see each other and the state is what you expect.
3. `ironmesh run --debug` — verbose logs. The relevant lines start with `[bridge]`, `[handshake]`, or `[transport]`.

If the daemon won't start, the most common cause is a stale passphrase mismatch between the two machines. Re-run `ironmesh setup --force` on the offending side; it rewrites the passphrase file.

## Updating

```bash
ironmesh upgrade
```

Reads the latest version from PyPI and reports whether you should run `pip install --upgrade ironmesh`. v0.9.x peers stay interoperable with each other; v0.8.x peers stay interoperable on the existing wire surfaces. The full version-skew matrix is in [STABILITY_PROMISE.md](STABILITY_PROMISE.md).
