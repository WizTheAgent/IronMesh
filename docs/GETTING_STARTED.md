# Getting Started

This is the multi-node walkthrough — picks up where [QUICKSTART.md](QUICKSTART.md) leaves off and gets you to a real two-machine mesh you can talk to from Python.

If you haven't run the 60-second demo yet, do that first:

```bash
pip install ironmesh
ironmesh demo
```

When it prints the `[ok] handshake complete` and `[ok] ... received b'ping'` lines, your install works. The demo spawned two daemons in subprocesses on localhost, ran the handshake, exchanged a hello, and tore them down. No config files, no two machines, no credentials. Now we go further.

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
4. **Trust gate** — should messages from newly-pinned peers queue until you promote the peer with `ironmesh trust set-state <node_id> trusted`? The wizard recommends and defaults to **yes**; answer no to keep the legacy trust-on-first-message behavior, and you can flip it later.

The passphrase MUST be identical on every machine in the mesh. It's the shared secret behind the handshake. 12+ characters; longer is better. Don't reuse a password you use anywhere else.

## 3. Start the daemon on each machine

At the end of the wizard, `ironmesh setup` prints the exact
`ironmesh run` command for that machine — copy-paste it. It looks
like:

```bash
ironmesh run \
    --name alice \
    --port 8765 \
    --passphrase-file ~/.ironmesh/passphrase \
    --keys-path ~/.ironmesh/keys.json \
    --require-message-promotion
```

> **Note — encrypted key file.** The wizard encrypts `keys.json` with
> the mesh passphrase, and `ironmesh run` tries the mesh passphrase
> automatically — the printed command works as-is, no extra flag. If
> your key file uses a *different* passphrase, the daemon prompts for
> it on a terminal, or supply it headlessly with
> `--keys-passphrase-file <path>` or the `IRONMESH_KEYS_PASSPHRASE`
> env var (`--keys-passphrase <pass>` also works but is discouraged —
> argv is visible in the process list). `--name` is always required —
> a bare `ironmesh run` exits with an argument error.

Within 5–10 seconds the two should find each other via mDNS and complete the handshake. Each side prints something like:

```
[INFO] Peer alice (<node_id>) online via websocket — ephemeral ECDH complete
```

If they don't find each other within ~30 seconds, run the diagnostic:

```bash
ironmesh doctor
```

It walks eight checks — identity key file, trust store, message
store, pending-trust queue, gate environment variables, port
conflicts, audit-chain integrity, and on-disk feature state — each
with a remediation hint. `ironmesh doctor --peer HOST:PORT` adds a
dry-run reachability check against the other machine.

## 4. Pin the trust

After the first handshake, each side has the other in `pending` (or `trusted` if you turned the trust gate off in setup). List them:

```bash
ironmesh trust list
```

If the trust gate is on, promote the peer:

```bash
ironmesh trust set-state <node_id> trusted
```

The trust file is `~/.ironmesh/known_peers.json`. Pinning is **TOFU** (trust on first use): the first time you see a peer, you accept its public key. Future reconnects must use the same key or the peer is rejected. Capability changes are also tracked — a peer that suddenly advertises new capabilities goes to `pending-cap-change` for review (`ironmesh trust cap-diff <node_id>`).

## 5. Send a message from Python

The `Agent` SDK runs its own daemon in-process (it does not attach to
an `ironmesh run` daemon), so give it its own port and stop the
machine's daemon first — or just use two fresh terminals. On machine
A:

```python
from ironmesh import Agent

# Passphrase comes from the argument or the IRONMESH_PASSPHRASE env
# var — the SDK does not read ~/.ironmesh/passphrase on its own.
me = Agent("alice", port=8765, passphrase="your-mesh-passphrase")

# Receive — register a handler before starting.
@me.on_message()
def handler(peer_id, payload):
    print(f"got: {payload!r} from {peer_id[:12]}")

me.run(foreground=False)          # returns the event loop, runs in background

# Send from any thread once running. The transport layer picks
# WebSocket / RNS / LXMF automatically.
me.send_sync("bob", b"hello from alice")

# ... when done:
me.stop()
```

On machine B, either run a mirror script or one of the [`examples/`](https://github.com/WizTheAgent/IronMesh/tree/main/examples) scripts. The simplest is `basic_chat.py`.

That's the SDK. Three calls — `Agent(...)`, `me.send_sync(name, payload)` (or `await me.send_to(...)` in async code), `@me.on_message()` — cover the 80% case.

## 6. Where to go next

You now have a working LAN mesh and a Python SDK that sends + receives. The next steps depend on what you're building:

- **Add a third + fourth machine.** Same recipe — `ironmesh setup`, `ironmesh run`. Discovery scales out via mDNS up to ~50 hosts on a flat LAN.
- **Bridge to a local LLM.** Walk through [`examples/llm_bridge.py`](https://github.com/WizTheAgent/IronMesh/blob/main/examples/llm_bridge.py). One agent owns the LLM, the others ask it questions over the mesh.
- **Cross WAN.** When two daemons can't reach each other's ports directly, the proven recipes are an overlay network (Tailscale / Nebula) or a port-forward — see [NAT_TRAVERSAL.md](NAT_TRAVERSAL.md). A bundled relay server (`python -m ironmesh.nat_relay`) also ships, but the daemon-side attach flag is not wired up yet, so it is not an end-to-end recipe today.
- **Cross over LoRa.** Install `'ironmesh[rns]'` and start with [Reticulum guide](RETICULUM.md). Sub-second 64-byte probes at SF8/BW125 — measured, not estimated.
- **Capability-based routing instead of hardcoding peer names.** Read [CAPABILITIES.md](CAPABILITIES.md) and `examples/capability_routing.py`. `Agent.send_to_capability("llm:*", payload)` discovers + dispatches without you knowing which peer is online.
- **Group broadcast.** When you want every peer in the mesh to hear the same message: `me.daemon.broadcast_via_rns_group(payload)` (RNS transport with `--rns-group-broadcast` on every peer). Two-phase delivery handles same-segment + cross-host. See `examples/group_broadcast.py`.
- **Production deploy.** Read [OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md). It covers systemd unit files, the audit-log retention story, what `ironmesh doctor` won't catch, and the locked surfaces in [STABILITY_PROMISE.md](STABILITY_PROMISE.md).
- **Integrate with MCP / OpenClaw / A2A / ACP.** Three separate guides — [OPENCLAW_MCP_SETUP.md](OPENCLAW_MCP_SETUP.md), [OPENCLAW_CHANNEL_SETUP.md](OPENCLAW_CHANNEL_SETUP.md), [A2A_INTEGRATION.md](A2A_INTEGRATION.md), [ACP_INTEGRATION.md](ACP_INTEGRATION.md). Pick the one matching your agent stack.

## When something goes wrong

Three things to try, in order:

1. `ironmesh doctor` — fastest signal on configuration / network / RNS health.
2. `ironmesh trust list` — confirm both sides see each other and the state is what you expect.
3. `ironmesh run --log-level DEBUG` — verbose logs. The relevant lines are tagged `[ironmesh.bridge]`, `[ironmesh.protocol]`, or `[ironmesh.discovery]`.

If the daemon won't start, the most common cause is a stale passphrase mismatch between the two machines. Re-run `ironmesh setup --force` on the offending side; it rewrites the passphrase file.

## Updating

```bash
ironmesh upgrade
```

Reads the latest version from PyPI and reports whether you should run `pip install --upgrade ironmesh`. v0.9.x peers stay interoperable with each other; v0.8.x peers stay interoperable on the existing wire surfaces. The full version-skew matrix is in [STABILITY_PROMISE.md](STABILITY_PROMISE.md).
