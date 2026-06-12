# IronMesh Python SDK

`ironmesh.agent.Agent` is the high-level SDK entry point — a wrapper over
the daemon that hides asyncio event-loop threading, bus subscription, and
shutdown sequencing. It's for developers who want to send and receive
encrypted mesh messages without becoming WebSocket/asyncio experts.

For a step-by-step multi-node tutorial see
[`GETTING_STARTED.md`](GETTING_STARTED.md); this page is the API reference.

## Install

```bash
pip install ironmesh            # core
pip install ironmesh[rns]       # + Reticulum / LoRa transport
```

## Quick start

```python
from ironmesh.agent import Agent

agent = Agent("my-bot", passphrase="secret-passphrase-12")

@agent.on_message()
def handle(peer_id: str, payload: bytes):
    print(f"From {peer_id}: {payload.decode()}")
    agent.reply(peer_id, b"ack")

agent.run()
```

The passphrase must be identical on every node in the mesh and at least
12 characters. It can also be supplied via the `IRONMESH_PASSPHRASE`
environment variable instead of the constructor argument.

## Constructor

```python
Agent(
    name: str,
    port: int = 8765,
    passphrase: str | None = None,
    *,
    bind: str = "0.0.0.0",
    capabilities: list[str] | None = None,
    open_discovery: bool = True,
    allow_plaintext: bool = True,
    gui: bool = False,
    mesh_routing: str = "relay",
    reticulum: bool = False,
    passphrase_env: str = "IRONMESH_PASSPHRASE",
    **daemon_kwargs,
)
```

| Argument | Default | Purpose |
|---|---|---|
| `name` | — | Agent name, advertised on the mesh. |
| `port` | `8765` | WebSocket listen port. |
| `passphrase` | `None` | Shared mesh secret (≥ 12 chars). Falls back to the `passphrase_env` variable. |
| `bind` | `0.0.0.0` | Listen address. |
| `capabilities` | `None` | Capabilities to advertise at startup (e.g. `["llm:llama3"]`). |
| `open_discovery` | `True` | Allow mDNS auto-connect. |
| `allow_plaintext` | `True` | Permit `ws://` fallback when `wss://` is unavailable. |
| `gui` | `False` | Serve the operator dashboard. |
| `mesh_routing` | `"relay"` | Multi-hop routing mode. |
| `reticulum` | `False` | Enable the Reticulum / LoRa transport (requires `ironmesh[rns]`). |

Advanced daemon options are forwarded via `**daemon_kwargs`. For direct
control, use `agent.daemon` (the underlying `BridgeDaemon`).

## Receiving messages

`@agent.on_message(msg_type="MSG")` registers a handler that receives
`(peer_id: str, payload: bytes)`. Multiple handlers for the same type
fire in registration order.

```python
@agent.on_message()
def handle(peer_id, payload):
    print(peer_id, payload.decode())
```

`@agent.on(event_type)` registers a handler for any bus event type; the
handler receives the raw event `data` dict.

## Sending messages

`message` is a `str` (UTF-8 encoded automatically) or `bytes`.

| Method | Returns | Notes |
|---|---|---|
| `await agent.send(target, message, *, msg_type="MSG", priority="NORMAL")` | `str` (msg_id) | `target` is an agent name or 32-hex node_id; requires a known online peer. |
| `agent.send_sync(target, message, *, …, timeout=10.0)` | `str` | Blocking; requires `run()` first. |
| `await agent.send_to(name, message, *, …)` | `dict` | Picks the best transport: online peer → RNS-discovered → LXMF. The recommended outbound primitive. |
| `agent.send_to_sync(name, message, *, …, timeout=30.0)` | `dict` | Blocking variant. |
| `await agent.send_to_capability(pattern, message, *, strategy="first")` | `dict` | Routes to a peer matching a capability glob. |
| `agent.send_to_capability_sync(…, timeout=30.0)` | `dict` | Blocking variant. |
| `agent.reply(peer_id, message, *, …)` | `None` | Fire-and-forget reply from inside a handler. |

### Capability routing strategies

For `send_to_capability(pattern, …, strategy=…)`:

- `"first"` (default) — best-ranked match (lowest measured RTT first); tries the next match on failure.
- `"random"` — random match, for load distribution across capability-equivalent peers.
- `"all"` — fan out to every match in parallel (returns a `"transport": "fanout"` descriptor with per-target results).

The local node is never selected even when it satisfies the capability.

## Peers and discovery

| Member | Type | Purpose |
|---|---|---|
| `agent.peers` | `list[dict]` | Online peers with live metrics (`node_id`, `name`, `rtt_ms`, message counts, `transport`). |
| `agent.unified_peers` | `list[dict]` | Every peer reachable via any transport, including announce-only nodes not yet handshaken. |
| `agent.node_id` | `str \| None` | This agent's node_id (available after `run()`). |
| `agent.peer_by_name(name)` | `dict \| None` | Look up a peer by name across all transports. |

## Capabilities

- `agent.advertise(*capabilities)` — advertise capabilities, e.g. `agent.advertise("llm:llama3", "tool:filesystem")`.
- `agent.discover(pattern) -> list[tuple[node_id, capability]]` — find peers by capability glob pattern.

See [`CAPABILITIES.md`](CAPABILITIES.md) for the capability model.

## Lifecycle

- `agent.run(foreground=True)` — start the agent. `foreground=True` (default) blocks until Ctrl-C; `foreground=False` returns the asyncio event loop for caller-managed lifetime.
- `agent.stop()` — graceful shutdown.

## Escape hatch

Every `Agent` wraps a `BridgeDaemon`, exposed as `agent.daemon`, for
advanced use cases that need direct daemon access.

## See also

- [`GETTING_STARTED.md`](GETTING_STARTED.md) — multi-node walkthrough.
- [`CAPABILITIES.md`](CAPABILITIES.md) — capability registry.
- [`LORA.md`](LORA.md) — running over LoRa / Reticulum.
- [`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md) — wire format.
