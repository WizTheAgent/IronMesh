# IronMesh v0.8.0

**Release date: 2026-04-16**

v0.8.0 is a major feature release on top of the v0.7.2 hardening foundation.
The protocol wire format is unchanged — all v0.7.x nodes interoperate with
v0.8.0 nodes on the mesh.

## Highlights

### Agent SDK — join the mesh in 3 lines

```python
from ironmesh.agent import Agent

agent = Agent("my-bot", passphrase="a-strong-passphrase-12")

@agent.on_message()
def handle(peer_id, payload):
    print(f"From {peer_id}: {payload.decode()}")
    agent.reply(peer_id, b"ack")

agent.run()
```

High-level wrapper over `BridgeDaemon` that hides the asyncio / WebSocket
plumbing. Decorator API, sync and async send, capability discovery, and
graceful lifecycle management.

### Framework adapters

First-party integration for the three major agent frameworks:

- **LangChain** — `create_ironmesh_toolkit(agent)` returns four `BaseTool`s
  (send, receive, peers, discover) you can hand to any `AgentExecutor`.
- **CrewAI** — `create_mesh_crew_agent()` factory plus tool bundle.
- **AutoGen** — `register_ironmesh(agent, autogen_agent)` wires IronMesh
  into AutoGen's `function_map` with OpenAI-style specs.

### Multi-mesh federation

`FederationGateway` bridges two independent IronMesh meshes with
policy-controlled capability forwarding. Each mesh keeps its own trust
boundary; the gateway runs two Agent instances (one per mesh) and forwards
messages that match its allow/deny glob rules.

### Go reference client

Full wire protocol implementation in Go (`clients/go/`) — frame
serialization, X25519 ECDH, XSalsa20-Poly1305 SecretBox, Ed25519 detached
signatures, and the 3-stage handshake. Crypto primitives verified against
the Python reference.

### Professional codebase audit

Comprehensive cleanup pass that removed dead code (`transport.py`,
`scripts/test_harness.py`, stale `requirements.lock.md`), migrated the
default keys path from a legacy vendor-prefixed location to
`~/.ironmesh/`, patched a tarfile path-traversal edge case in
`backup.py`, and tightened exception handling throughout the Agent SDK.

## What changed

- **Version**: 0.7.2 → 0.8.0
- **Python**: requires 3.10+ (3.9 dropped in 0.7.2, confirmed here)
- **New top-level exports**: `Agent`, `FederationGateway`, `FederationPolicy`
- **New packages shipped**: `ironmesh.agent`, `ironmesh.federation`,
  `ironmesh.adapters.{langchain,crewai,autogen}_adapter`, `ironmesh_mcp`
- **Docker**: `wiztheagent/ironmesh:0.8.0` + `:latest`
- **PyPI**: `pip install ironmesh==0.8.0`

## Breaking changes

None at the wire-protocol level. The only source-level migration is the
default keys path (legacy vendor-prefixed location →
`~/.ironmesh/keys.json`). Existing deployments can keep the old path by
passing `--keys-path` explicitly; new installs get the cleaner default.

## Verification

- 510 pytest tests pass on Ubuntu + Windows across Python 3.10 – 3.13
- `ruff check .` clean
- `bandit -ll` clean (no HIGH-severity findings)
- `pip-audit` clean on all dependencies
