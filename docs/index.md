# IronMesh

**Local-first agent-to-agent mesh protocol.**
Multi-hop routing, end-to-end encryption, capability discovery,
LoRa transport. No central server. No telemetry. No accounts.

```bash
pip install ironmesh
ironmesh setup
ironmesh run
```

## What it is

IronMesh is a peer-to-peer mesh protocol for AI agents and any
process that wants encrypted messaging without a cloud middleman.
Two daemons on the same LAN find each other via mDNS, do a
forward-secret handshake, and exchange signed + encrypted messages
over WebSocket. Add `--reticulum` and the same daemons reach each
other over LoRa, packet radio, I2P, or TCP-over-Yggdrasil with no
operator-typed addresses. Add `--lxmf` and Sideband / Nomadnet
phones can DM your agents.

The unified `Agent.send_to(name)` SDK call doesn't care which
transport was used — WebSocket on LAN, RNS Link over LoRa, LXMF
through a propagation node — the resolver picks the right one and
falls through gracefully. `Agent.send_to_capability("llm:*")` does
the same for capability-based routing.

## Where to start

* **[Quickstart](QUICKSTART.md)** — `pip install` to first
  cross-host handshake in five minutes.
* **[Getting Started](GETTING_STARTED.md)** — multi-node setup
  walkthrough.
* **[Reticulum guide](RETICULUM.md)** — every knob for the LoRa /
  RNS transport.
* **[NAT traversal](NAT_TRAVERSAL.md)** — WAN deployment recipes,
  including the bundled NAT relay shipped in v0.9.2.
* **[Protocol spec](PROTOCOL_SPEC.md)** — wire-level details for
  third-party implementers.
* **[Threat model](THREAT_MODEL.md)** — what IronMesh defends
  against and what's out of scope.
* **[Stability promise](STABILITY_PROMISE.md)** — what surfaces are
  frozen at v1.0 and what's expressly not.
* **[Metrics reference](METRICS_REFERENCE.md)** — catalog of every
  Prometheus metric + OTel span exported by the daemon.
* **[Roadmap to 1.0](ROADMAP_TO_1.0.md)** — release ladder and the
  v1.0 stability commitment.

## Why

IronMesh exists because the agent-protocol space was settling on
HTTP + central directories at the exact moment AI agents started
needing real peer-to-peer communication. A2A is HTTP. ACP is stdio
to a process you trust. MCP is the same. None of them are mesh.
None of them work when the cloud is down or the WAN is slow or
the agent is on a Pi behind CGNAT.

IronMesh is mesh. End-to-end encrypted. Forward-secret. Operates
the same on a LAN, over LoRa, or across federated meshes. The
agent SDK is three lines:

```python
from ironmesh.agent import Agent
agent = Agent("my-bot", passphrase="...")
agent.run()
```

Then any other agent on the mesh can call `send_to("my-bot",
payload)` and your handler runs.
