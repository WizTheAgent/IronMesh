# Reticulum integration guide

IronMesh ships with optional support for the [Reticulum Network Stack](https://reticulum.network)
as a peer transport. With the `rns` extra installed, an IronMesh node can
auto-discover other IronMesh nodes anywhere on the Reticulum mesh — over
LoRa, packet radio, I2P, or TCP/Yggdrasil — and exchange messages with
the same end-to-end encryption guarantees as the WebSocket transport.

```bash
pip install ironmesh[rns]
ironmesh run --reticulum --name alice
```

That is the entire setup for a node that plugs into the local Reticulum
fabric. Everything below is operational detail and tuning.

## What you get

| Feature | What it does |
| --- | --- |
| **Auto-discovery** | Nodes hearing each other's RNS announces auto-populate a peer registry — no operator-typed destination hashes required. mDNS does the same for LAN; this is the LoRa / I2P / WAN equivalent. |
| **Per-packet ratchets** | Forward secrecy on Packets sent outside an established Link. Ratchet keys rotate on a timer (default 30 min) and are advertised in subsequent announces. Tunable with `--rns-ratchet-interval` / `--rns-retained-ratchets`. |
| **Live link metrics** | MTU, MDU, expected bps, RSSI, SNR, Q sampled every 5 s and exposed on the dashboard JSON API as `rns_*` fields. Phy stats are populated only on radio interfaces. |
| **RNS Resource for large payloads** | Frames above 32 KB are auto-routed through `RNS.Resource` (chunked, bz2-compressed, integrity-checked, resumable). Hard cap of 64 MB per Resource. Feature-gated on the peer's announced `resource` capability. |
| **Public RPC paths** | Three open paths queryable by any RNS-speaking client without an ironmesh dependency: `/im/info`, `/im/cap/list`, `/im/cap/find`. Useful for capability discovery from Sideband, Nomadnet, or custom Python scripts. |
| **Native link liveness** | Heartbeat loop uses `link.no_data_for()` for fast dead-link detection on RNS, and PINGs at a 5x cadence to save LoRa bandwidth. |
| **`Transport.await_path`** | Outbound link setup uses RNS's native path-response signal instead of busy-polling. |

## Setup

### 1. Install RNS

The `rns` extra pulls in `rns>=1.1.9`:

```bash
pip install ironmesh[rns]
```

If you also want the LXMF listener (see below):

```bash
pip install ironmesh[lxmf]
```

### 2. Configure your Reticulum interfaces

IronMesh does not own your `~/.reticulum/config` — that is for you to
shape based on the radios, modems, or WAN tunnels you have. A minimal
config that works for development is just `AutoInterface` (LAN multicast):

```ini
[interfaces]
  [[Default Interface]]
    type = AutoInterface
    enabled = yes
```

For a node that bridges LAN and a Heltec LoRa32 over USB:

```ini
[interfaces]
  [[Default Interface]]
    type = AutoInterface
    enabled = yes
    interface_mode = full

  [[LoRa]]
    type = RNodeInterface
    enabled = yes
    interface_mode = gateway
    port = /dev/ttyUSB0
    frequency = 915000000
    bandwidth = 125000
    txpower = 17
    spreadingfactor = 8
    codingrate = 5
```

`interface_mode` shapes how this interface participates in announce
propagation. Pick based on what the interface connects you to:

| Mode | Use when |
| --- | --- |
| `full` | Default. Full participation, both ways. |
| `gateway` | This interface bridges between two segments and should resolve unknown paths on behalf of clients on the other side. Use on the LoRa/WAN side of a multi-radio node. |
| `boundary` | Like `gateway` but more conservative — won't propagate announces from one side to the other unless asked. |
| `roaming` | Mobile nodes on intermittent links. Suppresses some announce noise. |
| `access_point` | This node is a fixed AP others connect through. |

### 3. Start IronMesh with the Reticulum flag

```bash
ironmesh run --reticulum --name alice --passphrase-file ~/.ironmesh/passphrase
```

The daemon logs its destination hash at startup:

```
Reticulum transport active — destination 4e3ca5ae80d945cdb0c8a24bd4f38f63
```

Other IronMesh nodes on the same Reticulum fabric will hear the
announce and auto-discover this node within one announce cycle (default
5 minutes; tune with `--rns-announce-interval`).

## Interface Access Codes (IFAC)

IFAC is Reticulum's network-layer membership mechanism. When an
interface is configured with a passphrase, only peers on that interface
that also know the passphrase can join — packets without a valid IFAC
signature are dropped at the interface boundary.

This is **complementary to**, not a replacement for, IronMesh's own
passphrase. They sit at different layers:

| Layer | Mechanism | What it gates |
| --- | --- | --- |
| Reticulum interface | IFAC passphrase | Whether you can speak to this RNS interface at all |
| IronMesh protocol | `--passphrase` | Whether your IronMesh handshake completes |

A defensible deployment uses both: IFAC keeps non-members off the
interface entirely (cheap rejection at the radio layer), and the
IronMesh passphrase gates which peers are allowed to handshake at the
agent layer.

### Configuring IFAC

Add a `passphrase` line to the interface block in `~/.reticulum/config`:

```ini
[interfaces]
  [[Mesh]]
    type = AutoInterface
    enabled = yes
    passphrase = some-shared-network-secret
```

All nodes on the interface must use the same passphrase. Restart `rnsd`
or your IronMesh daemon for the change to take effect.

IFAC has measurable per-packet overhead — Ed25519 signature plus a
1–64 byte access code. On a 3.12 kbps LoRa segment that overhead is
not free, so weigh it against the threat you're mitigating.

## LXMF interop (optional)

[LXMF](https://github.com/markqvist/LXMF) is the Reticulum-native
messaging format used by Sideband (iOS/Android) and Nomadnet. With the
`lxmf` extra installed, IronMesh can run an LXMF delivery identity
alongside its main bridge so that Sideband / Nomadnet users can message
IronMesh agents and vice versa.

```bash
pip install ironmesh[lxmf]
ironmesh run --reticulum --lxmf --name gateway
```

The LXMF listener:

* Registers an LXMF delivery identity (persistent, derived from a key in
  `~/.ironmesh/lxmf/`).
* Announces it on the Reticulum mesh so Sideband / Nomadnet users can
  see and message it.
* Forwards inbound LXMessages to a configured IronMesh agent.
* Lets IronMesh agents send outbound LXMessages by destination hash.

Tune the storage path with `--lxmf-storage` and the display name shown
to other Reticulum users with `--lxmf-display-name`.

### Telemetry publishing

With `--lxmf-telemetry-target <dest_hash>` set, the listener sends a
plain-text metrics summary to the given LXMF destination at a
configurable interval (default 5 minutes). The format is intentionally
simple:

```
# IRONMESH-TELEMETRY v1
name: alice
node_id: 611979d276ae2c4d77eac2b826a17975
uptime_s: 3601
peers_total: 4
peers_online: 3
rns_discovered: 7
messages_sent: 1240
messages_received: 1815
bytes_sent: 342188
bytes_received: 411903
handshake_successes: 12
lxmf_in: 3
lxmf_out: 3
```

Any LXMF client renders this as a regular text message — Sideband
shows it in the thread, Nomadnet treats it as a standard LXMessage.
Future releases may add Sideband-specific telemetry-field encoding
for native graph / map rendering; the plain-text format above remains
supported as the lowest-common-denominator contract.

Fleet monitoring pattern: run one always-on LXMF client that listens
at a known destination; every IronMesh node in the fleet targets
that destination with `--lxmf-telemetry-target`. The receiver sees a
time-series of metrics summaries flow in via regular Reticulum
transport — no HTTP endpoints exposed, no central service, no
account system.

### Propagation node mode

LXMF supports propagation nodes — store-and-forward infrastructure that
holds messages for offline recipients and synchronises with other
propagation nodes. Any always-on IronMesh node with persistent storage
(a NAS, a Pi, a VPS) can opt in:

```bash
ironmesh run --reticulum --lxmf --lxmf-propagation-node --name relay
```

This is a pure good-citizen feature — your node now serves *other
people's* offline-tolerant LXMF traffic across the mesh. Storage path
defaults to `~/.ironmesh/lxmf/propagation/`; tune with
`--lxmf-propagation-storage`.

## Public RPC paths

Every IronMesh-on-RNS node exposes three open RPC paths on its
destination, queryable by any RNS-speaking client:

| Path | Returns | Notes |
| --- | --- | --- |
| `/im/info` | `{name, version, node_id, capabilities, features}` | Public node identity card |
| `/im/cap/list` | `{local: [...], remote: {node_id: [...]}}` | Full capability registry |
| `/im/cap/find` | `[{node_id, capability}, ...]` | Pattern-matched lookup; query body: `{"pattern": "llm:*"}` |

All three are `ALLOW_ALL` — they expose only information that is
already broadcast in announces or derivable by any peer. They are
explicitly a discovery surface, not a write surface. Admin / control
paths added in a later release use `ALLOW_LIST` gated to identity
hashes in the trust store.

A working example client lives at
[`examples/rns_capability_client.py`](https://github.com/WizTheAgent/IronMesh/blob/main/examples/rns_capability_client.py).
It imports only the `rns` package — no ironmesh dependency.

## Admin RPC paths (gated)

Three additional paths expose admin-level information about the
running daemon. Each is gated by an explicit allow-list of RNS
identity hashes — calls from any other identity get a structured
`{"error": "unauthorized"}` response.

| Path | Returns |
| --- | --- |
| `/im/admin/status` | Daemon health snapshot — uptime, peer counts, message rates, byte totals, handshake successes |
| `/im/admin/peers` | Full per-peer state dictionaries (same shape as `PeerState.to_dict()`) |
| `/im/admin/audit` | Last N audit-log entries; query body `{"n": 100}`, capped at 1000 |

### Configuring the allow-list

Pass identity hashes via CLI flag or environment variable:

```bash
ironmesh run --reticulum --rns-admin-identities aabbcc...,ddeeff...
# or
IRONMESH_RNS_ADMIN_IDENTITIES=aabbcc...,ddeeff... ironmesh run --reticulum
```

Each entry is a hex-encoded RNS identity hash (case-insensitive,
colons / spaces tolerated). The hash is what the admin client's
`RNS.Identity` produces — read it from the admin host with `rnstatus`
or by calling `RNS.hexrep(identity.hash, delimit=False)` programmatically.

An empty allow-list (the default) means admin RPC is registered but
every call returns unauthorized. This is the safe default — admin
access is opt-in, not opt-out.

### Why an explicit list and not the IronMesh trust store?

Two reasons:

1. **Different identity space.** RNS identities and IronMesh node IDs
   are separate keysets. A peer can be in the IronMesh trust store
   without ever having identified over RNS, and vice versa. Coupling
   them requires a mapping that can stale.
2. **Admin scope is intentionally narrower.** Most peers in your
   trust store should not be able to read your audit log or query
   your peer table. Promoting "trusted to handshake with" into
   "trusted to administer" is an explicit operator decision.

A future release will add an optional cross-reference so identities
in the IronMesh trust store with a specific role tag (e.g. `admin`)
are automatically eligible. Until then, the explicit list is the
contract.

## Running as a Reticulum Transport Node

A Transport Node forwards announces and packets on behalf of other
nodes — it's how the Reticulum mesh stays connected across multi-hop
paths. Any always-on IronMesh host that bridges multiple interfaces
(e.g. a Pi with both a LAN AutoInterface and a LoRa RNodeInterface)
is a strong candidate to also run as a Transport Node.

This is a **Reticulum-level** setting, not an IronMesh daemon flag.
Edit your `~/.reticulum/config`:

```ini
[reticulum]
  enable_transport = Yes
```

Restart `rnsd` (or your IronMesh daemon if it's running its own
Reticulum instance) for the change to take effect. The node will
announce itself as a Transport Node and start serving path requests
for unknown destinations on behalf of its neighbours.

Pair this with `interface_mode = gateway` on the wide-area interface
so the node actively resolves paths *across* the gateway boundary,
not just within each segment.

### Trade-offs

* **Pro:** Better path convergence, higher throughput across the
  whole local mesh, helps every peer behind your node reach destinations
  they couldn't see directly.
* **Pro:** Caches public keys, so peers can recall identities through
  you without each having to hear the original announce.
* **Con:** Extra outbound bandwidth — you're forwarding announces and
  packets that aren't yours. On a metered or expensive WAN link this
  can be material. Use `interface_mode = boundary` to limit cross-
  segment propagation to explicit requests.

## Bootstrap interfaces (`bootstrap_only`)

A bootstrap interface is a temporary first-contact path that detaches
once better local infrastructure is discovered. Useful when the only
way to reach a new node is via a slow or expensive medium (a TCP
tunnel over cellular, an out-of-band relay) but you expect a faster
local interface to come up shortly after.

Mark such an interface with `bootstrap_only` in the Reticulum config:

```ini
[interfaces]
  [[Cellular Tunnel]]
    type = TCPClientInterface
    enabled = yes
    bootstrap_only = yes
    target_host = relay.example.org
    target_port = 4242
```

Once any other interface comes up that exposes the same destinations,
Reticulum stops using the bootstrap interface and the connection costs
go away. Good fit for off-grid IronMesh deployments that occasionally
need a one-off fallback.

## Interface discovery

Newer Reticulum versions support encrypted on-network discovery of
*interfaces themselves* — different from announce-handler discovery
(which finds destinations). Enable it on a node that should auto-form
mesh segments without explicit interface configuration on every host:

```ini
[reticulum]
  discover_interfaces = Yes
  required_discovery_value = some-shared-network-secret
```

`required_discovery_value` works like an IFAC at the discovery layer —
only nodes that share the secret will peer up. Pair with IFAC on each
discovered interface for end-to-end membership control.

Combined with IronMesh's announce-handler discovery, a fresh node can
go from "just installed" to "fully meshed with the rest of the fleet"
without any operator-typed addresses on either side.

## Distributed blackhole list (opt-in)

Reticulum supports a network-wide spam/abuse control list that can be
published and synchronised across Transport Nodes. When enabled, a
node refuses to forward packets from sources on the list and can
publish its own additions for other nodes to pick up.

```ini
[reticulum]
  publish_blackhole = Yes
```

This pairs naturally with IronMesh's pending-trust gate
(`--require-message-promotion`). When a peer is rejected by the gate,
their RNS Identity hash can be optionally fed into the local
blackhole publication — a future IronMesh release will wire this
automatically. For now, blackhole entries must be managed via RNS's
own config and CLI tools.

**Operational caution:** blackhole publication is consensus-free —
any node can publish any source. Treat published lists as advisory,
not authoritative. The IronMesh trust store remains the source of
truth for who you talk to.

## Fast LAN with BackboneInterface

For IronMesh-to-IronMesh traffic on a single LAN segment, RNS's
`BackboneInterface` (Linux / Android only) is significantly faster
than `TCPClientInterface` / `TCPServerInterface`. It uses kernel
event APIs (`epoll` on Linux) to handle thousands of concurrent links
with low overhead, and it's wire-compatible with the TCP interface
types — a node running `BackboneInterface` and a node running
`TCPClientInterface` interoperate transparently.

```ini
[interfaces]
  [[Backbone]]
    type = BackboneInterface
    enabled = yes
    listen_on = 0.0.0.0
    port = 4242

  [[Backbone Client]]
    type = BackboneInterface
    enabled = yes
    target_host = backbone.local
    target_port = 4242
```

When BackboneInterface is available, prefer it for LAN segments
between IronMesh nodes. The IronMesh WebSocket transport remains
fully supported and is still useful for the GUI dashboard (which is
inherently HTTP/WS-shaped) — but it stops being the only fast path
between daemons.

### Picking the right LAN transport

| Scenario | Recommended |
| --- | --- |
| Daemon ↔ daemon on Linux LAN | `BackboneInterface` |
| Daemon ↔ daemon on macOS / Windows LAN | `AutoInterface` (multicast) or `TCPClientInterface` |
| Browser → dashboard | IronMesh WebSocket (`--port 8765`) |
| Daemon ↔ daemon over WAN | `TCPClientInterface` (over a tunnel) or `I2PInterface` |
| Daemon ↔ daemon over LoRa | `RNodeInterface` |

You can run multiple interface types on the same node — RNS picks the
shortest path automatically, and IronMesh's mesh router weighs hop
count against link rate when choosing an outbound peer.

## Seamless transport for agents

With the pieces above in place, IronMesh peers are reachable via
WebSocket, RNS Link, and LXMF — potentially all three for the same
peer. Rather than forcing agent code to know which transport it's
speaking over, the `Agent` SDK exposes a single unified call:

```python
from ironmesh.agent import Agent

agent = Agent("alice", passphrase="...", reticulum=True, lxmf=True)
agent.run(foreground=False)

# Send to Bob — doesn't matter whether Bob is on the LAN, on the
# LoRa segment, or an LXMF destination the node has never connected to.
result = await agent.send_to("bob", "hello")
print(result)  # {"transport": "rns", "target": "node-bob", "tier": 2, ...}
```

The resolver tries transports in this order:

1. **Existing online peer** — if `bob` is currently connected via
   WebSocket or an RNS Link, the existing session is used.
2. **RNS-discovered peer** — if an announce from `bob` has been
   heard but no Link has been established yet, one is established
   on demand. Subsequent sends reuse the Link.
3. **LXMF** — if the argument looks like a 32-byte destination hash
   and the `--lxmf` listener is running, the message is posted as
   an LXMessage. Delivery is store-and-forward if the recipient is
   offline (propagation nodes hold it).

The OpenClaw channel, ACP stdio adapter, and A2A HTTP gateway all
call `Agent.send_to` internally, so adding a transport (Yggdrasil,
future mediums) is a single-site change in the daemon rather than a
per-adapter rewrite.

### Inspecting reachability

`Agent.unified_peers` returns every known peer with a `reachable_via`
list naming the transports that can reach them right now:

```python
for p in agent.unified_peers:
    print(p["name"], p["reachable_via"],
          "rtt:", p.get("estimated_rtt_ms"),
          "hops:", p.get("rns_hops"))
# bob   ['websocket', 'rns_announce']  rtt: 12.0  hops: None
# carol ['rns_announce']               rtt: None  hops: 4
# dave  ['rns']                        rtt: 180.0 hops: 3
```

An AI agent can use this to decide whether to send now (LAN peer,
low latency), queue for later (LoRa peer, high latency), or skip
(unreachable). All the context it needs to make scheduling decisions
is in that single dict.

## Tuning

| Flag | Default | Notes |
| --- | --- | --- |
| `--rns-announce-interval` | 300 s | How often to re-announce. Lower for faster discovery, higher for less radio noise. |
| `--rns-ratchet-interval` | 1800 s | Ratchet key rotation interval. |
| `--rns-retained-ratchets` | 8 | Number of past ratchet keys retained for in-flight packets. |
| `--rns-no-ratchets` | (off) | Disable ratchets entirely. Only for interop with very old RNS peers. |
| `--rns-connect` | (none) | Comma-separated destination hashes to connect on startup. Optional now that auto-discovery exists. |

## Troubleshooting

### "destination not-started" in logs

The `rnsd` daemon isn't running, or `~/.reticulum/config` has no usable
interfaces. Run `rnstatus` to confirm interface health.

### Discovery works but Links never establish

Check the IronMesh passphrase matches on both ends — auto-discovery
operates above the IronMesh handshake, so peers can be visible without
being mutually authenticated. The dashboard `/api/state` shows discovered
peers separately from connected peers.

### LoRa throughput is way below expected

Check `rns_estimated_bps` on the dashboard — it reflects RNS's own
estimate from MTU + spreading factor + coding rate. On SF8/BW125 with
17 dBm TX power, expect ~3 kbps best-case.

### Resource transfers fail mid-stream

RNS Resources resume automatically across temporary Link drops. If a
transfer fails permanently, check the receiver's logs for an
`_on_resource_concluded` warning — non-COMPLETE statuses are dropped
silently from the queue, so the sender's retry policy needs to catch up.
