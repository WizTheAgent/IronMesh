# NAT Traversal — Running IronMesh Across the Internet

IronMesh is built local-first. Default discovery is mDNS, which only
works on a single LAN. For most deployments that is the right answer
— if your agents live on the same network, you don't need anything
else.

For deployments that span networks (homelab + VPS, friend across
town, fleet of edge devices behind separate NATs), the supported
approach is to **layer IronMesh on top of an overlay network that
already solved NAT traversal.** You get a flat virtual LAN; IronMesh
runs on it like any LAN deployment. No new code, no STUN / TURN /
ICE infrastructure, no public ports to expose.

This doc walks through the three overlay options that work well
with IronMesh today.

> **v0.9.2 ships the relay half of the hybrid design.** An operator-run
> rendezvous server (`python -m ironmesh.nat_relay`) forwards sealed
> envelopes between NATted peers. The relay never sees plaintext — it
> reads only the outermost `{type, to}` envelope. See §4 below.
> Hole-punching on top of the relay fallback is still on the roadmap
> for a later release. The full design doc lives at
> [`NAT_TRAVERSAL_DESIGN.md`](NAT_TRAVERSAL_DESIGN.md).
>
> For the fastest WAN deployment today, Tailscale + IronMesh (§2) is
> still the lowest-friction option. The bundled relay in §4 is for
> operators who want to avoid a third-party dependency.

## Option 1 — Tailscale (easiest)

Tailscale is a managed WireGuard mesh that handles NAT traversal,
key exchange, and ACLs. Free for personal use up to 100 devices and
3 users; paid plans for orgs. You install the client on each node,
authenticate, and every node gets a stable `100.x.y.z` Tailnet IP
that other nodes can reach directly.

### 15-minute setup

```bash
# On every node (Linux)
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# On Windows: install from https://tailscale.com/download/windows
# On macOS:   brew install --cask tailscale
# On Android: install the Tailscale app

# Note the Tailscale IP each node gets
tailscale ip -4
# 100.64.1.10  (example — yours will differ)
```

Then run IronMesh on each node, binding to the Tailscale interface:

```bash
# Node A (e.g. 100.64.1.10)
export IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase
ironmesh run --name alice --port 8765 --bind 100.64.1.10 \
    --allowed-peers bob

# Node B (e.g. 100.64.1.11)
export IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase
ironmesh run --name bob --port 8765 --bind 100.64.1.11 \
    --allowed-peers alice
```

Tailscale's MagicDNS gives every node a `<name>.<tailnet>.ts.net`
hostname; you can use that instead of the IP if you prefer.

### Trade-offs

- **Pros:** trivial setup, works through the most hostile NATs,
  ACL controls, identity tied to your SSO. The default for
  "I just want it to work."
- **Cons:** requires a Tailscale account; control plane is operated
  by Tailscale, Inc. (key exchange happens via their coordination
  server, though traffic is end-to-end WireGuard between your
  nodes). If you want full sovereignty over the control plane,
  self-host [Headscale](https://github.com/juanfont/headscale) — a
  drop-in OSS Tailscale coordinator.

## Option 2 — Yggdrasil (privacy-maximalist)

Yggdrasil is a fully decentralized end-to-end-encrypted overlay
network. No central coordinator, no accounts, no SaaS. Every node
gets a deterministic `200::/7` IPv6 address derived from its public
key. Connections find each other through a self-organizing routing
protocol that works across NATs (with a peer hint).

### Setup

```bash
# Install yggdrasil-go on every node
# Linux: see https://yggdrasil-network.github.io/installation.html
# Generate a config with sane defaults
sudo yggdrasil -genconf | sudo tee /etc/yggdrasil/yggdrasil.conf

# Add at least one public peer to bootstrap
sudo nano /etc/yggdrasil/yggdrasil.conf
#   Peers:
#   [
#     "tls://ygg-tor-uk.someserver.com:54321"
#   ]
# Public peer list: https://github.com/yggdrasil-network/public-peers

# Start the daemon
sudo systemctl enable --now yggdrasil

# Each node gets an IPv6 address
ip -6 addr show tun0
# inet6 200:abcd:1234:.../7
```

Then run IronMesh on each node:

```bash
ironmesh run --name alice --port 8765 \
    --bind 200:abcd:1234::1 \
    --allowed-peers bob
```

### Trade-offs

- **Pros:** zero accounts, zero central control, fully E2EE between
  Yggdrasil nodes, addresses are cryptographically bound to keys.
  Matches IronMesh's freedom-tool thesis better than any other
  overlay. The default for "no one is allowed to see who is on my
  network."
- **Cons:** smaller network than Tailscale (fewer reliable public
  peers, harder bootstrapping), IPv6-only (some software is finicky),
  routing latency is higher than direct WireGuard. Best when
  privacy / sovereignty matters more than convenience.

## Option 3 — Reticulum (off-grid + cross-internet)

Reticulum is the most comprehensive option for IronMesh because
IronMesh already speaks Reticulum natively (`ironmesh[rns]`). RNS
runs over LoRa, packet radio, TCP, serial, or any combination
simultaneously. For internet-spanning deployments you can use
Reticulum's `TCPClientInterface` / `TCPServerInterface` to bridge
nodes through any reachable host.

### Setup

```bash
# On every node, install IronMesh with the rns extra
pip install 'ironmesh[rns]'

# Configure RNS at ~/.reticulum/config
# Minimal example — node A acts as a TCP server; node B connects to
# it. For symmetric setups use a known-good public RNS bridge.
```

Server node (`alice`):

```ini
[interfaces]
  [[Public TCP server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 0.0.0.0
    listen_port = 4242
```

Client node (`bob`):

```ini
[interfaces]
  [[Connect to alice]]
    type = TCPClientInterface
    enabled = yes
    target_host = alice.example.com
    target_port = 4242
```

Run IronMesh with the Reticulum transport on both:

```bash
ironmesh run --name alice --port 8765 --reticulum \
    --allowed-peers bob

ironmesh run --name bob --port 8765 --reticulum \
    --allowed-peers alice
```

The `--reticulum` flag enables RNS as a parallel transport alongside
WebSocket. Both transports run concurrently — RNS handles the
internet-spanning leg, WebSocket handles any LAN peers.

### Trade-offs

- **Pros:** integrates natively with IronMesh's existing transport
  abstraction; same client can speak LoRa, TCP-over-RNS, and
  WebSocket simultaneously; survives partial connectivity loss
  gracefully (a node with both LoRa and TCP can fall back if one
  drops).
- **Cons:** requires you to operate at least one TCP-reachable node
  (or rely on a public RNS bridge); RNS routing latency is higher
  than direct overlays for purely internet-bound traffic. Best when
  you want internet + LoRa as a single unified mesh.

## Architecture: how it composes

```
┌─────────────────────────────────────────────────────────────┐
│                    IronMesh agent layer                     │
│   (capability discovery, MCP tools, conversation envelope)  │
├─────────────────────────────────────────────────────────────┤
│                IronMesh transport abstraction               │
│         WebSocket  │  Reticulum  │  (future: native)        │
├─────────────────────────────────────────────────────────────┤
│                    Network layer (any of):                  │
│   LAN  │  Tailscale  │  Yggdrasil  │  Internet via RNS      │
└─────────────────────────────────────────────────────────────┘
```

You can mix and match. A common pattern: WiFi LAN at home, Tailscale
to a friend's homelab, Reticulum + LoRa for the off-grid Pi cluster.
All three networks present as peers to the same IronMesh agent.

## Choosing

| Need | Use |
|---|---|
| Just works, lowest friction | **Tailscale** |
| Full sovereignty, no SaaS | **Yggdrasil** (or self-hosted Headscale) |
| Internet + LoRa unified | **Reticulum** |
| LAN only | **Default mDNS** (no overlay needed) |

## Option 4 — Bundled NAT relay (v0.9.2+)

If you don't want to run Tailscale, Nebula, or Headscale, IronMesh
now ships with a built-in rendezvous / relay server. Run it on any
box with a public IP (or any box reachable by every peer you want
to connect — a VPS, a home server with a port-forward, a LAN
jumphost), and every NATted IronMesh node can reach every other
NATted IronMesh node through it.

### Run the relay

```bash
# On the public host — requires one open TCP port (default 18787)
python -m ironmesh.nat_relay --port 18787 --bind 0.0.0.0
```

That's it. The relay is a single-purpose process with no database
and no identity of its own. Peers register over a long-lived
outbound WebSocket; the relay forwards sealed envelopes between
registered peers by ``node_id``. Plaintext never touches the relay.

### Attach peers to it

Every IronMesh node opts in with ``--nat-relay wss://relay.host:18787``.
The first outbound WebSocket registers the local node_id; subsequent
``send_to`` calls that can't find a direct or mesh route fall back
through the relay.

### Threat model

The relay is **metadata-aware, payload-blind**. An operator of the
relay can observe:

- which node_ids are registered and for how long,
- who talks to whom, at what frequency, with what byte volume.

The relay **cannot** decrypt payloads — every frame is a sealed
envelope encrypted end-to-end between sender and destination. Cross
reference: ``THREAT_MODEL.md §5 Cross-asset attacks`` for the full
adversary analysis. If metadata exposure to the relay operator is
unacceptable for your deployment, use option 1 (Tailscale) instead
— it hides the metadata at the IP layer.

### When to run your own vs. use a community relay

- **Run your own** if you have a VPS and want full control. It's ~200
  lines of Python with no state; an ops-free workload.
- **Use a community relay** if you're personal / low-volume and the
  metadata trade is acceptable. (No public community relay is
  operated by the IronMesh project itself — this is operator-run
  infrastructure by design.)

## What's intentionally not in scope here

- **STUN / TURN / ICE.** Requires either a third-party signaling
  server (which negates the privacy story) or a custom one (which
  is a non-trivial protocol implementation). Tracked for v1.1+.
- **UPnP / NAT-PMP automatic port forwarding.** Works on consumer
  routers, fails reliably on every restrictive NAT IronMesh actually
  needs to traverse. Not worth shipping.
- **Public IPv4 + port-forwarding.** Works fine if you have one,
  doesn't need a recipe — just `--bind <public-ip>` and open the
  port on your router. Use TLS in this case.
