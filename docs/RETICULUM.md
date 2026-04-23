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
[`examples/rns_capability_client.py`](../examples/rns_capability_client.py).
It imports only the `rns` package — no ironmesh dependency.

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
