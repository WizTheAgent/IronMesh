# IronMesh over LoRa

IronMesh runs off-grid over **LoRa** using the
[Reticulum Network Stack](https://reticulum.network) as its radio
transport. With the `rns` extra installed and an RNode-class LoRa radio
attached, a node auto-discovers other IronMesh nodes on the Reticulum
mesh and exchanges messages with the same end-to-end encryption as the
LAN / WebSocket transport.

This page is the LoRa-focused quickstart. For the full Reticulum
integration guide — auto-discovery, per-packet ratchets, tuning — see
[`RETICULUM.md`](RETICULUM.md). For measured latency / delivery numbers,
see [`LORA_VALIDATION.md`](LORA_VALIDATION.md).

## Requirements

- An [RNode](https://unsigned.io/rnode/)-class LoRa radio (or any
  Reticulum-supported LoRa interface) on each node.
- `ironmesh[rns]` installed.
- A Reticulum config with your LoRa interface enabled (an
  `RNodeInterface`; see the Reticulum documentation).

## Setup

```bash
pip install ironmesh[rns]
ironmesh run --reticulum --name alice
```

That is the entire IronMesh-side setup for a node that plugs into the
local Reticulum fabric over LoRa. Nodes that hear each other's Reticulum
announces auto-populate a peer registry — no operator-typed destination
hashes required. It's the LoRa / WAN equivalent of mDNS on the LAN.

From the SDK ([`SDK.md`](SDK.md)):

```python
from ironmesh.agent import Agent

agent = Agent("alice", passphrase="secret-passphrase-12", reticulum=True)
agent.run()
```

WebSocket (LAN) and Reticulum (LoRa) run concurrently, so a node uses the
fast path when peers are local and falls back to LoRa when off-grid.

## What to expect on the air

Measured on a single-hop 915 MHz link (SF8, BW125, CR5, 17 dBm TX) to a
Sideband / RNode peer at strong signal (RSSI ≈ −45 dBm, SNR ≈ +12 dB):

| Payload | Round-trip time | Delivery |
|---|---|---|
| 16 B | 1.07 – 1.23 s | 3/3 |
| 64 B | 1.17 – 1.25 s | 3/3 |
| 256 B | 1.77 – 1.98 s | 3/3 |

The ~1 s baseline is LoRa airtime (request + reply frames) plus path
discovery at SF8/BW125's 3.12 kbps on-air rate; each payload doubling
adds roughly 200 ms at this spreading factor. Full methodology and
RSSI / SNR detail are in [`LORA_VALIDATION.md`](LORA_VALIDATION.md).

> LoRa is a low-bandwidth, high-latency transport — best for short
> control and coordination messages, not bulk transfer. Multi-hop and
> long-range interference sweeps beyond the single-hop validation above
> are still pending.

## See also

- [`RETICULUM.md`](RETICULUM.md) — full Reticulum integration and tuning.
- [`LORA_VALIDATION.md`](LORA_VALIDATION.md) — measured latency / delivery.
- [`SDK.md`](SDK.md) — the Python `Agent` API.
