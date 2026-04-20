# IronMesh Benchmarks

Published, reproducible numbers for what to expect from IronMesh on
real hardware. All measurements made with the stock `mesh_bench.py`
harness in `tests/harness/`.

> **Methodology note.** Every number below is from a real run, not a
> simulation. The reproduction steps below produce numbers within the
> published variance on the same hardware class. Numbers will be
> refreshed every minor version per the release checklist.

## TL;DR

| Transport | 1 hop, 64 B | 1 hop, 1 KB | Delivery | Notes |
|---|---|---|---|---|
| **LAN (WebSocket)** | p50 12 ms / p95 75 ms | p50 13 ms / p95 78 ms | 100% | x86 desktop ↔ Pi 5, gigabit LAN |
| **LoRa (915 MHz, SF8/BW125)** | p50 ~1.2 s | n/a (>1 KB fragments) | 100% | 1 hop, strong signal (RSSI -45 dBm) |

## LAN benchmark (WebSocket transport, single hop)

Hardware: Windows 11 desktop ↔ Raspberry Pi 5 (8 GB), gigabit LAN, no
TLS. 50 trials per payload size, IronMesh v0.7.2+.

| Payload | Delivery | p50 RTT | p95 RTT | Goodput |
|---|---|---|---|---|
| 64 B | 100 % | **12.0 ms** | 74.6 ms | 6.2 KB/s |
| 256 B | 100 % | **12.7 ms** | 72.3 ms | 23.4 KB/s |
| 1 KB | 100 % | **13.1 ms** | 78.0 ms | 76.9 KB/s |

The handshake (3-stage: passphrase HMAC → signed ephemeral X25519 ECDH
→ XSalsa20-Poly1305 session) adds a one-time ~30 ms cost at session
establishment; steady-state per-message overhead is roughly 8–10 ms of
crypto + 2–4 ms of WebSocket framing on this hardware.

## LoRa benchmark (Reticulum / RNode transport, single hop)

Hardware: two RNode-equipped peers, 1 hop, strong signal indoor.
915 MHz, SF8, BW125, CR5, 17 dBm TX. From `docs/LORA_VALIDATION.md`.

| Payload | Probes | Delivered | RTT (min — max) | RSSI | SNR |
|---|---|---|---|---|---|
| 16 B | 3 | **3 / 3 (100 %)** | 1.07 — 1.23 s | -46 dBm | +12.5 dB |
| 64 B | 3 | **3 / 3 (100 %)** | 1.17 — 1.25 s | -46 dBm | +12.4 dB |
| 256 B | 3 | **3 / 3 (100 %)** | 1.77 — 1.98 s | -45 dBm | +12.4 dB |

The ~1 second baseline is the sum of LoRa airtime for the request
frame, receiver processing, LoRa airtime for the reply, and Reticulum
path-discovery amortization. It is consistent with the LoRa
physical-layer on-air bitrate of 3.12 kbps at SF8/BW125.

Each doubling of payload adds roughly 200 ms at this SF/BW combination.
At 256 B the round-trip is ~1.8 s — well within usable territory for
agent messaging, status updates, and small RPCs. Payloads above ~500 B
are fragmented by Reticulum's Buffer/Channel layer and reassembled
transparently; the 1 MB ceiling at the IronMesh layer (`MAX_RNS_MSG`)
holds.

## Behavior under loss

`mesh_bench.py --chaos 0.25` injects 25% client-side packet drops.
Observed:

- Delivery rate tracks the injection rate within 2 percentage points
  (i.e. ~75% messages delivered).
- p50 RTT for *delivered* messages is unchanged from the no-loss case.
- The retry + queue mechanisms absorb the loss cleanly — no flap, no
  cascading drops.

This is what you want from a mesh: degrade gracefully under network
loss instead of falling off a cliff.

## Resource footprint

Single daemon, idle (no message traffic):

| Hardware | RSS | CPU |
|---|---|---|
| Raspberry Pi 5 (8 GB) | ~45 MB | <1 % |
| Raspberry Pi Zero 2 W (512 MB) | ~38 MB | 1–2 % |
| Commodity x86 desktop (Win/Linux) | ~50 MB | <1 % |

Under sustained 100 messages/second between two peers:

| Hardware | RSS | CPU |
|---|---|---|
| Raspberry Pi 5 | ~55 MB | 8–12 % (single core) |
| x86 desktop | ~60 MB | 2–4 % |

## What is *not* benchmarked yet

Honest gaps that the next benchmark pass will fill:

- **Multi-hop on the same LAN.** Single-hop only above. Need a 3-node
  daisy-chain with each hop going through `MeshRouter` and a 5-node
  mesh with redundant paths to validate the distance-vector + dedup
  paths under load.
- **WAN over an overlay (Tailscale, Yggdrasil).** The recommended
  cross-NAT path. Need real measurements at typical home-internet
  RTTs (~30 ms baseline).
- **Large-mesh stress.** Master plan calls for 50+ synthetic nodes,
  100–1000 msg/s, with degradation curves documented honestly. Not
  yet captured.
- **LoRa multi-hop.** Single LoRa hop above; multi-hop needs a real
  three-radio test with a repeater node.

## Reproducing these numbers

```bash
# Sender
ironmesh run --name alice --port 8765 --allowed-peers bob \
    --passphrase-file ~/.ironmesh/passphrase

# On the responder host, run the bench responder (echoes BENCH frames)
python tests/harness/bench_responder.py --port 8766 \
    --passphrase-file ~/.ironmesh/passphrase

# On the sender host, run the harness
python -m tests.harness.mesh_bench \
    --target-host 192.0.2.20 --target-port 8766 \
    --target-name bob \
    --passphrase-file ~/.ironmesh/passphrase \
    --sizes 64,256,1024,4096 --trials 50 \
    --output results.csv
```

Output is a CSV with one row per probe: payload size, RTT, success
flag, retry count. Aggregate however you like.

For LoRa, see [`LORA_VALIDATION.md`](LORA_VALIDATION.md) for the full
RNode + Reticulum reproduction recipe.

## Cadence

Numbers refresh every minor version (e.g. v0.9.0). Patch releases
inherit the most recent minor's published numbers unless the patch
explicitly changes a hot path. The release checklist
(`.github/RELEASE_CHECKLIST.md` Section 5) requires a fresh harness
run before any tag.
