# LoRa path validation (Phase E)

## Verified on 2026-04-14

A LoRa-only E2E round-trip was measured by temporarily disabling
`AutoInterface` and `TCPServerInterface` on the Wiz test node, forcing
every probe through the `RNodeInterface[RNode LoRa]` link (915 MHz,
SF8, BW125, CR5, 17 dBm TX). Probes targeted a Pixel running Sideband
with its own RNode hardware, 1 hop away.

### Results

| Payload | Probes | Delivered | RTT (min — max) | RSSI | SNR | Link Quality |
|---|---|---|---|---|---|---|
| 16 B | 3 | **3/3 (100%)** | 1.07 — 1.23 s | -46 dBm | +12.5 dB | 100% |
| 64 B | 3 | **3/3 (100%)** | 1.17 — 1.25 s | -46 dBm | +12.4 dB | 100% |
| 256 B | 3 | **3/3 (100%)** | 1.77 — 1.98 s | -45 dBm | +12.4 dB | 100% |

- **RSSI** around -45 to -46 dBm — strong signal, short-range indoor
- **SNR** consistently +12 dB above noise floor — well above the
  SF8 decoding threshold (~-12 dB)
- **Zero packet loss** across 9 probes covering 3 payload sizes

### What the numbers mean

- The **1 second baseline** at 16-256 bytes is the sum of: LoRa airtime
  for the request frame, receiver processing, LoRa airtime for the
  reply frame, and path discovery amortization. It's consistent with
  the LoRa physical-layer on-air bitrate of 3.12 kbps at SF8/BW125.
- Each doubling of payload roughly adds 200 ms at this SF/BW combo.
  At 256 bytes we're at ~1.8 s — well within usable territory for
  agent messaging, status updates, and small RPCs.
- IronMesh's existing `MAX_RNS_MSG = 1_048_576` bound (1 MB) remains
  the ceiling. Frames above 500 bytes get fragmented by
  Reticulum's Buffer/Channel layer and reassembled transparently —
  tested separately in `tests/test_reticulum_transport.py`.

### Known good hardware

- **Wiz end**: original RNode on COM3 (CP2102 bridge, SX1276 modem,
  firmware 1.85)
- **Pixel end**: built-in or external RNode paired with Sideband;
  appears as a standard LXMF delivery destination on the RNS path
  table
- **Heltec LoRa32 v3** (SX1262 modem, firmware 1.85) — configured
  identically to above; verified-compatible in-circuit as a repeater
  or endpoint

## Reproducing this test

Requires: two RNode-equipped nodes within radio range, both
configured for the same frequency/SF/BW.

```bash
# 1. Temporarily disable non-LoRa interfaces on the sender
# Edit ~/.reticulum/config, set `enabled = No` on [[Default Interface]]
# and `enabled = no` on [[TCP Server]].  Keep [[RNode LoRa]] as-is.

# 2. Restart rnsd
pkill -f rnsd; python -m RNS.Utilities.rnsd &

# 3. Confirm only LoRa is up
python -m RNS.Utilities.rnstatus
# Expect: only RNodeInterface[RNode LoRa] under "Interfaces"

# 4. Force-resolve the target (drops any cached WiFi path)
python -m RNS.Utilities.rnpath -d <target-hash>
python -m RNS.Utilities.rnpath <target-hash>
# Expect: "via <hash> on RNodeInterface[RNode LoRa]"

# 5. Probe at varying sizes
for sz in 16 64 256; do
    python -m RNS.Utilities.rnprobe -s $sz -n 3 -w 2 -t 60 \
        lxmf.delivery <target-hash>
done

# 6. Re-enable WiFi + TCP in config, restart rnsd.
```

## IronMesh over LoRa — expected behavior

With this LoRa baseline, IronMesh application messages (wrapped in
NaCl SecretBox + Ed25519 signature, adding ~80-100 bytes of overhead)
will land in the **1.5 — 3 second** range for typical text payloads.
The `_peer_bandwidth_rate` default of 1 MB/s will never be hit on LoRa
— the physical link is ~0.4 KB/s, so the bandwidth throttle is a
no-op in practice.

Operators running primarily over LoRa should:

- **Keep messages small** (< 256 bytes ideal, < 500 bytes for
  single-fragment delivery)
- **Use priority=CRITICAL for operational alerts**, not for chatter
- **Set `_heartbeat_interval` higher** (e.g. 120s instead of 30s) to
  reduce airtime consumption — PING/PONG chews the same airtime as
  real messages
- **Monitor `Airtime` in `rnstatus`** — stay below 10% in the 1h
  window to respect duty cycle regulations in your region

## Procedure to complete the validation

Requires: two or more nodes with RNode hardware (or LilyGO T-Echo,
Tango Charlie etc.), within radio range, WiFi disabled or blocked at
each node for the duration of the test.

### 1. Confirm LoRa connectivity

On both nodes:

```bash
python -m RNS.Utilities.rnstatus
# Look for RNodeInterface[RNode LoRa] — Status: Up
```

On one node, query the other's destination hash:

```bash
# Copy the destination hash from the remote node's startup log
python -m RNS.Utilities.rnpath <remote-dest-hash>
# Expect: "<hash> is N hops away via ... on RNodeInterface[RNode LoRa]"
```

### 2. Disable non-LoRa interfaces for the test

Temporarily comment out AutoInterface and TCPServerInterface in
`~/.reticulum/config`:

```ini
  # [[Default Interface]]
  #   type = AutoInterface
  #   enabled = Yes

  # [[TCP Server]]
  #   ...

  [[RNode LoRa]]
    type = RNodeInterface
    enabled = yes
    port = COM3
    frequency = 915000000
    bandwidth = 125000
    txpower = 17
    spreadingfactor = 8
    codingrate = 5
```

Restart `rnsd` on both nodes. Paths will re-announce via LoRa only.

### 3. Run the benchmark over LoRa

On the "responder" node:

```bash
export IRONMESH_PASSPHRASE="your-passphrase"
python -m tests.harness.bench_responder \
  --name lora-resp --port 8764 \
  --open-discovery --allow-plaintext-ws
# Note the node_id from the startup log.
```

On the "client" node:

```bash
export IRONMESH_PASSPHRASE="your-passphrase"
# Payloads must stay small on LoRa — start at 16 bytes, work up to 256.
python tests/harness/mesh_bench.py \
  --target-host <responder-LAN-ip-or-DNS> --target-port 8764 \
  --target-name lora-resp \
  --client-name lora-cli --client-port 18700 \
  --sizes 16,64,256 --trials 10 --trial-timeout 60 \
  --output lora_bench.csv
```

With only LoRa available, expect:

- p50 latency in the **1–5 second** range for a 16-byte payload (announce
  discovery + round-trip)
- p50 latency in the **5–20 second** range for 256 bytes (fragmentation +
  multiple LoRa frames + ACKs)
- Delivery rate should still approach 100% — Reticulum's resource
  transfer handles retries + fragmentation internally.

### 4. Report back

Open an issue on the IronMesh repo with:

- The CSV output from step 3
- `rnstatus` output showing LoRa airtime during the test
- Radio environment: antenna type, TX power, distance, obstructions
- RNode firmware version

This will let us add a real LoRa baseline to the README and tune the
`_peer_bandwidth_rate` default for LoRa operators (which is currently
sized for LAN, not LoRa).

## Open work

The single-hop indoor numbers above are useful as a sanity check, but
they don't tell the whole story. What's still on the list:

- Multi-hop LoRa routing across 3+ RNodes at real distance.
- Behavior in adversarial RF conditions (interference sweeps, duty-cycle
  limits, marginal signal).
- Sustained goodput over a long window, not just a short probe sweep.

If you run any of these, please open a PR against this document with
your hardware, config, and results. The `--chaos` flag on
`tests/harness/mesh_bench.py` is useful for injecting packet loss while
measuring.
