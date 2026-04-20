# Reference Deployment — Off-Grid

A working IronMesh deployment that operates with **no internet, no
cell, no WiFi infrastructure**. Two endpoint nodes plus an optional
relay, all on LoRa via Reticulum, talking long-distance over open RF
spectrum. Encrypted end-to-end, runs on hardware that costs under
$60 per node, fits in a backpack, runs for days on a power bank.

> **Audience:** preppers, ham operators, expedition teams, journalists
> in adversarial network environments, anyone who wants to verify
> "the cloud went down — does my mesh still work?" The answer is yes.

## What you'll build

```
┌──────────────────────┐                  ┌──────────────────────┐
│  Endpoint A          │                  │  Endpoint B          │
│  Pi Zero 2 W         │   LoRa 915 MHz   │  Pi Zero 2 W         │
│  + RNode (Heltec V3) │ ◄──────────────► │  + RNode (Heltec V3) │
│  + 5000 mAh battery  │   (or via relay) │  + 5000 mAh battery  │
│                      │                  │                      │
│  ironmesh +          │                  │  ironmesh +          │
│    --reticulum       │                  │    --reticulum       │
└──────────────────────┘                  └──────────────────────┘

         (optional relay node in the middle if range is tight)
```

End-to-end encrypted IronMesh agent messages over a Reticulum LoRa
link. No WiFi. No internet. The only RF signature is the LoRa carrier
itself, which looks like background telemetry on a spectrum analyzer.

## Bill of materials per node

| Part | Approx cost | Notes |
|---|---|---|
| Raspberry Pi Zero 2 W | $15 | Anything that boots Raspberry Pi OS works (Pi 3, 4, 5 all fine — Zero 2 W is the cheapest still-fast-enough option). |
| Heltec WiFi LoRa 32 V3 | $20 | SX1262 modem, ESP32-S3, USB-C. Flash with [RNode firmware](https://github.com/markqvist/Reticulum#rnode-firmware). |
| MicroSD card (16+ GB, A1 class) | $5 | |
| 5000 mAh USB-C power bank | $15 | A 10,000 mAh bank gives ~36 hours runtime under typical message load. |
| 3D-printed enclosure | $0–5 | Print a Pi-Zero-and-Heltec sandwich case. STL files plentiful on Printables. |
| Antenna upgrade (915 MHz / 2 dBi gain) | $5 | Stock SMA stubby is fine for short range; upgrade for line-of-sight kilometers. |

**Total: ~$60 per node** before optional power upgrades.

## Step 1 — Flash RNode firmware on each Heltec

Flashing turns the Heltec board into a generic Reticulum modem.
Plug it into a USB-C port on any computer and run:

```bash
pip install rnodeconf
rnodeconf --autoinstall
# Pick "Heltec LoRa 32 v3" from the menu when prompted.
```

When it finishes, the Heltec exposes itself as a serial device
(`/dev/ttyUSB0` on Linux, `COMx` on Windows) speaking the RNode
protocol.

## Step 2 — Install IronMesh on each Pi

```bash
# On each Pi (Raspberry Pi OS Bookworm)
sudo apt update && sudo apt install -y python3-pip python3-venv

python3 -m venv ~/ironmesh-venv
source ~/ironmesh-venv/bin/activate
pip install --upgrade pip
pip install 'ironmesh[rns]'

ironmesh --version
```

## Step 3 — Configure Reticulum on each Pi

Reticulum needs to know how to talk to the local RNode. Edit
`~/.reticulum/config` (created by `rnsd` on first run):

```ini
[reticulum]
  enable_transport = True
  share_instance = Yes

[interfaces]
  [[Default Interface]]
    type = AutoInterface
    enabled = no       # we want LoRa-only for this deployment

  [[RNode LoRa Modem]]
    type = RNodeInterface
    enabled = yes
    port = /dev/ttyUSB0      # or whatever the Heltec enumerated as
    frequency = 915000000    # 915 MHz, US ISM
    bandwidth = 125000       # 125 kHz — best range / data trade
    txpower = 17             # 17 dBm; raise to 20 if your RNode supports it
    spreadingfactor = 8      # SF8 — 1 sec airtime per 64-byte frame
    codingrate = 5
```

Start the Reticulum daemon:

```bash
rnsd &
sleep 3
rnstatus
# Expect: RNodeInterface[RNode LoRa Modem] under "Interfaces"
```

## Step 4 — Set the shared mesh passphrase

Generate once on either Pi, copy to the other via USB stick (the
whole point is no network):

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))" > ~/passphrase
chmod 600 ~/passphrase
```

On the **other** Pi, copy that file the same way. Both ends export:

```bash
export IRONMESH_PASSPHRASE_FILE=~/passphrase
```

Add to `~/.bashrc` so it persists across reboots.

## Step 5 — Start IronMesh on each Pi

```bash
# Pi A
ironmesh run --name alpha --port 8765 --reticulum \
    --allowed-peers bravo

# Pi B
ironmesh run --name bravo --port 8765 --reticulum \
    --allowed-peers alpha
```

The daemons announce themselves over RNS. Within a few seconds each
Pi prints the discovery + handshake stages over the LoRa link:

```
[discovery] discovered bravo via RNS path table
[handshake] bravo online -- ECDH complete (over RNS, 1.42 s)
```

## Step 6 — Send a message

From a Python script, ssh session, or just `ironmesh run` interactive:

```python
from ironmesh import Agent

a = Agent("alpha", passphrase=open("/home/pi/passphrase").read().strip(),
          rns_enabled=True)
a.start()

# After bravo is online:
a.send_sync("bravo", "hello over LoRa")
```

Latency: ~1–2 seconds for a 64-byte message at SF8/BW125 over 1 hop
(see [BENCHMARKS.md](../BENCHMARKS.md) for the full table).
Throughput: ~3 kbps on-air, plenty for agent control messages and
short text.

## Adding a relay

Two endpoints can talk directly up to several kilometers in line of
sight, less in dense urban / forest environments. To extend range,
add a third Pi + Heltec configured identically to either endpoint
(no special "relay mode" needed — RNS handles multi-hop routing
automatically). Place it on a hilltop, rooftop, or vehicle.

The relay node doesn't need to run IronMesh at all — it just
forwards Reticulum frames. But running IronMesh on it lets the relay
be a third agent in your mesh.

## Pairing with WiFi for opportunistic uplink

Real off-grid deployments often have intermittent connectivity. Edit
the Reticulum config to **add** an `AutoInterface` alongside the
`RNodeInterface`. When WiFi is available, RNS will use the faster
path automatically; when it goes away, traffic falls back to LoRa
seamlessly. From IronMesh's perspective, nothing changes — peers
stay online, messages keep flowing.

## What you've just demonstrated

- **End-to-end encrypted agent mesh on RF.** No WiFi, no cell, no
  internet. Two Pi Zeros + two Heltecs + one passphrase.
- **Audit-graded crypto** (Ed25519 + X25519 + XSalsa20-Poly1305) on a
  bandwidth-constrained transport.
- **Zero infrastructure dependence.** No DNS, no STUN, no relay
  servers, no cloud. The only thing you need is RF spectrum.
- **Days of runtime per power bank.** A daemon under typical agent
  load draws 1–2% CPU on a Pi Zero 2 W; the Heltec adds ~50 mA
  receive / ~80 mA transmit. A 10 Ah power bank lasts a day and
  change easily.

## Hardening

- Pre-flash the RNode firmware **before** taking it into the field;
  flashing requires `pip install rnodeconf` and a working network.
- Backup the passphrase file separately from the Pi (paper, USB held
  by a different person). If the Pi is lost, the mesh shouldn't
  follow.
- Use `ironmesh setup --enable-trust-gate` on first run so messages
  from any newly-discovered peer queue at the daemon and require
  promotion. RF is broadcast — a hostile peer on the same frequency
  could otherwise inject anything.
- Consider rotating the passphrase quarterly. The on-disk
  `~/.ironmesh/passphrase` is the only persistent secret; rotating
  it requires a coordinated update across all peers.
- For high-stakes operations, replace the stock antenna with a
  directional Yagi pointed at the other endpoint. Smaller RF
  footprint = harder to detect, longer range, less interference.

## Going further

- **Add an Android phone** as a third node via the [Sideband](https://github.com/markqvist/Sideband)
  app paired with another RNode. Sideband speaks LXMF over RNS;
  IronMesh exposes an LXMF gateway in `examples/lxmf_gateway.py`.
- **Heltec V3 mesh repeater chain** — a string of solar-powered
  Heltec nodes along a ridgeline can extend the mesh tens of
  kilometers without any of them needing a Pi at all.
- **Combine with HF (HFLink, JS8Call) for global reach** — RNS
  supports any byte-stream interface; HF radios with KISS-mode TNCs
  let an IronMesh deployment span continents at very low bitrate.
