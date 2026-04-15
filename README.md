# IronMesh

**Website:** [ironmesh.org](https://ironmesh.org) &nbsp;•&nbsp; **Contact:** [info@ironmesh.org](mailto:info@ironmesh.org) &nbsp;•&nbsp; **Security:** [info@ironmesh.org](mailto:info@ironmesh.org) (see [SECURITY.md](SECURITY.md))

> **⚠️ v0.7.2-beta — stable protocol, pre-1.0 release.** 472 tests passing, hardening
> complete, live-validated on a 3-node mesh with a real Android client (Sideband) and
> a single-hop LoRa link at SF8/BW125.
> See [Known limitations](#known-limitations) before deploying in production.
> Full changelog: [`CHANGELOG.md`](CHANGELOG.md).

**Your agents. Your network. Your rules.**

Zero-config, end-to-end encrypted agent-to-agent communication that never leaves your local network.

## Why IronMesh Exists

When we looked for a way to make AI agents talk to each other on a local network, there was nothing. Every existing protocol assumes you're connected to the internet, routing through someone else's cloud, trusting someone else's infrastructure.

- Google's A2A? Requires HTTPS and internet connectivity. Your agents can't talk if the cloud goes down.
- Anthropic's MCP? Tool integration, not peer-to-peer. It doesn't let agents talk to each other.
- ACP? Local IPC only — can't cross machines on your LAN.
- ANP? Decentralized but complex DID setup, still assumes internet.

None of them work if you pull the ethernet cable from your router. None of them work in a basement. None of them work off-grid.

**IronMesh was built because that's unacceptable.**

We believe in self-hosted AI. Run whatever model you want — local LLMs, local agents, local everything — on hardware you own, on a network you control. No API keys to some corporation that can revoke your access. No telemetry phoning home. No terms of service that change overnight.

In a world that's increasingly pushing centralized AI controlled by a handful of private corporations and governments, the ability to run your own agents that communicate securely on your own network isn't a luxury — it's a necessity. If your AI can only function when it's tethered to someone else's server, it's not really yours.

IronMesh is for preppers, homelab operators, privacy advocates, tinkerers, and anyone who thinks the answer to "what if the internet goes down?" shouldn't be "then nothing works."

**Local-first. Offline-capable. Mesh-ready. Zero-config. No cloud required. Ever.**

## Features

- **Zero-config discovery** — mDNS/Zeroconf auto-discovers agents on your LAN. No manual IP configuration. Identity keys are never broadcast — exchanged only during authenticated handshake. Default-deny: requires `--allowed-peers` or `--open-discovery` to enable auto-connect.
- **End-to-end encryption** — NaCl/libsodium (XSalsa20-Poly1305 + X25519 ECDH). Battle-tested crypto, not homebrew. Plaintext messages are never accepted after handshake.
- **Binary wire protocol** — Compact binary frame format with Ed25519 signatures on every frame. No JSON on the wire after handshake.
- **Forward secrecy** — Ephemeral keys per session, destroyed after handshake. Compromising today's keys can't decrypt yesterday's traffic.
- **Mutual authentication** — Both client and server prove they know the passphrase. No trusting a server that can't authenticate itself.
- **Mandatory Ed25519 signatures** — Every message is signed by the sender and verified by the receiver. No unsigned messages accepted.
- **Channel binding** — The authentication nonce is embedded in the ECDH handshake signature, cryptographically binding the two stages together.
- **Offline-capable** — Messages queued in encrypted SQLite when peers are offline, automatically delivered on reconnect.
- **Replay protection** — Monotonic sequence numbers (no seq=0 bypass) + timestamp validation block replay attacks.
- **Trust-On-First-Use** — SSH-style key pinning. If a peer's identity key changes, the connection is **immediately terminated** (not just logged). mDNS fingerprint pinning prevents address spoofing of known peers.
- **Integrity-protected trust store** — HMAC-SHA256 detects any tampering with the known_peers file.
- **Mandatory key encryption** — Identity keys are encrypted at rest with Argon2id by default. Plaintext keys auto-migrate to encrypted on next startup.
- **Encrypted storage** — SQLite message payloads are encrypted with SecretBox. No plaintext at rest.
- **Tamper-evident audit log** — Every security event (auth failures, TOFU mismatches, key rotations, peer connections) recorded with HMAC-SHA256 chain. Any tampering breaks the chain and is detected.
- **Token-authenticated GUI** — Dashboard requires a per-session bearer token (printed at startup). No unauthenticated access to metrics or state.
- **Auth failure blocking** — 3 failed auth attempts from an IP in 5 minutes triggers a 5-minute block. Rate-limited mDNS discovery prevents flood attacks.
- **TLS-first connections** — Client tries wss:// before ws://. Plaintext WebSocket fallback requires explicit `--allow-plaintext-ws`.
- **Multi-hop mesh routing (v0.4)** — Distance-vector routing with split horizon, poisoned reverse, TTL loop prevention, and per-source-sharded dedup. Messages traverse intermediate peers automatically. See [docs/MESH.md](docs/MESH.md).
- **End-to-end encryption (v0.4)** — NaCl `SealedBox` payload wrapping over X25519 keys derived from each node's identity. Relays cannot read message bodies. Inner Ed25519 source signature survives per-hop re-encryption.
- **Capability discovery (v0.4)** — Agents advertise services like `llm:llama3` or `tool:filesystem` and discover them across the mesh with `find_capability("llm:*")`. See [docs/CAPABILITIES.md](docs/CAPABILITIES.md).
- **Prometheus metrics (v0.4)** — `/metrics` endpoint serves Prometheus exposition format by default; JSON remains available via `?format=json`.
- **Reticulum / LoRa transport (v0.5)** — Optional second transport layer over [Reticulum](https://reticulum.network/). Agents communicate over LoRa radio (915 MHz) with no internet at all — just RNode hardware. Both WebSocket and Reticulum run simultaneously. Enable with `--reticulum` and the `rns` package (`pip install ironmesh[rns]`). See below for setup.
- **Audit log rotation (v0.4)** — Logs rotate at 10 MB with cryptographic chain anchors so tamper evidence survives across rotation.
- **Model agnostic** — IronMesh doesn't care what AI you're running. Ollama, llama.cpp, vLLM, a bash script — if it can open a WebSocket, it can use IronMesh.
- **Cross-platform** — Works on Raspberry Pi, Windows, Linux, Mac. Tested daily on a Pi 5 and a Windows gaming rig.

## How It Compares

| Feature | IronMesh | Google A2A | Anthropic MCP | ACP | ANP |
|---------|-----------|------------|---------------|-----|-----|
| Works offline / no internet | **Yes** | No (HTTPS) | N/A | Yes | No |
| True peer-to-peer | **Yes** | No (client-server) | No (tool calls) | No (IPC) | Yes |
| Zero-config LAN discovery | **Yes** (mDNS) | No | No | No | No (DID) |
| E2E encryption | **Yes** (NaCl) | TLS only | N/A | No | Yes |
| Forward secrecy | **Yes** | Depends | N/A | No | No |
| LAN native | **Yes** | No | No | Yes | No |
| Survives internet outage | **Yes** | No | N/A | Yes | No |
| Self-hosted, no vendor lock-in | **Yes** | No | No | Partial | Partial |
| Mesh routing | **Yes (v0.4)** | No | No | No | Yes |
| Capability discovery | **Yes (v0.4)** | No | No | No | No |

## Quick Start

**👉 New to IronMesh? Read [GETTING_STARTED.md](GETTING_STARTED.md) — a
5-minute path from zero to two nodes talking.**

### Install

```bash
# Option A: pip
pip install ironmesh

# Option B: Docker
docker compose up -d

# Option C: One-line installer (Linux/macOS)
./scripts/install.sh

# Option D: Android via Termux — see docs/TERMUX.md
```

### Start a bridge on Machine A (e.g., your Raspberry Pi)

```bash
# Passphrase from file (recommended — never appears in process list)
echo "my-strong-secret-phrase" > ~/.ironmesh/passphrase
chmod 600 ~/.ironmesh/passphrase
export IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase

ironmesh run --name kingpi --port 8765 --allowed-peers wiz
```

### Start a bridge on Machine B (e.g., your desktop)

```bash
export IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase
ironmesh run --name wiz --port 8765 --allowed-peers kingpi
```

That's it. Both agents discover each other via mDNS, authenticate with the shared passphrase, exchange ephemeral encryption keys, and establish a secure channel. No config files, no cloud accounts, no internet required.

> **Note:** `--passphrase` was removed from the CLI to prevent passphrase leaks via `ps aux`. Use `--passphrase-file`, `IRONMESH_PASSPHRASE_FILE`, or interactive `getpass` prompt instead.

### Programmatic usage

```python
import asyncio
from ironmesh.bridge import BridgeDaemon

async def main():
    daemon = BridgeDaemon(
        name="my-agent",
        port=8765,
        passphrase="shared-secret",
        allowed_peers=["peer-agent"],
    )
    daemon.run(background=True)

    # Send an encrypted message to a discovered peer
    await daemon.send_message(
        to_node="peer-fingerprint",
        msg_type="MSG",
        payload=b"Hello from my-agent!",
    )

asyncio.run(main())
```

### LoRa / Reticulum transport (v0.5)

IronMesh can communicate over LoRa radio using [Reticulum](https://reticulum.network/) as a second transport layer. Both WebSocket (LAN) and Reticulum (LoRa) run simultaneously — no internet required for either.

**Prerequisites:**
- An [RNode](https://unsigned.io/rnode/) (e.g. Heltec V3) flashed with RNode firmware
- `rnsd` running with the RNode interface configured
- The `rns` Python package: `pip install ironmesh[rns]`

**Start with Reticulum enabled:**

```bash
# Terminal 1 (node A)
ironmesh run --name kingpi --reticulum --passphrase-file /path/to/passphrase

# Terminal 2 (node B) — connect to node A's RNS destination hash
ironmesh run --name wiz --reticulum --rns-connect <kingpi_dest_hash> --passphrase-file /path/to/passphrase
```

The destination hash is printed at startup: `Reticulum transport active — destination <hash>`.

**CLI flags:**

| Flag | Description |
|------|-------------|
| `--reticulum` | Enable Reticulum transport |
| `--rns-configdir PATH` | Reticulum config directory (default: `~/.reticulum`) |
| `--rns-announce-interval N` | Seconds between RNS announces (default: 300) |
| `--rns-connect HASHES` | Comma-separated destination hashes to connect on startup |

## Architecture

```
+-------------------+       mDNS discovery       +-------------------+
|   Agent: kingpi   |<--------------------------->|   Agent: wiz      |
|   (Raspberry Pi)  |                             |   (Windows PC)    |
+-------------------+                             +-------------------+
| Your AI / App     |                             | Your AI / App     |
| Bridge Daemon     |<--- WebSocket (encrypted)-->| Bridge Daemon     |
| Protocol Layer    |    XSalsa20-Poly1305        | Protocol Layer    |
| Crypto (NaCl)     |    X25519 ECDH              | Crypto (NaCl)     |
| SQLite Store      |    Forward Secrecy          | SQLite Store      |
| mDNS Discovery    |    No internet needed       | mDNS Discovery    |
+-------------------+                             +-------------------+
```

### Handshake flow

```
Client                                 Server
  |                                      |
  |<-- PASSPHRASE_CHALLENGE -------------| (32-byte server nonce)
  |--- HMAC-SHA256(pass, nonce) -------->|
  |<-- PASSPHRASE_VERIFIED + server_proof| (mutual auth: HMAC(pass, nonce[::-1]))
  |    verify server_proof               |
  |                                      |
  |--- HELLO (eph_pub_A, id_pub_A) ---->| signed(Ed25519) + channel_binding(nonce)
  |<-- HELLO (eph_pub_B, id_pub_B) -----| signed(Ed25519) + channel_binding(nonce)
  |    verify Ed25519 signature          | verify Ed25519 signature
  |    TOFU check on id_pub_B           | TOFU check on id_pub_A
  |    derive peer_id from id_pub_B     | derive peer_id from id_pub_A
  |                                      |
  | ECDH(eph_priv_A, eph_pub_B)         | ECDH(eph_priv_B, eph_pub_A)
  |    = shared_secret                   |    = shared_secret
  |  (ephemeral privkeys destroyed)      | (ephemeral privkeys destroyed)
  |                                      |
  |<=== Encrypted + Signed messages ===>| (SecretBox + Ed25519 on every message)
```

## Use Cases

- **Home AI mesh** — Raspberry Pi running Ollama talks to your desktop running a coding agent. No cloud involved.
- **Off-grid comms** — Agents on a local network with no internet connection coordinate tasks, share data, run workflows.
- **Prepper infrastructure** — Self-contained AI network that works when the internet doesn't. Solar-powered Pi cluster running local models.
- **Privacy-first AI** — Keep all agent communication on your LAN. Nothing leaves your network. Nothing gets logged by a third party.
- **Lab / air-gapped networks** — Agents in isolated environments that can never touch the internet.
- **Multi-device AI workflows** — Your phone agent, desktop agent, and server agent all talk directly to each other.

## Web Dashboard

IronMesh includes a built-in web GUI for real-time monitoring and management. No extra software needed — it's served directly by the bridge daemon on `port + 1`. The GUI is **off by default** and must be explicitly enabled with `--gui`.

```bash
ironmesh run --name wiz --port 8765 --gui
# Dashboard: http://127.0.0.1:8766/?token=<printed-at-startup>
# Metrics:   http://127.0.0.1:8766/metrics?token=<printed-at-startup>
```

The dashboard provides:
- **Metrics cards** — Uptime, active peers, messages sent/received, bytes, handshakes, rate limits
- **Peer table** — Live view of all connected peers with status, verification, traffic, and latency
- **Message feed** — Real-time scrolling log of all agent-to-agent messages with timestamps and direction
- **Send form** — Select a peer, type a message, and send it directly from the browser

**Security:** The dashboard runs on `127.0.0.1` only (localhost). A unique bearer token is generated per session and printed in the startup banner — all `/metrics`, `/api/state`, and `/ws` endpoints require it (via `?token=` query parameter or `Authorization: Bearer` header).

See [docs/DASHBOARD.md](docs/DASHBOARD.md) for full details.

## CLI Commands

```bash
# Run the bridge daemon (passphrase via file or env — REQUIRED)
ironmesh run --name <agent> --passphrase-file <path> [--port 8765] [--bind 0.0.0.0]

# Enable GUI dashboard (off by default)
ironmesh run --name <agent> --passphrase-file <path> --gui

# Restrict peer discovery to named agents only
ironmesh run --name <agent> --passphrase-file <path> --allowed-peers friend1,friend2

# Allow open mDNS discovery (insecure — connects to any peer)
ironmesh run --name <agent> --passphrase-file <path> --open-discovery

# Run with TLS (hardened: TLS 1.2+, no compression, server cipher preference)
ironmesh run --name <agent> --passphrase-file <path> --tls-cert cert.pem --tls-key key.pem

# Key management (key files encrypted with passphrase by default)
ironmesh keys generate [--path <path>] [--passphrase <pass>]
ironmesh keys info [--path <path>]

# Trust management (TOFU)
ironmesh trust list
ironmesh trust revoke <node_id>
```

> **Note:** `--passphrase` was removed from the CLI (visible in `ps aux`). Use `--passphrase-file`, `IRONMESH_PASSPHRASE_FILE` env var, or interactive `getpass` prompt.

## Configuration

Environment variables:
- `IRONMESH_PASSPHRASE_FILE` — path to file containing passphrase (**recommended** — avoids /proc/environ exposure)
- `IRONMESH_PASSPHRASE` — shared passphrase (**required** — IronMesh refuses to start without one; prefer file-based method above)
- `IRONMESH_NAME` — agent name
- `IRONMESH_PORT` — WebSocket port
- `IRONMESH_LOG_LEVEL` — DEBUG/INFO/WARNING/ERROR

## Security

- **Encryption:** XSalsa20-Poly1305 authenticated encryption (NaCl SecretBox). Plaintext never accepted after handshake. Binary wire format.
- **Key exchange:** X25519 ECDH with ephemeral keys (forward secrecy) + channel binding to auth stage
- **Identity:** Ed25519 signing keys. Mandatory detached signatures on every binary frame. TOFU key pinning with tamper-resistant store.
- **Mutual auth:** HMAC-SHA256 passphrase proof — both sides prove knowledge. No default passphrase. Minimum 12 characters enforced.
- **Peer identity:** peer_id derived from cryptographic fingerprint (128-bit), not self-reported
- **Replay protection:** Monotonic sequence numbers (seq=0 rejected) + 30-second timestamp window
- **Rate limiting:** Per-peer token bucket + per-IP connection throttling + per-IP auth failure blocking (3 failures = 5-min ban)
- **Key storage:** Argon2id passphrase encryption by default. Plaintext keys auto-migrate to encrypted on startup.
- **Storage encryption:** SQLite payloads encrypted with SecretBox. No plaintext at rest.
- **Audit log:** Tamper-evident HMAC-SHA256 chain records all security events (auth failures, TOFU, key rotations, connections).
- **mDNS hardening:** Default-deny auto-connect. Fingerprint pinning prevents address spoofing. Rate limiting on discovery events.
- **TLS-first:** Client tries wss:// before ws://. Plaintext fallback requires `--allow-plaintext-ws`. Server TLS: 1.2+ enforced, no compression.
- **GUI security:** Dashboard disabled by default. When enabled, requires per-session bearer token for all API endpoints.
- **OPSEC:** `--passphrase` removed from CLI (leaks in `ps aux`). Passphrase via file, env var, or interactive prompt only.
- **Privacy:** Identity keys never broadcast via mDNS — exchanged only during authenticated handshake
- **No telemetry.** No analytics. No phone-home. Ever.

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

## Development

```bash
git clone https://github.com/WizTheAgent/ironmesh.git
cd ironmesh
pip install -e ".[dev]"
pytest tests/ -v --cov=ironmesh
```

## What's new in v0.7.2

- **Per-peer observability** — Prometheus metrics labelled by peer/name: `ironmesh_peer_rtt_ms`, `_retries_total`, `_bytes_sent_total`, `_bytes_received_total`, `_online`. End-to-end message lifetime histogram (p50/p90/p99). New stable-schema `/api/mesh_stats` JSON endpoint for harness/dashboard polling.
- **Backpressure** — Offline queue capped per peer (default 1000 msgs) with priority-aware eviction. Per-peer bandwidth throttle (default 1 MB/s sustained, 1 MB burst) with wait-or-drop. Prevents a noisy or stuck peer from starving the mesh.
- **Peer-drop alerting** — Audit event `PEER_DROPPED_LONG` emitted once per drop when a peer stays offline past the threshold (default 5 min).
- **Simultaneous-dial tie-breaker** — Eliminates the online/offline flap storm on 3+ node meshes. Deterministic agent-name rule applied uniformly across mDNS, discover, and reconnect loops.
- **mDNS multi-NIC fix** — Route-based local-IP detection (prefers the LAN adapter, not VirtualBox/WSL/Docker host-only). Zeroconf interface restriction when `--bind` is set.
- **Agent integrations** — [MCP server](ironmesh_mcp/) exposes IronMesh as tools for Claude Desktop / MCP-capable agents. [Trusted skills package](skills/ironmesh/) for Claude Code: `/ironmesh-status`, `/ironmesh-send`, `/ironmesh-peers`, `/ironmesh-audit`.
- **Benchmark harness** — `tests/harness/mesh_bench.py` + `bench_responder.py` with `--chaos <rate>` for loss injection. `scripts/chaos-netem.sh` for tc-netem link chaos. Live baseline: 100% delivery, p50 ≈ 12 ms, goodput 38-77 KB/s @ 1 KB.
- **Ops polish** — `scripts/startup-capture.sh` (auto-logs GUI token to `/var/log/ironmesh-token.log`), `docs/REPIN.md` (revoke/re-pin playbook), 456 passing tests.

Full list in [CHANGELOG.md](CHANGELOG.md).

## Known limitations

Things that work but are rough, or are claimed but not yet end-to-end verified:

- **Docker image** — Builds clean, runs as non-root UID 1000, imports IronMesh, binds ports. Not yet pushed to Docker Hub.
- **PyPI release** — Not yet published. Install from source: `pip install git+https://github.com/WizTheAgent/ironmesh.git@v0.7.2-beta`.
- **LoRa end-to-end latency** — Measured live at 915 MHz SF8/BW125 between two RNode-equipped nodes (1 hop, strong signal): 16-byte probe 1.07 — 1.23 s, 64-byte probe 1.17 — 1.25 s, 256-byte probe 1.77 — 1.98 s, 100% delivery across 9 probes. Multi-hop + long-range interference sweeps are still pending — see [`docs/LORA_VALIDATION.md`](docs/LORA_VALIDATION.md) for the test procedure and results.
- **`install.sh`** — The systemd install script hasn't been re-tested on a clean Ubuntu VM since the v0.7.2 code changes. The file itself is unchanged from v0.7.1, but caveat operator.
- **Android client** — Use [Sideband](https://unsigned.io/sideband/) + the bundled LXMF gateway (`examples/lxmf_gateway.py`). Proven end-to-end in v0.7.1 with a Google Pixel. No first-party Android app planned — LXMF is the right layer for that.
- **Windows service** — No Windows service wrapper shipped. Run under WSL2 or in a terminal with `ironmesh run ...`.
- **GUI dashboard password** — The per-session GUI token (32 bytes) is the only auth. If you expose the dashboard beyond localhost (NOT recommended), put it behind a reverse proxy with your own auth.

## Legacy highlights (v0.4 → v0.7.1)

- **Multi-hop mesh routing** — Distance-vector with split horizon, poisoned reverse, TTL loop prevention, route persistence, partition detection, circuit breakers. See [docs/MESH.md](docs/MESH.md).
- **End-to-end encryption over multi-hop** — NaCl `SealedBox` payload wrapping; relays cannot read forwarded messages.
- **Capability discovery** — Agents advertise services and discover them across the mesh. See [docs/CAPABILITIES.md](docs/CAPABILITIES.md).
- **Reticulum / LoRa transport** — Optional second transport layer with RNode hardware.
- **Session key rotation** — Automatic rekey with tie-breaker to prevent simultaneous initiation.
- **Audit log rotation** — 10 MB rotation with cryptographic chain anchors across files.
- **Full security audit** — 53/62 items closed in v0.7.1; remaining 9 deferred to v0.7.2+ (see CHANGELOG).

## Three-node quick start (v0.4)

```bash
# Terminal 1 — node-a, talks only to b
ironmesh run --name node-a --port 8765 --allowed-peers node-b

# Terminal 2 — node-b, the relay
ironmesh run --name node-b --port 8766

# Terminal 3 — node-c, talks only to b
ironmesh run --name node-c --port 8767 --allowed-peers node-b \
  --capability llm:llama3
```

Within ~60 seconds, `node-a` learns a route to `node-c` through `node-b`.
You can then send messages from `node-a` to `node-c` and they will be
relayed through `node-b` — but `node-b` cannot read the message bodies
(end-to-end encryption). From `node-a`, `daemon.find_capability("llm:*")`
returns `[("node-c-fingerprint", "llm:llama3")]`.

## Included Examples

Look in [`examples/`](examples/) for runnable integration patterns:

| File | What it does |
|---|---|
| [`basic_chat.py`](examples/basic_chat.py) | Two-node encrypted text chat |
| [`multi_agent.py`](examples/multi_agent.py) | Coordinator + worker pattern |
| [`file_transfer.py`](examples/file_transfer.py) | Reliable file send over the mesh |
| [`llm_bridge.py`](examples/llm_bridge.py) | Turn any node into an encrypted Ollama agent |
| [`lxmf_gateway.py`](examples/lxmf_gateway.py) | Bridge IronMesh ↔ Reticulum LXMF (Sideband iOS/Android interop) |

## Mobile

Two paths to reach a phone:

1. **LXMF gateway + Sideband** (recommended) — run the gateway on a
   gateway node and use [Sideband](https://unsigned.io/sideband) on
   iOS/Android to message IronMesh peers. Works over LoRa.
2. **Termux on Android** — run IronMesh directly on the phone via the
   Termux terminal. See [docs/TERMUX.md](docs/TERMUX.md).

## Roadmap

- [x] **Multi-hop mesh routing** (v0.4)
- [x] **End-to-end encryption layer** (v0.4)
- [x] **Capability advertisement and discovery** (v0.4)
- [x] **Prometheus metrics + structured JSON logs** (v0.4)
- [x] **Audit log rotation with cross-file chain anchors** (v0.4)
- [x] **LoRa / Reticulum transport** (v0.5)
- [x] **Transport failover (WS ↔ RNS)** (v0.5.1)
- [x] **Session key rotation + LoRa QoS** (v0.5.2)
- [x] **Encrypted backup, signed revocation, fuzzing** (v0.6)
- [x] **Docker, installer, LXMF gateway, mobile dashboard** (v0.7)
- [ ] NAT traversal for cross-subnet discovery
- [ ] Rust port for embedded boards (Heltec V3 direct flash)
- [ ] v1.0 stable milestone after 10-20 real-world deployments
- [ ] Per-message forward secrecy (ratcheting)
- [ ] Plugin sandbox / isolation
- [ ] File sync / shared state between agents
- [x] Binary wire protocol with signed frames
- [x] Web UI for monitoring and management (token-authenticated)
- [x] Tamper-evident audit logging
- [x] Encrypted storage at rest (SQLite + key files)
- [x] mDNS fingerprint pinning + default-deny
- [x] Auth failure IP blocking

## Philosophy

IronMesh exists because we believe:

1. **Your AI should work without the internet.** If your agent goes silent because AWS is down, that's a single point of failure you chose to accept.
2. **Communication between your agents is nobody else's business.** Not your ISP's, not a cloud provider's, not a government's.
3. **Self-hosted means self-hosted.** Not "self-hosted but calls home for auth." Not "self-hosted but requires a cloud API key." Actually self-hosted.
4. **Simple beats complex.** Zero-config mDNS discovery, one shared passphrase, and your agents are talking. No certificate authorities, no DID documents, no OAuth flows.
5. **Prepare for the worst.** Networks go down. Internet gets shut off. Censorship happens. Your local AI mesh should keep working regardless.

## Contact

- **Website** — [ironmesh.org](https://ironmesh.org)
- **General / operator questions** — [info@ironmesh.org](mailto:info@ironmesh.org)
- **Security issues** — [info@ironmesh.org](mailto:info@ironmesh.org) — please **don't** open a public issue first. See [SECURITY.md](SECURITY.md) for disclosure policy.
- **Bugs / feature requests** — [GitHub Issues](https://github.com/WizTheAgent/IronMesh/issues) (use the templates)

## License

MIT — Use it however you want. Fork it, modify it, deploy it on your off-grid Pi cluster. No strings attached.
