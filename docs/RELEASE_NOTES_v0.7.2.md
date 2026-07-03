# IronMesh v0.7.2-beta

> Release date: 2026-04-14
> Git tag: `v0.7.2-beta`

**Your agents. Your network. Your rules.** Zero-config, end-to-end encrypted
agent-to-agent communication that never leaves your local network — now
hardened for multi-node deployments and validated end-to-end over both WiFi
and LoRa.

## TL;DR

- **456 tests passing, zero regressions**
- **Wiz's full production-hardening checklist closed** (observability, queue
  backpressure, peer-drop alerts, per-peer bandwidth throttle, multi-NIC mDNS
  fix)
- **Live validated** on a 3-node LAN mesh + a real Android Sideband client
  over LoRa at SF8/BW125 (100% delivery, 1.07-1.98 s RTT at 16-256 B)
- **New agent integrations**: MCP server (`ironmesh_mcp`) and trusted skills
  package (`skills/ironmesh/`) — any MCP-capable agent or Claude Code agent
  can now drive IronMesh as a transport
- **Beta label is deliberate** — protocol is stable, but this is the first
  public release. Report edge cases, don't bet your production data on it.

## Major protocol bug fixed

**Event loop not started on `BridgeDaemon.run(background=True)`.** The v0.7.1
code returned a freshly-created loop without calling `run_forever()` on it,
so every scheduled coroutine (mDNS auto-connect, server handshakes,
LXMF→IronMesh forwarding, heartbeat pings) was a dead letter. The LXMF
gateway's forwarding path silently failed because of this. v0.7.2 spawns a
`run_forever()` thread before returning the loop to the caller.

**Simultaneous-dial collision storm.** Both ends of an mDNS pair dialed
each other at the same tick, creating duplicate sessions that both sides
tore down, producing a rapid online/offline flap. Fixed with a deterministic
agent-name tie-breaker applied uniformly in `_on_peer_discovered`,
`_discover_loop`, and `_reconnect_loop`.

**`_local_ip()` returned the wrong NIC on multi-homed hosts.**
`getaddrinfo(hostname)` picked up VirtualBox/WSL/Docker bridge addresses
ahead of the real LAN adapter, causing peers to dial unreachable IPs. Fixed
by preferring gateway-route-based detection.

## Wiz's hardening checklist — closed

| Ask | Delivered |
|---|---|
| Per-hop RTT + retry counts + message lifetime | `/api/mesh_stats` + labelled Prometheus metrics |
| DoS guard: backpressure on queues | `MessageStore(max_pending_per_peer=1000)` with priority-aware eviction |
| Per-peer bandwidth throttle | TokenBucket bytes/s, wait-or-drop ceiling |
| Peer-drop alerting | `_long_drop_watchdog` emits `EVENT_PEER_DROPPED_LONG` once per drop |
| One-shot startup with token capture | `scripts/startup-capture.sh` |
| Re-pin procedure docs | `docs/REPIN.md` |
| Chaos test harness | `tests/harness/mesh_bench.py --chaos <rate>` |

## New in v0.7.2

### Per-peer observability

Prometheus metrics labelled by peer/name so you can graph each peer
independently:

```
ironmesh_peer_online{peer="...",name="..."}            0 or 1
ironmesh_peer_rtt_ms{peer="...",name="..."}            latest PING RTT
ironmesh_peer_retries_total{peer="...",name="..."}     total retries
ironmesh_peer_bytes_sent_total{peer="...",name="..."}  cumulative bytes
ironmesh_peer_bytes_received_total{peer="...",name="..."}
ironmesh_message_lifetime_seconds{quantile="0.5"}      p50 end-to-end
ironmesh_pending_queue_dropped_total                   queue cap hits
ironmesh_peer_bandwidth_drops_total                    bandwidth cap hits
ironmesh_peer_long_drops_total                         long-drop alerts
```

Plus a compact JSON snapshot at `/api/mesh_stats` (stable schema) for
dashboards and benchmark polling.

### Retry reasons taxonomy

Every retry is tagged with a reason, exposed via `peer.retries_by_reason`:

- `direct_send_failed` — WS send raised before reaching peer
- `routed_send_failed` — mesh relay next-hop unreachable
- `queued_offline` — peer was offline, went to pending store
- `queue_full_dropped` — pending store at cap, lower priority than all queued
- `bandwidth_throttled` — per-peer bytes/sec budget exhausted
- `rekey_failed` — session key rotation errored

### Agent integrations

**MCP server** (`python -m ironmesh_mcp`) exposes 8 tools over stdio
JSON-RPC to any MCP-capable host (Claude Desktop, Claude Code, custom
clients):

- `ironmesh_list_peers`, `ironmesh_send_message`, `ironmesh_get_mesh_stats`
- `ironmesh_get_peer_stats`, `ironmesh_list_messages`, `ironmesh_get_audit_log`
- `ironmesh_trust_list`, `ironmesh_revoke_peer`

Register with Claude Desktop via `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ironmesh": {
      "command": "python",
      "args": ["-m", "ironmesh_mcp"],
      "env": {"IRONMESH_PASSPHRASE": "your-passphrase"}
    }
  }
}
```

**Trusted skills package** (`skills/ironmesh/`) for Claude Code and
compatible agents:

- `/ironmesh-status` — mesh health summary
- `/ironmesh-peers [filter]` — per-peer metrics drill-down
- `/ironmesh-send <peer> <payload> [priority]` — send a MSG
- `/ironmesh-audit [limit] [filter]` — tail the tamper-evident audit log
- `/ironmesh-trust` — list pinned peers, revoke compromised ones

### Benchmark harness

```bash
python tests/harness/mesh_bench.py \
  --target-host <peer-ip> --target-port 8764 \
  --sizes 64,256,1024 --trials 30 --chaos 0.15 \
  --output results.csv
```

Measured live on a 3-node LAN mesh (Wiz ↔ KingPi ↔ Gatekeeper):

| Payload | Delivery | p50 RTT | p95 RTT | Goodput |
|---|---|---|---|---|
| 64 B  | 100% | 12.0 ms | 74.6 ms | 6.2 KB/s |
| 256 B | 100% | 12.7 ms | 72.3 ms | 23.4 KB/s |
| 1 KB  | 100% | 13.1 ms | 78.0 ms | 76.9 KB/s |

Under `--chaos 0.25` (25% client-side drop injection), delivery rate
tracked the injection rate within 2% and p50 RTT for delivered messages
was unchanged — the retry + queue mechanisms absorb the loss cleanly.

### LoRa end-to-end measurement

Forced LoRa-only route between two RNode-equipped nodes (915 MHz,
SF8, BW125, CR5, 17 dBm TX), 1 hop, indoor:

| Payload | Delivery | RTT range | Signal |
|---|---|---|---|
| 16 B | 3/3 (100%) | 1.07 — 1.23 s | -46 dBm, +12.5 dB SNR |
| 64 B | 3/3 (100%) | 1.17 — 1.25 s | -46 dBm, +12.4 dB SNR |
| 256 B | 3/3 (100%) | 1.77 — 1.98 s | -45 dBm, +12.4 dB SNR |

See [`docs/LORA_VALIDATION.md`](LORA_VALIDATION.md) for the full
procedure and reproduction steps.

## Known limitations (please read before deploying)

- **Available on PyPI** — `pip install ironmesh` works; add `[rns]` for the LoRa/Reticulum transport.
- **Docker Hub** — `docker pull wiztheagent/ironmesh:0.7.2-beta` (also `:latest`, `:0.7.2`).
- **Docker image builds clean** but is not yet pushed to Docker Hub
- **Multi-hop LoRa goodput sweep** not yet measured (single-hop only in
  this release)
- **`install.sh` / systemd unit** have not been re-tested on a clean VM
  since the v0.7.2 code changes
- **Android client** uses Sideband + the bundled LXMF gateway — there
  is no first-party Android app planned (and LXMF is the right layer
  for that)
- **Windows service wrapper** — not shipped; run under WSL2 or foreground

## Upgrade notes from v0.7.1

No wire-protocol changes. An existing v0.7.1 peer on the LAN will
connect to a v0.7.2 peer without any config changes. The trust store
format is unchanged; the MAC is still bound to the agent's identity
key (audit C-03).

New config surface (all optional, defaults sized for LAN):

```python
# MessageStore
max_pending_per_peer: int = 1000   # 0 = unlimited (legacy)

# BridgeDaemon
_peer_bandwidth_rate = 1_048_576   # bytes/sec, 0 disables
_peer_bandwidth_burst = 1_048_576  # bytes
_peer_bandwidth_max_wait = 5.0     # sec; wait > this = drop
_long_drop_threshold_seconds = 300 # 0 disables
```

## Test suite

- **456 tests passing** (up from 430 at v0.7.1)
- 4 pre-existing failures + 16 errors from older feature changes all
  repaired
- New coverage: discovery multi-NIC, queue bounds, bandwidth throttle,
  long-drop watchdog, TokenBucket.wait_time, mesh_stats schema, MCP
  JSON-RPC loop

## Acknowledgments

- **Wiz** — the production hardening checklist that drove most of this
  release, plus the name
- **Reticulum (Mark Qvist, unsigned.io)** — the transport substrate
  that makes the LoRa/off-grid story possible
- **Sideband (unsigned.io)** — what turned a protocol into a phone app
- **libsodium / PyNaCl / websockets** — the crypto and WebSocket
  implementations IronMesh leans on

## Deferred to v0.8

- Signed capability announcements (wire-version change required)
- Circuit-breaker state persistence across restarts
- Adaptive LoRa message sizing (RNS already fragments; adding another
  layer would be double-work)
- Native Android client (Sideband + LXMF gateway is the answer for v0.7)

---

**Report issues**: https://github.com/WizTheAgent/ironmesh/issues

**License**: MIT
