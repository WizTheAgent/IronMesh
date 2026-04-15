# IronMesh v0.5 — Architecture & Protocol Specification

**Purpose**: Local-first, offline-capable, encrypted agent-to-agent communication. No cloud. No internet. No compromises.

**Origin**: Built because no existing A2A protocol works without the internet. Google A2A needs HTTPS. MCP is tool calls, not P2P. ACP can't cross machines. ANP needs DIDs and internet. IronMesh is the protocol that works when you pull the plug on your router.

**Operator**: KingPi (Raspberry Pi 5) + Wiz (Windows Gaming PC)
**Protocol Version**: 0.5.0
**Date**: 2026-04-10

---

## 1. Design Principles

1. **Local-first, always.** Everything works on a LAN with no internet. Internet is never required, not even for setup.
2. **Zero-config.** mDNS discovery + shared passphrase. No certificate authorities, no cloud accounts, no manual IP configuration.
3. **Real encryption.** NaCl/libsodium primitives. Forward secrecy via ephemeral ECDH. No "encrypt later" or "TLS is enough."
4. **Model agnostic.** IronMesh doesn't care what AI you run. Local LLMs, cloud models, scripts, IoT devices — if it speaks WebSocket, it can participate.
5. **Survive anything.** Offline queue means messages get delivered even if peers go down. Designed for unreliable networks and power outages.

---

## 2. System Architecture

```
+---------------------------+                       +---------------------------+
|         KingPi            |                       |         Wiz               |
|   Raspberry Pi 5          |      WebSocket:8765   |   Windows Gaming PC       |
|   (Self-hosted Ollama)    |<--------------------->|   (Local AI / Claude)     |
|                           |   Encrypted Channel   |                           |
|  +---------------------+  |   (XSalsa20-Poly1305) |  +---------------------+  |
|  | Bridge Daemon        |  |   Forward Secrecy     |  | Bridge Daemon        |  |
|  | (bridge.py)          |  |   (Ephemeral ECDH)    |  | (bridge.py)          |  |
|  +---------------------+  |                       |  +---------------------+  |
|  | Protocol + Frames    |  |                       |  | Protocol + Frames    |  |
|  | (protocol.py)        |  |                       |  | (protocol.py)        |  |
|  +---------------------+  |                       |  +---------------------+  |
|  | Crypto (NaCl)        |  |                       |  | Crypto (NaCl)        |  |
|  | (crypto.py)          |  |                       |  | (crypto.py)          |  |
|  +---------------------+  |                       |  +---------------------+  |
|  | mDNS Discovery       |  |   mDNS (UDP 5353)    |  | mDNS Discovery       |  |
|  | (discovery.py)       |<--_ironmesh._tcp.local--|  | (discovery.py)       |  |
|  +---------------------+  |                       |  +---------------------+  |
|  | SQLite Store         |  |                       |  | SQLite Store         |  |
|  | (store.py)           |  |                       |  | (store.py)           |  |
|  +---------------------+  |                       |  +---------------------+  |
|  | TOFU Trust           |  |                       |  | TOFU Trust           |  |
|  | (trust.py)           |  |                       |  | (trust.py)           |  |
|  +---------------------+  |                       |  +---------------------+  |
+---------------------------+                       +---------------------------+
```

---

## 3. Module Structure

| File | Purpose |
|------|---------|
| `__init__.py` | Package metadata, version, public API exports |
| `crypto.py` | ECDH key exchange, SecretBox encrypt/decrypt, Ed25519 signing, detached signatures, secure_wipe |
| `keys.py` | Ed25519 identity keygen, X25519 ephemeral keygen, save/load with Argon2id (mandatory encryption by default) |
| `protocol.py` | MessageType enum, Frame binary wire format (with Ed25519 signatures), ReplayGuard, TokenBucket, PeerState, Handshake, MessageBus (immutable data passing) |
| `bridge.py` | Main daemon: WebSocket server, auth flow, ECDH handshake, binary frame message routing, offline queue, metrics, token-authenticated GUI dashboard, audit logging, mDNS fingerprint pinning, auth failure IP blocking |
| `discovery.py` | mDNS/Zeroconf service announce + listener with rate limiting and TXT record size validation |
| `store.py` | Async SQLite message store with encrypted payloads (SecretBox), schema migrations, offline queue, peer metadata, parameterized queries |
| `trust.py` | TOFU (Trust-On-First-Use) peer key pinning with agent-key-derived HMAC |
| `transport.py` | Transport abstraction layer (WebSocket now, TCP/QUIC/LoRa later) |
| `reticulum_transport.py` | Reticulum (LoRa) transport — `RNSLinkAdapter` (duck-typed WebSocket over RNS Link) + `ReticulumTransport` lifecycle manager. Optional dependency (`rns`). |
| `hooks.py` | Hook/plugin system with circuit breaker (auto-unregister after 3 consecutive failures) |
| `config.py` | Centralized configuration with file/env loading |
| `cli.py` | CLI entry point with subcommands: run, trust, keys. Passphrase via file/env/getpass only (no CLI argv). |
| `audit.py` | Tamper-evident HMAC-SHA256 chained audit log for all security events |

---

## 4. Cryptographic Primitives

All from **PyNaCl** (libsodium). No custom crypto.

| Primitive | Algorithm | Purpose |
|-----------|-----------|---------|
| **Key Exchange** | X25519 ECDH (ephemeral) | Derive per-session shared secret. Forward secrecy. |
| **Symmetric Encrypt** | XSalsa20-Poly1305 (SecretBox) | Encrypt all messages after handshake |
| **Identity/Signing** | Ed25519 | Agent identity, message integrity verification |
| **Auth** | HMAC-SHA256(passphrase, nonce) | Mutual pre-auth gate. Both sides prove knowledge. Constant-time comparison. |
| **Key file protection** | Argon2id KDF + SecretBox | Encrypt secret keys at rest |

**Key distinction from v2.1**: Identity keys (Ed25519) are now used ONLY for identity/signing. ECDH uses ephemeral X25519 keys generated per session. This gives true forward secrecy — compromising identity keys cannot decrypt past sessions.

---

## 5. Handshake Flow (v0.3 — Ephemeral ECDH)

### Stage 1: Mutual Passphrase Authentication

```
Client (A)                                    Server (B)
   |                                              |
   |<----- PASSPHRASE_CHALLENGE ------------------| (32-byte random nonce)
   |        "protocol_version": "ironmesh/0.3"  |
   |                                              |
   |------ proof = HMAC-SHA256(pass, nonce) ----->|
   |                                              |
   |<----- PASSPHRASE_VERIFIED ------------------| + server_proof = HMAC-SHA256(pass, nonce[::-1])
   |        verify server_proof (mutual auth)     |
   |                                              |
   |  (on failure at any step: close connection)  |
```

### Stage 2: Signed Ephemeral ECDH Key Exchange (with Channel Binding)

```
   |------ HELLO (signed Ed25519) ------------------>|
   |        ephemeral_public: <X25519 pub A>         |
   |        identity_public:  <Ed25519 pub A>        |
   |        name: "kingpi"                           |
   |        channel_binding: <auth_nonce.hex()>      |
   |        signature: Ed25519(canonical_payload)     |
   |                                                 |
   |   Server: verify signature, TOFU check,         |
   |   derive peer_id from identity key fingerprint  |
   |                                                 |
   |<----- HELLO (signed Ed25519) -------------------|
   |        ephemeral_public: <X25519 pub B>         |
   |        identity_public:  <Ed25519 pub B>        |
   |        name: "wiz"                              |
   |        channel_binding: <auth_nonce.hex()>      |
   |        signature: Ed25519(canonical_payload)     |
   |                                                 |
   |   Client: verify signature, TOFU check,         |
   |   derive peer_id from identity key fingerprint  |
   |                                                 |
   | session_key = ECDH(eph_priv_A, eph_pub_B)      |
   | (eph_priv_A deleted from memory)                |
   |                                                 |
   |       session_key = ECDH(eph_priv_B, eph_pub_A) |
   |       (eph_priv_B deleted from memory)           |
```

### Stage 3: Encrypted + Signed Messages

All subsequent messages use SecretBox(session_key) for encryption AND Ed25519 for mandatory signatures. Messages include monotonic sequence numbers (seq > 0) for replay protection. Plaintext or unsigned messages are rejected.

---

## 6. Security Features

| Feature | Implementation |
|---------|---------------|
| Mutual authentication | HMAC-SHA256 passphrase proof — both client AND server prove knowledge |
| Binary wire format | Compact binary frames with Ed25519 detached signatures on every frame |
| Mandatory message signing | Ed25519 detached signature on every binary frame — unsigned/bad-sig frames rejected |
| Channel binding | Auth nonce embedded in ECDH HELLO signature, binding auth to key exchange |
| Forward secrecy | Ephemeral X25519 keys per session, destroyed after ECDH (secure_wipe) |
| Replay protection | Monotonic seq numbers (seq=0 rejected) + 30s timestamp window per peer |
| TOFU key pinning | Ed25519 key pinned on first use; mismatch = **immediate disconnect** (not warning) |
| mDNS fingerprint pinning | After handshake, peer address is pinned — rejects mDNS announcements from different addresses |
| Trust store integrity | HMAC-SHA256 (derived from agent identity key) protects known_peers.json against tampering |
| Derived peer IDs | peer_id = fingerprint of Ed25519 identity key (128-bit), not self-reported |
| Rate limiting | Per-peer token bucket + per-IP connection throttling + auth failure IP blocking (3 fails = 5-min ban) |
| mDNS default-deny | Auto-connect disabled unless `--allowed-peers` or `--open-discovery` specified. Rate-limited discovery events. |
| mDNS privacy | Identity keys never broadcast — exchanged only during authenticated handshake |
| Message size limits | Configurable max (default 1MB) |
| Mandatory key encryption | Argon2id KDF + SecretBox for keys at rest. Plaintext keys auto-migrate to encrypted on startup. |
| Encrypted storage | SQLite message payloads encrypted with SecretBox (key derived from passphrase) |
| Tamper-evident audit log | HMAC-SHA256 chain records all security events. Any tampering breaks the chain. |
| GUI token auth | Dashboard requires per-session bearer token for `/metrics`, `/api/state`, `/ws` endpoints |
| Longer fingerprints | 32 hex chars (128 bits) for collision resistance |
| TLS-first connections | Client tries wss:// before ws://. Plaintext fallback requires explicit `--allow-plaintext-ws` |
| Immutable hook/bus context | Hook and MessageBus callbacks receive frozen (read-only) MappingProxyType data |
| Hook circuit breaker | Failing hook callbacks auto-unregistered after 3 consecutive failures |
| Required passphrase | No default — IronMesh refuses to start without a passphrase (min 12 chars) |
| Passphrase OPSEC | `--passphrase` removed from CLI (leaks in `ps aux`). File, env var, or getpass only. |

---

## 7. Offline Message Queue

When a peer is offline:
1. Outbound messages saved to SQLite `pending_messages` table
2. On peer reconnect, all pending messages flushed in priority order (CRITICAL > HIGH > NORMAL > LOW)
3. Messages older than 24h purged by cleanup loop
4. Messages also prunable by age: `store.prune_old(days=30)`

---

## 8. mDNS Discovery

Service type: `_ironmesh._tcp.local.`

When a bridge starts, it registers:
- Service name: `{agent_name}._ironmesh._tcp.local.`
- Port: 8765 (configurable)
- TXT records: `agent`, `port`, `proto` (no pubkey — identity keys are exchanged only during authenticated handshake)

The `AgentListener` handles `ServiceStateChange.Added`, `Updated`, and `Removed` events with proper enum comparison and callback support.

---

## 9. Web GUI Dashboard & Metrics

The bridge daemon can run a web dashboard on `port + 1` (e.g., `http://127.0.0.1:8766/`). The GUI is **disabled by default** (opt-in with `--gui`). A single `websockets.serve()` instance handles both HTTP and WebSocket connections using `process_request`:

| Path | Method | Auth | Description |
|------|--------|------|-------------|
| `/` | GET | No | Serves embedded HTML dashboard (dark-themed, no external files) |
| `/metrics` | GET | **Token** | Backward-compatible metrics JSON (same format as legacy) |
| `/api/state` | GET | **Token** | Full state snapshot: metrics + peers + message history |
| `/ws` | WS | **Token** | Real-time event feed + send commands |

**Security:** The GUI binds to `127.0.0.1` only (localhost). A unique `secrets.token_urlsafe(32)` bearer token is generated per session and printed in the startup banner. All sensitive endpoints require the token via `?token=` query parameter or `Authorization: Bearer` header. The HTML page at `/` is served without auth (the page itself is not sensitive — the API endpoints it calls require the token).

**Enable:** Pass `--gui` to start the dashboard. It is off by default.

### Dashboard Features

- **Metrics cards** — Uptime, active peers, messages sent/received, bytes, handshakes, rate limits
- **Peer table** — Node ID, address, status (with color dots), verified flag, sent/received counts, latency
- **Real-time message feed** — Scrolling log with timestamps, direction arrows, message type, peer, payload
- **Send form** — Select peer, choose message type, type payload, send via Enter or button click

### WebSocket Protocol (GUI <-> Server)

**Server -> Client:**

| type | data | trigger |
|------|------|---------|
| `snapshot` | full state (metrics + peers + history) | on WS connect |
| `state_update` | full state | every 2 seconds |
| `message_event` | peer_id, msg_type, payload, timestamp | on bus events |
| `peer_event` | event (connected/disconnected), peer_id | on peer connect/disconnect |
| `send_ack` | msg_id | after successful send_message |
| `send_error` | error string | on send failure |

**Client -> Server:**

| action | params | effect |
|--------|--------|--------|
| `send_message` | to_node, msg_type, payload | Encrypts and sends via daemon.send_message() |
| `get_history` | peer_id (optional), limit | Queries SQLite message store |
| `refresh` | -- | Re-sends full state snapshot |

### Metrics JSON (backward compatible)

`GET /metrics` returns:

```json
{
  "uptime_seconds": 3600.0,
  "messages_sent": 142,
  "messages_received": 138,
  "bytes_sent": 45000,
  "bytes_received": 43000,
  "active_peers": 1,
  "total_peers": 2,
  "handshake_successes": 3,
  "handshake_failures": 0,
  "rate_limits_triggered": 0,
  "connections_total": 5
}
```

---

## 10. Hook/Plugin System

```python
from ironmesh.hooks import HookManager, HookPoint

hooks = HookManager()

@hooks.register(HookPoint.POST_RECEIVE)
async def log_messages(context):
    print(f"Received {context['msg_type']} from {context['peer_id']}")

@hooks.register(HookPoint.ON_PEER_CONNECT)
async def on_connect(context):
    print(f"New peer: {context['peer_name']}")
```

Hook points: `PRE_SEND`, `POST_RECEIVE`, `ON_PEER_CONNECT`, `ON_PEER_DISCONNECT`, `ON_HANDSHAKE_COMPLETE`, `ON_ERROR`

---

## 11. Dependencies

```
websockets>=12.0
aiosqlite>=0.19.0
pynacl>=1.5.0
zeroconf>=0.80.0
```

Dev: `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `mypy`

---

## 12. Launch Commands

**KingPi (Raspberry Pi 5):**
```bash
# Set passphrase via file (never appears in process list)
echo "YOUR_SHARED_SECRET" > ~/.ironmesh/passphrase && chmod 600 ~/.ironmesh/passphrase
export IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase

ironmesh run --name kingpi --port 8765 --allowed-peers wiz --gui
```

**Wiz (Gaming PC):**
```bash
export IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase
ironmesh run --name wiz --port 8765 --allowed-peers kingpi --gui
```

The passphrase must match on both sides. A passphrase is required (minimum 12 characters) — IronMesh will not start without one. The `--passphrase` CLI flag was removed for OPSEC (visible in `ps aux`). Use `--passphrase-file`, `IRONMESH_PASSPHRASE_FILE`, or interactive `getpass` prompt.

---

## 13. Peer State Machine

```
                    +-------------+
                    |   OFFLINE   |
                    +------+------+
                           | WS CONNECT
                    +------v------+
                    | CONNECTING  |
                    +------+------+
                           | PASSPHRASE AUTH
                    +------v------+
                    | HANDSHAKING |<-- KEY_ROTATE (re-handshake)
                    +------+------+
                           | ECDH COMPLETE
                    +------v------+
               +--->|   ONLINE    |<-- Flush pending queue
               |    +------+------+
               |           | HEARTBEAT TIMEOUT / ERROR
               |    +------v------+
               |    |   OFFLINE   |
               |    +------+------+
               |           | AUTO-RECONNECT (15s)
               +-----------+
```

---

## 14. Version Compatibility Matrix

| Feature | v0.3 | v0.4 | v0.5 | v0.5.1 | v0.5.2 | v0.6.0 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Binary frame + mandatory encryption | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Ed25519 detached signatures | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| TOFU key pinning | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Per-IP rate limiting + auth ban | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Mesh routing (multi-hop) | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| E2E SealedBox for relayed messages | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| Capability discovery | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| Audit log with HMAC chain + rotation | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| Reticulum (LoRa) transport | — | — | ✓ | ✓ | ✓ | ✓ |
| RNS Buffer/Channel reliable framing | — | — | — | ✓ | ✓ | ✓ |
| Transport failover (WS ↔ RNS) | — | — | — | ✓ | ✓ | ✓ |
| RTT measurement (heartbeat) | — | — | — | — | ✓ | ✓ |
| Session key rotation (in-session REKEY) | — | — | — | — | ✓ | ✓ |
| LoRa QoS / compression | — | — | — | — | ✓ | ✓ |
| Signed revocation broadcast | — | — | — | — | — | ✓ |
| mDNS `idhash` hint | — | — | — | — | — | ✓ |
| Jittered exponential backoff | — | — | — | — | — | ✓ |
| Protocol version rejection | — | — | — | — | — | ✓ |
| Encrypted backup/restore | — | — | — | — | — | ✓ |
| Signed audit log export | — | — | — | — | — | ✓ |
| Frame parser fuzzing | — | — | — | — | — | ✓ |

### Interoperability

- **Drop-in upgrade**: v0.6 peers negotiate with v0.3/0.4/0.5 peers; the
  minimum common feature set is used.
- **Hard floor**: `--min-protocol-version ironmesh/0.4` refuses v0.3 peers.
  Default floor remains `ironmesh/0.3` for maximum compat.
- **REKEY is silent on older peers**: a v0.6 node skips rekey for peers
  below v0.5 (`_peer_supports_rekey`).
- **REVOCATION is silent on older peers**: message is dropped by v0.3/0.4
  peers; v0.6 nodes still apply locally to block the revoked node from
  connecting to them.
- **LoRa compression flag**: `routing["compressed"]` is set only for
  v0.5.2+ RNS peers.

### Upgrade Path

1. Back up keys + trust + audit: `ironmesh backup --out node.imb`
2. Upgrade the package on each node
3. Restart the bridge — peers re-handshake automatically
4. Verify connectivity with `ironmesh trust list` and the dashboard
5. Once all peers are v0.6+, raise `--min-protocol-version ironmesh/0.5`
   to enforce modern features

---

*IronMesh v0.6 — Local-first encrypted A2A protocol — No cloud, no internet, no compromises.*
