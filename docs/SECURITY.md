# IronMesh Security Model

## Why Security Matters Here

IronMesh exists so you can run AI agents that communicate on **your** network without depending on corporate infrastructure. That means the security can't depend on corporate infrastructure either. No certificate authorities, no cloud key management, no "trust us" from a vendor. The crypto has to be solid, local, and verifiable.

The cryptographic primitives come from libsodium (via PyNaCl), the same library used by Signal, WireGuard, and many other projects. Nothing homebrew, nothing exotic.

## Threat Model

IronMesh is designed for **networks you control** — home LANs, lab networks, off-grid setups, air-gapped subnets. It provides defense-in-depth against realistic threats in those environments.

### What IronMesh protects against

| Threat | Defense |
|--------|---------|
| **Passive eavesdropping** | All messages encrypted with XSalsa20-Poly1305 (authenticated encryption) |
| **Message tampering** | Poly1305 MAC detects any modification — tampered messages are rejected |
| **Replay attacks** | Monotonic sequence numbers + 30-second timestamp window |
| **Unauthorized devices** | Mutual passphrase authentication — both client AND server prove knowledge of the shared secret |
| **Identity spoofing** | TOFU (Trust-On-First-Use) key pinning — connection **immediately terminated** if a peer's identity key changes (not just logged) |
| **Message forgery** | Mandatory Ed25519 signatures on every message — unsigned or bad-signature messages are rejected |
| **Session key compromise** | Forward secrecy — ephemeral X25519 keys per session, private keys destroyed after handshake |
| **Handshake downgrade** | Channel binding — authentication nonce embedded in ECDH handshake signature, cryptographically binding the two stages |
| **Key file theft** | Mandatory Argon2id passphrase encryption for key files at rest. Plaintext keys auto-migrate to encrypted on startup. |
| **Identity spoofing via self-reported IDs** | Peer ID derived from cryptographic fingerprint of identity key (128-bit), not self-reported |
| **Connection floods** | Per-IP rate limiting (token bucket) throttles excessive connections. Auth failure blocking: 3 failed attempts from an IP = 5-minute ban. |
| **mDNS spoofing** | Default-deny auto-connect (requires `--allowed-peers` or `--open-discovery`). Fingerprint pinning after successful handshake rejects mDNS address changes for known peers. Rate-limited discovery events. |
| **Trust store tampering** | HMAC-SHA256 integrity protection on known_peers file (key derived from agent identity key) — any tampering detected and rejected |
| **Data at rest** | SQLite message payloads encrypted with SecretBox (key derived from passphrase). No plaintext stored. |
| **Audit trail tampering** | Tamper-evident HMAC-SHA256 chain audit log. Each entry's HMAC covers the previous entry's HMAC. Any insertion, deletion, or modification breaks the chain. |
| **GUI exploitation** | Dashboard disabled by default (opt-in `--gui`). When enabled, requires per-session bearer token for all API/WebSocket endpoints. |
| **Passphrase exposure** | `--passphrase` removed from CLI (visible in `ps aux`). Passphrase via file, env var, or interactive getpass only. |
| **Information leaks** | Version banner only shows protocol version; identity keys never broadcast via mDNS — exchanged only during authenticated handshake |
| **Wire sniffing** | Binary wire format (not JSON) after handshake. Client tries wss:// before ws://. Plaintext fallback requires explicit flag. |
| **Relay reading message bodies** (v0.4) | Multi-hop messages are wrapped in a NaCl `SealedBox` keyed to the destination's X25519 public key. Relays cannot decrypt the body. |
| **Relay forging messages** (v0.4) | Inner Ed25519 signature over the plaintext (computed by the source's identity key, carried inside the encrypted body) survives every per-hop re-encryption and is verified at the destination. |
| **Routing loops** (v0.4) | TTL counter (default 5 hops) plus explicit hop-list inspection drops any frame that re-enters a relay it has already visited. |
| **Dedup cache exhaustion** (v0.4) | Per-source-sharded cache: 128 sources × 1024 entries × 5min TTL. A flooding source cannot displace other sources' state. |
| **Route announcement poisoning** (v0.4) | Routes are tagged with `learned_from` and expire after `route_ttl`. Split horizon + poisoned reverse prevent two-hop loops. |
| **Capability spoofing** (v0.4) | Capability announcements are signed (via the same per-frame Ed25519 signing). A node cannot claim capabilities on behalf of another node — the registry silently ignores `learn_remote(self_node_id, ...)`. |
| **Audit log rotation tampering** (v0.4) | Each rotated archive carries its own HMAC chain, anchored to the previous archive's tail HMAC via a fresh `EVENT_LOG_ROTATED` entry at the start of each new file. `verify_chain_across_archives()` walks the entire history. |

### What requires additional measures

| Threat | Notes |
|--------|-------|
| **Physical access to a node** | An attacker with physical access can extract keys from disk. Use full-disk encryption and passphrase-protected key files. |
| **Fully compromised host** | If your machine is owned, all bets are off. IronMesh protects the wire, not the endpoint. |
| **Volumetric DDoS** | Rate limiting helps but can't prevent a determined flood. Use firewall rules. |
| **Traffic analysis** | Message sizes and timing are visible. We don't pad or obfuscate. |
| **Active MITM on first connection** | TOFU trusts the first key it sees. If an attacker intercepts the very first connection, they can pin their key. Verify fingerprints out-of-band for high-security setups. |
| **Mesh metadata analysis** (v0.4) | A relay can see source, destination, msg_id, timestamp, and message type. It cannot read bodies, but it can profile traffic patterns. If anonymity is required, run `--mesh-routing=off` and form trusted cliques with `--allowed-peers`. |
| **Adversarial relay drop** (v0.4) | A malicious relay can simply drop your messages. The circuit breaker tracks failed deliveries and `EVENT_CIRCUIT_BREAKER_TRIPPED` audit events surface chronic offenders, but IronMesh cannot route around an adversarial relay without an alternate topology. |
| **Compromised destination key** (v0.4) | End-to-end confidentiality fails if the destination's long-term Ed25519 secret is exfiltrated. Forward secrecy of `SealedBox` (per-message ephemeral X25519) only protects past messages if those ephemerals were also discarded — they are never persisted in IronMesh. |

## v0.4 Mesh Trust Model

> **Important:** v0.4 ships with `--mesh-routing=relay` enabled by default,
> meaning your node will forward traffic on behalf of other agents on the
> mesh. This is a deliberate trust shift compared to v0.3's pure
> point-to-point model. Read this section before deploying.

### What relays can and cannot see

| Visible to a relay | Hidden from a relay |
|---|---|
| `frame.source` (originator's node id) | The decrypted message body |
| `frame.destination` (final recipient) | The inner Ed25519 source signature contents |
| `frame.msg_id` and timestamp | The original `MessageType` semantic payload |
| The wire `MessageType` (e.g. `MSG`, `CONTROL`) | |
| The encrypted `e2e_payload` ciphertext | |

### How end-to-end confidentiality works

When a message is sent via `BridgeDaemon.send_message(to_node, payload)`,
IronMesh:

1. Looks up the destination's pinned Ed25519 identity key.
2. Derives the destination's X25519 public key via libsodium's blessed
   `crypto_sign_ed25519_pk_to_curve25519`.
3. Wraps the plaintext in a NaCl `SealedBox` (one fresh ephemeral X25519
   keypair per message — forward secrecy).
4. Stores the sealed ciphertext in `Frame.e2e_payload`.
5. Computes an Ed25519 detached signature over the **plaintext** using
   the source's identity key, and stores it in `Frame.source_signature`.
6. Hands the frame to `MeshRouter.relay_message()` (or sends directly if
   the destination is a neighbor).

Each relay along the path:

1. Decrypts the *outer* SecretBox payload with its session key with the
   previous hop and verifies the per-hop Ed25519 signature.
2. Inspects `frame.destination`. If it is not the relay itself, the
   relay decrements `ttl`, appends its own node id to `hops`, and
   re-encrypts the frame with the next-hop session key.
3. The `e2e_payload` and `source_signature` fields are forwarded
   untouched.

The destination:

1. Decrypts the outer per-hop wrap.
2. Decrypts `e2e_payload` with its X25519 secret (derived from its own
   Ed25519 secret).
3. Verifies `source_signature` against the source's pinned identity key.
4. Hands the plaintext to the application bus.

If `e2e_payload` cannot be set (the destination's identity key is
unknown to the source), IronMesh falls back to per-hop encryption only
and emits a warning. In that mode, relays would technically be able to
read the body — operators who require strict end-to-end confidentiality
should pre-pin destination keys via TOFU.

### Operating with mesh routing disabled

If your threat model includes "I do not trust my mesh peers not to drop
or analyze my traffic", run with `--mesh-routing=off` and form a closed
clique with `--allowed-peers`. In that mode, IronMesh behaves identically
to v0.3 — direct WebSocket sessions only, no routing table, no relay
forwarding.

## Cryptographic Primitives

All from **PyNaCl** (libsodium bindings). No custom crypto.

| Purpose | Algorithm | Why |
|---------|-----------|-----|
| Key exchange | X25519 ECDH | Industry standard for key agreement. Used by WireGuard, Signal. |
| Message encryption (per-hop) | XSalsa20-Poly1305 (SecretBox) | Authenticated encryption. Fast, misuse-resistant, well-audited. |
| Message encryption (e2e, v0.4) | NaCl SealedBox (ephemeral X25519 + XSalsa20-Poly1305) | Forward-secret per-message ephemeral keys. Relays cannot read forwarded bodies. |
| Identity/signing | Ed25519 | Fast, secure, compact signatures. |
| Inner source signature (v0.4) | Ed25519 detached over plaintext | Survives per-hop re-encryption. Provides end-to-end source authenticity. |
| Ed25519 → X25519 conversion (v0.4) | libsodium `crypto_sign_ed25519_*_to_curve25519` | Lets us reuse the existing identity key for sealing. The blessed conversion path. |
| Passphrase auth | HMAC-SHA256(passphrase, nonce) | Mutual challenge-response. Both sides prove knowledge. Constant-time comparison prevents timing attacks. |
| Key file encryption | Argon2id KDF + SecretBox | Memory-hard KDF resists GPU/ASIC brute force. |
| Fingerprinting | SHA-256 (first 32 hex chars = 128 bits) | Peer identification. Longer fingerprints resist collision attacks. |
| Trust store integrity | HMAC-SHA256 | Detects tampering with known_peers file. |
| Audit log integrity | HMAC-SHA256 chain (with cross-rotation anchors in v0.4) | Append-only tamper evidence; verifiable across log rotation events. |

## Key Management

### Identity Keys (Ed25519)
- Generated once per agent, persisted to `~/.ironmesh/keys.json`
- Used for identity verification and message signing
- Can be passphrase-protected with Argon2id (recommended for sensitive deployments)
- Key rotation triggers re-handshake with all connected peers

### Ephemeral Keys (X25519)
- Brand new keypair generated for **every** WebSocket connection
- Used solely for ECDH shared secret derivation
- Private key is deleted from memory immediately after the shared secret is computed
- Never written to disk, never reused
- This is what gives IronMesh forward secrecy — even if your identity key is compromised later, past session traffic can't be decrypted

### Session Keys
- 32-byte shared secret derived from ephemeral ECDH
- Used as the SecretBox key for all messages in the session
- Unique per connection — reconnecting generates entirely new session keys
- Cleared from memory on disconnect

## Authentication Flow

### Mutual Passphrase Authentication

```
1. Server generates 32-byte random nonce
2. Server sends nonce to client (plaintext — this is not a secret)
3. Client computes HMAC-SHA256(passphrase, nonce) and sends the hash as proof
4. Server computes the same HMAC and compares using hmac.compare_digest() (constant-time)
5. Match → Server sends PASSPHRASE_VERIFIED + server_proof = HMAC-SHA256(passphrase, reversed_nonce)
6. Client verifies server_proof (mutual authentication — server proves it also knows the passphrase)
7. Mismatch at any step → connection closed
```

The passphrase is never sent over the wire. The nonce prevents replay. The reversed nonce for server proof provides domain separation (client and server proofs are different). HMAC-SHA256 (not bare SHA-256) prevents length-extension attacks.

### Signed Key Exchange with Channel Binding

```
8.  Client sends HELLO: ephemeral X25519 public + Ed25519 identity public
    - Signed with Ed25519: canonical JSON includes channel_binding = auth_nonce.hex()
9.  Server verifies client HELLO signature + TOFU check on identity key
10. Server sends HELLO: ephemeral X25519 public + Ed25519 identity public
    - Signed with Ed25519: same channel_binding field
11. Client verifies server HELLO signature + TOFU check
12. Both derive session key: ECDH(my_ephemeral_private, their_ephemeral_public)
13. Ephemeral private keys destroyed. Encrypted communication begins.
```

Channel binding (step 8, 10) cryptographically ties the ECDH handshake to the authentication stage. An attacker who bypasses passphrase auth can't splice in a different ECDH exchange.

### Peer ID Derivation

After handshake, the peer's identity is derived from their Ed25519 public key fingerprint (128-bit SHA-256 prefix), not from any self-reported field. This prevents identity spoofing.

## TOFU (Trust-On-First-Use)

Works like SSH known_hosts, but **enforced** — not just a warning:

1. First time you connect to a peer → their Ed25519 identity public key is saved to `~/.ironmesh/known_peers.json` (HMAC-protected)
2. Every subsequent connection → the identity key is compared against the stored one
3. If it matches → trusted, proceed normally
4. If it doesn't match → **connection is immediately terminated.** An ERROR frame is sent to the peer, the WebSocket is closed, and all peer state is cleaned up. This is not a warning — it's enforcement.

The trust store file is integrity-protected with HMAC-SHA256. If the file is tampered with (e.g., an attacker adds an entry), the MAC check fails and the entire store is rejected.

You can manage trust via the CLI:
```bash
ironmesh trust list           # See all pinned peers
ironmesh trust revoke <id>    # Remove a peer's pinned key
```

For high-security setups, verify peer fingerprints out-of-band (e.g., read them to each other over the phone) before the first connection.

## Hardening Recommendations

1. **Use a strong passphrase.** A passphrase is **required** — minimum 12 characters enforced. IronMesh refuses to start without one.
2. **Use passphrase files, not env vars.** Set `IRONMESH_PASSPHRASE_FILE` pointing to a `chmod 600` file. Env vars are visible via `/proc/environ`. The `--passphrase` CLI flag was removed entirely (visible in `ps aux`).
3. **Key files are encrypted by default.** Argon2id-protected. If you have legacy plaintext keys, they auto-migrate to encrypted on next startup (as long as a passphrase is available).
4. **Restrict peer discovery.** Use `--allowed-peers kingpi,wiz` to only connect to named agents. Default-deny blocks all mDNS auto-connect unless `--allowed-peers` or `--open-discovery` is set.
5. **Keep the GUI off unless needed.** Dashboard is disabled by default. Enable with `--gui`. When enabled, all endpoints require the per-session bearer token printed at startup.
6. **Bind to specific interfaces.** Use `--bind 192.168.1.50` instead of the default `0.0.0.0` to limit exposure.
7. **Firewall the WebSocket port.** Only allow connections from your LAN. `ufw allow from 192.168.0.0/24 to any port 8765`
8. **Use TLS/WSS for defense in depth.** `--tls-cert /path/to/cert.pem --tls-key /path/to/key.pem` (TLS 1.2+ enforced, no compression, server cipher preference). Client-side connections try wss:// first.
9. **Use full-disk encryption** on any machine running IronMesh, especially Raspberry Pis that could be physically stolen.
10. **Monitor the audit log.** Security events are logged to `~/.ironmesh/audit.log` with tamper-evident HMAC chain. Verify integrity periodically.
11. **Keep PyNaCl updated.** The crypto is only as good as the library implementing it.
12. **Verify fingerprints out-of-band** for high-security setups, especially before the first connection to a new peer.

## What IronMesh does NOT do

- **Does not anonymize you.** Your IP is visible to peers on the LAN. This is a local protocol, not Tor.
- **Does not phone home.** No telemetry, no analytics, no update checks. It's your software on your network.
- **Does not require internet.** Not now, not ever. If it needs the internet, it's failed its mission.
- **Does not trust any third party.** No CAs, no cloud KMS, no vendor APIs. The only trust is the passphrase you share and the keys you verify.
