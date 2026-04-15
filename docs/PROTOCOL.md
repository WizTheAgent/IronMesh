# IronMesh Protocol Specification

**Protocol identifier:** `ironmesh/0.6`
**Document version:** v0.6 (2026-04)
**Status:** Reference specification
**License:** MIT (same as the project)

## Version and Compatibility

The protocol identifier follows `ironmesh/MAJOR.MINOR`.  Peers exchange
this string in the HELLO message during handshake.  Features are
negotiated per-capability, not per-MAJOR.MINOR — a v0.6 peer can still
communicate with v0.3 peers using only the features both understand.

### Feature gates by version

| Feature | Introduced | Negotiation |
|---|---|---|
| Binary wire format, mandatory encryption | 0.3 | Baseline |
| Multi-hop mesh routing | 0.4 | Peer advertises in HELLO |
| End-to-end SealedBox over relays | 0.4 | Sender wraps when destination key known |
| Capability discovery | 0.4 | CAPABILITY_ANNOUNCE messages |
| Reticulum/LoRa transport | 0.5 | Transport-layer, transparent to protocol |
| In-session session rekey (REKEY_REQUEST/REKEY_RESPONSE) | 0.5 | Skipped silently for peers < 0.5 |
| Signed revocation broadcast (REVOCATION) | 0.6 | Dropped by peers < 0.6 |
| mDNS `idhash` hint | 0.6 | Optional TXT field; ignored by older peers |
| LoRa QoS compression (`routing["compressed"]`) | 0.5.2 | Only applied to RNS transport peers |

### Version rejection

An implementation MAY refuse connections from peers below a
configurable minimum via `--min-protocol-version ironmesh/X.Y` (default
`ironmesh/0.3`).  Refusal occurs after the HELLO is parsed and before
the peer is added to the active peer list.

## Conformance

A compatible implementation must pass the invariants in
[`tests/test_conformance.py`](../tests/test_conformance.py).  These
tests cover:

- Frame magic bytes (`0xE7F6`)
- Version byte (3 or 4+)
- Mandatory `FLAG_ENCRYPTED` on all frames after handshake
- Ed25519 detached signature when `FLAG_SIGNED` is set
- Monotonic sequence numbers (seq=0 rejected post-handshake)
- 30-second replay timestamp window
- Handshake order and mutual HMAC-SHA256 passphrase proof
- Channel binding (server_nonce echoed in signed HELLO)
- TOFU behavior (new/trusted/mismatch/revoked)

## Wire Format

### Frame Header (32 bytes) + Optional Signature (64 bytes)

```
Offset  Size  Field           Description
0       2     magic           0xE7F6 (constant)
2       1     version         Protocol version (4 in v0.4; 3 still accepted from legacy peers)
3       1     flags           Bit flags (see below)
4       8     sequence        Monotonic sequence number (uint64 big-endian)
12      8     timestamp       Millisecond UNIX timestamp (uint64 big-endian)
20      8     msg_id          SHA-256(msg_id)[:8] — first 8 bytes of hash (full UUID in encrypted payload)
28      4     payload_len     Encrypted payload length (uint32 big-endian)
32      var   payload         Encrypted payload (SecretBox ciphertext)
32+N    64    signature       Ed25519 detached signature over encrypted payload (when FLAG_SIGNED set)
```

### Flags

| Bit | Name              | Description |
|-----|-------------------|-------------|
| 0   | HIGH_PRIORITY     | Message is high priority |
| 1   | CRITICAL_PRIORITY | Message is critical priority |
| 2   | ENCRYPTED         | Payload is SecretBox ciphertext |
| 3   | SIGNED            | 64-byte Ed25519 detached signature appended after payload |

**Note on msg_id:** The 8-byte msg_id in the header is `SHA-256(full_uuid)[:8]`, not a raw truncation. This preserves entropy for collision resistance. The full UUID is available in the decrypted JSON payload.

**Note on signatures:** When FLAG_SIGNED is set, a 64-byte Ed25519 detached signature follows immediately after the encrypted payload. The signature covers the encrypted payload bytes directly (not the header), binding the signature to the exact ciphertext received. This prevents any payload substitution. Frames received with FLAG_SIGNED but no verify key are rejected.

### Encrypted Payload

When ENCRYPTED flag is set, the payload is a NaCl SecretBox ciphertext:
- 24-byte nonce prepended to ciphertext
- Decrypted payload is JSON:

```json
{
  "type": "MSG",
  "payload": "<base64>",
  "msg_id": "abc12345",
  "source": "<fingerprint>",
  "source_display": "node-a",
  "destination": "<fingerprint>",
  "timestamp": 1234567890.123,
  "priority": "NORMAL",
  "sequence": 42,
  "retries": 0,
  "routing": {},
  "ttl": 3,
  "hops": [],
  "source_signature": "<base64 v0.4 inner Ed25519 sig>",
  "e2e_payload": "<base64 v0.4 NaCl SealedBox ciphertext>"
}
```

### v0.4 Frame additions

The two optional fields `source_signature` and `e2e_payload` carry the
end-to-end authenticity and confidentiality layer. Relays MUST forward
both fields untouched. Only the destination decrypts `e2e_payload` (using
its own X25519 secret derived from its Ed25519 identity) and verifies
`source_signature` against `frame.source`'s pinned identity key.

| Field | Type | Set by | Read by | Survives re-encryption |
|---|---|---|---|---|
| `source_signature` | Ed25519 detached sig (64 bytes, base64) | Original source | Destination | Yes |
| `e2e_payload` | NaCl SealedBox ciphertext (base64) | Original source | Destination | Yes |
| outer SecretBox payload | per-hop session key | Each relay | Next hop | No (re-encrypted at every hop) |
| outer Ed25519 signature | per-hop sender | Next hop | Next hop | No (re-signed at every hop) |

## Handshake Sequence

### Stage 1: Passphrase Authentication

```
Server -> Client: {
  "type": "PASSPHRASE_CHALLENGE",
  "from": "<server_fingerprint>",
  "nonce": "<hex_encoded_32_bytes>",
  "protocol_version": "ironmesh/0.3"
}

Client -> Server: {
  "type": "PASSPHRASE_CHALLENGE",
  "from": "<client_fingerprint>",
  "proof": "<hex_hmac_sha256(passphrase, nonce)>"
}

Server -> Client: {
  "type": "PASSPHRASE_VERIFIED",
  "from": "<server_fingerprint>",
  "status": "verified",
  "server_proof": "<hex_hmac_sha256(passphrase, reversed_nonce)>"
}

Client verifies server_proof using hmac.compare_digest (mutual authentication).
```

### Stage 2: Signed Ephemeral ECDH Key Exchange (with Channel Binding)

Both HELLO messages are **signed with Ed25519** and include **channel binding** to the auth stage.

The canonical payload for signing is compact, sorted JSON:
```json
{"channel_binding":"<auth_nonce_hex>","ephemeral_public":"<b64>","identity_public":"<b64>","name":"<name>","protocol_version":"ironmesh/0.3"}
```

```
Client -> Server: {
  "type": "HELLO",
  "from": "<client_fingerprint>",
  "name": "wiz",
  "ephemeral_public": "<base64_x25519_public>",
  "identity_public": "<base64_ed25519_public>",
  "protocol_version": "ironmesh/0.3",
  "signature": "<base64_ed25519_signature_of_canonical_payload>"
}

Server verifies:
  1. Ed25519 signature over canonical payload (including channel_binding)
  2. TOFU check on identity_public (pin on first use, reject on mismatch)
  3. Derive peer_id from identity_public fingerprint (not from "from" field)

Server -> Client: {
  "type": "HELLO",
  "from": "<server_fingerprint>",
  "name": "kingpi",
  "ephemeral_public": "<base64_x25519_public>",
  "identity_public": "<base64_ed25519_public>",
  "protocol_version": "ironmesh/0.3",
  "signature": "<base64_ed25519_signature_of_canonical_payload>"
}

Client verifies signature + TOFU check (same as server).
```

Both sides compute: `shared_secret = ECDH(my_ephemeral_private, their_ephemeral_public)`

Ephemeral private keys are destroyed after this step (forward secrecy).

### Stage 3: Binary Encrypted + Signed Message Loop

All subsequent messages use the **binary wire format** (not JSON). Each frame consists of:
1. 32-byte header (magic, version, flags, sequence, timestamp, msg_id hash, payload length)
2. Variable-length SecretBox ciphertext (encrypted JSON payload)
3. 64-byte Ed25519 detached signature (when FLAG_SIGNED is set)

The encrypted payload, when decrypted, is JSON:

```json
{
  "type": "MSG",
  "payload": "<base64>",
  "msg_id": "550e8400-e29b-41d4-a716-446655440000",
  "source": "<fingerprint>",
  "timestamp": 1234567890.123,
  "sequence": 42
}
```

**Legacy JSON format** is still accepted for backward compatibility during migration, but all new messages are sent as binary frames.

**Mandatory constraints after handshake:**
- `FLAG_ENCRYPTED` must be set — plaintext frames are rejected
- `FLAG_SIGNED` must be set — unsigned frames are rejected
- Ed25519 detached signature must verify against the encrypted payload bytes
- `sequence` must be > 0 (seq=0 is rejected) and monotonically increasing
- Timestamp must be within 30 seconds of receiver's clock

## Message Types

| Type | Direction | Description |
|------|-----------|-------------|
| PASSPHRASE_CHALLENGE | Both | Passphrase auth proof |
| PASSPHRASE_VERIFIED | Server->Client | Auth succeeded |
| PASSPHRASE_REJECTED | Server->Client | Auth failed |
| HELLO | Both | Key exchange + identity |
| GOODBYE | Both | Graceful disconnect |
| MSG | Both | Application message |
| ACK | Both | Message acknowledgment |
| PING | Both | Keep-alive |
| PONG | Both | Keep-alive response |
| ERROR | Both | Error notification |
| KEY_ROTATE | Both | Identity key changed |
| REQ | Both | Request (correlated) |
| RESP | Both | Response (correlated) |
| HEARTBEAT | Both | Health check |
| HEALTH | Both | Health report |
| DISCOVER | Both | Peer discovery |
| DISCOVER_RESP | Both | Discovery response |
| RATE_LIMITED | Server->Client | Rate limit notification |
| PEER_INFO | Both | Detailed info (post-auth only) |
| SYS | Both | System command |
| ROUTE_ANNOUNCE | Both | v0.4 — distance-vector routing table announcement |
| ROUTE_UNREACHABLE | Both | v0.4 — destination unreachable from this hop |
| CAPABILITY_ANNOUNCE | Both | v0.4 — advertised capability set from a node |
| CAPABILITY_QUERY | Both | v0.4 — query for capabilities matching a glob pattern |

### v0.4 message schemas

```jsonc
// ROUTE_ANNOUNCE
{
  "origin": "<announcer node id>",
  "routes": [
    { "destination": "<node id>", "cost": 2, "next_hop": "<node id>" },
    ...
  ],
  "sequence_number": 17
}

// ROUTE_UNREACHABLE
{
  "destination": "<node id>",
  "original_msg_id": "<uuid>",
  "reason": "no_route" | "ttl_expired" | "loop_detected"
}

// CAPABILITY_ANNOUNCE
{
  "origin": "<advertising node id>",
  "capabilities": ["llm:llama3", "tool:filesystem", ...],
  "sequence_number": 4
}

// CAPABILITY_QUERY
{
  "pattern": "llm:*"
}
```

## Security Properties

### Forward Secrecy
- New X25519 ephemeral keypair per WebSocket connection
- Ephemeral private key zeroed after ECDH derivation
- Session key never written to disk
- Compromise of identity keys does not reveal past session content

### Replay Protection
- Monotonic sequence numbers per peer per session
- Sequence 0 is **rejected** — all post-handshake messages must have seq > 0
- 30-second timestamp window (rejects older or future frames)
- Per-peer sliding window of recent sequence numbers (1024)

### Mandatory Message Signing
- Every message after handshake must include an Ed25519 signature over the encrypted payload
- Messages without a signature are rejected
- Messages with an invalid signature (wrong key) are rejected
- The signing key is the sender's Ed25519 identity key

### TOFU (Trust-On-First-Use)
- On first connection, peer's Ed25519 identity key is pinned (trust store protected by HMAC-SHA256)
- On subsequent connections, identity key is compared
- Key mismatch → **connection immediately terminated** (ERROR frame sent, WebSocket closed, peer state cleaned up)
- Trust can be revoked via CLI: `ironmesh trust revoke <node_id>`

### Rate Limiting
- Per-peer: 100 msg/sec burst, 20 msg/sec sustained (token bucket)
- Per-IP: connection throttling for new connections from the same source
- Per-server: 10 new connections per minute
- Max message size: 1 MB (configurable)

## Mesh Routing (v0.4)

IronMesh v0.4 implements proactive distance-vector routing with split
horizon, poisoned reverse, TTL loop prevention, and per-source-sharded
dedup. Each node periodically broadcasts a `ROUTE_ANNOUNCE` to its direct
neighbors containing its filtered routing table. Nodes learn routes,
expire them after `route_ttl`, and forward messages whose `destination`
field is not their own node id. Forwarded frames have their `ttl`
decremented and the relay's node id appended to `hops`. A frame is
dropped (and an `EVENT_ROUTE_LOOP` audit event emitted) if the relay
itself appears in `hops`.

See `docs/MESH.md` for full detail.

## End-to-end Encryption (v0.4)

The original source wraps the plaintext payload in a NaCl `SealedBox`
keyed to the destination's X25519 public key (derived from its Ed25519
identity via libsodium's `crypto_sign_ed25519_pk_to_curve25519`). The
sealed ciphertext is carried in the new `e2e_payload` field. Relays
forward this field opaquely; only the destination — which holds the
matching X25519 secret — can decrypt it.

The original source also computes an Ed25519 detached signature over the
plaintext payload bytes using its own long-term identity key. This
*inner* signature is carried in `source_signature` and verified at the
destination against the source's pinned identity key. Because both
fields live inside the encrypted body and are never modified by relays,
they survive every per-hop re-encryption.

## Versioning

- Protocol version in HELLO: `ironmesh/0.4` (v0.3 peers still accepted)
- Wire format version in frame header: `4` (v0.3 frames with version `3` still accepted from legacy peers)
- v0.3 peers remain interoperable for direct messaging. They are NOT
  used as relays — `ROUTE_ANNOUNCE` is not sent to them and any frame
  whose next-hop has `supports_mesh = False` falls back to the offline
  queue if no direct path exists.
- Breaking changes increment the major version
- Peers MUST reject frames with unsupported version numbers
