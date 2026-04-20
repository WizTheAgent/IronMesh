# IronMesh Wire Protocol Specification

**Version:** 4 (ironmesh/0.6)
**Status:** Stable. Describes the wire format as implemented in v0.8.3 (unchanged from v0.8.2).

This specification is the canonical reference for implementing IronMesh
in any language. The Python implementation in `protocol.py` and `bridge.py`
is the reference; this document formalizes what it does.

## 1. Transport Layer

IronMesh runs over any bidirectional byte stream. Supported transports:

| Transport | Default port | Negotiation |
|---|---|---|
| WebSocket (ws:// or wss://) | 8765 | Client dials; server listens |
| Reticulum (LoRa/RNS) | N/A (hash-based) | Buffer/Channel bidirectional stream |

The protocol is transport-agnostic. Any channel that delivers ordered,
reliable byte streams works. The framing described below sits on top.

## 2. Handshake

The handshake has three stages. All stages run over plaintext JSON
messages on the WebSocket/stream. Binary frames begin only after
stage 3 completes.

### Stage 1: Passphrase Authentication (mutual)

```
Client                              Server
  │                                   │
  │◄── PASSPHRASE_CHALLENGE ──────────│  {"type":"PASSPHRASE_CHALLENGE","nonce":"<32-byte-hex>"}
  │                                   │
  │─── PASSPHRASE_RESPONSE ──────────►│  {"type":"PASSPHRASE_RESPONSE","proof":"<hmac-hex>"}
  │                                   │
  │◄── PASSPHRASE_VERIFIED ──────────│  {"type":"PASSPHRASE_VERIFIED","server_proof":"<hmac-hex>"}
  │    (client verifies server_proof) │
```

- **Server nonce:** 32 bytes of cryptographic randomness, hex-encoded.
- **Client proof:** `HMAC-SHA256(passphrase_utf8, nonce_bytes)`, hex-encoded.
- **Server proof:** `HMAC-SHA256(passphrase_utf8, reversed(nonce_bytes))`, hex-encoded. Provides mutual authentication — the client verifies the server also knows the passphrase.
- **On failure:** Server sends `{"type":"PASSPHRASE_REJECTED"}` and closes.

### Stage 2: Identity Exchange (HELLO)

```
Client                              Server
  │                                   │
  │─── HELLO ────────────────────────►│
  │◄── HELLO ─────────────────────────│
```

HELLO payload (JSON, signed with Ed25519):

```json
{
  "type": "HELLO",
  "ephemeral_public": "<X25519-public-b64>",
  "identity_public": "<Ed25519-public-b64>",
  "name": "<agent-name>",
  "protocol_version": "ironmesh/0.6",
  "capabilities": ["llm:llama3", "tool:filesystem"],
  "channel_binding": "<nonce-hex>",
  "signature": "<Ed25519-detached-sig-b64>"
}
```

- **ephemeral_public:** Freshly generated X25519 public key for this session (base64).
- **identity_public:** Long-lived Ed25519 identity public key (base64).
- **signature:** Ed25519 detached signature over the canonical JSON of the HELLO body (sorted keys, no whitespace). Binds the identity to the ephemeral key.
- **channel_binding:** The server's original nonce from Stage 1, included in the signed payload to prevent relay attacks.
- **TOFU check:** After receiving the peer's HELLO, each side checks its trust store. If the identity key is new → pin it (TOFU). If it's changed → reject and disconnect (possible MITM).

### Stage 3: ECDH Key Agreement

Both sides independently compute:

```
shared_secret = X25519(my_ephemeral_private, peer_ephemeral_public)
```

- The shared secret is 32 bytes.
- Ephemeral private keys are destroyed immediately after derivation.
- The shared secret is used as the NaCl `SecretBox` key for all subsequent frames.

After Stage 3, all communication switches to the **binary wire format** below.

## 3. Binary Frame Format (v4)

All post-handshake messages are binary frames. No plaintext JSON is
accepted after the handshake completes.

```
Offset  Size   Field
──────  ─────  ─────────────────────────────────────
0       2      Magic: 0xE7F6
2       1      Version: 4
3       1      Flags (bitfield)
4       8      Sequence number (uint64, big-endian)
12      8      Timestamp (uint64, milliseconds since epoch, big-endian)
20      8      msg_id hash (first 8 bytes of SHA-256 of msg_id string)
28      4      Encrypted payload length (uint32, big-endian)
32      N      Encrypted payload (NaCl SecretBox)
32+N    64     [Optional] Ed25519 detached signature over encrypted payload
```

**Total header size:** 32 bytes (fixed).
**Minimum frame size:** 32 + encrypted_payload_length.

### Flags (byte at offset 3)

| Bit | Mask | Name | Meaning |
|---|---|---|---|
| 0 | 0x01 | HIGH_PRIORITY | Priority escalation |
| 1 | 0x02 | CRITICAL_PRIORITY | Highest priority |
| 2 | 0x04 | ENCRYPTED | Payload is SecretBox-encrypted (mandatory after handshake) |
| 3 | 0x08 | SIGNED | 64-byte Ed25519 signature appended after payload |

**FLAG_ENCRYPTED must always be set** for post-handshake frames. A frame
without FLAG_ENCRYPTED is rejected immediately.

### Encrypted Payload

The encrypted payload is a NaCl `SecretBox` (XSalsa20-Poly1305) ciphertext.
When decrypted, it produces a JSON object:

```json
{
  "type": "MSG",
  "from": "<source-node-id-32hex>",
  "msg_id": "<32-hex-random>",
  "payload": "<base64-of-application-payload>",
  "destination": "<dest-node-id-32hex>",
  "ttl": 5,
  "hops": 0,
  "priority": "NORMAL",
  "e2e_payload": "<base64-of-sealed-box>",
  "source_signature": "<base64-of-64-byte-Ed25519-sig>"
}
```

**Fields:**
- `type`: Message type (see Section 4).
- `from`: Source node_id (SHA-256 of Ed25519 public key, truncated to 32 hex chars).
- `msg_id`: 16 random bytes, hex-encoded (128-bit, cryptographically random).
- `payload`: Application data, base64-encoded bytes.
- `destination`: Target node_id (for direct delivery) or empty (for the connected peer).
- `ttl`: Time-to-live hop count for mesh routing (decremented per relay).
- `hops`: Number of hops traversed so far.
- `priority`: `"CRITICAL"`, `"HIGH"`, `"NORMAL"`, or `"LOW"`.
- `e2e_payload`: Optional NaCl SealedBox ciphertext for end-to-end encryption through relays. Only the final destination can open it.
- `source_signature`: Optional Ed25519 signature over the plaintext `payload` bytes, produced by the original source. Survives per-hop re-encryption by relays.

### Outer Signature (when FLAG_SIGNED is set)

The 64-byte Ed25519 signature at the end of the frame covers the
**encrypted payload bytes** (not the header, not the plaintext). This is
per-hop authentication — each relay can verify the frame came from the
previous hop, but cannot read the contents.

## 4. Message Types

| Type | Direction | Purpose |
|---|---|---|
| `HELLO` | Bidirectional | Identity exchange (Stage 2) |
| `MSG` | Peer → Peer | Application message |
| `PING` | Either | Heartbeat probe |
| `PONG` | Either | Heartbeat response |
| `ACK` | Recipient → Sender | Delivery acknowledgment |
| `ERROR` | Either | Error notification |
| `KEY_ROTATE` | Either | Request re-handshake |
| `REKEY_REQUEST` | Initiator → Responder | In-session key rotation |
| `REKEY_RESPONSE` | Responder → Initiator | New ephemeral public key |
| `CAPABILITY_ANNOUNCE` | Any → Mesh | Advertise local capabilities |
| `CAPABILITY_QUERY` | Any → Mesh | Search for capabilities |
| `ROUTE_ANNOUNCE` | Any → Mesh | Distance-vector routing update |
| `GOODBYE` | Either | Graceful disconnect |
| `CONV` (v0.8.2+) | Peer → Peer | Structured multi-turn conversation frame |

### 4.1 CONV envelope (v0.8.2+)

A `CONV` frame's payload is a UTF-8 JSON object ("envelope") used for
multi-turn agent-to-agent dialogue. Every turn carries enough context
that the receiver can enforce caps and the orchestrator can route
without its own state.

```json
{
  "v": 1,
  "conv_id": "8f3c2a1b",
  "turn": 0,
  "max_turns": 5,
  "kind": "prompt",
  "body": "the actual prompt or response text",
  "reply_to": "<msg_id of the preceding message>",
  "from_role": "security-analyst",
  "to_role": "network-engineer",
  "budget": { "max_seconds": 60, "max_bytes": 16384 },
  "end_reason": ""
}
```

**Required fields**

| Field | Type | Meaning |
|---|---|---|
| `v` | int | Envelope version. Receivers MUST accept `v=1`. |
| `conv_id` | string | Opaque, non-empty identifier for the conversation. |
| `kind` | enum | `prompt`, `response`, `end`, or `error`. |
| `body` | string | The human-readable turn content. For `end`/`error`, a short reason. |

**Optional fields**

| Field | Meaning |
|---|---|
| `turn` | Non-negative integer turn counter. 0 = the seed prompt. |
| `max_turns` | Cap enforced by every participant. Receiver MUST send a `kind="end"` / `end_reason="turn-limit"` frame if it gets a frame with `turn >= max_turns > 0` and refrain from calling its model. |
| `reply_to` | The `msg_id` of the frame this replies to. |
| `from_role` / `to_role` | Human-readable role labels (see `ironmesh.roles`). Not cryptographically bound. |
| `budget.max_seconds` / `budget.max_bytes` / `budget.max_tokens` | Optional caps. Any participant that has run past one of them SHOULD end the conversation with `end_reason="budget-exceeded"`. |
| `end_reason` | One of `turn-limit`, `goal-achieved`, `budget-exceeded`, `error`. Only meaningful on `kind="end"`. |

**Termination**

A CONV exchange ends when any of the following happens:

1. A participant sends a frame with `kind="end"` (graceful).
2. Turn cap reached: the next recipient responds with `kind="end"` / `end_reason="turn-limit"` instead of invoking its model.
3. Budget exceeded: any participant that tracks budget state sends `kind="end"` / `end_reason="budget-exceeded"`.
4. Smart termination: the LLM's reply starts with `[DONE] <reason>`; the bridge strips the marker and emits `kind="end"` / `end_reason="goal-achieved"`.
5. Error: the model returned an `[LLM-ERR]` string, or the envelope failed validation; bridges send `kind="error"`.

**Forward compatibility**

Unknown top-level keys MUST be preserved on round-trip by any
library-level parser so a future field added by an updated peer
doesn't silently drop. See `ironmesh.conversation.ConvEnvelope.extra`
for the Python reference implementation.

**Legacy `[CONV:id:turn/max]` prefix**

Prior to v0.8.2 conversation state was carried as a magic prefix on
ordinary `MSG` payloads. The v0.8.2 `llm_bridge.py` still accepts that
form for one release so older orchestrators keep working; all newly
written code should emit a real CONV frame.

## 5. Cryptographic Primitives

| Operation | Algorithm | Library |
|---|---|---|
| Symmetric encryption | XSalsa20-Poly1305 (NaCl SecretBox) | libsodium / PyNaCl |
| Key agreement | X25519 ECDH | libsodium / PyNaCl |
| Identity signatures | Ed25519 | libsodium / PyNaCl |
| Passphrase proof | HMAC-SHA256 | stdlib |
| msg_id generation | 16 bytes from CSPRNG | `nacl.utils.random(16)` |
| Key fingerprint | SHA-256(Ed25519_public)[:16] (32 hex chars) | stdlib |
| Trust store MAC | SHA-256(agent_key + "ironmesh-trust-store-v1") | stdlib |
| Audit log chain | HMAC-SHA256 per entry, chained | stdlib |

### End-to-End Encryption (SealedBox)

For multi-hop mesh routing, the `e2e_payload` field carries a NaCl
`SealedBox` ciphertext. The sender derives a Curve25519 public key from
the destination's Ed25519 identity key, seals the plaintext, and stores
it in `e2e_payload`. Relay nodes cannot decrypt this — only the final
destination can unseal it using its own Curve25519 private key
(converted from Ed25519).

### Session Key Rotation (REKEY)

To maintain forward secrecy across long sessions, the node with the
lexicographically smaller `node_id` periodically initiates a rekey:

1. Initiator sends `REKEY_REQUEST` with a new X25519 ephemeral public key.
2. Responder replies with `REKEY_RESPONSE` containing their new ephemeral public key.
3. Both sides compute a new shared secret via ECDH and replace the session key.
4. Old session key is securely wiped.

Default interval: 1800 seconds (30 minutes).

## 6. Node Identity

- **node_id:** `SHA-256(Ed25519_public_key_bytes)[:32]` — 32 hex characters.
- **Fingerprint:** Same as node_id. Used in TOFU pinning, routing tables, and mDNS.
- **Agent name:** Human-readable name (e.g. "alice", "bob"). Not cryptographically bound — used for mDNS discovery, the simultaneous-dial tie-breaker, and display. Advertised in the HELLO frame's `name` field and persisted on `PeerState.agent_name` after handshake (v0.8.1+).

## 7. Replay Protection

Each peer maintains a per-peer monotonic sequence counter:

- Sender increments `next_send_seq` before each frame.
- Receiver tracks `last_recv_seq` per peer.
- Frames with `sequence <= last_recv_seq` are rejected (replay).
- Sequence 0 is never valid for post-handshake frames.
- Frames with timestamps older than 30 seconds or more than 10 seconds in the future are rejected.

## 8. Protocol Version Negotiation

Both HELLO messages include a `protocol_version` string (e.g. `"ironmesh/0.6"`).
Each side compares `MAJOR.MINOR`:

- Same MAJOR + MINOR ≥ peer's: fully compatible.
- Same MAJOR + MINOR < peer's: compatible at the lower version's feature set.
- Different MAJOR: incompatible; disconnect.

Known versions: `ironmesh/0.3`, `0.4`, `0.5`, `0.5.1`, `0.6`.

## 9. Implementing in Another Language

To build a minimal IronMesh client (not a full daemon):

1. **Open a WebSocket** to the daemon's port (ws:// or wss://).
2. **Stage 1:** Read `PASSPHRASE_CHALLENGE`, compute HMAC proof, send `PASSPHRASE_RESPONSE`, verify `PASSPHRASE_VERIFIED`'s server_proof.
3. **Stage 2:** Generate an ephemeral X25519 keypair + an Ed25519 identity keypair. Send HELLO (JSON, signed). Read peer's HELLO. TOFU-pin the peer's identity key.
4. **Stage 3:** Compute `X25519(my_eph_private, peer_eph_public)`. Destroy ephemeral private key.
5. **Send messages:** Build a Frame (Section 3), encrypt payload with SecretBox(shared_secret), sign if desired, send as a WebSocket binary message.
6. **Receive messages:** Read binary WebSocket message, parse header, decrypt payload with SecretBox, verify signature if present.

The Go reference client at `clients/go/` implements exactly this flow.

## 10. Test Vectors

See `tests/test_conformance.py` and `tests/test_protocol.py` for
serialization round-trip tests. A portable test-vector JSON file is
planned for v0.9.
