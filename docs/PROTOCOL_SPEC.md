# IronMesh Wire Protocol Specification

**Version:** 4 (ironmesh/0.6 → ironmesh/0.9)
**Status:** Stable. Describes the wire format as implemented in v0.8.3
through the `ironmesh/0.9` protocol line. The binary frame envelope is
unchanged across this whole range — every v0.8.x and v0.9.x peer
remains interoperable. The `ironmesh/0.9` line changes the HELLO
contents only: a domain-separated HELLO signature, and — on the
Reticulum transport — a mandatory RNS link binding inside the signed
HELLO body. Both are version-gated with a legacy fallback so pre-0.9
peers keep working (see "HELLO signature domain separation" and
"RNS link binding" in Section 2).

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

#### Stage 1 skip on identified RNS Links (v0.9.2+, optional)

When all of the following hold, stage 1 is skipped entirely:

1. The transport is an established `RNS.Link`.
2. Both peers advertise the `hskip` feature in their RNS announces
   (`f` field of the announce app_data).
3. Both peers have opted in via `rns_skip_handshake = true` (CLI:
   `--rns-skip-handshake`).
4. The remote `RNS.Identity` has been bound to the Link (RNS provides
   this on every Link establishment).

When skipped, both sides substitute a fixed sentinel for the
`server_nonce` in subsequent stage-2 signature canonicalization:

```
SKIP_BINDING_SENTINEL = SHA-256(b"ironmesh-handshake-skip-channel-binding-v1")
                      = 32 bytes, deterministic
```

Both sides derive the same sentinel without exchanging anything; the
HELLO signature is otherwise identical. Saves three round-trips on
LoRa, where each is ~250 ms at 3.12 kbps.

**Trade-off:** the IronMesh-layer channel binding no longer binds
per-session (since the sentinel is constant). The underlying RNS
Link provides per-session integrity via its own ephemeral key
exchange, so the bind property is preserved at a lower layer. The
IronMesh-layer passphrase is also unused on the skip path — Identity
authentication via the Link replaces it. The passphrase remains the
gate on every other transport.

**Binding requirement (protocol `ironmesh/0.9`).** Because the skip
sentinel is constant, a skip-path HELLO signature would be replayable
across links without an IronMesh-layer per-session bind. As of
`ironmesh/0.9` the skip therefore additionally REQUIRES the RNS link
binding (see "RNS link binding" below): both HELLOs MUST carry a
signed `rns_link_id` matching the link they arrive on, and both sides
REFUSE the skip otherwise — a client refuses a `SKIP_OFFER` when the
connection has no verifiable link id or the server advertises a
pre-0.9 version, and a server rejects a post-skip HELLO that is
unsigned or unbound. Pre-0.9 peers cannot produce the binding, so
mixed-version meshes that enable `hskip` must either upgrade both
ends or run the full stage-1 handshake.

**Negotiation rule (v0.9.2 corrected design — server-driven).**
The server is the active party and SPEAKS FIRST. After Stage 1 begins
on an RNS Link, the server checks both peers' eligibility (RNS
identity present + remote's last-seen announce advertises `hskip` +
local opt-in). If eligible, the server emits `SKIP_OFFER` carrying
the channel-binding sentinel; otherwise it emits the legacy
`PASSPHRASE_CHALLENGE`. The client type-dispatches on the first
server message — never decides skip unilaterally:

```
SKIP_OFFER          → use channel_binding sentinel, go straight to HELLO
PASSPHRASE_CHALLENGE → full challenge / verify flow
```

This eliminates the asymmetric-decision race that would crash the
handshake when announces propagated unevenly across the mesh.

**Defense-in-depth.** The client MUST verify that the
`channel_binding` field of `SKIP_OFFER` equals
`SKIP_BINDING_SENTINEL` byte-for-byte (`hmac.compare_digest`). Any
other value — including a missing field, non-hex string, or a
32-byte alternative — MUST be rejected and the connection closed.
This blocks a downgrade-to-attacker-chosen-sentinel attack.

**Operator counters.** The reference implementation surfaces three
Prometheus counters: `ironmesh_handshake_skips_offered_total`
(server emitted SKIP_OFFER), `_activated_total` (client accepted),
`_rejected_total` (client rejected for malformed or wrong binding).
Healthy fleet sums of `offered` and `activated` should match;
divergence reveals send failures or downgrade-rejects, and any
non-zero `_rejected` rate is alert-worthy.

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
  "signature": "<Ed25519-detached-sig-b64>",
  "x25519_public_b64": "<X25519-identity-public-b64>",
  "x25519_binding_signature_b64": "<Ed25519-detached-sig-b64>"
}
```

- **ephemeral_public:** Freshly generated X25519 public key for this session (base64).
- **identity_public:** Long-lived Ed25519 identity public key (base64).
- **signature:** Ed25519 signature over the canonical HELLO bytes (see "HELLO signature domain separation" below). Binds the identity to the ephemeral key. The signature scheme is version-gated: `ironmesh/0.9+` peers use a 64-byte detached domain-separated signature; older peers use the legacy attached signature.
- **channel_binding:** The server's original nonce from Stage 1, included in the signed payload to prevent relay attacks.
- **rns_link_id (protocol `ironmesh/0.9+`, Reticulum transport only):** Hex link id of the RNS Link the HELLO travels on. Part of the signed canonical body when present (see "RNS link binding" below). MUST be absent on the WebSocket transport — receivers reject a WebSocket HELLO that carries it.
- **TOFU check:** After receiving the peer's HELLO, each side checks its trust store. If the identity key is new → pin it (TOFU). If it's changed → reject and disconnect (possible MITM).
- **x25519_public_b64 (v0.9.4+, optional, RESERVED):** Long-lived X25519 identity public key used for E2E SealedBox encryption. When present, receivers prefer this over the legacy `ed25519_to_curve25519(identity_public)` derivation. Pre-v0.9.4 receivers ignore the field. The field name is formally reserved by this spec — future versions MUST NOT repurpose it.
- **x25519_binding_signature_b64 (v0.9.4+, optional, RESERVED):** 64-byte Ed25519 detached signature of `x25519_public_b64` (raw 32 bytes, not the base64) under the `SIG_CTX_X25519_BINDING = b"ironmesh-sig-v1/x25519-identity-binding\x00"` domain-separation context. Cryptographically binds the advertised X25519 to the pinned Ed25519 identity. Receivers MUST verify this binding under the peer's `identity_public` before trusting the advertised X25519 — otherwise the field is ignored and legacy derivation runs. The field name is formally reserved.

**Wire-compat invariant.** The two `x25519_*` fields sit OUTSIDE the signed HELLO canonical body. Pre-v0.9.4 receivers reconstruct the canonical from the original 5 keys (channel_binding, ephemeral_public, identity_public, name, protocol_version) and verify the HELLO signature identically to v0.9.4. v0.9.4 senders use the same canonical body — the X25519 binding is its own Ed25519 signature, separate from the HELLO sig. Mixed v0.9.4 ⇄ v0.9.4 meshes interoperate cleanly.

### HELLO signature domain separation (protocol `ironmesh/0.9`)

**Canonical bytes.** Both signature schemes bind to the same canonical
byte sequence — the JSON serialization of exactly these five keys with
`sort_keys=True, separators=(",", ":")`, UTF-8 encoded (the same
canonicalization convention as `CAPABILITY_ANNOUNCE`, so cross-language
clients reproduce the bytes exactly):

```
{"channel_binding":"<nonce-hex>","ephemeral_public":"<b64>","identity_public":"<b64>","name":"<agent-name>","protocol_version":"ironmesh/X.Y"}
```

On the Reticulum transport, `ironmesh/0.9+` HELLOs add `rns_link_id`
as a sixth key (sorted into place by the same canonicalization); the
five-key form above remains the canonical body for the WebSocket
transport and for pre-0.9 RNS peers. See "RNS link binding" below.

The reference implementation exposes this as
`protocol.canonical_hello_bytes()`. The `channel_binding` nonce inside
the canonical body is what prevents cross-connection replay of a
captured HELLO signature; the `protocol_version` inside the body is
what makes the scheme negotiation tamper-evident (see below).

**Two schemes, version-gated:**

| Peers | Scheme |
| --- | --- |
| Both advertise `ironmesh/0.9+` | 64-byte detached Ed25519 signature over `SIG_CTX_HELLO \|\| canonical_hello_bytes`, where `SIG_CTX_HELLO = b"ironmesh-sig-v1/hello\x00"` (22 bytes incl. NUL) |
| Either peer advertises `< ironmesh/0.9` | Legacy attached Ed25519 signature (`sig \|\| message`) over `canonical_hello_bytes` |

Domain separation prevents a signature coerced from the daemon in one
protocol role (e.g. a capability announce) from being replayed as a
valid HELLO, and bounds the blast radius of any future cryptanalytic
result against a specific signed shape. This is a load-bearing property
for deployments running the default mesh-mode TLS (`CERT_NONE`), where
peer authentication rests entirely on the application-layer handshake.

**Negotiation.** Each side learns the other's version before it
verifies (and, on the server, before it signs):

1. The server advertises `protocol_version` in its first message
   (`PASSPHRASE_CHALLENGE` or `SKIP_OFFER`). The client selects its
   HELLO signing scheme from that advertisement: `0.9+` → context
   signature, otherwise legacy.
2. The client advertises `protocol_version` inside its signed HELLO
   body. The server REQUIRES the context signature from any client
   advertising `0.9+`, verifies legacy otherwise, and signs its own
   HELLO with the scheme selected by the client's advertised version.
3. The client REQUIRES the context signature on the server's HELLO
   when the server's HELLO advertises `0.9+`, legacy otherwise.

**Downgrade analysis.** The scheme selector (`protocol_version`) is
inside the signed canonical body, and the two signature forms are
mutually exclusive (a detached signature never verifies as an attached
one and vice versa). Consequences:

- Once a peer's identity key is pinned, an attacker cannot rewrite the
  advertised version, swap the signature scheme, or replay a pre-0.9
  legacy-signed HELLO (fresh nonce) without invalidating the
  signature. Tampering fails closed.
- The server's first-message advertisement is NOT signed. An active
  attacker who strips it causes a 0.9+ client to fall back to the
  legacy signature — but a 0.9+ server then rejects that HELLO,
  because the client's own signed `protocol_version` demands the
  context scheme. Between two 0.9+ peers this tampering is therefore
  denial of service, not a silent downgrade.
- **Honest limitation:** on TOFU first contact (no pinned identity,
  default `CERT_NONE` TLS), an active on-path attacker can substitute
  its own identity keys and advertise a pre-0.9 version, keeping the
  session on the legacy path — but such an attacker can equally
  impersonate the peer outright, which is the inherent TOFU
  first-contact exposure, not a weakness introduced by this
  negotiation. Operators who need to refuse legacy HELLO signatures
  entirely can raise the minimum accepted protocol version
  (`--min-protocol-version ironmesh/0.9`), which converts the fallback
  into a hard reject.

**Migration window / cross-language clients.** Clients that have not
yet implemented the context signature (the bundled TypeScript client
advertises `ironmesh/0.6`; the Go example targets the same line)
continue to interoperate through the legacy fallback — they advertise
a pre-0.9 version, so both directions of their handshakes stay on the
attached-signature path. To adopt the new scheme, a client must (all
three together): advertise `ironmesh/0.9+`, sign its HELLO with
Ed25519 over `SIG_CTX_HELLO || canonical_hello_bytes` (detached,
64 bytes), and require the same form on the peer's HELLO whenever the
peer's HELLO advertises `0.9+`. Advertising `0.9+` while still
attaching a legacy signature will be rejected by 0.9+ daemons.

### RNS link binding (protocol `ironmesh/0.9`, Reticulum transport)

Before 0.9, the HELLO's Ed25519 signature proved control of the
claimed IronMesh identity but said nothing about the RNS link it
travelled on — any holder of a valid RNS identity could open a link
and present a HELLO for an unrelated IronMesh identity, and on the
stage-1 skip path (constant sentinel) a captured HELLO signature was
replayable across links.

**Mechanism.** On RNS Links, `ironmesh/0.9+` peers include
`rns_link_id` — the lowercase hex link id of the RNS Link — both as a
top-level HELLO field and as a sixth key inside the signed canonical
body. The link id is the truncated hash of the RNS link-request
packet, observed identically by both endpoints without being
exchanged, so each receiver independently reads the id of the link
the HELLO actually arrived on and compares. It was chosen over the
RNS destination hash because it is per-session (a destination hash is
static, so it could not restore per-session binding on the skip path)
and because both sides can derive it directly from the link object
rather than from announce state.

**Receiver rules (0.9+ daemons):**

1. WebSocket transport: `rns_link_id` MUST be absent. Presence is a
   protocol violation — reject.
2. RNS, field present: MUST equal the local link's id
   (constant-time comparison); the signature MUST verify over the
   six-key canonical body. Mismatch — reject.
3. RNS, field absent: reject when the peer advertises
   `ironmesh/0.9+` (the binding is a mandatory part of the 0.9 RNS
   contract), when stage 1 was skipped, or when the operator enabled
   `--rns-require-link-binding`. Otherwise the peer is pre-0.9 and
   the legacy (unbound) behavior applies — see SECURITY.md for the
   honestly-scoped residual.
4. Stage-1 skip path: the binding is REQUIRED unconditionally and the
   HELLO MUST be signed — an unsigned or unbound post-skip HELLO is
   rejected, and a client refuses a `SKIP_OFFER` from a pre-0.9
   server or on a connection with no readable link id.

**Version gating.** The binding rides the `ironmesh/0.9` version gate
rather than a separate feature flag: the 0.9 protocol line is
introduced in the same release, so no deployed peer advertises 0.9
without the binding, and reusing the gate avoids adding a second
negotiation knob that could itself become a downgrade surface. The
advertised version sits inside the signed canonical body, so the
binding requirement inherits the same tamper-evidence as the
signature-scheme negotiation above.

**Cross-language clients.** The bundled TypeScript and Go clients are
WebSocket-only — they never produce or verify `rns_link_id` and are
unaffected. A future RNS-speaking client MUST implement this section
to advertise `ironmesh/0.9+` on an RNS Link.

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
| `SKIP_OFFER` (v0.9.2+) | Server → Client | Stage-1 skip offer carrying the channel-binding sentinel (only on identified RNS Links) |
| `GROUP_BROADCAST` (v0.9.2+) | Peer → Peer | Phase-2 cross-host fan-out of a shared-secret group broadcast payload |

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

### 4.2 Signed CAPABILITY_ANNOUNCE envelope (v0.9.4+)

`CAPABILITY_ANNOUNCE` frames carry capability advertisements. From
v0.9.4 onward, any announce whose `origin` field differs from the
delivering peer's `peer_id` MUST carry an inner Ed25519 signature so
the receiver can authenticate the announce against the origin's pinned
identity key. Direct-from-peer announces (`origin == peer_id`) without
the inner signature remain accepted for backward compatibility with
pre-v0.9.4 senders — the outer hop signature already authenticates
them.

```json
{
  "origin":       "<node-id>",
  "capabilities": ["chat", "embed", "..."],
  "announced_at": 1736812800.0,
  "version":      1,
  "signature":    "<b64 Ed25519 over canonical-bytes>"
}
```

**Canonical signing input.** The signing operation binds to the JSON
serialization of the object `{origin, capabilities, announced_at,
version}` with `sort_keys=True, separators=(",", ":")` — same
canonicalization convention used for HELLO. Cross-language client
implementations MUST reproduce these bytes exactly.

**Domain-separated signature.** The signing operation is
`Ed25519.sign(SIG_CTX_CAPABILITY_ANNOUNCE || canonical_bytes)` where
`SIG_CTX_CAPABILITY_ANNOUNCE = b"ironmesh-sig-v1/capability-announce\x00"`.
The NUL terminator is part of the context label; senders MUST include
it and verifiers MUST require it.

**Receiver MUST:**

1. Reject the announce if the body lacks `signature` AND `origin != peer_id`.
   The default action is to drop the frame, increment the
   `capability_announce_bad_signature_total` counter, and emit a
   `CAPABILITY_ANNOUNCE_BAD_SIG` audit event with `reason="missing-sig"`.
2. Look up `origin`'s pinned Ed25519 identity key. Unknown origins are
   not TOFU-pinned from the announce body — drop with
   `reason="unknown-origin"`.
3. Reject if `(time.time() - announced_at) > capability_announce_max_age`
   (default 300 s). This bounds the replay window of a stolen origin
   signature. Drop with `reason="stale"`.
4. Track `(origin, announced_at)` in an LRU. A second copy of the same
   pair inside the freshness window is a no-op (silently dropped, not
   re-applied).
5. Verify the signature. On `BadSignatureError`, drop with
   `reason="bad-sig"`.
6. On successful verification, learn the caps via the registry AND
   cache the verbatim signed envelope bytes for re-broadcast to other
   neighbors. The mesh-routed relay flow continues to converge:
   intermediate hops re-broadcast the cached envelope as-is; the next
   receiver re-verifies it.

**Mesh-routed announce trust.** The current implementation accepts a
signed envelope from any directly-connected peer (which is itself
authenticated by the per-hop SecretBox + outer signature). This is the
"yes-implicit" trust this design adopts: the immediately-relaying
peer is already trusted because the session through which the announce
arrives required TOFU. **Future NAT-relay v2 design MUST preserve this
property** — a relay node MUST NOT be able to inject a signed envelope
the receiver couldn't otherwise reach.

**No PFS for the announce signature.** Ed25519 long-term key signs.
If the origin's identity key is later compromised, historical signed
announces remain replayable inside the freshness window. Mitigation:
the revocation flow in the trust store — once a peer is revoked,
future announces with its signature are dropped at the receiver. See
`THREAT_MODEL.md` §2.

**TOFU bootstrap is out of band.** Signed-announce verification assumes the
origin's Ed25519 identity key is already pinned in the receiver's
trust store. Mesh announces are *updates* to known peer state, not
the trust-establishing channel itself. Initial TOFU pinning happens
through one of:

1. **Direct LAN handshake.** Two peers completing the v0.4 binary
   handshake on the same LAN segment pin each other's identity keys
   via the normal `PEER_CONNECT` path. Common case for home, office,
   and data-center meshes.
2. **Out-of-band trust import.** `ironmesh trust pin <node-id>
   <pubkey-b64>` lets an operator install a peer's identity key from
   any side channel — Signal, fingerprint card, secure email. See
   `OPERATOR_RUNBOOK.md` §9.
3. **Bridged transport handshake.** A peer completing a Reticulum /
   LXMF link or an `ironmesh-acp` / `ironmesh-a2a` session goes
   through the same identity exchange as the LAN path.

**Pure-LoRa or fully-disconnected mesh deployments** where peers will
never share a direct trust-establishing channel MUST rely on the
out-of-band import path. Mesh announces alone will never bootstrap a
new peer's trust — by design. An announce from an unknown origin is
dropped with `reason="unknown-origin"` and the
`capability_announce_bad_signature_total` counter ticks up. Operators
of such deployments should pin all expected origin keys before
bringing the mesh online.

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

Known versions: `ironmesh/0.3`, `0.4`, `0.5`, `0.5.1`, `0.6`, `0.7`, `0.8`, `0.9`.

The `ironmesh/0.8` line is **wire format v5**, introduced in
IronMesh v0.9.2. The wire format itself is unchanged from v4; v5
captures the optional Stage 1 skip on identified RNS Links, which
peers negotiate via the `hskip` feature flag in their RNS announces.
A v5 peer interoperates fully with v4 peers — without the announce
flag, the full Stage 1 handshake runs as before.

The `ironmesh/0.9` line activates the domain-separated HELLO
signature (see "HELLO signature domain separation" in Section 2) and,
on the Reticulum transport, the mandatory RNS link binding (see "RNS
link binding" in Section 2). The binary frame format is unchanged. A
0.9 peer interoperates fully with older peers: when either side
advertises a pre-0.9 version, the HELLO falls back to the legacy
attached signature (and, on RNS, the unbound legacy HELLO — unless
the operator enabled `--rns-require-link-binding`). When BOTH sides
advertise 0.9+, the context signature is REQUIRED in both directions,
and on RNS Links the `rns_link_id` binding is REQUIRED as well.
The server additionally advertises `protocol_version` in its Stage 1
first message (`PASSPHRASE_CHALLENGE` / `SKIP_OFFER`) so the client
can select its HELLO signing scheme before signing; daemons have
emitted this field since well before the 0.9 line, and clients that
do not understand it simply ignore it.

### Announce app_data feature flags

Peers running the Reticulum transport advertise a JSON app_data blob
in their RNS announces. The compact key set:

| Key | Type | Meaning |
| --- | --- | --- |
| `n` | string | Agent name (human-friendly) |
| `v` | string | IronMesh version (e.g. `"0.9.2"`) |
| `i` | string | IronMesh node_id (Ed25519 fingerprint) |
| `c` | list | Capability strings (truncated if app_data > 256 bytes) |
| `f` | list | Feature flags (see below) |

Feature flag values currently defined:

| Flag | Meaning |
| --- | --- |
| `mesh` | IronMesh distance-vector routing supported |
| `resource` | Peer accepts large payloads via `RNS.Resource` (>32 KB auto-routed) |
| `lxmf` | Peer hosts an LXMF gateway listener |
| `hskip` | Peer agrees to skip Stage 1 handshake on identified RNS Links |
| `group` | Peer participates in shared-secret mesh-wide broadcast (chunk B) |

Unknown flags are ignored — both sides MUST tolerate flags they
don't recognise.

### Shared-secret group broadcast key derivation (v0.9.2+)

A peer that advertises the `group` feature derives a shared
`RNS.Destination.GROUP` from the daemon passphrase via two
domain-separated HKDF-SHA256 expansions. Every peer on the mesh
runs this same derivation and lands on the identical destination
hash — no key exchange.

```
identity_material = HKDF-SHA256(
    secret = passphrase,
    salt   = b"ironmesh-group-identity-v1",
    info   = b"identity",
    length = 64,
)                                          # → fed to RNS.Identity.from_bytes()

group_key = HKDF-SHA256(
    secret = passphrase,
    salt   = b"ironmesh-group-key-v1",
    info   = b"broadcast",
    length = 32,
)                                          # → loaded as the GROUP destination's symmetric key
```

The two derivations are domain-separated (different salt + info)
so rotating one cannot leak material into the other. Cross-language
implementations MUST byte-equal the reference values in
`tests/conformance/vectors/group.identity_material_derivation.json`
and `group.symmetric_key_derivation.json`.

**Two-phase delivery.** Phase 1 sends a packet to the GROUP
destination on the local RNS segment (O(1), reaches every peer on
the same RNS Transport — e.g., one rnsd or one LoRa medium).
Phase 2 fans out a per-peer `GROUP_BROADCAST` frame over every
established IronMesh connection to peers that advertised the
`group` feature (O(N), bridges the cross-host gap because RNS
GROUP destinations cannot be `announce()`d). Receivers dedup on
SHA-256 of the payload (60-second window, 10,000-entry hard cap)
so a peer reachable via both phases handles the payload exactly
once.

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
serialization round-trip tests. Portable golden vectors for
language-agnostic conformance live in `tests/conformance/` and are
the basis of the v1.0 conformance test suite — any third-party
implementation should pass them to claim spec compliance.

### 10.1 v0.9.4 signing test vectors

The following deterministic byte sequences let cross-language clients
verify their canonicalization + signing implementations against the
reference. All fields are hex unless noted.

**Inputs (deterministic for the vector):**

| Field | Value |
|---|---|
| `ed25519_seed` | `0000000000000000000000000000000000000000000000000000000000000000` |
| `ed25519_public` | `3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29` |
| `hkdf_salt` | `0102030405060708090a0b0c0d0e0f10` |

**Derived (master-seed format):**

| Field | Value |
|---|---|
| `x25519_seed` (HKDF-SHA256, info `ironmesh-identity-x25519-v1\x00`) | `ce7108ff0eca1ceecad3694e28326172e3ee1bc42cce6b12f10decc128d090ab` |
| `x25519_public` (scalar base-mult of `x25519_seed`) | `c6dba2b75b4701f39f307f2e9b94ad2a1bcadf360936a8cc502c24c6968dca5f` |
| `binding_sig` (Ed25519 over `SIG_CTX_X25519_BINDING \|\| x25519_public`) | `36ec773252ec8cae3f53948091f0f2159b26edf449ab38f1f6c4cf17eadd340220a338caa13f3641139b038658006e9cb5c6f62001d2cb71b2debadaccb2300e` |

`SIG_CTX_X25519_BINDING = b"ironmesh-sig-v1/x25519-identity-binding\x00"` (40 bytes
including the trailing NUL).

**CAPABILITY_ANNOUNCE canonicalization + signing:**

Input announce body:

```json
{
  "origin": "alice-node",
  "capabilities": ["chat", "embed"],
  "announced_at": 1736812800.0,
  "version": 1
}
```

Canonical bytes (`sort_keys=True, separators=(",", ":")`):

```
{"announced_at":1736812800.0,"capabilities":["chat","embed"],"origin":"alice-node","version":1}
```

Hex of canonical bytes:

```
7b22616e6e6f756e6365645f6174223a313733363831323830302e302c
226361706162696c6974696573223a5b2263686174222c22656d626564
225d2c226f726967696e223a22616c6963652d6e6f6465222c22766572
73696f6e223a317d
```

(Single line on the wire; wrapped here for readability.)

Ed25519 signature under `SIG_CTX_CAPABILITY_ANNOUNCE =
b"ironmesh-sig-v1/capability-announce\x00"` (37 bytes incl. NUL):

```
e6c0239a7e5557282b8cb6ea7fdbda0f0dd049564b43602a2f16f5e8ce
fa6015c6b7ea72e8e4e9d92096e1670dba109906c06d79cdecad462e74
fac628a48107
```

A conformant cross-language implementation given the inputs above
MUST reproduce every derived value byte-for-byte.

## 11. Implementation Status by Version

This table makes it explicit when each part of the spec became part
of the contract. Anything labeled "v1.0+" is committed to under
SemVer; anything labeled v0.9.x is allowed to break with a
documented migration path until v1.0 ships.

| Section | Stable since | Notes |
| --- | --- | --- |
| Stage 1–3 handshake | v0.3 | Wire-stable since the line started |
| Binary frame format v4 | v0.4 | No breaking changes since |
| HELLO Ed25519 signature | v0.5.1 | Identity binding to ephemeral keys |
| HELLO domain-separated signature | protocol `ironmesh/0.9` | `SIG_CTX_HELLO` context signature when both peers advertise 0.9+; legacy attached fallback for older peers |
| RNS link binding | protocol `ironmesh/0.9` | `rns_link_id` inside the signed HELLO body couples the IronMesh identity to the RNS link session; required for 0.9+ RNS peers and on the stage-1 skip path |
| TOFU pinning | v0.6 | Trust store with HMAC integrity |
| Capability registry | v0.4 | Persisted with HMAC since v0.9.0 |
| Pending-trust gate | v0.8.5 | Opt-in until v1.0 (default-deny under review) |
| Reticulum transport | v0.5 | Auto-discovery via announce: v0.9.1 |
| Per-packet ratchets on RNS | v0.9.1 | Forward secrecy outside Links |
| `RNS.Resource` for >32 KB | v0.9.1 | Auto-routed when peer advertises `resource` |
| Public RNS RPC paths | v0.9.1 | `/im/info`, `/im/cap/list`, `/im/cap/find` (admin paths `/im/admin/*` are operator interfaces, not part of the v1.0 stability promise) |
| LXMF listener | v0.9.1 | Sideband / Nomadnet interop |
| Stage 1 skip on RNS Links | v0.9.2 | Opt-in, requires both peers' `hskip` advertise; server-driven `SKIP_OFFER` negotiation with sentinel-binding rejection |
| Shared-secret group broadcast | v0.9.2 | Opt-in (`--rns-group-broadcast`); two-phase delivery (RNS GROUP packet + IronMesh `GROUP_BROADCAST` fan-out); SHA-256 dedup |
| Capability-aware routing | v0.9.2 | `Agent.send_to_capability()` |
| External security audit | v1.0 | Audit results published with the release |
