# Trust Binding — Wire-Protocol Extensions for v0.9

**Status:** Accepted design. Not yet implemented. Targeted for v0.9.

This doc specifies the three wire-protocol extensions that close the
remaining trust-binding gaps flagged in
[`TRUST_BINDING.md`](TRUST_BINDING.md): transcript hashes, reconnect
continuity challenge, and deterministic session identifiers. Each
requires adding or modifying fields in the handshake or data-plane
frames, which is why they can't ship in a patch release.

## Summary of extensions

| # | Extension | What it proves | Scope of change |
|---|---|---|---|
| 1 | Deterministic session ID = H(handshake transcript) | Two peers observed the same handshake | HELLO payload: add `session_id` field |
| 2 | Rolling transcript hash in signed PING | Both peers have seen the same message history | PING: add `transcript_tip` + Ed25519 sig |
| 3 | Reconnect continuity challenge | The peer resuming is the same one that left | HELLO extension: `last_session_id` + `last_transcript_tip` |

All three extensions are **opt-in in v0.9** via HELLO-time negotiation,
**default-on in v0.9.1 or v1.0** after a minor-release soak period.
Legacy v0.8.x peers stay interoperable with v0.9 peers that have the
extensions enabled (the extensions are advertised as optional features
and skipped when the peer doesn't support them).

## Extension 1 — Deterministic session ID

### Problem

Today, each handshake produces a session that has no durable
identifier. Reconnect produces a new session; nothing ties the old
one to the new one. Dedup and continuity logic have to piece session
boundaries together from peer identity + sequence numbers.

### Design

On handshake completion, both peers compute:

```
session_id = SHA-256(
    "ironmesh-session-v1" ||       # domain separator
    client_identity_pubkey_32 ||
    server_identity_pubkey_32 ||
    client_ephemeral_pubkey_32 ||
    server_ephemeral_pubkey_32 ||
    passphrase_challenge_nonce_32 ||
    passphrase_challenge_response_mac_32
)
```

The session ID is 32 bytes, hex-encoded for display. It's
deterministic — both peers arrive at the same value — but
cryptographically bound to the full handshake transcript. Any MITM
that tampered with the handshake (e.g. a downgrade attack swapping
ephemeral keys) produces a different session ID on each side, which
is detectable.

### Wire changes

Add `session_id` to the HELLO payload:

```
HELLO:
    ephemeral_public: <32 bytes>
    identity_public:  <32 bytes>
    name:             <str>
    channel_binding:  <32 bytes>
    session_id:       <32 bytes>    # NEW in v0.9
    signature:        Ed25519(canonical_payload)
```

Servers verify the client's `session_id` matches their own
computation. Mismatch → abort handshake, emit
`HANDSHAKE_SESSION_ID_MISMATCH` audit event.

### Backwards compatibility

In v0.9, `session_id` is optional on the HELLO. A v0.8.x peer that
doesn't send it is accepted (logs a `DEPRECATION` warning). A v0.9
peer that doesn't receive it skips the verification. By v1.0, the
field is required and handshakes abort on absence.

### Benefit

- Dedup + continuity logic gains a durable key across sessions.
- Audit events can reference `session_id` instead of (node_id + time
  window) pairs.
- Opens the door to extensions 2 and 3.

## Extension 2 — Rolling transcript hash

### Problem

Within a session, peers exchange hundreds to thousands of frames.
Sequence numbers catch reorder; AEAD catches tamper. Neither catches
**selective drop**: a MITM that passes every frame except one.

### Design

Both peers maintain a per-session rolling hash:

```
H_0 = SHA-256("ironmesh-transcript-v1" || session_id)
H_i = SHA-256(H_{i-1} || frame_mac_i || direction_byte)

where direction_byte = 0x01 if frame was SENT by this peer,
                      0x02 if RECEIVED.
```

`frame_mac_i` is the existing outer MAC of the i-th frame (already
in the wire format). `direction_byte` ensures each peer's hash is
locally distinct even in symmetric sessions; both peers' final
hashes after the same N frames can be computed from either side.

Periodically (every 60 seconds, or every 1024 frames, whichever
comes first), each peer includes its current `transcript_tip` in a
PING frame:

```
PING:
    seq: <u64>
    timestamp: <u64>
    transcript_tip: <32 bytes>         # NEW in v0.9
    transcript_tip_signature: Ed25519  # over (session_id || tip)
```

On receiving PING, the peer:

1. Verifies the signature against the known peer identity.
2. Computes the **expected** tip: what the received side's hash
   would be if both sides saw the same frames.
3. If mismatch → emit `TRANSCRIPT_HASH_MISMATCH` audit event, log at
   WARN level, and optionally close the session (configurable).

### Computing the expected tip

The recipient knows its own direction-annotated rolling hash. To
verify the sender's tip, it computes what the sender's hash would
have been — a mirror-image hash with the direction bits flipped.
Both sides update in lockstep; a single dropped frame on one side
diverges permanently.

### Wire changes

PING gains two optional fields: `transcript_tip` (32 bytes) and
`transcript_tip_signature` (64 bytes). Total PING size overhead:
96 bytes. Sent at most every 60s or 1024 frames. Overhead is
negligible.

### Backwards compatibility

In v0.9, the fields are optional on PING. Absence is silently
ignored. By v1.0, at least one transcript exchange per session is
required; sessions without at least one exchange cap at 1024 frames
before disconnect.

### Benefit

- Selective drop detection: a MITM that eats one frame diverges both
  hashes; next PING exchange catches it.
- Selective injection detection: same.
- No impact on latency — the hash is computed from the MAC that's
  already been verified, not from the frame content.

## Extension 3 — Reconnect continuity challenge

### Problem

When a peer disconnects and reconnects, IronMesh today treats the
new connection as a fresh session. There's no link between the
previous session's state and the new one. A hostile peer that
hijacks the identity key (or uses a stolen key) can reconnect
without ever observing the prior session's transcript.

### Design

On reconnect, the client HELLO includes:

```
HELLO:
    ...existing fields...
    session_id:              <32 bytes>   # NEW — as Extension 1
    last_session_id:         <32 bytes>   # NEW — the prior session's ID
    last_transcript_tip:     <32 bytes>   # NEW — the prior session's final tip
    last_transcript_sig:     Ed25519      # NEW — signed by the client identity
```

The `last_*` fields are optional. Presence signals "I'm claiming
continuity with the prior session identified by `last_session_id`."

The server:

1. Looks up the stored `last_session_id` for this peer identity.
2. Verifies the signature against the peer's identity public key.
3. Compares the client's claimed `last_transcript_tip` to the
   server's stored tip from the end of that session.
4. **Match** → log `RECONNECT_CONTINUITY_VERIFIED`; server accepts
   the handshake as a continuation. Relevant session state (routing
   table entries, rate-limit counters, etc.) can be preserved.
5. **Mismatch** → log `RECONNECT_CONTINUITY_VIOLATED`; treat as a
   potential hostile key-holder. The handshake is still allowed to
   proceed (the peer has a valid identity key), but the peer is
   demoted to `pending-cap-change` regardless of prior trust state.
   Operators can review the violation and re-promote.
6. **No last_* fields** → log `RECONNECT_NO_CONTINUITY_CLAIM`; treat
   as a fresh session. This is the default for v0.8.x peers and for
   v0.9 peers that didn't opt in.

### Wire changes

Three new optional fields on HELLO. Total overhead for a reconnect
with continuity claim: 128 bytes. Negligible.

### Backwards compatibility

Fully opt-in. A v0.8.x client that never sends `last_*` fields is
indistinguishable from a v0.9 client that chose not to claim
continuity. Both are allowed. Operators who want strict continuity
can set `require_continuity_claim=True` on the daemon (v0.9.1), at
which point reconnects without a valid continuity claim are
rejected for peers that previously claimed continuity.

### Benefit

- Key-theft-without-session-theft detection: an attacker who
  exfiltrates the identity key but wasn't party to the original
  session produces `RECONNECT_CONTINUITY_VIOLATED` on first use.
- Sudden key-rotation ambiguity resolved: a legitimate key rotation
  by the peer either (a) re-uses the transcript state or (b) drops
  the continuity claim, which is distinguishable from theft.

## Negotiation

Which extensions are enabled on a given session is negotiated at
HELLO time via a new `extensions` field:

```
HELLO:
    ...
    extensions: ["session-id-v1", "transcript-hash-v1",
                 "reconnect-continuity-v1"]
```

The server responds with the intersection of its supported
extensions and the client's advertised list. Only extensions in the
intersection are active for the session. All unknown extensions are
silently ignored (unknown-extension-forward-compatibility rule).

Default enablement per version:

| Version | session-id | transcript-hash | reconnect-continuity |
|---|---|---|---|
| v0.8.x | no | no | no |
| v0.9 | opt-in (`--session-binding=optional`) | opt-in | opt-in |
| v0.9.1 | **default-on** | opt-in | opt-in |
| v1.0 | **required** | **default-on** | **default-on** |

`--session-binding=strict` on any version upgrades all three to
required; mismatches abort the handshake. Intended for closed
high-security deployments.

## Implementation sequence

1. **Extension 1** first — everything else builds on session IDs.
2. **Extension 3** second — uses session IDs, doesn't require
   transcript hashes (the `last_transcript_tip` can be 0s for a
   v0.9 peer that hasn't opted into Extension 2).
3. **Extension 2** third — most invasive; touches every frame's
   MAC-verification path.

Each extension is a separate PR with its own test surface (unit +
Hypothesis fuzz + concurrency + integration).

## Audit events (v0.9)

New audit event types:

- `HANDSHAKE_SESSION_ID_MISMATCH` — computed IDs differ; handshake
  aborted
- `TRANSCRIPT_HASH_MISMATCH` — peer's signed tip ≠ local expected
  tip
- `RECONNECT_CONTINUITY_VERIFIED` — peer claimed continuity and it
  checked out
- `RECONNECT_CONTINUITY_VIOLATED` — peer claimed continuity and it
  did not
- `RECONNECT_NO_CONTINUITY_CLAIM` — peer reconnected without a
  claim (v0.9 info event; v0.9.1+ warning if operator set strict)

All chained into the existing HMAC audit log.

## Threats in scope

- Active MITM with selective drop / inject (Extension 2)
- Identity-key theft without session-state access (Extension 3)
- Handshake downgrade attacks (Extension 1 — IDs differ if ephemeral
  keys were swapped)
- Session-hijack via reconnect-race (Extension 3 — hijacker's
  `last_transcript_tip` diverges)

## Threats NOT in scope (remain for later extensions)

- Traffic analysis / metadata leakage — addressed by Phase 8
  (mixnet, cover traffic)
- Cross-session replay — addressed by per-session key derivation,
  already in place
- Quantum adversary — requires post-quantum crypto; separate track

## Open questions

- Transcript hash: SHA-256 vs. BLAKE3? BLAKE3 is faster but adds a
  dependency. **Proposed:** SHA-256 for the wire, BLAKE3 as an
  internal optimization if profiling shows the hash is on the hot
  path (unlikely; MACs dominate).
- Reconnect continuity: should the server persist `last_transcript_
  tip` across restarts? **Proposed:** yes, in `known_peers.json`
  alongside the existing TOFU fields. Adds ~96 bytes per peer.
- Migration: v0.8.x → v0.9 upgrade path assumes no transcript history
  exists. A v0.9 peer connecting to an upgraded-from-v0.8.x server
  will get `RECONNECT_NO_CONTINUITY_CLAIM` for the first session
  regardless of prior state. **Proposed:** document this; don't try
  to reconstruct history from audit log.

## References

- RFC 8446 (TLS 1.3) — transcript hashes, session resumption
- Noise Protocol Framework — handshake-transcript-derived session
  keys
- Signal X3DH — triple DH + session identifier derivation
