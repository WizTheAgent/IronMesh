# NAT Traversal Design — IronMesh (deferred)

**Status:** *Accepted design, implementation deferred.* Dated
2026-04-16. This document is a finished design proposal; it's on the
roadmap under "Later" ([docs/ROADMAP.md](ROADMAP.md)) but is not
currently being built. Priority shifted to polish + audit work for
the v0.8.x line before adding WAN support.

When implementation resumes, no re-design is expected — this doc is
the starting point.

**Goal:** let two IronMesh agents on different LANs — behind consumer
routers, carrier-grade NAT, or corporate firewalls — talk to each other
without a single public IP between them, while preserving every
security property of the current LAN-only deployment.

Today (v0.8.3) IronMesh runs fine on a single LAN because mDNS + direct
WebSocket dial is enough. It falls over the moment both peers are
behind NAT and neither has a routable public `ip:port`. This design
fixes that.

---

## 1. Requirements

| # | Requirement | Why |
|---|---|---|
| R1 | Two peers behind NAT must be able to exchange encrypted messages | Core goal |
| R2 | The solution must NOT require either peer to own a public IP | Home users, LoRa gateways, laptops on coffee-shop WiFi |
| R3 | The solution may introduce an **operator-run** public node, but that node must **not** be able to read payloads | Trust boundary is unchanged: only the two peers hold the session key |
| R4 | Existing LAN-only deployments must keep working unchanged | Backwards compat, zero-config still wins |
| R5 | Configuration burden on the end user is at most one flag | Matches the "zero-config" brand |
| R6 | Latency penalty ≤ ~50 ms above a direct connection when the relay is well-placed | Acceptable for agent messaging; not acceptable for real-time audio, but that's not our use case |
| R7 | Any new messages on the wire must be encrypted + authenticated + replay-protected | Same as every other IronMesh message |
| R8 | Protocol version negotiated; older peers don't break | `ironmesh/0.6` → `ironmesh/0.7`; feature-gated at peer level |
| R9 | Observable from the existing metrics + dashboard | Ops visibility for relay load, hole-punching success rate |

---

## 2. Options considered

### Option A — Pure relay

One or more nodes run in **relay mode**. Every NATted peer opens an
outbound WebSocket to a relay and registers its identity. When peer X
wants to reach peer Y:

1. X's daemon checks whether it has a direct (LAN) route to Y.
2. If not, it looks up Y in the relay's registry.
3. X sends the encrypted frame to the relay, tagged with Y's `node_id`.
4. The relay forwards the frame to Y over Y's already-open outbound
   connection.

The relay never holds a session key and never sees plaintext — it's a
dumb forwarder for `SealedBox` ciphertext.

**Pros**

- Works 100% of the time as long as both peers have outbound
  connectivity (even captive portals, symmetric NAT, CGN).
- Simple mental model; simple code.
- Existing `MeshRouter` is already a distance-vector forwarder —
  mostly a matter of letting it accept a relay peer as a gateway.

**Cons**

- Everything pays one extra hop of latency, even when hole-punching
  would have worked.
- The relay is a metadata target (who talks to whom, how much).
- The relay is a bandwidth / CPU centralization point; needs ops
  attention.

### Option B — Pure STUN + hole-punching

Peers discover their mapped `ip:port` using a STUN server. A
coordinator exchanges those mappings. Both peers then dial each other
simultaneously; most NATs see the outbound from each side, punch a
hole, and the inbound arrives on that existing mapping.

**Pros**

- Lowest latency once the hole is punched.
- No central forwarder; no metadata target.

**Cons**

- Fails on **symmetric NAT** (~10-20% of home routers, almost 100% of
  carrier-grade NAT, most corporate firewalls). That's a lot of users.
- Still requires SOME public infrastructure (STUN + coordinator).
- Implementation complexity: full STUN RFC 5389, NAT-type detection,
  synchronized dial timing, keep-alives.
- No graceful fallback if hole-punching fails — the conversation just
  never starts.

### Option C — **Hybrid** (chosen)

Try hole-punching first (Option B). If it doesn't succeed within N
seconds, fall back to relay (Option A). Encapsulate both paths behind
one `ConnectionType` enum the rest of the bridge doesn't care about.

**Pros**

- Best latency when hole-punching works (~70% of real-world pairs).
- Always succeeds because relay is the guaranteed backstop.
- One code path above the transport layer; `send_message()` doesn't
  change.

**Cons**

- Most code. But the STUN + relay pieces are mostly independent, so we
  can still ship in the order "relay first, STUN second."
- Slightly more complex observability — we now care about which path
  a given peer is using.

**Choice:** Option C. User explicitly approved hybrid. Ship order:
1. Relay path (covers 100% of cases, gets us functional WAN support fast).
2. STUN hole-punching layered on top (latency optimization).

---

## 3. Architecture

```
┌────────────────┐       public internet        ┌────────────────┐
│  Peer A (NAT)  │                              │  Peer B (NAT)  │
│                │                              │                │
│  wiz           │ ----- STUN query ----->      │  relay-registered │
│                │<---- mapped ip:port ----     │                │
│                │                              │                │
│                │ ─── simultaneous dial ──>    │                │
│                │                              │                │
│                │ ← direct encrypted session   │                │
│                │   (if hole-punch succeeds)   │                │
│                │                              │                │
│                │     OR                       │                │
│                │                              │                │
│                │ ─── RELAY_FORWARD ─────>     │                │
│                │         │                    │                │
└────────────────┘    ┌────v─────────┐          └────────────────┘
                      │ ironmesh-relay │
                      │ (public host) │
                      └────────────────┘
```

### Components

**`ironmesh/nat.py`** (new module)

- `STUNClient` — minimal RFC 5389 client. One public method:
  `async get_mapped_endpoint(server="stun.l.google.com:19302") -> (ip, port)`.
- `NATType` enum (`OPEN`, `FULL_CONE`, `RESTRICTED`, `PORT_RESTRICTED`,
  `SYMMETRIC`, `UNKNOWN`). Detected with two successive STUN queries
  from the same socket to different servers.
- `ConnectionType` enum (`DIRECT`, `HOLE_PUNCHED`, `RELAYED`).
  Attached to `PeerState.connection_type`.
- `RelayClient` — opens a persistent WebSocket to a relay host, handles
  reconnection, forwards frames.
- `RelayServer` — opposite side: accepts `RELAY_REGISTER` connections,
  indexes them by `node_id`, forwards frames to registered peers when
  asked.

**`bridge.py` flags**

| Flag | Meaning |
|---|---|
| `--relay <host:port>` | Dial this relay on startup; register our node_id; use it as a gateway for any peer we can't reach directly. |
| `--relay-mode` | Become a relay. Accept RELAY_REGISTER, serve RELAY_FORWARD. Does NOT participate in application dialogue. |
| `--stun <host:port>` | STUN server for hole-punching (default `stun.l.google.com:19302`). Empty = disable hole-punching, use relay exclusively. |
| `--no-nat` | Disable all NAT-traversal. LAN-only (today's default). |

### New message types (protocol `ironmesh/0.7`)

Added to `MessageType`, documented in `PROTOCOL_SPEC.md §4.3`:

| Type | Direction | Purpose |
|---|---|---|
| `RELAY_REGISTER` | NATted peer → Relay | "I am node X, accept my outbound socket as my inbox." Signed with identity key. |
| `RELAY_LOOKUP` | Peer → Relay | "Is node Y registered?" Returns current connection status. |
| `RELAY_FORWARD` | Peer → Relay → Peer | Inner payload is a whole encrypted IronMesh frame. Relay forwards verbatim. Carries destination `node_id`. |
| `HOLE_PUNCH_RENDEZVOUS` | Coordinator → Peer | "Peer Y's current public mapping is `ip:port`; try dialing there now." |
| `HOLE_PUNCH_READY` | Peer → Peer | Empty ping sent to trigger NAT mapping; receiver drops it. |

### Frame wrapping

A `RELAY_FORWARD` looks like this (JSON shown for clarity; wire is
binary):

```
outer frame (relay ↔ peer):
  msg_type = RELAY_FORWARD
  payload = {
    "dest": "<node_id of ultimate recipient>",
    "inner": <base64 of the COMPLETE inner Frame bytes>,
  }
  signature = Ed25519 by *sender* (peer's identity key)
  ...
```

The inner frame is the **exact** frame peer A would have sent if the
connection were direct. That means the session-key encryption, the
per-peer replay counter, and the Ed25519 signature from peer A are all
intact. The relay can verify the OUTER frame (identity-key signed by A)
but cannot decrypt the inner payload.

**Security invariant:** compromising a relay gets you
`(sender, receiver, timestamp, ciphertext length)` — no payload, no
session key, no ability to inject or replay (inner replay guard is
per-peer end-to-end).

---

## 4. Threat model delta

Compared to today, adding relay mode introduces these new threats:

| # | Threat | Mitigation |
|---|---|---|
| T1 | Malicious relay reads payloads | Inner frame stays encrypted with the peer-to-peer session key; relay holds no key material. Handshake over relay uses the same NaCl SealedBox primitive as LAN. |
| T2 | Malicious relay injects forged frames | Inner frame carries Ed25519 signature by the sender's identity key. Receiver verifies; relay can't forge. |
| T3 | Malicious relay replays frames | Inner frame carries monotonic `sequence` number; peer-to-peer replay guard catches dupes. |
| T4 | Malicious relay drops frames | Detectable as silence → peer's existing `_long_drop_watchdog` fires → alert. End-to-end ACKs (already present) catch this. |
| T5 | Malicious relay correlates traffic | True. Operator accepts this in exchange for working NAT traversal. The `--stun` path sidesteps it when hole-punching succeeds. |
| T6 | Relay DDoS / resource exhaustion | Per-peer rate limits (already present in `_connection_rate_limiter` + per-IP limiter). Add `RELAY_FORWARD` to the rate-limited set. Optional `--relay-max-peers N`. |
| T7 | Unauthorized registration | `RELAY_REGISTER` is signed with the registrant's identity key; the relay only forwards to registered peers that the sender has in its TOFU store. No public directory. |
| T8 | Hole-punch coordinator lies about mappings | Mappings are advisory; a dial to a wrong `ip:port` either fails or reaches a stranger who can't complete the IronMesh handshake (passphrase + TOFU catch it). No new authentication needed. |

**Not in scope for v0.8.5:** anonymity from the relay operator (T5).
Users who need that run their own relay.

---

## 5. Observability

New metrics (emitted via Prometheus `/metrics`):

| Metric | Type | Labels |
|---|---|---|
| `ironmesh_connection_type` | gauge | `peer_id`, `type={direct,hole_punched,relayed}` |
| `ironmesh_relay_forwarded_total` | counter | `direction={in,out}`, `dest_peer_id` |
| `ironmesh_holepunch_attempts_total` | counter | `outcome={success,failure}` |
| `ironmesh_stun_queries_total` | counter | `server`, `outcome` |
| `ironmesh_nat_type` | gauge | `type` (detected once at startup) |
| `ironmesh_relay_registered_peers` | gauge | — (relay-mode only) |

New dashboard fields:
- Peer row gains a **Connection** column: `direct` / `via relay (hop)` / `hole-punched`.
- Summary card: "NAT: symmetric" / "open internet" / etc.

---

## 6. Configuration examples

### Running a relay (on a public host)

```bash
# ports 443 (WSS) and 80 optional
export IRONMESH_PASSPHRASE_FILE=/etc/ironmesh/passphrase
ironmesh run \
    --name public-relay-1 \
    --port 8765 \
    --relay-mode \
    --bind 0.0.0.0 \
    --tls-cert /etc/ironmesh/fullchain.pem \
    --tls-key /etc/ironmesh/privkey.pem
```

Relay mode is incompatible with `--gui` by default (no interactive UI
on a headless host); allowed with `--gui --force`.

### NATted agent using a relay

```bash
ironmesh run \
    --name wiz \
    --relay relay.ironmesh.org:8765 \
    --stun stun.l.google.com:19302 \
    --passphrase-file ~/.ironmesh/passphrase
```

Behavior:
1. Dial relay, register identity. Fail if relay unreachable.
2. Fetch our public mapping via STUN (for later hole-punching).
3. For any outgoing send to a peer:
   a. Try direct LAN connection (existing path).
   b. If not online locally, request hole-punch via relay.
   c. If hole-punch fails within 5 s, send via relay forwarder.

### Disable NAT traversal (today's behavior)

```bash
ironmesh run --name wiz --no-nat ...
```

---

## 7. Tests to write

Before shipping, each of these must exist and pass:

**Unit**

- STUN response parsing: valid + malformed + timeout.
- `ConnectionType` transitions.
- `RelayClient` reconnect logic (disconnect mid-forward, resume).
- `RELAY_FORWARD` envelope round-trip.
- Relay drops unsigned registrations.
- Relay drops forwards to unregistered dests with `RATE_LIMITED`.

**Integration**

- Two agents behind simulated NAT (via network namespaces on Linux CI)
  + one relay on the host network. Prove: message send end-to-end,
  session key never visible to relay process.
- Hole-punching success when both sides are `FULL_CONE`.
- Hole-punching failure → relay fallback when one side is `SYMMETRIC`.
- Relay crash mid-conversation: both peers reconnect, session resumes.
- 500 parallel messages through a relay: no drops, no dupes, no
  ordering violations.

**Security properties (property-based / Hypothesis)**

- Relay cannot produce a frame the receiver accepts without the
  sender's identity key (signature invariant).
- Relay cannot produce a frame that passes the receiver's replay guard
  with an old `sequence` (replay invariant).
- Inner frame bytes are bit-identical after pass-through.

---

## 8. What this plan explicitly is NOT

- **Not** a production STUN/TURN replacement. For high-scale
  deployments run a real TURN server behind the IronMesh relay.
- **Not** UDP. All IronMesh transport stays WebSocket for now; LoRa
  via Reticulum unchanged.
- **Not** IPv6-first. Works the same either way (STUN handles both)
  but we don't add `--prefer-ipv6`.
- **Not** an anonymity system. The relay sees who-talks-to-whom and
  when. If you want metadata privacy, run your own relay or use the
  hole-punch path exclusively.

---

## 9. Migration & backward-compat

- Peer announces capability `nat:relay` / `nat:holepunch` / `nat:direct`
  based on what it's configured for.
- Protocol version negotiated during HELLO. A `0.6` peer receives no
  RELAY_* frames. A `0.7` peer asks the relay for `nat:direct` peers
  directly first (they might be on the same LAN).
- `--no-nat` on v0.8.5 is equivalent to v0.8.2 behavior. Zero upgrade
  cost for existing LAN deployments.

---

## 10. Open questions for the review checkpoint

Before I start coding, please confirm:

1. **Relay-first or STUN-first ship order?** I recommend relay-first
   (higher impact per hour, works everywhere). STUN hole-punching
   layered in after. Alternative: gated behind `--experimental-holepunch`
   so we can ship it as a beta in 0.8.5 and tune in 0.8.6.

2. **Default STUN server?** `stun.l.google.com:19302` is the pragmatic
   choice (high availability, public). Users may object to Google. I
   propose shipping with `stun.l.google.com:19302` as default + clearly
   documenting how to change to `stun.cloudflare.com:3478` or your
   own.

3. **Relay identity trust?** Today peers verify relay by TOFU — the
   first time they register they pin the relay's Ed25519 key. Later
   key changes break registration and require `ironmesh trust revoke`.
   Alternative: explicit CA-signed certificates for relays. My
   recommendation: TOFU is consistent with the rest of the system;
   no CA needed.

4. **Relay mode GUI?** Running a relay with `--gui` wastes a port+1
   and exposes a dashboard most ops don't want public. My default:
   `--relay-mode` implies `--no-gui` unless `--force-gui` is set.

5. **Rate-limit defaults on a relay?** I propose `RELAY_FORWARD` at
   20 fps per registered peer, burst 100 (same as per-peer message
   rate). Relay admins override with `--relay-peer-rate 50`.

6. **Do we want a hosted relay at `relay.ironmesh.org`?** I can set
   up a Docker-compose service file and instructions; you decide
   whether to run one publicly.

---

**Review → reply with any of:**

- *ship it as written* — I start Phase 2 (implementation).
- *change X* — I edit the doc and wait for reapproval.
- *defer Y to 0.8.6* — I'll trim scope.

Nothing gets coded until you sign off on this doc.
