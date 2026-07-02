# Reporting Security Issues

If you believe you've found a security vulnerability in IronMesh, please
**do not** open a public GitHub issue.

## How to report

Email: **info@ironmesh.org** (or open a private security advisory via
GitHub's "Report a vulnerability" button on this repo).

Please include:

- A clear description of the vulnerability
- Steps to reproduce (if applicable, a minimal PoC)
- The IronMesh version affected
- Your assessment of impact (what can an attacker achieve?)
- Any suggested mitigation

We aim to acknowledge receipt within **48 hours** and provide a triage
assessment within **7 days**. Critical issues will be prioritized for a
point release within **14 days** of confirmation.

## Scope

**In scope** (we want to hear about these):

- Cryptographic weaknesses in the wire protocol, handshake, or trust store
- Authentication or authorization bypasses
- Remote code execution, memory corruption, or denial-of-service
  vectors against the daemon
- Information disclosure (identity keys, message plaintext, session keys)
- Flaws in the mDNS / Reticulum / LoRa integration that expose traffic
- Trust-store tampering or TOFU bypass
- Replay attacks, side channels, timing oracles

**Out of scope** (please don't send these as security reports):

- Issues in Python dependencies for which an upstream advisory already
  exists (report upstream, please)
- Attacks requiring physical access to an operator's trusted machine
  (the threat model assumes the operator's own host is trusted — see
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md))
- DoS via a legitimate-but-expensive protocol operation (e.g. sending
  the peer a huge message under the 1 MB cap); open a regular issue
  for those
- Missing TLS on the local dashboard when bound to 127.0.0.1

## Responsible disclosure

We ask for a **90-day coordinated disclosure window** from the date
we acknowledge receipt. If we haven't shipped a fix by then, you're
free to disclose publicly. If we ship a fix earlier, we'll coordinate
the disclosure timing with you and credit you in the release notes
(unless you prefer anonymity).

## The threat model

The full threat model is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
The short version:

- IronMesh protects agent-to-agent messaging on a local network or
  LoRa radio from passive eavesdropping, active MITM (TOFU-pinned),
  and replay
- It does **not** protect against a compromised operator host, a
  compromised identity key on disk (encrypt it with a passphrase!),
  or traffic analysis (frame sizes, timing, and mDNS announces are
  observable to anyone on the LAN)
- It does **not** claim anonymity. Peer identities are deliberately
  stable — that's the point of TOFU

### Reticulum (LoRa) transport caveats

Reticulum is an **opt-in** transport enabled by installing
`ironmesh[rns]` and passing `--reticulum`. The WebSocket path is the
default; most deployments never touch RNS. Two previously documented
residual risks are mitigated as of protocol `ironmesh/0.9`:

- **RNS link binding (mitigated as of `ironmesh/0.9`, scoped to 0.9+
  peers).** On RNS Links, 0.9+ peers include the id of the specific
  RNS link inside the signed HELLO canonical body (`rns_link_id`),
  and the receiver rejects any HELLO whose claimed link id does not
  match the link it actually arrived on. This couples the IronMesh
  Ed25519 identity to the RNS link session: a signed HELLO cannot be
  relayed onto a different link, and on the handshake-skip path
  (`--rns-skip-handshake`) the skip is REFUSED outright unless the
  binding is present and signature-verified — the constant skip
  sentinel is no longer replayable across links. **Honest scope:**
  pre-0.9 RNS peers cannot produce the binding, so their handshakes
  keep the old behavior — a pre-0.9 peer holding a valid RNS identity
  can still send a HELLO claiming a different IronMesh identity (the
  Ed25519 signature still prevents impersonating anyone whose keys it
  doesn't hold). The residual therefore remains for legacy RNS peers
  only. Operators can pass `--rns-require-link-binding` to reject
  RNS peers that send no binding, closing the residual completely on
  fully-upgraded meshes; the handshake skip already requires it
  unconditionally. The WebSocket path is unaffected (the field is
  rejected there).
- **Per-peer cumulative buffering cap (mitigated as of 0.9).** In
  addition to the per-frame 1 MB cap, each RNS link now enforces a
  cumulative bound (`MAX_PEER_BUFFERED_BYTES`, 64 MB) across the
  reassembly buffer plus every received-but-unconsumed message and
  Resource payload. A peer that overruns it trips the cap **before**
  memory pressure: the link is closed, buffers are freed, and a
  warning is logged (`RNS: per-peer buffered-bytes cap exceeded`).

Remaining residual:

- **The buffering cap is per-link, not per-identity.**
  `MAX_PEER_BUFFERED_BYTES` bounds each RNS link independently, so a
  single RNS identity that opens N links can buffer roughly N × 64 MB
  before the caps trip. This is a known, accepted limitation; an
  aggregate per-identity bound is planned follow-up work.
- **rns dependency** is pinned as `rns>=0.9.0` with no upper bound
  in v0.8.5.2. For strict environments, pin `rns>=0.9.0,<0.10.0` in
  your own install.

If RNS isn't enabled, none of this applies.

### TLS and peer authentication (design choice)

- IronMesh's outbound WebSocket client uses `ssl.CERT_NONE` +
  `check_hostname = False` **by default**. TLS in this mode is for
  line-level confidentiality only; **peer authentication is handled
  at the application layer** via TOFU-pinned Ed25519 identity keys
  and a signed HELLO that covers the channel-binding nonce. An
  attacker with a self-signed TLS cert still fails the Ed25519
  signature check on HELLO and cannot impersonate a pinned peer.
- As of protocol version `ironmesh/0.9`, the HELLO signature is
  **domain-separated**: when both peers advertise 0.9+, the HELLO is
  signed with a detached Ed25519 signature under the dedicated
  `SIG_CTX_HELLO` context label, so a signature obtained from any
  other protocol surface can never be replayed as a HELLO (and vice
  versa). Peers on older versions fall back to the legacy attached
  signature so mixed-version meshes interoperate. The advertised
  version travels inside the signed HELLO body, so for pinned peers
  the scheme cannot be silently downgraded in transit — tampering
  fails the handshake. On TOFU first contact an active on-path
  attacker can still present itself as a pre-0.9 peer (or impersonate
  outright — the inherent TOFU first-contact exposure); operators can
  set `--min-protocol-version ironmesh/0.9` to refuse legacy HELLO
  signatures entirely. See docs/PROTOCOL_SPEC.md, "HELLO signature
  domain separation".
- For deployments where WSS endpoints are issued real certificates
  (operator CA, internal Let's Encrypt, public ACME), pass
  **`--strict-tls`** to require CA-validated certs on the outbound
  WSS path: hostname check + `CERT_REQUIRED`. Pair with
  `--pinned-ca <path>` to use a private CA bundle as the trust
  anchor; without it the system trust store is used. This adds
  TLS-layer authentication on top of the Ed25519 application-layer
  check, satisfying transport-only auditors who expect WSS to
  authenticate the endpoint.
- `--allow-plaintext-ws` is a compatibility fallback: when TLS fails
  and this flag is set, the client retries over `ws://`. The daemon
  logs a WARNING with "INSECURE" every time this happens so operators
  can spot accidental fallback.

### LAN discovery (mDNS) caveats

- mDNS discovery is unauthenticated by design — that's how mDNS
  works. Anyone on the same LAN can publish or query an
  `_ironmesh._tcp` record. An adversary on the LAN can therefore:
  enumerate IronMesh nodes, advertise spoofed nodes to harvest
  connection attempts, or replay stale records.
- Spoofing does **not** bypass authentication. Every connection,
  however discovered, runs the full handshake (passphrase HMAC →
  signed ephemeral X25519 → TOFU-pinned Ed25519 identity check). A
  spoofer cannot pass any of those without the mesh passphrase **and**
  the impersonated peer's Ed25519 secret key.
- Default behavior is **deny** — mDNS auto-connect is gated behind
  `--open-discovery` (testing only) or `--allowed-peers` (an explicit
  allowlist). Production deployments should always pass
  `--allowed-peers` or distribute peer endpoints out-of-band rather
  than relying on mDNS as a trust source.

### Threat-model assumption — peer set

IronMesh's per-peer rate limits, queue caps, and message-size limits
assume that peers on the mesh are **mutually trusted parties** (your
own agents, your team's agents, peers you've explicitly pinned). The
protocol is hardened against passive eavesdropping, active MITM, and
replay between any pair of peers, but it is not designed to absorb
adversarial peer pressure (e.g. an actively-malicious pinned peer
flooding the queue with maximum-size messages within their per-peer
cap). If your deployment exposes the mesh to potentially-hostile peers,
add an external rate limiter / WAF and treat the application-layer
caps as defense-in-depth, not the primary control. A future
release may add a global daemon-wide bandwidth cap as belt-and-suspenders.

### Storage-at-rest properties (v0.8.5+)

- **Message payloads are encrypted** before insertion into SQLite via
  `_encrypt_payload` (XSalsa20-Poly1305 with a storage key derived
  from the mesh passphrase). The `messages`, `pending_messages`, and
  `pending_trust_messages` tables all store ciphertext bodies.
- **Storage-key derivation is Argon2id-hardened**: the storage key is
  derived by running Argon2id (moderate cost parameters, the same that
  protect the identity key file) over the mesh passphrase with a
  per-database random salt persisted in the `_meta` table, then
  expanding a domain-separated storage subkey via HKDF-SHA256. A
  leaked disk image therefore does not permit a fast offline
  dictionary attack on the passphrase. Databases written by earlier
  releases (which used a single unsalted SHA-256 of the passphrase)
  are re-encrypted under the new key automatically on the first
  daemon start; payloads that predate at-rest encryption entirely are
  left untouched and remain readable.
- SQLite journal files (`*.db-wal`, `*.db-shm`) inherit the same
  property: because the encryption happens in the application layer
  before the INSERT, the WAL and shared-memory pages hold ciphertext
  only. Verified empirically against live production state —
  known-plaintext substrings (including real Ollama-generated
  responses) were absent from the WAL.
- **Message metadata is NOT encrypted at rest**: `msg_id`, `source`
  (peer fingerprint), `destination`, `timestamp`, `msg_type`, and
  `priority` are stored as plaintext columns. This is a deliberate
  design choice — the daemon needs to index and query them — but
  means a local attacker with disk access can see who talked to whom
  and when, just not what was said.
- **Trust store** (`known_peers.json`) is both integrity-protected
  and **confidential at rest as of v0.9.4**: the on-disk envelope is
  SecretBox-encrypted (XSalsa20-Poly1305) with a key derived from the
  daemon's identity secret, and the surrounding HMAC-SHA256 covers
  the ciphertext for tamper evidence and multi-daemon collision
  detection. A host-disk leak no longer exposes the peer graph (node
  IDs, fingerprints, capability sets). Pre-v0.9.4 plaintext stores
  load through the legacy v1 path and migrate forward automatically
  on the next save — no operator action required.
- **Audit log** (`audit.log`) is plaintext JSON with an HMAC chain.
  Not confidential; tamper-evident.
- **Backup archives** (`ironmesh backup`) ARE additionally encrypted
  with a user-supplied passphrase on top of the per-message storage
  key — so a leaked backup doesn't expose payloads.

## Hall of fame

Security researchers who've reported valid findings will be listed
here (with their permission).

_(empty — this is the first public release. Let's fill it up.)_
