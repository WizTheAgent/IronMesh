# IronMesh Threat Model

Assets, threats, mitigations, and residual risks, organized under STRIDE
(Spoofing, Tampering, Repudiation, Information disclosure, Denial of
service, Elevation of privilege). Written for security reviewers,
operators, and contributors evaluating deployment fit.

For cryptographic primitives and the wire-level detail, see
`SECURITY.md` and `PROTOCOL_SPEC.md`.

---

## 1. Assets

| # | Asset | Sensitivity | Location |
|---|-------|-------------|----------|
| A1 | Ed25519 identity private key | **Critical** | `~/.ironmesh/keys.json` (Argon2id + SecretBox) |
| A2 | Ephemeral X25519 session private key | High (in-memory only, wiped after ECDH) | RAM, never written |
| A3 | Session key (shared secret) | High | `PeerState.session_key` in RAM |
| A4 | Passphrase (for keys + mutual auth) | High | RAM, file, or env var |
| A5 | Trust store (TOFU pins + revocations) | High — integrity | `~/.ironmesh/known_peers.json` (HMAC-SHA256) |
| A6 | Audit log | Medium — integrity | `~/.ironmesh/audit.log` (HMAC chain) |
| A7 | Message content (application payload) | Varies — user-defined | SQLite (encrypted) + wire (encrypted) |
| A8 | Message metadata (source, dest, msg_id, timestamp) | Low-Medium | Visible to relays in mesh |
| A9 | Peer identities (Ed25519 public key fingerprints) | Low — public-but-privacy-relevant | Exchanged during handshake only |
| A10 | RNS (Reticulum) destination hash | Low — public | mDNS + announces |
| A11 | RNS Identity private key + ratchet keys (v0.9.1+) | High | `~/.reticulum/ironmesh_<short>_identity` + `_ratchets` |
| A12 | LXMF delivery identity (v0.9.1+) | High | `~/.ironmesh/lxmf/identity` |
| A13 | Pending-trust message queue (v0.8.5+) | Medium — integrity | SQLite `pending_trust_messages` |
| A14 | RNS admin RPC allow-list (v0.9.1+) | Medium — integrity | `--rns-admin-identities` CLI / env var |

---

## 2. STRIDE per Asset

### A1 — Identity private key

| Threat | Mitigation |
|--------|-----------|
| **S** — Spoofing via theft of key file | Argon2id KDF + SecretBox at rest; minimum 12-char passphrase; OS file permissions (0600) |
| **T** — Tampering with key file | SecretBox is AEAD — tampered ciphertext fails decryption |
| **R** — Operator denies generating/using a key | Audit log records `STARTUP` with node_id; cross-file HMAC chain |
| **I** — Passive disclosure | Keys never transmitted; never broadcast via mDNS; only fingerprint/public-key exchanged during authenticated handshake |
| **D** — Denial: delete keys | **RESIDUAL** — loss of identity. *Mitigation (v0.6):* `ironmesh backup`/`restore` commands |
| **E** — Privilege escalation | N/A — key is the highest authority; compromise = full ownership |

### A2 — Ephemeral ECDH private key

| Threat | Mitigation |
|--------|-----------|
| **S** — Reuse as identity | Ephemeral keys are never self-reported as identity; peer_id derived from Ed25519 fingerprint (`bridge.py:955-958`) |
| **T** — Manipulate during handshake | Signed HELLO with channel binding (server_nonce in signature); `bridge.py:914-943` |
| **I** — Memory scrape | `secure_wipe()` after ECDH (`crypto.py:145-170`); window is microseconds |
| **D** — DoS via handshake abort | Per-IP rate limit + 3-failure ban |

### A3 — Session key

| Threat | Mitigation |
|--------|-----------|
| **S** — Impersonate peer with stolen session key | Session keys are per-connection, per-pair; cannot forge new connections |
| **T** — Modify encrypted messages | XSalsa20-Poly1305 AEAD; tampering fails verification |
| **R** — Deny sending a message | Ed25519 detached signature on every frame (`FLAG_SIGNED`) |
| **I** — Long-lived key compromise | v0.5.2 session rotation (`--rekey-interval`) + forward secrecy from ephemeral ECDH |
| **D** — Force rekey storm | Rekey has its own interval and tie-breaker (`bridge.py:_rekey_loop`); DoS bounded |

### A4 — Passphrase

| Threat | Mitigation |
|--------|-----------|
| **S** — Guess via online brute force | HMAC-SHA256 challenge, constant-time compare; 3-failure IP ban for 5 min |
| **S** — Offline brute force (key file stolen) | Argon2id KDF with OPSLIMIT_MODERATE + MEMLIMIT_MODERATE — each attempt ≥ 100 ms + 64 MB RAM |
| **I** — Disclosure via `ps aux` | `--passphrase` removed from CLI (v0.3); only `--passphrase-file` / env var / interactive `getpass` |
| **I** — Disclosure via shell history | Operator guidance in `SECURITY.md` |

### A5 — Trust store

| Threat | Mitigation |
|--------|-----------|
| **T** — Swap pinned keys on disk | HMAC-SHA256 derived from agent secret; tamper → entire store rejected on load (`trust.py:54-72`) |
| **T** — Inject fake revocation | v0.6 revocations require Ed25519 signature from the claimed revoker, which must be a pinned peer |
| **I** — Read pinned fingerprints | Fingerprints are non-sensitive by design (SHA-256 of public key) |

### A6 — Audit log

| Threat | Mitigation |
|--------|-----------|
| **T** — Delete or reorder entries | HMAC chain: each entry covers previous HMAC; cross-rotation anchor at each file boundary |
| **R** — External auditor challenges integrity | v0.6 `ironmesh audit export --out x.json` produces Ed25519-signed bundle; `verify-export` independently validates |
| **D** — Log flood | Rotation at 10 MB, 5 archive files retained; rate-limited events |

### A7 — Message content

| Threat | Mitigation |
|--------|-----------|
| **S** — Send-as-another-peer | Inner Ed25519 source signature (v0.4+) survives per-hop re-encryption |
| **T** — Relay modifies content | XSalsa20-Poly1305 + detached Ed25519 signature; E2E SealedBox wrapping when destination key known |
| **R** — Peer denies sending | Inner signature proves origin |
| **I** — Read in transit | SecretBox per-hop encryption; SealedBox for E2E over relays |
| **I** — Read at rest | SQLite payload encrypted with SecretBox; database file permissions 0600 |

### A8 — Message metadata

| Threat | Mitigation |
|--------|-----------|
| **I** — Relay learns who-talks-to-whom | **RESIDUAL** — source/dest visible to relays for routing; no onion-style anonymization |
| **I** — Timing analysis | **RESIDUAL** — no cover traffic or batching |

### A9 — Peer identities

| Threat | Mitigation |
|--------|-----------|
| **I** — Passive fingerprinting of all nodes on LAN | Public keys NOT in mDNS; v0.6 `idhash` (8 bytes of SHA-256) balances discovery vs. privacy; full identity requires completing handshake |
| **I** — Correlation across sessions | Same identity key = same fingerprint; use `ironmesh keys generate --rotate-keys` or restore from backup to change identity |

### A10 — RNS destination hash

| Threat | Mitigation |
|--------|-----------|
| **I** — Public knowledge of RNS destination | Accepted — RNS requires destinations to be addressable. Destination hash does not reveal identity key |

### A11 — RNS Identity + ratchet keys (v0.9.1+)

| Threat | Mitigation |
|--------|-----------|
| **S** — Theft of RNS Identity file | OS file permissions (0600); per-daemon paths so multi-tenant hosts can't cross-read; no IronMesh-managed encryption (RNS handles its own at-rest crypto) |
| **T** — Tamper with ratchet store | RNS validates the ratchet file signature; tamper triggers RNS-level KeyError surfaced as a startup warning |
| **I** — Memory scrape of ratchet keys | Ratchets rotate on a configurable interval (default 30 min); compromise of one window doesn't decrypt others; RESIDUAL: per-window window is in RAM during use |
| **D** — Force ratchet rotation | Rotation is local + interval-bounded; no remote-triggered rotation |
| **E** — Use RNS Identity to impersonate IronMesh node_id | RNS Identity hash and IronMesh node_id are separate keyspaces; the announce app_data binds them together via signature, but compromise of one does not auto-compromise the other |

### A12 — LXMF delivery identity (v0.9.1+)

| Threat | Mitigation |
|--------|-----------|
| **S** — Theft of LXMF identity file | OS file permissions; LXMF identity is separate from IronMesh identity, so loss does not compromise the IronMesh trust store |
| **I** — LXMF announces broadcast destination | Accepted — LXMF requires public addressability for store-and-forward propagation |
| **D** — LXMF flood from untrusted senders | `inbound_route` allowlist + `default_inbound_peer` catch-all; unmapped traffic is dropped, never forwarded |

### A13 — Pending-trust message queue

| Threat | Mitigation |
|--------|-----------|
| **D** — Fill the queue from a malicious peer | Per-peer cap (`pending_trust_queue_cap`, default 100); oldest evicted on overflow; per-peer audit-log rate limit prevents log flood |
| **I** — Read queued payloads | SQLite encrypted with SecretBox; database file 0600 |
| **R** — Operator denies queueing | Audit log records every `MSG_GATED_QUEUE` event with source identity hash |

### A14 — RNS admin RPC allow-list (v0.9.1+)

| Threat | Mitigation |
|--------|-----------|
| **E** — Unauthorized admin call | Per-call identity check against the configured allow-list (CLI / env var); empty list = admin RPC disabled by default |
| **T** — Allow-list tampering | Allow-list is loaded from CLI / env at startup; runtime mutation requires daemon restart, leaving an audit trail |
| **R** — Operator denies granting access | Each granted identity hash is logged at startup |

---

## 3. Cross-asset Attacks

| Attack | Mitigation |
|--------|-----------|
| **MITM on first connection (TOFU bootstrap)** | **RESIDUAL** — first-contact trust. Operator should pin keys out-of-band for high-value peers. v0.6 adds signed revocation to recover if first contact was compromised |
| **Compromised peer broadcasts false revocations** | Revocations are signed; receivers only trust revocations from already-pinned peers. Admin must manually clear fraudulent revocations with `ironmesh trust list-revoked` + `clear_revocation()` |
| **Replayed old messages** | Monotonic sequence numbers per-peer; 30 s timestamp window; per-source dedup cache |
| **mDNS spoofing** | Default-deny auto-connect; allowlist (`--allowed-peers`) or `--open-discovery`; v0.6 `idhash` lets receivers filter before handshake |
| **Downgrade to older protocol** | v0.6 `--min-protocol-version` rejects peers below threshold |
| **Resource exhaustion via handshake storm** | Per-IP rate limit + 3-failure-5-min ban + v0.6 jittered exponential backoff on outbound reconnects |
| **RNS announce spoofing (v0.9.1+)** | RNS announces are signed by the announcing Identity; receivers verify via RNS's own validation. Announce-driven discovery records the identity hash, but a Link must still complete (mutual Identity auth) before any IronMesh trust is granted |
| **Capability advertisement forgery** | Capability advertisements ride the encrypted IronMesh wire layer (signed envelopes). Local capability registry is HMAC-protected; remote-cap learning requires an authenticated peer. v0.9.0 cap-binding pins `SHA-256(sorted-caps)` alongside the identity in the trust store — peer reconnecting with changed caps demotes to `pending-cap-change` |
| **Cross-mesh federation forwards** | Federation gateway enforces per-edge allow/deny policy; every cross-mesh forward is audit-logged. Out-of-scope: no anonymity for a sender across federation boundaries |
| **Resource transfer >32KB on RNS (v0.9.1+)** | Hard cap of 64 MB per `RNS.Resource` prevents lockout; integrity verified by RNS at the Resource layer; receiver accepts only when peer advertised the `resource` feature in announces |
| **Handshake-skip downgrade attack (v0.9.2+)** | Defended at five layers. (1) The skip is opt-in on both ends + advertised in the RNS announce. (2) The announce is signed by the announcing RNS Identity, so a MITM cannot inject `hskip` on a peer's behalf. (3) The negotiation is **server-driven via `SKIP_OFFER`** — the client never decides skip unilaterally, so an attacker who suppresses one announce cannot cause a half-skipped handshake. (4) The `SKIP_OFFER`'s `channel_binding` field MUST equal the deterministic 32-byte sentinel `SHA-256(b"ironmesh-handshake-skip-channel-binding-v1")` — verified client-side via `hmac.compare_digest`. A peer that offers any other value (missing, non-hex, or 32 attacker-chosen bytes) is rejected and the connection closed; the rejection is counted in `ironmesh_handshake_skips_rejected_total` and fires a critical-severity alert in the bundled Prometheus rules. (5) As of protocol `ironmesh/0.9`, the skip additionally REFUSES to run unless the peer's signed HELLO carries a verified RNS link binding (`rns_link_id` matching the link it arrived on), so the constant skip sentinel is not replayable across links |

---

## 4. Out of Scope

IronMesh does not defend against:

- **Physical compromise of a node** — if the attacker has RAM or disk while the daemon runs, session keys are extractable
- **Compromised host OS** — kernel-level malware can intercept before encryption
- **Volumetric DDoS** — upstream routing/firewall is the defense
- **Traffic analysis by a global passive adversary** — no cover traffic or padding
- **Side-channel timing attacks on libsodium** — libsodium is assumed correct; any side-channel is inherited
- **Zero-day bugs in libsodium / PyNaCl** — cryptographic primitives are trusted; IronMesh cannot mitigate breaks in them
- **Legal compelled disclosure** — operator must secure their own passphrases

---

## 5. Assumptions

1. The operator runs IronMesh on a trusted host (not a VPS of an untrusted provider).
2. The passphrase is strong (minimum 12 chars enforced; 20+ recommended).
3. Initial trust bootstrap (TOFU) happens on a network segment where the first-contact key exchange is not under active MITM.
4. Backups (`ironmesh backup`) are stored separately and protected by a different strong passphrase.
5. System clocks on all peers are within 30 s of each other (for replay window).

---

## 6. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  Operator-controlled host                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  IronMesh daemon process                            │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │  In-memory secrets (session keys,           │    │    │
│  │  │  ephemeral X25519 priv keys, passphrase)    │    │    │
│  │  └─────────────────────────────────────────────┘    │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │  Disk: keys.json (Argon2id+SecretBox),      │    │    │
│  │  │        trust.json (HMAC), audit.log         │    │    │
│  │  │        (HMAC chain), data.db (SecretBox)    │    │    │
│  │  └─────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────┘    │
│                       │                                     │
│  ╔════════════════════╪═════════════════════════════════╗   │
│  ║  Local network (LAN)                                 ║   │
│  ║                    │                                 ║   │
│  ║  ┌─────────────────┴───────────────────────────┐     ║   │
│  ║  │  WebSocket transport (default-deny mDNS;    │     ║   │
│  ║  │  every connection requires passphrase auth) │     ║   │
│  ║  └─────────────────────────────────────────────┘     ║   │
│  ╚══════════════════════════════════════════════════════╝   │
│                       │                                     │
│  ╔════════════════════╪═════════════════════════════════╗   │
│  ║  Reticulum mesh (LAN + LoRa + I2P + WAN)             ║   │
│  ║                    │                                 ║   │
│  ║  ┌─────────────────┴───────────────────────────┐     ║   │
│  ║  │  RNS Link (forward-secret AEAD by RNS) →     │     ║   │
│  ║  │  IronMesh frame (SecretBox + Ed25519 sig)    │     ║   │
│  ║  │  Optional: handshake skip on identified     │     ║   │
│  ║  │  Links (passphrase replaced by Identity     │     ║   │
│  ║  │  authentication at the RNS Link layer)      │     ║   │
│  ║  └─────────────────────────────────────────────┘     ║   │
│  ╚══════════════════════════════════════════════════════╝   │
└─────────────────────────────────────────────────────────────┘
```

The double-line boundary marks the trust transition: anything inside
the operator's host is trusted by the IronMesh threat model; anything
outside is hostile by default. Each network layer adds its own
crypto so a break in one layer doesn't compromise the others — RNS
Link encryption is independent of IronMesh-layer SecretBox, which is
independent of E2E SealedBox for relay traffic.

---

## 7. Change Log

- **Unreleased (main, protocol `ironmesh/0.9`)**: Post-v0.9.4.2 hardening.
    - **Domain-separated HELLO signature** — when both peers advertise
      `ironmesh/0.9+`, the HELLO carries a detached Ed25519 signature
      under the dedicated `SIG_CTX_HELLO` context label, closing the
      cross-protocol signature-reuse surface on the handshake.
      Version-gated with a legacy attached-signature fallback; the
      advertised version sits inside the signed body, so the scheme
      cannot be silently downgraded for pinned peers.
      `--min-protocol-version ironmesh/0.9` refuses legacy HELLOs.
    - **RNS link binding** — on RNS Links, 0.9+ peers include the id
      of the specific link inside the signed HELLO body
      (`rns_link_id`) and receivers reject any mismatch, coupling the
      IronMesh identity to the RNS link session. The
      `--rns-skip-handshake` path now refuses to run without a
      verified binding; `--rns-require-link-binding` refuses unbound
      pre-0.9 RNS peers entirely.
    - **Per-link cumulative buffering cap** on the Reticulum
      transport (64 MB per link across reassembly + unconsumed
      messages; overrun closes the link and frees the buffers).
    - **At-rest storage key derived via Argon2id + HKDF-SHA256** with
      a per-database persisted salt (previously a single unsalted
      SHA-256 of the passphrase) — a leaked disk image no longer
      permits a fast offline dictionary attack. Existing databases
      re-encrypt automatically on first start; the migration marker
      is withheld on a wrong-passphrase open.
- **v0.9.4**: Phase 2 of the Ed25519/X25519 dual-use migration.
    - **HELLO advertises master-seed X25519 public** with an Ed25519
      binding signature under `SIG_CTX_X25519_BINDING`. Receivers
      that recognize the fields verify the binding under the peer's
      pinned Ed25519 identity and switch E2E SealedBox sealing to
      the advertised X25519. Mixed v0.9.4 ⇄ v0.9.4 meshes interop
      via the legacy `ed25519_to_curve25519` fallback path.
    - **Auto-migration on first start**: a v0.9.4 daemon loading a
      legacy v1/v2 keystore silently writes the master-seed envelope
      forward (preserves Ed25519 seed byte-for-byte → every TOFU pin
      stays valid). `.legacy.bak` is preserved for one full release
      cycle.
    - **Residual dual-use exposure during phase 2**: a v0.9.4 daemon
      that hasn't yet auto-migrated (best-effort failure, e.g. read-
      only filesystem) continues using the legacy `ed25519_to_curve25519`
      derivation, leaving the dual-use property of the secret unchanged
      for that node. Operators see a WARNING in the log when this
      happens.
- **v0.9.4**: Pre-audit hardening pass.
    - **Master-seed key envelope (Option A Phase 1)** — `keys.json` v3
      adds an HKDF-derived X25519 subkey + per-node salt while preserving
      the Ed25519 seed byte-for-byte (TOFU pin survival). Phase 1 is a
      disk-format upgrade only; wire path unchanged. Reduces audit
      severity of the Ed25519/X25519 dual-use finding by establishing
      the storage layer that Phase 2 (v0.9.4) will switch to. Migration
      is opt-in via `ironmesh keys migrate`; legacy v1/v2 envelopes
      continue to load. Tamper-on-disk of the encrypted X25519 subkey
      is detected at load time via the HKDF redrive check.
    - **Signed `CAPABILITY_ANNOUNCE` frames** — closes the prior "relay-impersonation poisons trust binding" gap. Announces whose `origin` differs from the delivering peer require an inner Ed25519 signature from `origin`. 300 s freshness window + per-`(origin, announced_at)` replay-dedup LRU. New audit event `CAPABILITY_ANNOUNCE_BAD_SIG`, new metric `capability_announce_bad_signature_total`, new config `capability_announce_max_age` (default 300 s).
    - **Known limitation, accepted with mitigation:** the announce signature has no perfect-forward-secrecy property. If `origin`'s long-term Ed25519 key is later compromised, historical signed announces remain replayable inside the 300 s freshness window. Mitigated by the existing revocation flow — once a peer is revoked locally, future announces carrying its signature are dropped at the receiver. The narrow freshness window keeps the residual replay surface bounded.
    - **Domain-separated Ed25519 signing helpers** (`crypto.sign_detached_with_context` / `verify_detached_with_context`) reduce the severity of the Ed25519/X25519 dual-use concern by binding signatures to per-purpose context labels. Signed CAPABILITY_ANNOUNCE is the first signing surface to use this; existing wire signatures stay as-is pending the master-seed migration tracked separately for v0.9.4 → v1.0.
    - **Frame-length ceiling** `MAX_FRAME_BYTES = 1 MiB` enforced before buffer alloc in `Frame.deserialize_and_decrypt` (defeats 4 GiB attacker-declared length DoS).
    - **JSON nesting guard** `MAX_JSON_DEPTH = 64` on all wire-parsed JSON.
    - **`ReplayGuard.MAX_SEQUENCE = 2^48`** upper bound prevents self-DoS from oversized sequence.
    - **CVE-2020-10735 mitigation**: `sys.set_int_max_str_digits(4300)` at bridge bootstrap (Python 3.10 deployments).
    - **Fail-closed TOFU check**: malformed-data branch now refuses connection with a `WARNING` log rather than passing as "trust verified".
    - **Narrowed signing-path excepts** — programmer errors propagate instead of silently dropping inner signatures.
- **v0.9.3**: Trust store encrypted at rest (closes the prior "host-disk leak exposes peer graph" caveat). Optional `--strict-tls` for transport-layer authentication on outbound WSS. Optional `--max-msgs-per-sec` global daemon-wide cap, defense-in-depth for hostile-peer exposure. New audit events: `TRUST_STORE_ENCRYPTED`, `STRICT_TLS_ENABLED`, `GLOBAL_RATE_LIMIT_TRIGGERED`.
- **v0.9.2**: Handshake skip on identified RNS Links (opt-in, both peers advertise `hskip`); capability-aware routing (`send_to_capability`); A11–A14 added; cross-asset attack table extended for RNS-specific threats.
- **v0.9.1**: Reticulum integration sweep — auto-discovery via announces, per-packet ratchets, RNS Resource auto-routing, public capability RPC paths, identity-gated admin RPC, LXMF interop. Added A11–A14 assets.
- **v0.9.0**: OpenClaw / ACP / A2A interop surfaces; capability registry persistence; cross-transport replay detection; cap-set-binding TOFU extension.
- **v0.8.5**: Pending-trust message gate (A13).
- **v0.6.0**: Added signed revocation broadcast, version rejection, mDNS idhash, jittered backoff, backup/restore, audit export, frame parser fuzzing.
- **v0.5.2**: Session key rotation, RTT metrics, LoRa QoS, test harness.
- **v0.5.1**: Transport failover (WS ↔ RNS), TOFU address pinning fix, RNS Buffer rewrite.
- **v0.5.0**: Reticulum (LoRa) transport.
- **v0.4.0**: Mesh routing, E2E SealedBox, capability discovery, audit log rotation.
- **v0.3.0**: Binary wire format, mandatory encryption + signatures, rate limiting.

---

## 8. External-Audit Pre-Pack

For external security reviewers consuming this document:

- This file (`THREAT_MODEL.md`) is the model.
- `SECURITY.md` is the cryptographic primitive justifications +
  vulnerability disclosure policy.
- `PROTOCOL_SPEC.md` is the wire-level specification + the
  per-feature stable-since table (§11).
- `tests/conformance/` contains golden vectors covering every
  message type and state transition.
- The per-release live-stress test reports are operator-internal —
  out-of-scope for external reviewers but available on request.
- The repo's `git log` is the change history; every fix to a
  security-relevant code path carries a commit message describing
  the bug class and reproduction.

A v1.0 release commits to this document remaining accurate. Any
material change to the trust model or any new asset added between
v1.0 and the next major version will surface here with a dated
change-log entry.
