# IronMesh Threat Model

This document enumerates the assets, threats, mitigations, and residual
risks for IronMesh v0.6.0.  It uses the STRIDE framework
(Spoofing, Tampering, Repudiation, Information disclosure, Denial of
service, Elevation of privilege) and is intended for security reviewers,
operators, and contributors evaluating deployment fit.

For the cryptographic primitives and wire-level detail, see
`SECURITY.md` and `PROTOCOL.md`.

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

## 6. Change Log

- **v0.6.0**: Added signed revocation broadcast, version rejection, mDNS idhash, jittered backoff, backup/restore, audit export, frame parser fuzzing.
- **v0.5.2**: Session key rotation, RTT metrics, LoRa QoS, test harness.
- **v0.5.1**: Transport failover (WS ↔ RNS), TOFU address pinning fix, RNS Buffer rewrite.
- **v0.5.0**: Reticulum (LoRa) transport.
- **v0.4.0**: Mesh routing, E2E SealedBox, capability discovery, audit log rotation.
- **v0.3.0**: Binary wire format, mandatory encryption + signatures, rate limiting.
