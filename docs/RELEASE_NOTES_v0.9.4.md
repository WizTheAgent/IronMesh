# IronMesh v0.9.4 — Release Notes

## Headline

A combined security + pre-audit hardening release. v0.9.4 bundles the
originally-planned v0.9.3 security point release (strict TLS, trust-store
at-rest encryption, global rate cap, trust CLI subcommands) with a
substantial pre-audit hardening pass: Phase 1 + Phase 2 of the
Ed25519/X25519 dual-use migration, signed `CAPABILITY_ANNOUNCE` frames,
frame-length ceiling, JSON depth guard, replay upper bound, narrowed
exception handling across rate-limit / shutdown / cleanup paths, and
fail-closed TOFU verification.

**Wire protocol:** `ironmesh/0.8`, additive only. Every v0.8.x and v0.9.x
peer stays interoperable. Pre-v0.9.4 receivers ignore the new HELLO
fields cleanly. v0.9.4 receivers verify the new fields when present and
fall back to legacy derivation when absent.

**Operator action:** none required for a stock deployment. v0.9.4
daemons silently auto-migrate legacy v1/v2 keystores to the new v3
master-seed envelope on first start, preserving the Ed25519 seed
byte-for-byte (every TOFU pin remains valid). A `.legacy.bak` is
written alongside the original file for one full release cycle in
case rollback is needed.

## Highlights

### Trust store encrypted at rest

`known_peers.json` is now SecretBox-encrypted with a key derived from
the daemon's identity secret. A host-disk leak no longer exposes the
peer graph (node IDs, fingerprints, capability sets). HMAC-SHA256
over the ciphertext keeps tamper evidence and the existing
multi-daemon collision detection. Pre-v0.9.4 plaintext stores load
through the legacy v1 path and migrate forward automatically on the
next save.

Force the migration immediately with `ironmesh trust migrate`.

### Strict TLS + pinned CA

`--strict-tls` requires a CA-validated cert (hostname check +
`CERT_REQUIRED`) on outbound WebSocket connections, for deployments
where WSS endpoints carry real certificates. Pair with `--pinned-ca
<path>` to use a private CA bundle as the trust anchor. Default mesh
mode is unchanged (`CERT_NONE` + `check_hostname=False`) so
self-signed mesh certs continue to work; peer authentication still
runs at the application layer via TOFU-pinned Ed25519 + signed HELLO.

### Global daemon-wide rate cap

`--max-msgs-per-sec N` adds a global cap on inbound message rate
across all peers, on top of the existing per-peer limiter. Off by
default; enable when the mesh is exposed to potentially-hostile
peers. Burst capacity = ceil(rate). The
`GLOBAL_RATE_LIMIT_TRIGGERED` audit event fires (sampled at ≤ 1/10 s)
when the cap rejects an inbound message.

### Trust + keys CLI

Four new `ironmesh trust` subcommands cover the out-of-band trust
workflow:

- `trust verify <node-id> <fp>` — checks an out-of-band fingerprint
  against the pinned store. Prefix match ≥ 8 hex; `--json` for
  machine output.
- `trust migrate [--dry-run]` — rewrites a v1 plaintext envelope to
  the v2 encrypted shape; idempotent.
- `trust export <node-id>` — dumps a peer's pin as JSON for backup
  or side-channel sharing.
- `trust pin <node-id> <pubkey-b64> [--state ...]` — offline manual
  pin from any out-of-band channel; required for pure-LoRa or
  disconnected deployments where the LAN handshake path is
  unavailable.

`ironmesh keys fingerprint [--format hex|colons|json]` prints this
node's identity fingerprint for read-aloud or side-channel paste-in.

### Signed CAPABILITY_ANNOUNCE frames

Capability advertisements whose `origin` differs from the delivering
peer now require an inner Ed25519 signature from `origin` under the
`SIG_CTX_X25519_BINDING` domain-separation context. The receiver
verifies the signature against the origin's pinned identity key
before learning the caps. Closes the prior relay-impersonation gap
where a malicious relay could poison a third party's pinned
cap-set baseline. 300 s freshness window (configurable via
`capability_announce_max_age`) plus a per-`(origin, announced_at)`
replay-dedup LRU.

Direct-from-peer announces (`origin == peer_id`) without the inner
signature remain accepted for backward compatibility with pre-v0.9.4
senders.

### Ed25519/X25519 dual-use migration — Phases 1 + 2

The long-standing Ed25519/X25519 dual-use property (the X25519 key
for ECDH was derived from the Ed25519 secret via libsodium's
identity-to-curve25519 transform) is being phased out in three steps.
v0.9.4 ships Phases 1 + 2:

- **Phase 1 (disk format).** `keys.json` v3 envelope adds an
  HKDF-derived 32-byte `x25519_seed`, 16-byte `hkdf_salt`, and the
  X25519 public + an Ed25519-signed binding under
  `SIG_CTX_X25519_BINDING`. The Ed25519 seed itself is preserved
  byte-for-byte — every existing TOFU pin remains valid.
- **Phase 2 (wire format).** HELLO carries two optional fields:
  `x25519_public_b64` and `x25519_binding_signature_b64`. Receivers
  that recognize the fields verify the binding signature under the
  peer's pinned Ed25519 identity and switch E2E SealedBox sealing
  to the advertised X25519. Mixed-mesh interop is preserved via the
  legacy `ed25519_to_curve25519` fallback.

Auto-migration runs on first start when a v0.9.4 daemon loads a
legacy v1/v2 keystore. Failure is non-fatal — the daemon continues
on legacy keys with a `WARNING` and the operator can re-run
`ironmesh keys migrate` once the underlying condition (disk
full, permissions, etc.) is fixed.

Phase 3 (v1.0 default-on) and Phase 4 (v1.x deprecation of legacy
fallback) remain on the roadmap. The Phase 4 cutoff comes with a
6-month deprecation runway.

### Pre-audit hardening (frame, JSON, replay, mitigations)

A targeted hardening pass to make the upcoming external audit
maximally productive — closing every gap we can already see so the
audit budget focuses on findings the project didn't catch first:

- **Frame-length ceiling.** `MAX_FRAME_BYTES = 1 MiB` enforced
  before the buffer slice in `Frame.deserialize_and_decrypt`. The
  wire field is u32 (4 GiB max); without the ceiling, a single
  attacker frame could force allocation of up to 4 GiB before the
  truncation check. Now caught early.
- **JSON nesting depth guard.** `MAX_JSON_DEPTH = 64` on inbound
  JSON parsed from the wire (deepest legitimate IronMesh shape is
  6). Applied to `Frame.deserialize_and_decrypt` and the signed
  CAPABILITY_ANNOUNCE branch.
- **`ReplayGuard.MAX_SEQUENCE = 2^48`.** Defeats the self-DoS edge
  case where a peer ratchets its own `last_seq` with an oversized
  value and can never receive again.
- **CVE-2020-10735 mitigation** (PEP 686). Daemon bootstrap calls
  `sys.set_int_max_str_digits(4300)` so the cap is uniform across
  Python 3.10 / 3.11 / 3.12 / 3.13.
- **`PROTOCOL_VERSION = "ironmesh/0.8"`** in `bridge.py` brings the
  code constant into alignment with the docs.

### Exception narrowing — signing, TOFU, rate-limit, shutdown paths

- **Signing-path narrowed `except`.** `Frame.encrypt_and_serialize`
  no longer swallows every `Exception` when generating the inner
  Ed25519 signature; programmer errors propagate. The verify paths
  (outer signature, decryption, inner-source signature) likewise
  narrowed to `BadSignatureError` / `CryptoError`.
- **Fail-closed TOFU check.** `_check_tofu_for_peer` previously
  caught every non-`ConnectionError`/`ImportError` exception with a
  `debug` log and silently let the connection proceed. Now narrowed
  to `ValueError` with a `WARNING` log and a re-raise as
  `ConnectionError` — every other exception propagates.
- **12 best-effort blocks in `bridge.py`** (rate-limit / shutdown
  / cleanup notify paths) narrowed to documented type sets.
  Behaviour unchanged on the happy path and on the expected failure
  cases; `AttributeError` / `KeyboardInterrupt` / other programmer
  errors now propagate.

### Domain-separated Ed25519 signing helpers (Option C dual-use mitigation)

New `crypto.sign_detached_with_context` /
`verify_detached_with_context` plus a registry of stable per-purpose
context labels (`SIG_CTX_CAPABILITY_ANNOUNCE`,
`SIG_CTX_X25519_BINDING`, etc.). The signed CAPABILITY_ANNOUNCE
surface is the first wire-level consumer; existing wire signatures
stay as-is pending Phase 3 of the migration.

### Constant-time fingerprint comparison

`_lookup_dest_identity` in `bridge.py` previously used `==` to match
a pinned peer's fingerprint against a node-ID lookup key. Switched
to `hmac.compare_digest` for consistency with the rest of the file
(both sides are public data so no real timing-side-channel, but the
pattern unifies the trust-evaluation surfaces).

### Audit events + Prometheus metrics

New audit events: `TRUST_STORE_ENCRYPTED`, `STRICT_TLS_ENABLED`,
`GLOBAL_RATE_LIMIT_TRIGGERED`, `CAPABILITY_ANNOUNCE_BAD_SIG`.

New Prometheus metrics:
- Gauges: `trust_store_version`, `strict_tls_enabled`.
- Counters: `global_msg_rate_limit_total`,
  `capability_announce_bad_signature_total`.

Stable per `STABILITY_PROMISE.md`.

### Doctor 8th check

`ironmesh doctor` now surfaces the trust-store envelope version on
disk (1 legacy plaintext / 2 encrypted / 3 master-seed / 0 no file
yet). 7/7 became 8/8.

### Dependency upper bounds

Every runtime, optional, and dev dependency in `pyproject.toml`
caps at the next major. Protects integrators from a future upstream
breaking change landing in a patch upgrade. Patch and minor bumps
continue to flow through automatically.

## Migration guidance

### From v0.9.3 (planned but not shipped)

Not applicable — v0.9.3 was the originally-planned point release.
Its scope is included in v0.9.4 as documented above. Operators
running on v0.9.2 see one combined upgrade.

### From v0.9.2

1. `pip install -U ironmesh` (or `docker pull
   wiztheagent/ironmesh:0.9.4`).
2. On first daemon start, the trust store migrates from v1 plaintext
   to the v2 encrypted envelope, and the keystore migrates from
   v1/v2 to the v3 master-seed envelope. Both preserve identity
   keys byte-for-byte. `.legacy.bak` is written alongside the
   original `keys.json`.
3. No operator action otherwise. The new HELLO `x25519_*` fields
   are advertised additively; pre-v0.9.4 receivers ignore them.

Migration guides:
- `docs/migration/v0_9_3_trust_store_encryption.md` (trust store v2)
- `docs/migration/v0_9_4_master_seed_format.md` (keystore v3 +
  HELLO advertisement)

### Rollback

`.legacy.bak` next to `keys.json` is the rollback target for one
full release cycle (through v0.9.5). A v0.9.2 daemon cannot read
the v3 envelope; copy `.legacy.bak` back over `keys.json` to revert.

## Wire-format invariant

The wire format remains `ironmesh/0.8` (additive only since v0.9.2).
Every existing frame shape is byte-identical. The new HELLO fields
sit outside the signed canonical body, so the HELLO signature
remains byte-compatible across v0.9.2 / v0.9.3 / v0.9.4.

## What's NOT in v0.9.4

- The post-quantum hybrid handshake (X25519 + ML-KEM-768) is a
  Phase 4+ item, deferred past v1.0.
- Cross-language test vectors for the new signing contexts are
  published in `PROTOCOL_SPEC.md §10.1`; Go and TS client updates
  to consume them ship separately.

## Verification

- 1068+ tests collected (per the working tree, `pytest
  --collect-only`); ruff CI-scope clean; release-qc green.
- Wheel + sdist build clean; 30 public modules import; CLI entry
  point operational. `scripts/release-smoke.sh` PASS.
- Live-mesh validation: per the standing 72-hour single-node-at-a-
  time upgrade procedure. See `docs/OPERATOR_RUNBOOK.md` §9 for
  the new metric to watch + the rollback drill.
