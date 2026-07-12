# IronMesh v0.9.5 — Release Notes

## Headline

A security-hardening release on top of v0.9.4.2. v0.9.5 introduces the
`ironmesh/0.9` protocol line — a domain-separated HELLO signature and,
on the Reticulum transport, a mandatory RNS link binding — alongside a
storage-KDF upgrade, transport buffering caps, a supply-chain gate, a
first-run golden-path fix, and a documentation-accuracy pass. Every
change on the wire is additive and version-gated with a legacy
fallback, so v0.8.x and v0.9.x peers stay interoperable.

**Wire protocol:** `ironmesh/0.9`, additive only. The binary frame
envelope is unchanged (still v4). The new HELLO signature scheme and
RNS link binding activate only when both peers advertise
`ironmesh/0.9+`; any peer at an older version keeps the exact legacy
path, byte-for-byte. See the **Wire-compatibility** section below.

**Operator action:** none required. Upgrade with
`pip install --upgrade ironmesh==0.9.5` or pull
`wiztheagent/ironmesh:0.9.5`. The at-rest storage key re-derives (and
the database re-encrypts) automatically on first start.

## What shipped

### Security hardening

**HELLO signature domain separation (protocol `ironmesh/0.9`).**
When both peers advertise `ironmesh/0.9+`, the HELLO is signed with a
64-byte detached Ed25519 signature under the dedicated `SIG_CTX_HELLO`
domain-separation context instead of the context-free attached
signature. This closes the cross-protocol signature-reuse surface on
the most security-critical handshake message — the one that carries
peer authentication under default mesh-mode TLS (`CERT_NONE`). The
advertised `protocol_version` sits INSIDE the signed canonical HELLO
body, so the scheme cannot be silently downgraded for a pinned peer
without invalidating the signature. Version-gated with a legacy
fallback: any peer below `ironmesh/0.9` (including the bundled
TypeScript client, which advertises `ironmesh/0.6`) uses the unchanged
legacy attached signature.

**RNS link binding + per-peer buffering cap (protocol `ironmesh/0.9`,
Reticulum transport).** On RNS Links, `ironmesh/0.9+` peers bind their
HELLO to the id of the link it travels on (`rns_link_id` inside the
signed canonical body); the receiver reads the link id off the link the
HELLO actually arrived on and rejects any mismatch, cryptographically
coupling the IronMesh identity to the RNS link session. The
`--rns-skip-handshake` path now refuses to run without a verified
binding. Pre-0.9 RNS peers keep the legacy behavior unless
`--rns-require-link-binding` is set. Each RNS link also enforces a
64 MB cumulative buffering cap that closes the link and frees memory
when overrun. `rns_link_id` is omitted entirely on the WebSocket path,
so the canonical HELLO body there stays byte-identical to the five-key
form.

**Aggregate per-identity buffering cap.** All live RNS links keyed to
the same remote identity now share a 128 MB aggregate bound on top of
the 64 MB per-link cap, closing the multi-link bypass where one
identity could hold the per-link cap times its open link count.
Unidentified links share a single anonymous bucket.

**At-rest storage key derived via Argon2id + HKDF-SHA256.** The
SQLite message store previously derived its at-rest key from a single
unsalted SHA-256 of the mesh passphrase; it now uses Argon2id + HKDF
with a per-database persisted salt, so a leaked disk image no longer
allows a fast offline dictionary attack on the passphrase. Existing
databases re-encrypt under the new key automatically on the first
daemon start. The migration only records completion once it has
migrated at least one payload (or confirmed there were none), so a
database first opened under the wrong passphrase still migrates
correctly on a later correct open.

### Supply chain + CI integrity

- Dependencies install from a hash-pinned lockfile (`requirements.lock`);
  `pip-audit` audits the lockfile pins; the mypy step is blocking via an
  error-count baseline gate (`.mypy-baseline`).
- CI now asserts its checks actually ran: pytest jobs enforce
  minimum-passed / maximum-skipped result floors, the integration job
  fails (rather than silently skipping) if an adapter framework won't
  install or import, the packaging job verifies the conformance-vector
  suite wasn't empty, and `leak-scan.sh` errors out instead of reporting
  clean when its git file listing fails.

### `bridge.py` decomposition (no behavior change)

The ~7,850-line daemon module was split into focused mixins — pure code
movement, verified against the full suite: `dashboard_html.py`,
`dashboard.py`, `handshake.py`, `routing.py`, `trust_ops.py`,
`metrics.py`, and `ratelimit.py`. `BridgeDaemon` composes the mixins by
inheritance and `bridge.py` re-exports every name it previously exposed,
so existing import paths (`from ironmesh.bridge import ...`) keep working
unchanged.

### First-run golden path + encrypted-by-default keys

- The `ironmesh run` command printed by `ironmesh setup` now works
  as-is. Commands that load an encrypted identity key file (`run`,
  `trust`, `doctor`, `audit export`, `keys info/fingerprint/migrate`)
  resolve the key-file passphrase through a full precedence chain —
  `--keys-passphrase` (discouraged; argv is visible in the process
  list) > `--keys-passphrase-file <path>` > `IRONMESH_KEYS_PASSPHRASE`
  env var > the mesh passphrase tried silently > an interactive prompt
  naming the key file > a hard error listing every option. `run
  --rotate-keys` no longer drops the key-file passphrase, and headless
  invocations error out actionably instead of hanging on a hidden
  prompt.
- Auto-generated (and `--rotate-keys`-rotated) identity key files are
  now encrypted with the mesh passphrase by default, matching the
  documented claim; a plaintext key file found on disk is re-encrypted
  forward on the next start. Writing an unencrypted key file requires
  the explicit `--plaintext-keys` opt-in.

### Operator UX polish

- `ironmesh demo` tears down cleanly and prints an unmistakable final
  `Demo complete` line; the mDNS-close shutdown deadlock and the noisy
  interpreter-exit task destruction are fixed.
- Client-side handshake auth rejection logs an actionable message
  (likely mesh-passphrase mismatch, which sources to check, and the
  `ironmesh doctor --peer` dry-run) instead of a bare `Auth rejected`.
- `ironmesh doctor` check 8 points strict-TLS / global-rate-cap
  remediation at the running daemon's `/metrics` endpoint instead of a
  nonexistent `ironmesh status` command.
- Missing-Reticulum hints recommend `pip install ironmesh[rns]` instead
  of the bare `pip install rns`.
- The `nat_relay` module docstring no longer implies a daemon-side
  `--nat-relay` attach flag exists.

### AutoGen adapter

The AutoGen adapter gains `create_mesh_tools()`, returning the mesh
functions as construction-time tools for the modern `autogen-agentchat`
API (legacy `register_ironmesh()` unchanged). The adapter integration
test drives a real `AssistantAgent` end-to-end instead of skipping, and
CI installs `autogen-agentchat` in place of the discontinued legacy
`pyautogen` module.

### Documentation accuracy

- Project-status language aligned with the Alpha classifier
  ("production-grade" removed; crypto described as built on audited
  libsodium primitives, distinct from the still-pending external
  protocol audit), and a post-quantum migration plan (hybrid X25519 +
  ML-KEM-768, pre-v1.0) added to `SECURITY.md`.
- Accuracy pass against shipped behavior: protocol-line references
  brought to `ironmesh/0.9` across README / ARCHITECTURE / WHATS_NEW /
  STABILITY_PROMISE / THREAT_MODEL, getting-started walkthroughs
  corrected to commands and SDK calls that exist, the not-yet-wired
  `--nat-relay` daemon flag and the CLI-unread JSON-config / env-var
  family documented honestly, and missing security flags added to
  `docs/CONFIGURATION.md`.
- Docs-site links that pointed at repository files outside `docs/` now
  use absolute GitHub URLs, so `mkdocs build --strict` passes with zero
  broken-link warnings.

## Wire-compatibility

**v0.9.5 introduces protocol `ironmesh/0.9`, but every wire change is
additive and version-gated with a legacy fallback — no existing wire
bytes change for existing peers, and v0.8.x / v0.9.x interop is
preserved.**

The evidence, by surface:

- **`VALID_PROTOCOL_VERSIONS`** (`protocol.py`) gains `ironmesh/0.9`
  additively; every prior string (`ironmesh/0.3` … `ironmesh/0.8`)
  remains present, so no older peer's advertised version is rejected.
- **HELLO signature** (`crypto.py` `SIG_CTX_HELLO`, `handshake.py`
  `_peer_supports_hello_ctx` / `HELLO_CTX_MIN_VERSION`). The
  domain-separated signature is emitted and required only when BOTH
  peers advertise `ironmesh/0.9+`; if either side is older, both sides
  fall through to `crypto.sign_message` — the unchanged legacy attached
  signature over the same canonical bytes. The gate keys on the peer's
  advertised version, and that version travels inside the signed
  canonical body, so a downgrade cannot be forced against a pinned
  peer without invalidating the signature.
- **RNS link binding** (`protocol.py` `canonical_hello_bytes`). The
  `rns_link_id` sixth key is added to the canonical HELLO body only on
  RNS Links toward `ironmesh/0.9+` peers; when it is `None` (the
  WebSocket path, and every pre-0.9 RNS peer) the body is byte-identical
  to the original five-key form. Pre-0.9 RNS peers keep legacy behavior
  unless the operator opts in with `--rns-require-link-binding`.
- **Frame envelope** (`protocol.py` `Frame.VERSION = 4`). Unchanged.
  The frame still accepts v3 and v4 frames; no header field, flag, or
  layout changed.

Files / specs checked: `protocol.py` (`VALID_PROTOCOL_VERSIONS`,
`canonical_hello_bytes`, `Frame`), `crypto.py` (`SIG_CTX_HELLO`),
`handshake.py` (`_peer_supports_hello_ctx`, `HELLO_CTX_MIN_VERSION`,
negotiation gate), `bridge.py` (`PROTOCOL_VERSION`,
version-gated sign/verify call sites), and `docs/PROTOCOL_SPEC.md`
("HELLO signature domain separation", "RNS link binding"). No change
that breaks v0.8.x / v0.9.x interop was found.

## What's NOT in v0.9.5

- No binary frame-envelope changes (still v4).
- The post-quantum hybrid handshake (X25519 + ML-KEM-768) is planned
  pre-v1.0; the migration plan is published in `SECURITY.md`, but the
  handshake itself does not ship here.
- External audit findings: pending the audit engagement.

## Verification

- 1198 tests collected; full unit suite green (`pytest tests/
  --ignore=tests/integration`). ruff CI-scope clean. release-qc
  `FAIL: 0`; doc-sync-check PASS.
- Wheel + sdist build clean; public modules import; CLI entry point
  operational.

## Upgrade

```
pip install --upgrade ironmesh==0.9.5
docker pull wiztheagent/ironmesh:0.9.5
```

No keystore migration and no peer-mesh coordination required. The
at-rest storage key re-derives and the database re-encrypts on first
start. v0.8.x and v0.9.x daemons interoperate with v0.9.5 daemons on
the unchanged legacy wire paths.
</content>
</invoke>
