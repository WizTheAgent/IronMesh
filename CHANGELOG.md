# IronMesh Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Supply-chain hardening: CI installs dependencies from a hash-pinned lockfile (`requirements.lock`), pip-audit now audits the lockfile pins, and the mypy step is blocking via an error-count baseline gate (`.mypy-baseline`).

## [0.9.4.2] — 2026-05-23 — Operator-polish sweep

A focused sweep of operator-facing fixes surfaced by the v0.9.4
multi-node verification run. No protocol changes, no wire-format
changes — drop-in replacement for v0.9.4.1.

### Added

- **Multi-homed peer address selection.** When an mDNS announcement
  carries multiple IPv4 addresses (multi-homed peer with both a LAN
  and a VPN interface, for example), the discovery callback now
  prefers the candidate whose `/24` matches one of the local host's
  interfaces. Falls back to the first announced address when no
  subnet matches, so single-homed setups behave exactly as before.
  Local interface set is cached after the first lookup.
  - Known limitation: interface detection via `gethostbyname_ex` is
    ineffective on Linux hosts whose hostname maps to `127.0.1.1`
    (the subnet match finds nothing and it falls back safely to the
    first announced address). A `getsockname()` probe is queued as a
    follow-up.
  - New module-level helpers in `bridge.py`:
    `_ipv4_to_int`, `_select_closest_subnet_address`.
  - New `BridgeDaemon._local_subnet_prefixes` instance method.
  - `tests/test_subnet_preference.py` covering parse + selection
    (15 cases including malformed inputs and the no-match fallback).
- **`ironmesh doctor --peer HOST:PORT`.** Dry-run diagnostic that
  opens a plaintext `ws://` connection and reports the failure point
  cleanly — unreachable host, port closed, transport error, or
  "connected but no initial frame within 3s". Checks reachability and
  whether an initial frame arrives; does not complete authentication,
  so it cannot confirm a passphrase match (a no-frame result can mean
  a passphrase mismatch, a TLS-required peer, or a non-IronMesh host).
  Avoids the auth-failure-block storm the operator would otherwise
  hit. Pair with `--passphrase-file` for non-interactive runs.
- **`tools/start-daemon-detached.sh`.** Reliable SSH-detached
  daemon launch using `setsid`. `nohup ... & disown` over SSH does
  NOT actually survive logout — the daemon receives SIGHUP when
  the controlling terminal closes. The wrapper puts the daemon in
  its own session/process group so it survives. Stdout/stderr land
  in `~/.ironmesh/daemon.log`.
- **`tools/transfer-wheel.sh`.** Wheel transfer with SHA256
  verification on the remote end. `scp` over a flaky home WAN has
  been observed to complete with exit code 0 while transferring a
  truncated file; this wrapper streams via `ssh ... 'cat > path'`
  and re-checks the SHA after copy. Exits with a distinct non-zero
  status on a checksum mismatch so a stale wheel never reaches
  `pip install`.
- **`examples/llm_bridge.py` — `--db-path` / `--trust-path` flags.**
  CLI parity with the main `ironmesh run` command. The v0.9.4
  sibling-path auto-derivation from `--keys-path` is still in
  effect, so most operators don't need these — they're useful for
  multi-tenant deployments that share a key directory.

### Changed

- **`examples/llm_bridge.py` — default Ollama timeout 30s → 180s.**
  The previous default was too tight for 14B+ models on older GPUs;
  v0.9.4 live testing saw a model timeout mid-conversation despite
  the model being healthy. New default leaves headroom for long
  generations under load. Configurable via `--timeout`.
- **`examples/llm_bridge.py` — `query_ollama` retries transient
  failures once.** Connection failures and timeouts now retry after
  a 2-second backoff before surfacing `[LLM-ERR]` to the caller.
  HTTP 4xx (model not found, bad request) is treated as permanent
  and surfaces immediately without retry. Configurable via the
  `retries` / `backoff` kwargs.
- **`examples/llm_bridge.py` — better unknown-role error message.**
  When `--role <bad-name>` is passed, the error response now lists
  every valid role on its own line (rather than a comma-joined
  list) and adds a one-line nudge toward `--system-prompt` for
  custom personas.

### Test count

1083 collected (was 1068 at v0.9.4.1). +15 from the new
`test_subnet_preference.py` module.

## [0.9.4.1] — 2026-05-21 — CI fix: Windows py3.13 concurrent-migration race

### Fixed

- **`migrate_keys_to_master_seed` Windows race outcome.** On
  Windows + CPython 3.13, two threads racing to migrate the same
  legacy keystore could have the losing thread's `os.replace`
  surface a `PermissionError(13)` instead of the documented
  "already in master-seed format" `ValueError`. The function now
  catches `PermissionError` from both the legacy-backup copy and
  the final save, and — if the file is in master-seed format
  by that point — surfaces the same idempotent `ValueError` the
  pre-check would have raised. Behaviour on every other platform
  is unchanged. Caught by the v0.9.4 CI matrix
  (`test_two_threads_migrating_same_file_converge` on Windows
  py3.13 only); v0.9.4 functional behaviour is otherwise unaffected.


## [0.9.4] — 2026-05-19 — Combined release (v0.9.3 + v0.9.4)

Combined release. The v0.9.3 security hardening point release (strict TLS, trust-store at-rest encryption, global rate cap, trust CLI subcommands) and the v0.9.4 pre-audit hardening pass (Ed25519/X25519 dual-use migration phases 1 & 2, signed `CAPABILITY_ANNOUNCE`, frame-length ceiling, JSON depth guard, replay upper bound, narrowed exception handling, fail-closed TOFU, dependency upper bounds) ship together as v0.9.4. See `docs/RELEASE_NOTES_v0.9.4.md` for the full operator-facing write-up.

**Why there is no v0.9.2 or v0.9.3 on PyPI:** both versions were tagged during development but never published — the PyPI release history goes `0.9.1 → 0.9.4` (and on from `0.9.4` to `0.9.4.1`, `0.9.4.2`). The v0.9.2 "1.0 prep" work and the v0.9.3 security point release both reached users inside v0.9.4, so `pip install ironmesh` always resolves to a published version; there is no installable 0.9.2 or 0.9.3.

### Fixed (live-mesh hardening pass)

Six operator-facing fixes from a live multi-node dialogue verification
run against the staged v0.9.4 build:

- **Trust-store CRITICAL-log dedup.** A single MAC mismatch on
  `known_peers.json` no longer re-emits a CRITICAL log on every
  subsequent read; the first mismatch logs CRITICAL, subsequent reads
  against the same MAC drop to DEBUG. Prevents log floods on a
  long-running daemon with a stuck mismatch.
- **`SO_REUSEADDR` on the WebSocket listener** (`websockets.serve`
  `reuse_address=True`). A daemon restart can now re-bind the listen
  socket immediately on Windows instead of blocking on `TIME_WAIT`.
- **Sibling-path auto-derivation from `--keys-path`.** When the
  operator points `--keys-path` at a non-default directory,
  `--db-path`, `--routes-path`, `--capabilities-path`, and
  `--trust-path` now default to siblings in the same directory unless
  explicitly overridden. Avoids the surprise where a custom-keys
  deployment silently uses `~/.ironmesh/data.db` for its database.
- **Identity-rotation silent reset for routes + capabilities.** When
  `routes.json` or `capabilities.json` fails its HMAC check, the body
  is peeked: if the embedded `my_node_id` belongs to a previous
  identity, the file is removed silently (INFO log, key-rotation
  case). Genuine tamper events still WARN loudly. Same pattern that
  already shipped for the trust store.
- **Post-TOFU IP-block clear.** When a peer presents a valid
  TOFU-pinned (or fresh-pin) identity, the bridge clears any
  accumulated auth-failure history for the source IP. Prevents a peer
  that briefly mismatched passphrases from staying blocked on the
  same IP after correcting itself. The block exists to defeat
  brute-force on the passphrase, not to gate known-identity peers.
- **mDNS port-churn log dedup.** "Address changed for pinned peer" in
  `_on_peer_discovered` now logs at DEBUG when only the port changed
  (same host IP) and INFO only on genuine IP changes. Cuts noise from
  the ephemeral-port shuffle that happens after a peer-side daemon
  restart.

### Pre-audit hardening + dual-use migration

### Added

- **Wire-level X25519 advertisement (Phase 2 of the Ed25519/X25519
  dual-use split).** HELLO frames now carry two optional fields when
  the daemon's keypair is in the v0.9.4 master-seed format:
  `x25519_public_b64` (32-byte X25519 identity public, base64) and
  `x25519_binding_signature_b64` (64-byte Ed25519 signature of the
  X25519 public under the `SIG_CTX_X25519_BINDING` context). Receivers
  that recognize the fields verify the binding under the peer's
  Ed25519 identity and, on success, store the advertised X25519 on
  `PeerState.x25519_identity_public` for subsequent E2E sealing. When
  either field is absent OR the binding fails to verify, receivers
  fall back to the historical `ed25519_to_curve25519` derivation
  (full back-compat with pre-v0.9.4 senders).
  - **Mixed-mesh interop preserved.** The new fields sit OUTSIDE the
    signed HELLO canonical body, so pre-v0.9.4 receivers verify the
    HELLO signature exactly as before. v0.9.4 senders still sign the
    v0.9.4-shaped canonical, leaving sig-verify byte-compatible
    across versions. The binding's own Ed25519 signature provides the
    cryptographic link between the advertised X25519 and the pinned
    Ed25519 identity, with `SIG_CTX_X25519_BINDING` domain separation
    preventing cross-context misuse.
  - **E2E SealedBox upgraded.** `mesh_crypto.seal_to_destination`
    and `unseal_from_source` gained optional `dest_x25519_pub` /
    `my_x25519_secret` kwargs. When supplied (v0.9.4 master-seed
    path), the X25519 keys are used directly; when omitted (legacy
    path), the historical `ed25519_to_curve25519` derivation runs
    inside the helpers. Callers in `bridge.py` thread the
    advertised peer X25519 from PeerState and the local subkey from
    `AgentKeys.get_x25519_secret()`.
  - **Auto-migration on first start.** `ensure_agent_keys` (the
    daemon's keypair bootstrap path) now silently migrates legacy
    v1/v2 keystores forward to the v3 master-seed envelope on first
    load. The Ed25519 seed is preserved byte-for-byte — every TOFU
    pin in the mesh remains valid — and a `.legacy.bak` is written
    next to the original. Auto-migration is best-effort: if it
    fails (disk full, permissions, etc.) the daemon still starts on
    the legacy keys without the new HELLO advertisement.
  - **Reserved HELLO field names.** `x25519_public_b64` and
    `x25519_binding_signature_b64` are formally reserved in
    `PROTOCOL_SPEC.md` §2.2 — future versions MUST NOT repurpose
    these field names.
  - **18 new tests in `tests/test_x25519_advertisement.py`** covering
    advertisement shape, forward-compat for v0.9.4 receivers,
    receiver verification (accept valid / reject swapped-identity /
    reject malformed), E2E sealing roundtrips on both paths, mixed-
    mesh interop in both directions, auto-migration + TOFU
    fingerprint survival, best-effort failure handling, and
    domain-separation contract for the binding signature.

- **Master-seed key envelope (Phase 1 of the Ed25519/X25519 dual-use
  split).** `keys.json` gains a v3 format tagged `format = "master-seed-v1"`
  that carries the existing Ed25519 seed byte-for-byte plus a new
  32-byte `x25519_seed` (HKDF-SHA256 from the Ed25519 seed +
  per-node 16-byte `hkdf_salt`). Phase 1 does NOT change wire behaviour
  — `get_x25519_secret()` returns the stored subkey when present,
  otherwise falls back to the historical `ed25519_to_curve25519`
  transform. Phase 2 (v0.9.4) wires the HELLO advertisement so peers
  can prefer the advertised X25519 key.
  - **TOFU pin survival:** the Ed25519 seed and public are unchanged
    by the migration. Every existing pinned fingerprint stays valid.
  - **Opt-in migration:** `ironmesh keys migrate` converts a v1/v2
    file in place. The pre-migration bytes are preserved at
    `<path>.legacy.bak` for one full release cycle so operators have
    a rollback path. Existing daemons continue running on legacy
    files without action.
  - **New deployments:** `generate_keypair()` defaults to the
    master-seed format. Pass `master_seed_format=False` for the
    legacy shape (tests, reproducibility).
  - **Concurrent-daemon-startup safety:** per-process+thread tmp
    filename + atomic `os.replace`. Verified empirically by
    `tests/test_master_seed_format.py::TestConcurrentMigrationRace`
    — two threads racing on the same file converge to a single
    consistent envelope, never split-brain.
  - **Integrity check on load:** the stored `x25519_seed` must
    re-derive from `HKDF(ed25519_secret, hkdf_salt, INFO_X25519)`;
    tampering with the encrypted seed is detected even if the
    passphrase is correct.

- **Signed `CAPABILITY_ANNOUNCE` frames.** Capability advertisements
  whose `origin` differs from the delivering peer now require an inner
  Ed25519 signature from `origin` using the
  `SIG_CTX_CAPABILITY_ANNOUNCE` domain-separation context. Receiver
  enforces a 300 s freshness window (configurable via
  `capability_announce_max_age`) and a per-`(origin, announced_at)`
  replay-dedup LRU. Closes the prior relay-impersonation gap where a
  malicious relay could poison a third party's pinned cap-set baseline.
  Direct-from-peer announces (`origin == peer_id`) without the inner
  signature remain accepted for back-compat with pre-v0.9.4 senders.
  New audit event `CAPABILITY_ANNOUNCE_BAD_SIG`, new metric
  `capability_announce_bad_signature_total`, new config field
  `capability_announce_max_age`.
- **Cached signed-envelope re-broadcast.** Bridge caches the verbatim
  signed CAPABILITY_ANNOUNCE envelope per remote origin (LRU, 4096
  entries) and re-broadcasts it to neighbors within the freshness
  window, preserving mesh convergence across multi-hop topologies. The
  cache only stores envelopes that have already verified locally.

### Security

- **Narrowed exception handling on 12 best-effort `bridge.py` blocks.**
  The wide `except Exception: pass` blocks on rate-limit / shutdown /
  cleanup paths now catch a documented type set per call site instead
  of swallowing every class. Behaviour is unchanged on the happy path
  AND on the documented failure cases; programmer errors
  (`AttributeError`, `TypeError`, `KeyboardInterrupt`, etc.) now
  propagate rather than getting silently dropped:
  - Per-connection rate-limit notify, per-IP rate-limit notify, and
    auth-blocked notify → `(websockets.exceptions.ConnectionClosed,
    OSError, RuntimeError)`.
  - Duplicate-connection upgrade close, finally-block close,
    peer-revocation cleanup close, and TOFU-mismatch teardown → same
    set.
  - Per-peer + global RATE_LIMITED encrypted-control notify → same
    set + `ValueError` (covers the encrypted-control input-validation
    surface).
  - `_capabilities.save()` initial-write best-effort → `OSError`
    only; logged at `WARNING` (was silent).
  - `_open_trust_store` GUI helper → `(OSError, ValueError,
    RuntimeError)`; logged at `DEBUG`.
  - Two `_gui_broadcast` notification sends (capability revert +
    capability change) → `(RuntimeError, AttributeError)`; logged.
  - `on_peer_disconnect` user-supplied hook fire → KEPT wide with
    `# noqa: BLE001` and an explanatory comment + WARNING log on
    fire. User-defined callbacks can raise any class; narrowing
    here would silently drop hook callbacks that raise a custom
    type.

  Auditors looking at these sites now see explicit type sets with
  rationale comments. The narrow failure paths cannot mask a real
  bug because every other exception class continues to propagate.

- **CPython large-int-string-conversion DoS mitigation** (CVE-2020-10735 /
  PEP 686). Daemon bootstrap now calls `sys.set_int_max_str_digits(4300)`
  unconditionally so behaviour is uniform across Python 3.10 / 3.11 / 3.12
  / 3.13. Without this, a Python 3.10 deployment parsing untrusted JSON
  with a 100k-digit integer can spend multi-millisecond CPU per parse.
- **Constant-time fingerprint comparison.** `_get_peer_identity_key`
  in `bridge.py` previously used `==` to match a pinned peer's fingerprint
  against a node ID lookup key. Switched to `hmac.compare_digest` for
  consistency with the rest of the file. Both sides are public data so
  no real timing-side-channel, but auditors flag this pattern uniformly.
- **JSON nesting depth guard.** New `protocol.safe_json_loads` rejects
  inbound JSON nested deeper than `MAX_JSON_DEPTH = 64`. Applied to
  `Frame.deserialize_and_decrypt` so an attacker who lands a deeply-nested
  payload inside the 1 MiB frame ceiling cannot push downstream
  consumers into pathological recursion. The 64 limit is well above any
  legitimate IronMesh shape (deepest known = 6).
- **`ReplayGuard.MAX_SEQUENCE = 2^48` upper bound.** A peer that sent
  `seq=2^63` would permanently ratchet its own `last_seq` and never
  receive again — self-DoS, not a real external attack, but the bound
  defeats the edge case cheaply.
- **Domain-separated Ed25519 signing helpers** (Option C, dual-use
  mitigation): new `crypto.sign_detached_with_context` /
  `crypto.verify_detached_with_context` plus a registry of stable
  per-purpose context labels (`SIG_CTX_*`). NEW signing surfaces
  (signed capability announce, future trust-pin export) MUST use these;
  existing wire signatures stay as-is pending a coordinated migration.
  Reduces audit severity of the Ed25519/X25519 dual-use finding.
- **Fail-closed TOFU check.** `bridge.py` `_check_tofu_for_peer` previously
  caught every non-`ConnectionError`/`ImportError` exception with a `debug`-
  level log and silently let the connection proceed — meaning a peer whose
  identity could not be evaluated (malformed key, transient file error on
  the trust-store backing file, missing-keypair bootstrap race) was treated
  as "trust verified". The catch is now narrowed to `ValueError` (the
  recoverable "malformed input data" branch) with a `WARNING` log AND a
  re-raise as `ConnectionError` so the connection is refused. Every other
  exception class propagates so the daemon surfaces real failures instead
  of swallowing them as a successful TOFU pass.
- **`nat_relay.MAX_FRAME_BYTES` aligned with the wire-level ceiling.** The
  NAT relay previously carried its own `2 MiB` constant that diverged from
  the protocol's 1 MiB frame ceiling, producing inconsistent acceptance
  across code paths. The relay now imports `MAX_FRAME_BYTES` from
  `ironmesh.protocol` as the single source of truth, enforcing the same
  cap on every forward path.

### Added

- **`MAX_FRAME_BYTES` ceiling (1 MiB) on `Frame.deserialize_and_decrypt`**.
  The wire format's 4-byte `encrypted_length` field is u32, so a malicious
  peer could declare up to 4 GiB and force buffer allocation before any
  truncation check. Rejection now happens immediately after reading the
  length field, before the buffer slice. Aligned with the existing 1 MiB
  websocket `max_message_size` default. Same ceiling enforced on
  `encrypt_and_serialize` and `serialize_plaintext` send paths so a daemon
  never emits a frame its own peers would reject.
- Test module `tests/test_frame_hardening.py` covering attacker-declared
  4 GiB rejection, just-above-ceiling rejection, send-side rejection,
  and regression of the legitimate small-frame round-trip.

### Changed

- **Narrowed exception handling in the frame signing path** (`protocol.py`).
  Inner-source signature generation in `Frame.encrypt_and_serialize`
  previously caught every `Exception` and silently dropped the
  signature. It now catches only the crypto-input subset
  (`nacl.exceptions.CryptoError`, `TypeError`, `ValueError`) and emits
  a `WARNING` log when this happens. Programmer errors (`AttributeError`,
  bad-key-type, etc.), `KeyboardInterrupt`, and `MemoryError` now
  propagate so real bugs surface instead of silently disabling the
  inner-source signature forever. The verification paths
  (outer detached signature, payload decryption, inner-source
  signature verify) likewise narrowed to `BadSignatureError` /
  `CryptoError` from the bare `except Exception` they previously used.

### Security hardening (originally v0.9.3 scope)

### Added

- **`--strict-tls` flag** for outbound WebSocket connections.
  Default mesh mode keeps `CERT_NONE` + `check_hostname=False` (peer
  authentication runs at the application layer via TOFU-pinned
  Ed25519 + signed HELLO), preserving compatibility with self-signed
  mesh certs. Opt-in `--strict-tls` requires a CA-validated cert
  (hostname check + `CERT_REQUIRED`) for deployments where WSS
  endpoints are issued real certificates. Pair with
  `--pinned-ca <path>` to use a private CA bundle as the trust
  anchor; without it the system trust store is used.
- **At-rest encryption for the trust store** (`known_peers.json`).
  The on-disk envelope is now SecretBox-encrypted with a key derived
  from the agent identity secret, so a host-disk leak no longer
  exposes the peer graph (node IDs, fingerprints, capability sets).
  HMAC-SHA256 over the ciphertext keeps tamper evidence + multi-daemon
  collision detection. Pre-existing plaintext stores load through the
  legacy v1 path and migrate forward on the next save — no operator
  action required.
- **`--max-msgs-per-sec N` flag** — global daemon-wide cap on inbound
  message rate across all peers. Defense-in-depth on top of the
  existing per-peer caps. Off by default since per-peer limits are
  sufficient for mutually-trusted peer sets; enable when the mesh is
  exposed to potentially-hostile peers. Burst capacity = ceil(rate).

### Changed

- **Dependency upper bounds** added throughout `pyproject.toml`. Each
  runtime, optional, and dev dependency now caps at the next major
  release so a breaking upstream major bump cannot ship into an
  unsuspecting `pip install ironmesh` mid-release-cycle. Patch and
  minor bumps continue to flow through automatically.

### Documentation

- `SECURITY.md` — TLS section now describes both default and strict
  modes; new "LAN discovery (mDNS) caveats" subsection enumerates
  what mDNS spoofing can and cannot do (it cannot bypass the
  application-layer handshake); new "Threat-model assumption — peer
  set" subsection makes explicit that per-peer caps assume mutually
  trusted peers and recommends external rate limiting for deployments
  that expose the mesh to potentially-hostile peers.
- `docs/QUICKSTART.md` — trust-management section now points operators
  at out-of-band fingerprint verification before exchanging sensitive
  traffic with a new peer, and documents `--strict-tls` for
  transport-level authentication on top of the application-layer pin.

## [0.9.2] — 2026-04-27 — 1.0 prep mega-release

The mega-release on the road to 1.0. Every piece originally
scheduled across v0.9.2 → v0.9.7 (per `docs/ROADMAP_TO_1.0.md`)
landed in this single release so that v1.0 is a stability promise
rather than a feature push.

### Added

- **Stage-1 handshake skip on identified RNS Links** (chunk A,
  protocol/0.8). Opt-in via `--rns-skip-handshake`. When both peers
  advertise the `hskip` feature in their RNS announces, the IronMesh
  stage-1 challenge / verify is replaced by a deterministic 32-byte
  SHA-256 sentinel used as channel binding. RNS Link Identity
  authentication takes the place of the IronMesh-layer passphrase
  on these connections; the passphrase remains the gate everywhere
  else. **Server-driven negotiation:** the server is the active
  party and SPEAKS FIRST — when both sides are eligible it emits a
  new `SKIP_OFFER` message carrying the channel binding sentinel;
  otherwise it emits the legacy `PASSPHRASE_CHALLENGE`. The client
  type-dispatches on the first server message — never decides skip
  unilaterally. This eliminates the asymmetric-decision race that
  would otherwise crash handshakes when announces propagated
  asymmetrically. Defense-in-depth: client rejects any
  `SKIP_OFFER` whose channel_binding doesn't equal the deterministic
  sentinel (downgrade-attempt guard). The outbound side calls
  `link.identify(self._identity)` after RNS Link ACTIVE so the
  receiving side can match the peer's hskip-announce; the server
  briefly polls (1.5s budget) for the identify proof to land before
  deciding. Verified live cross-host — both sides' counters
  incremented to 1 on the first identified RNS Link.
  14 unit tests + live-fire cross-host validation. Documented in
  `PROTOCOL_SPEC.md §2 Stage 1 skip` + `THREAT_MODEL.md` cross-asset
  attacks (downgrade path).
- **Shared-secret mesh-wide broadcast** (chunk B). Opt-in via
  `--rns-group-broadcast`. Both the group Identity (64 B) and the
  symmetric group key (32 B) are derived from the daemon passphrase
  via HKDF-SHA256 with domain-separated `info` labels, so every peer
  in the mesh independently arrives at the exact same destination
  hash and can decrypt group traffic without any negotiation.
  Two-phase delivery — phase 1 is an O(1) RNS GROUP packet on the
  local segment (reaches everyone sharing the same RNS Transport,
  e.g., daemons connected to one rnsd, or all nodes on one LoRa
  medium); phase 2 is an O(N) IronMesh GROUP_BROADCAST fan-out over
  every established connection to peers that advertised the `group`
  feature in their RNS announce. The two-phase design fills the
  RNS architectural gap: GROUP destinations cannot be `announce()`d
  (RNS rejects with "Only SINGLE destination types can be
  announced"), so cross-host packets won't naturally route to a
  remote GROUP listener — phase 2 covers that path explicitly.
  Inbound surface: `on_group_broadcast(payload)` hook. Dedup keyed
  on payload SHA-256 with a 60 s window + 10,000-entry hard cap (an
  OrderedDict for O(1) eviction) — a peer that hears the same payload
  via BOTH phases handles it exactly once. New `GROUP_BROADCAST`
  message type in `protocol.py` carries the payload over established
  Links. Verified live cross-host. Documented in
  `PROTOCOL_SPEC.md §8 feature flags`.
- **`Agent.send_to_capability(pattern, payload)`** (chunk E). Resolves
  an fnmatch glob against the capability registry and dispatches via
  the unified-transport layer. Three strategies: `first` (best-RTT
  online peer wins, falls through on failure), `random` (load
  distribution), `all` (parallel fan-out with per-target results).
  Local node never picked. Documented in `PROTOCOL_SPEC.md §11`.
- **Wire-format v5 / `ironmesh/0.8`** (chunk C). The wire format
  itself is unchanged from v4 — v5 names the optional Stage 1 skip
  on identified RNS Links and the new `hskip` feature flag.
  Documented in `PROTOCOL_SPEC.md §8` (announce app_data) +
  `§11` (per-feature stable-since table).
- **100-node synthetic scale harness** (chunk D) at
  `scripts/stress_scale_100.py`. Spawns N daemons on sequential
  localhost ports, wires a random mostly-connected bootstrap
  topology, then validates (a) full mesh convergence within a
  deadline (every node sees every other node in `unified_peers`),
  (b) broadcast fan-out from node 0 is delivered to all N-1 others
  exactly once (dedup cache correctness at scale), (c) no daemon
  crashes during the run. Operator-run, not pytest-collected —
  ~30-60 s wall-clock and several hundred MB of RAM at the default
  N=100. Seed is fixed by default so topology is reproducible.
- **Conformance test suite skeleton** (chunk H). Language-agnostic
  golden vectors live in `tests/conformance/vectors/` with a
  documented JSON format. The Python reference implementation runs
  them via `tests/test_conformance_vectors.py`; alternate
  implementations (Go / Rust / Swift) are expected to load the same
  files and run an equivalent runner. First wave covers announce
  app_data (3 vectors), handshake skip sentinel (1 vector), and
  shared-secret group key derivation (2 vectors — identity material
  + symmetric key, both HKDF-SHA256 with documented salt+info+length)
  — more follow as the wire surface matures.
- **OpenTelemetry spans on the v0.9.x agent surfaces** (chunk I).
  `Agent.send_to_name`, `Agent.send_to_capability`, handshake skip
  activations all instrumented. Spans are no-ops on installs without
  the `otel` extra. Pre-canned **Grafana dashboard JSON** + **9
  Prometheus alert rules** ship under `scripts/observability/` —
  drop in for an immediate full ops view.
- **`docs/ROADMAP_TO_1.0.md`** publishing the v0.9.x → v1.0 release
  ladder commitment. Each release in the ladder carries a single
  focused theme; no v0.9.x release introduces a breaking change
  without a documented migration path. Originally a multi-release
  ladder; collapsed into v0.9.2 per release scope expansion.
- **Federation policy v2 — per-source matchers.** `FederationPolicy`
  now accepts a `per_source` list of glob-matched rules that override
  the global allow/deny for a specific sender. First match wins; falls
  through to global policy on no match. Backwards compatible — omit
  `per_source` and behavior is identical to v0.9.1. Use cases include
  per-team trust tiers (`ops-*` unrestricted, `guest-*` fully denied)
  and per-capability sub-scoping (`trader-*` allowed `tool:trade:read`,
  denied `tool:trade:write`). Six new tests in
  `tests/test_federation.py`.
- **Bundled NAT relay — operator-run rendezvous for WAN meshes.** New
  module `ironmesh.nat_relay` + entry `python -m ironmesh.nat_relay`
  implements Option A (pure relay) from `NAT_TRAVERSAL_DESIGN.md`. A
  single-purpose WebSocket server that forwards sealed envelopes
  between registered peers by `node_id`. The relay never holds session
  keys, never sees plaintext — it only reads the outermost `{type, to}`
  envelope. Per-peer forward-rate caps (100/s sustained) and registry
  caps (10k peers per instance) bound abuse. Eight new tests in
  `tests/test_nat_relay.py` (registry unit tests + E2E
  register/forward/unreachable/unregistered paths). Hole-punching on
  top of this relay fallback remains on the roadmap for a later
  release.
- **Metrics v0.9.2 — new counters for the agent-interop surfaces.**
  `ironmesh_capability_routes_attempted_total`,
  `_succeeded_total`, `_no_match_total` for `send_to_capability()`
  outcomes; `ironmesh_handshake_skips_offered_total` (server emitted
  SKIP_OFFER), `ironmesh_handshake_skips_activated_total` (client
  accepted), `ironmesh_handshake_skips_rejected_total` (client
  rejected for missing/non-hex/wrong channel_binding) for the chunk A
  skip path — three-way split so divergence between fleet-wide sums
  of offered vs activated surfaces send failures, and any non-zero
  `_rejected` rate flags downgrade-attempt or buggy-peer noise for
  the alert pipeline; `ironmesh_group_broadcasts_{sent,received,deduped}_total`
  for chunk B broadcast. All registered in the Prometheus spec and
  to_dict() JSON surface. Two new Prometheus alert rules:
  `IronMeshCapabilityRouteNoMatchSpike` and
  `IronMeshGroupBroadcastDedupStorm`. Full catalog in the new
  `docs/METRICS_REFERENCE.md`.
- **`docs/STABILITY_PROMISE.md` — the v1.0 stability contract.**
  Enumerates every wire-protocol surface, Python API, CLI flag,
  config-file field, metric name, and OTel span name that is frozen
  at v1.0. Defines the deprecation procedure (one minor of
  warnings + migration guide + next-major removal), security backport
  policy (≥ 6 months on the previous minor), and the wire-version
  negotiation matrix. The §6 commitment: v1.0 is the label, not a
  feature drop — nothing on the wire changes.
- **Docs site nav overhaul.** `mkdocs.yml` nav now surfaces the
  stability promise, metrics reference, security section, and testing
  section alongside the existing Operator / Transport / Integration /
  Specification groups. `docs/index.md` landing page updated with
  direct links to the new v0.9.2 deliverables.
- **Opt-in RNS multi-process RPC mitigation.** Two ironmesh daemons
  on one host without rnsd can collide on the default RNS shared-
  instance RPC port (37428) with different per-configdir authkeys.
  Set `IRONMESH_SEED_RNS_CONFIG=1` to enable a per-daemon config
  seeder that writes unique `shared_instance_port` and
  `instance_control_port` (deterministically derived from the
  daemon's node_id hash) into the daemon's configdir. **Off by
  default** because turning it on prevents the daemon from joining
  an existing rnsd shared instance. AutoInterface settings
  (`group_id`, `discovery_port`, `data_port`) are NEVER overridden —
  that would fragment the global cross-host mesh. The standard
  multi-daemon-on-one-host pattern remains rnsd; this seeder is for
  no-rnsd test setups only.
- **Shutdown WARN spam quieted.** Graceful shutdown previously fired
  `logger.warning("Failed to send frame to %s: %s", ...)` for every
  in-flight route announce hitting a closing peer. `ConnectionClosed`
  is now logged at DEBUG; unexpected exceptions still surface at
  WARNING.
- **Ratchet directory not pre-created on RNS singleton-reuse.** When
  a second in-process daemon reused an existing `RNS.Reticulum`
  singleton, RNS tried to write a per-destination ratchet file
  inside a configdir the second daemon had specified but never
  populated. Resulted in `FileNotFoundError` mid-init.
  `ReticulumTransport.start()` now ensures the configdir exists
  unconditionally on both the create-new and singleton-reuse paths.
- **GROUP destination duplicate registration in shared singleton.**
  When two in-process daemons both opted into `--rns-group-broadcast`
  with the same passphrase, the second's RNS Destination init failed
  with `'Attempt to register an already registered destination.'`
  silently leaving its `_group_destination = None`. The transport now
  detects an existing IN-direction GROUP destination via
  `RNS.Destination.hash_from_name_and_identity` + iteration of
  `RNS.Transport.destinations`, and adopts it. The first daemon's
  packet callback still owns receive; the second can SEND on the
  shared destination.
- **`broadcast_via_group` no longer recreates the OUT destination on
  every call.** The OUT-direction RNS.Destination is now constructed
  lazily on first use and cached on the transport. Avoids wasted
  Destination registrations and any RNS routing-cache confusion in
  high-frequency broadcast paths.
- **GROUP broadcast dedup cache is now bounded + O(1) hot-path.**
  Previously the cache used a plain dict and walked all entries on
  every receive to find stale ones — O(N) per receive, with no size
  cap. A burst of unique-payload broadcasts could drive unbounded
  memory growth and degrade receive latency. Now uses an
  `OrderedDict` capped at 10,000 entries with O(1) eviction of
  stale-or-oldest entries. New regression test
  `test_group_dedup_cache_is_bounded` enforces the cap.
- **NAT relay payload type validation.** `FORWARD` frames now require
  `payload` to be a non-null string (typically a base64-encoded
  sealed envelope); previously any JSON value (`null`, list, dict,
  number) was forwarded verbatim, surfacing as opaque downstream
  errors. `to` is also explicitly required to be non-empty. Forward-
  to-target failures are now logged at INFO instead of DEBUG so
  operators can see persistent delivery problems. Two new tests
  cover the validation paths.

### Documentation

- **Threat model formalised for v1.0 audit prep** (chunk G). New
  STRIDE entries for v0.9.x assets (RNS Identity + ratchets, LXMF
  delivery identity, pending-trust queue, RNS admin allow-list).
  New cross-asset attack rows for RNS announce spoofing, capability
  forgery, federation forwards, Resource transfer lockout,
  handshake-skip downgrade. New §6 trust-boundary diagram. New §8
  external-audit pre-pack listing every doc + fixture an auditor
  needs.
- **PROTOCOL_SPEC.md updated for wire/0.8.** New §11 implementation-
  status table marks every protocol surface as stable-since
  whatever release introduced it — the foundation of the v1.0
  stability promise.

### Deferred from this release

- NAT traversal hole-punching layer. The relay half of the hybrid
  design (Option A in `NAT_TRAVERSAL_DESIGN.md`) ships in v0.9.2; the
  STUN-based hole-punching optimization on top of it remains a future
  release item — the relay is always a correct fallback, so the gap
  is a latency optimization rather than a correctness one.
- 100-node synthetic scale test — full sustained-throughput baseline
  publishing to the docs site. The fixture ships in v0.9.2
  (`scripts/stress_scale_100.py`); the first baseline numbers will
  land in a follow-up commit once the harness runs on dedicated
  hardware instead of a shared workstation.
- Multi-hop federation gateway cascades. Federation v2 per-source
  rules ship in v0.9.2; cascading multi-mesh → multi-mesh → multi-mesh
  topologies are tracked for a later release.

## [0.9.1] — 2026-04-24 — Reticulum integration sweep

### Fixed (round-2 stress test discoveries)

- **Multiple Agent SDK instances in one process raced on the RNS
  singleton.** A second `ReticulumTransport.start()` would crash with
  "Attempt to reinitialise Reticulum, when it was already running"
  because RNS enforces one Reticulum instance per process. Now
  detects the existing singleton via `RNS.Reticulum._Reticulum__instance`
  and reuses it. Lets in-process tests, multi-Agent demos, and
  embedded use cases work cleanly.
- **Fallback ratchet path collided when no `_configdir` was passed.**
  The fallback used a single `<tmp>/ironmesh_ratchets` location, so
  multiple daemons in the same process (Agent SDK without
  `--rns-configdir`) would all write to the same file and corrupt it
  with "Invalid ratchet file signature" errors after the first cycle.
  Fallback path now includes the daemon node_id (or process PID as a
  last-resort tag).
- **LXMF listener never shut down with the daemon.** Its periodic
  announce + telemetry asyncio tasks would race with daemon shutdown
  and emit "loop closed" tracebacks during teardown. Daemon shutdown
  now stops the LXMF listener BEFORE the Reticulum transport.

### Fixed (discoveries during testing)

- **Per-packet ratchets were silently disabled.** `enable_ratchets()`
  expects a file path, not a boolean — the original `enable_ratchets(True)`
  call passed `True` as the path argument, RNS coerced it to fd 1, and
  the destination ran without forward-secret per-packet protection
  even though startup logged "ratchets enabled". Now passes a real
  per-daemon path under the Reticulum config directory.
- **Two daemons sharing a Reticulum config directory got the same
  destination hash.** The persistent RNS identity was loaded from a
  single `<configdir>/ironmesh_identity` file, so any two IronMesh
  daemons on the same host (parallel-deploy testing, multi-tenant
  hosts) produced indistinguishable destinations and raced on the
  ratchet store. Identity (and ratchet) filenames are now keyed by
  the IronMesh node_id so each daemon gets its own.
- **Inbound RNS handshakes hung when a "throughput optimisation"
  removed a 500 ms settle.** The settle existed so the client side
  could wire up its Buffer receive callback before the server
  started writing the passphrase challenge. Removing it dropped the
  challenge, the client waited for it forever, and every inbound
  handshake on the RNS path stalled. Restored the settle with a
  thorough docstring on why it has to stay.
- **`Agent.send_to(name)` tier-2 path (auto-Link an
  announce-discovered peer) hung indefinitely.** The internal
  `_do_client_handshake` runs an indefinite per-connection message
  loop after the handshake completes — it only returns when the
  connection closes. The send_to resolver was awaiting that
  function and so never proceeded to the actual `send_message`
  call. Fixed by spawning the connect as a background task and
  polling `self.peers` for the expected node_id to come online,
  with a 30 s deadline.



Multi-phase upgrade to the Reticulum transport adapter, bringing it in
line with the RNS 1.1.x feature surface and laying the groundwork for
deeper interop with the broader Reticulum ecosystem (Sideband, MeshChat,
Nomadnet, LXMF).

### Changed

- **`rns` extra now requires `>=1.1.9`** (was `>=0.9.0`). Required for
  ratchets, MTU autodiscovery, `Transport.await_path`, and the recent
  bz2 decompression-bomb fix. The `lxmf` extra also bumps accordingly.

### Added

- **Unified transport selection via `Agent.send_to()`.** A single call
  that picks the best available transport for a named peer:
  WebSocket / RNS Link for existing online peers, auto-established
  RNS Link for announce-discovered peers, LXMF for 32-byte
  destination hashes when the `--lxmf` listener is running. Returns
  a descriptor naming the transport and tier used
  (`{"transport": "rns", "target": "node-bob", "tier": 2, ...}`).
  The OpenClaw channel, ACP stdio adapter, and A2A HTTP gateway all
  call this internally — adding a future transport is a one-site
  change in the daemon rather than a per-adapter rewrite.
- **`Agent.unified_peers` — merged view across all transports.**
  Every known peer with a `reachable_via` list naming the
  transports that can reach them right now (`"websocket"`, `"rns"`,
  `"rns_announce"`). Includes live metrics (`estimated_rtt_ms`,
  `estimated_bps`, `rns_hops`) so AI agents can make scheduling
  decisions (send now / queue / skip) with a single dict lookup.
  Replaces the WS-only `Agent.peer_by_name` heuristic.
- **Auto-discovery of IronMesh peers over RNS.** Every IronMesh node now
  registers an `RNS.Transport` announce handler and emits a structured
  announce app_data payload (`{n,v,i,c,f}`) carrying the agent name,
  ironmesh version, node_id, capability list, and feature flags.
  Nodes hearing each other's announces auto-populate a discovery map
  — no operator-typed destination hashes required. Pre-v0.9.1 peers
  emitting plain-name app_data still appear; the decoder falls back
  cleanly. Schema is documented in `reticulum_transport.py`.
- **Live RNS link metrics on `PeerState` and dashboard.** A 5 s poller
  samples each active Link for MTU, MDU, expected bps, RSSI, SNR, Q,
  age, and silence duration, writing them onto the peer record. The
  dashboard JSON API surfaces them as `rns_link_mtu`, `rns_estimated_bps`,
  `rns_rssi`, `rns_snr`, `rns_q`, etc. — usable by any HTTP/MCP
  consumer. Phy stats are no-ops on non-radio links.
- **Native link liveness for RNS peers.** `_heartbeat_loop` no longer
  PINGs RNS peers every 30 s. Instead it consults `link.no_data_for()`
  via the latest stats sample and tears down silent Links above a
  configurable threshold. PINGs are still sent at a 5x cadence to
  keep IronMesh-protocol state warm. Saves real bandwidth on LoRa.
- **`Transport.await_path` for outbound link setup.** Replaces the
  busy-poll-with-exponential-backoff loop in `connect_to_destination`
  with the native RNS path-response signal. Path resolution wakes up
  as soon as the announce arrives instead of at the next backoff tick.
- **Early remote-identity capture.** `RNSLinkAdapter` installs
  `set_remote_identified_callback` and synchronously reads
  `get_remote_identity()` at construction so the remote's RNS Identity
  hash is available the moment RNS confirms it. Foundation for an
  optional handshake-skip in a later release.
- **RNS Resource for large payloads.** Outbound frames larger than 32 KB
  are auto-routed through `RNS.Resource(auto_compress=True)` instead of
  being inlined as length-prefixed Buffer writes. Resource handles
  chunking, sequencing, integrity, bz2 compression, and resume natively.
  Hard cap of 64 MB per Resource prevents lockout. Inbound Resources
  are accepted on every Link via `set_resource_concluded_callback` and
  fed onto the same async queue the Buffer path uses, so the daemon's
  message loop is unchanged. Routing is gated on the peer advertising
  the `resource` feature; old peers see no behavioural change.
- **LXMF interop listener (`--lxmf`).** New `lxmf_listener.py` module
  brings up an LXMF delivery identity alongside the IronMesh bridge so
  Sideband / Nomadnet users can message IronMesh agents and vice
  versa. Inbound LXMessages are routed to a configurable IronMesh
  peer (`--lxmf-default-peer` or per-source `inbound_route` map);
  outbound IronMesh MSG events on mapped peers round-trip to LXMF
  automatically. Loop prevention via `[LXMF]` / `[IM]` payload
  prefixes. Persistent identity in `~/.ironmesh/lxmf/`. New CLI
  flags: `--lxmf`, `--lxmf-storage`, `--lxmf-display-name`,
  `--lxmf-default-peer`. Requires the `lxmf` extra
  (`pip install ironmesh[lxmf]`).
- **LXMF telemetry publishing (`--lxmf-telemetry-target`).** When a
  target destination hash is configured, the listener sends a
  periodic plain-text metrics summary (uptime, peer counts, message
  rates, byte totals, handshake successes, LXMF stats) as an
  LXMessage to that destination. Format is the lowest-common-
  denominator `# IRONMESH-TELEMETRY v1` text block — any LXMF client
  renders it without special handling. Tunable cadence via
  `--lxmf-telemetry-interval` (default 300 s). Fleet monitoring
  without HTTP endpoints, central services, or account systems.
- **LXMF propagation node mode (`--lxmf-propagation-node`).** Opt-in
  store-and-forward infrastructure for offline LXMF peers. Recommended
  only on always-on hosts with persistent storage. Storage path
  configurable via `--lxmf-propagation-storage`.
- **`docs/RETICULUM.md` integration guide.** Single-page operator
  reference covering installation, interface configuration matrix
  (full / gateway / boundary / roaming / access_point), IFAC
  (Interface Access Code) network-layer membership, LXMF setup,
  the public RPC paths, tuning flags, and troubleshooting.
- **Admin RPC paths gated by identity allow-list.** Three additional
  paths expose daemon-level admin information, each requiring the
  caller's RNS identity hash to be in an explicit allow-list:
  `/im/admin/status` (uptime, peer counts, message rates),
  `/im/admin/peers` (full per-peer state), `/im/admin/audit` (last N
  audit entries; capped at 1000). Configure via `--rns-admin-identities`
  or `IRONMESH_RNS_ADMIN_IDENTITIES` env var. Empty allow-list
  (default) means every admin call returns unauthorized — admin
  access is explicitly opt-in. The allow-list is checked per-call so
  it can be updated at runtime without re-registering handlers.
  Documented in `docs/RETICULUM.md`.
- **Public RNS request handlers for capability RPC.** Three new paths
  are registered on the IronMesh destination, queryable by any
  RNS-speaking client without an ironmesh dependency:
  `/im/info` (node card), `/im/cap/list` (full capability registry),
  `/im/cap/find` (pattern-matched lookup, query `{pattern: str}`).
  All ALLOW_ALL — they're a public discovery surface, not a write
  surface. New `examples/rns_capability_client.py` demonstrates a
  pure-RNS client speaking these paths.
- **Per-packet ratchets on the IronMesh RNS destination.** Packets sent
  to an IronMesh destination outside an established Link now get
  forward secrecy via RNS's key-ratcheting system. Ratchet keys rotate
  on a configurable interval (`--rns-ratchet-interval`, default 30 min)
  and previous keys are retained briefly so in-flight packets still
  decrypt across rotations (`--rns-retained-ratchets`, default 8).
  Disable with `--rns-no-ratchets` if you must interoperate with very
  old RNS peers; ratchets are signalled via announces and ignored by
  peers that don't understand them, so leaving them on is generally
  safe. New env vars: `IRONMESH_RNS_RATCHETS`,
  `IRONMESH_RNS_RATCHET_INTERVAL`, `IRONMESH_RNS_RETAINED_RATCHETS`.

## [0.9.0] — OpenClaw, ACP, and A2A interop

Minor release on top of v0.8.5.8. No wire-protocol or schema changes
to the IronMesh mesh itself; every v0.8.x peer stays interoperable.
The v0.9.0 line opens up three new agent-interoperability surfaces —
the OpenClaw channel plugin, an Agent Client Protocol (ACP) stdio
adapter, and an Agent-to-Agent (A2A) HTTP gateway — alongside a set
of capability-persistence and operator-tooling fixes surfaced by
end-to-end testing of the OpenClaw integration.

### Added

- **`ironmesh-acp` — Agent Client Protocol stdio adapter.** New
  `ironmesh_acp` package + console script. Speaks JSON-RPC 2.0 over
  newline-delimited JSON on stdio (the wire format defined by
  `acp-core-v1@0.3.0`). Implements the v1 required surface:
  `initialize`, `session/new`, `session/prompt`, `session/cancel`,
  plus `session/update` notifications. Each ACP session targets one
  mesh peer (chosen via `meta.peer` on `session/new` or the
  `--default-peer` CLI flag); `session/prompt` dispatches as an
  encrypted MSG and the peer's reply is streamed back as an
  `agent_message_chunk` content block followed by a terminal
  `end_turn` update. Lets `acpx`, `codex`, `claude`, `droid`, and
  any other ACP-compatible client prompt remote mesh peers as if
  they were local agents. Bearer-token auth deferred — stdio
  trust model assumes the spawning client owns the process.
- **`ironmesh-a2a` — Agent-to-Agent HTTP gateway.** New
  `ironmesh_a2a` package + console script. Exposes the local mesh
  node as an A2A v0.3.0 peer with three HTTP endpoints:
  `GET  /.well-known/agent-card.json` (public AgentCard with
  protocol version, capabilities, skills, advertised security
  scheme), `POST /a2a/jsonrpc` (JSON-RPC 2.0; method
  `message/send`), and `POST /a2a/v1/inbox` (raw envelope dispatch
  matching the third-party `openclaw-a2a-gateway` shape).
  Bearer-token authentication via `--token` or
  `IRONMESH_A2A_TOKEN`; pass `--no-token` for dev-only unauthenticated
  mode. Anti-loop via `route_path` + `hop_count` (default max 8 hops).
  HMAC-from-ECDH per-peer authentication is deferred to v0.9.1.
- **Reply-routing fallback for non-correlation peers.** Both ACP and
  A2A adapters first attempt to match replies by `correlation_id`
  (the JSON envelope `{"correlation_id": "<uuid>", "body": "..."}`
  convention used by `ironmesh_request_service`). When the peer
  doesn't implement that convention (the bundled `llm_bridge.py`
  example, community agents), the adapter falls back to delivering
  the first inbound MSG from the target peer to the oldest pending
  request. Documented as a known limitation for mixed-protocol
  peers — correlation-aware peers always resolve precisely.

### Fixed

- **Capability registry now persists learned remote capabilities.**
  The capability gossip loop and the inbound `CAPABILITY_ANNOUNCE`
  handler both call `CapabilityRegistry.save()` after updating
  remote-capability state. Previously, `capabilities.json` was only
  written at startup (with an empty `remote: {}` body) and on
  local-capability changes; remote caps learned via gossip were held
  only in memory and lost on restart.
- **`ironmesh-mcp` accepts manual peer bootstrap.** New
  `--peer host:port[,host2:port2,…]` flag. When mDNS discovery is
  unavailable (restrictive networks, container bridges, name conflicts
  with another process holding the same mDNS slot), operators can
  pass explicit peer hints. The embedded daemon connects to each on
  startup.
- **`ironmesh audit verify --rotate-corrupt`.** New flag rotates a
  corrupted audit log to `audit.log.corrupted-<ISO timestamp>` and
  lets the daemon start a fresh chain on the next write. Recovery for
  the operator-runbook case where two daemons collided on the same
  audit path pre-v0.8.5.6.
- **TypeScript client honours per-message destination.**
  `IronMeshClient.sendMessage(payload, opts)` now respects an
  `opts.toNodeId` (32-hex) hint and writes it into the encrypted
  envelope's `destination` field. Previously the destination was
  hardcoded to the handshake peer, so messages addressed to another
  mesh node were always delivered to the directly-connected daemon
  instead of being relayed. The daemon's existing routing table
  handles the relay; no protocol changes were required.
- **`messages_sent_total` now counts the offline-queue flush path.**
  When a peer that had queued offline messages comes back online,
  `_flush_pending` drains the queue. Until v0.9.0 it bypassed both
  per-peer (`messages_sent`, `bytes_sent_total`) and daemon-level
  (`messages_sent_total`, `messages_delivered_total`) counters, so
  Prometheus under-reported any traffic that took the
  online → offline → online path. Surfaced during the v0.9.0
  live-mesh stress run; the flush path now updates all four
  counters in parity with the direct + routed send paths.
  Regression test: `tests/test_bridge.py::TestFlushPendingCounters`.

### Changed

- **OpenClaw channel plugin (`@wiztheagent/openclaw-ironmesh`) v0.2.0**
  (renamed from `@wiztheagent/openclaw-ironmesh-channel` to match
  manifest id):
  - Plugin entry now uses OpenClaw 2026.3.x's `register(api)` shape
    (matches the bundled telegram channel reference). Forward-compatible
    with the newer 2026.4+ `defineBundledChannelEntry` SDK shape via
    runtime detection.
  - Bundles its IronMesh WebSocket client, no peer/sibling
    `file:` dependency required at install time.
  - Added required `package.json:openclaw.{extensions,compat,build,
    channel}` block + sibling `openclaw.plugin.json` manifest. Both are
    required by OpenClaw 2026.3.x for `openclaw plugins install` to
    succeed.
  - `configSchema.required` no longer blocks `openclaw plugins
    install` and `openclaw config set`. Validation runs at channel
    activation instead.

## [0.8.5.8] — Counter correctness + observability polish

Patch release on top of v0.8.5.7. No protocol or schema changes; every
v0.8.x peer stays interoperable. Focus is on making the v0.8.5.7
observability layer robust under real operational pressure (audit-log
write failures, daemon restarts, out-of-process trust mutations).

### Added

- **Counter continuity across restart.** The daemon now reconciles
  mirrored Prometheus counters against the tail of the audit log
  (last 10,000 entries) on startup. Before this, every mirrored
  counter reset to zero on restart — which Prometheus reports as a
  counter reset, creating a negative delta in `rate()` and
  `increase()` queries. Counters now pick up where they left off;
  restart is invisible to downstream Grafana alerts.
- **Audit chain verified on startup.** The daemon runs
  `audit.verify()` once after opening the audit log and logs a
  WARNING with entry number + scan depth if the chain is corrupted.
  Pre-existing corruption (from multi-writer races pre-v0.8.5.6 or
  filesystem damage) now surfaces immediately instead of waiting for
  someone to run a manual `ironmesh audit verify`.
- **Structured `BridgeDaemon._emit_audit_with_reservation` helper.**
  Bundles the counter reservation + audit emit + failure recovery so
  every audit event that mirrors into a Prometheus counter goes
  through one correct path. A static-analysis test fails CI if any
  future call site spells out the reserve/emit pattern by hand.
- **Grafana dashboard: two new panels.** `docs/grafana/ironmesh-dashboard.json`
  now includes a cap-binding activity panel (cap-set changed,
  baselines pinned, operator-accepted, binding partial) and an
  operator-trust-actions + cross-transport-replay panel (revokes,
  promotions, blocks, state changes, replay alerts).
- **OPERATOR_RUNBOOK — new section 7:** trust-store corruption
  recovery playbook for the `Trust store integrity check FAILED`
  log line (read-only latch trip). Covers triage, recovery, and
  the most common cause (colliding test + production daemon on the
  same trust path).

### Added

- **`[lxmf]` install extra.** `pip install ironmesh[lxmf]` now pulls
  both `rns` and `lxmf` for the `examples/lxmf_gateway.py` reference
  agent. Previously the dependency was only documented in the
  example's startup error message; now it's a standard extra and
  documented in `examples/README.md`.

### Fixed

- **`ironmesh doctor` audit log check is no longer broken.** Check
  7/7 (audit chain integrity) was unpacking `verify_chain`'s return
  value as a 2-tuple `ok, msg = ...`, but `verify_chain` actually
  returns a 3-tuple `(ok, entries_checked, first_invalid_line)`.
  Whenever an audit log existed at the resolved path, the check
  raised `too many values to unpack (expected 2)` and reported FAIL
  for healthy daemons. Doctor also now derives the audit log path
  from `--db-path` (matching the daemon's own derivation) instead of
  hardcoding `~/.ironmesh/audit.log` — so on a custom-db-path daemon,
  doctor inspects the right file. Regression test in `test_cli.py`
  pins the unpacking signature.
- **`ironmesh trust` CLI now writes audit events to the target
  daemon's audit log.** Operators who run a daemon with a custom
  `--db-path` got stuck on a silent observability gap: the CLI wrote
  `PEER_CAP_ACCEPTED` / `PEER_PROMOTED` / `PEER_BLOCKED` /
  `PEER_STATE_CHANGED` / `PEER_REVOKED_LOCAL` events to the default
  `~/.ironmesh/audit.log`, while the daemon's audit log lived next to
  its db. The daemon's counter-sync loop only tailed its own log, so
  every operator-initiated mutation left the mirrored Prometheus
  counters (`ironmesh_peer_cap_accepted_total`, etc.) stuck at their
  pre-mutation values. Trust-store baseline updates also didn't
  properly converge on the running daemon, manifesting as a
  persistent "pending-cap-change" flap for peers that were
  legitimately trusted. The CLI now derives the audit log path from
  `--trust-path` (defaults to `<trust-path-dir>/audit.log`), and
  accepts an explicit `--audit-path` override when needed. Default
  behavior is unchanged for operators running a daemon with stock
  paths.
- **Prometheus counters no longer drift on audit-log write failure.**
  The daemon bumps its observability counters and reserves the
  matching audit event before emitting it to disk so the audit-log
  scanner loop doesn't double-count. If the audit emit then failed
  (disk pressure, flock timeout, rotation mid-write), the reservation
  used to be silently orphaned — either leaving the counter +1 above
  truth or silently absorbing the next real event of the same type.
  Seven call sites across `bridge.py` and `mesh.py` now release the
  reservation when the emit fails, and all audit-reserve emits are
  now funneled through the structured helper. Drift accumulated in
  long-running v0.8.5.7 daemons clears on next restart; the fix
  prevents future drift.
- **CLI audit-emit failures surface at WARNING.** `ironmesh trust
  revoke`, `trust set-state`, `trust cap-promote`, and `trust
  cap-reject` previously swallowed audit-log write failures silently
  — the trust mutation applied, no audit record was written, and
  the operator had no idea. Failures now print a WARNING to stderr
  identifying the event, the underlying error, and the audit log
  path so operators can investigate. The mutation itself is still
  applied (the audit emit is separate from the state change).
- **Dashboard version badge no longer lies.** The version pill in the
  operator console was a hardcoded string literal (`v0.8.5 · PRE-1.0`)
  that never got bumped alongside `__version__`, so the dashboard
  served by v0.8.5.6 and v0.8.5.7 both rendered "v0.8.5" even though
  the package and wire handshake were correct. Replaced the literal
  with a `{{IRONMESH_VERSION}}` placeholder and a render-time
  substitution driven by `ironmesh.__version__`. Added two regression
  tests in `test_gui.py` that assert the placeholder is present in
  the template and that the rendered HTML matches the current
  `__version__` — future drift fails loudly at CI.

### Operator-visible behavior change

- After upgrade, mirrored Prometheus counters no longer start at zero
  on restart — they pick up from the last 10,000 audit entries. Any
  existing Prometheus recording rule or Grafana panel that assumed
  zero-reset behavior across restart will see a different pattern
  (no more negative delta). Counter-type semantics are preserved;
  `rate()` and `increase()` continue to produce the expected values.

## [0.8.5.7] — Finish shipping cap-binding

Patch release on top of v0.8.5.6. No protocol or schema changes;
every v0.8.x peer stays interoperable. This release polishes the
capability-set binding feature that landed in v0.8.5.6, turning it
from "usable via CLI" into "usable end-to-end through the dashboard
+ CLI + MCP + Prometheus + OpenTelemetry."

### Added

- **Dashboard `PENDING CAP CHANGE` panel.** Parallels the existing
  PENDING TRUST panel with a per-peer row showing the capability-set
  diff (added / removed tokens) and an ACCEPT button. Live-updates
  via a new `cap_change_detected` WebSocket push from the daemon, so
  operators don't need to refresh.
- **Nine new Prometheus counters** — one per cap-binding /
  cross-transport / trust-state audit event type:
  `ironmesh_peer_cap_set_changed_total`,
  `ironmesh_peer_cap_baseline_total`,
  `ironmesh_peer_cap_accepted_total`,
  `ironmesh_peer_cap_binding_partial_total`,
  `ironmesh_msg_replay_cross_transport_total`,
  `ironmesh_peer_revoked_local_total`,
  `ironmesh_peer_state_changed_total`,
  `ironmesh_peer_promoted_total`,
  `ironmesh_peer_blocked_total`. All surface in `/metrics` and
  integrate with existing Grafana dashboards.
- **Audit-log counter sync loop.** The daemon tails its own audit log
  every second and reconciles counters for events written by
  out-of-process actors (CLI, MCP in a separate process).
  Daemon-originated bumps use a reservation mechanism so the scanner
  doesn't double-count. Rotation-aware — uses file-identity tracking
  (`st_ino`) to rescue events that landed in a `.1` file between
  scans.
- **OpenTelemetry spans** for the same events via
  `telemetry.emit_event(...)` — a new helper that opens a
  zero-duration span when OTel is configured, no-op otherwise.
  Span names follow the `peer.cap.*` / `msg.replay.*` convention.
- **`examples/cap_binding_workflow.py`** — runnable, fully in-process
  walkthrough of pin → observe → change → review → accept → match.
  No network, no LLM; exercises the same `TrustStore` paths the live
  daemon uses.
- **`ironmesh trust cap-reject <node_id>`** — explicit operator
  "no" to a pending cap change. Clears the pending hash, keeps the
  existing baseline, restores `trusted` state. `--block` flag also
  flips trust state to `blocked` in one shot for the "suspicious
  change" response flow.
- **`ironmesh trust cap-status <node_id>`** — single-peer deep dive
  with all cap-binding fields (baseline hash, pending hash, timestamps,
  diff if any). `--json` for scripts.
- **`ironmesh trust list --show-caps`** — adds a `Caps` column to the
  existing peers list showing `baseline` / `pending` / `unknown`.
- **`ironmesh audit tail --event <type> --since <window>`** — filtered
  audit tail for operator triage. Accepts multiple event types
  (comma-separated), relative windows (`1h`, `15m`, `2d`) or ISO-8601
  timestamps. `--json` for scripts, `--limit` for paging.
- **`ironmesh audit stats --since <window>`** — histogram of event
  types over a recent window. Answers "what happened in the last
  hour?" without manually paging the log.
- **Two new MCP tools** (total surface grows 23 → 25):
  - `ironmesh_cap_diff` — non-destructive cap diff for a single peer.
  - `ironmesh_cap_reject_peer` — reject the pending change, optional
    `block` flag.
- **`docs/OPERATOR_RUNBOOK.md`** — playbook for the seven common
  cap-binding + audit triage scenarios (peer demoting itself,
  `PEER_CAP_BINDING_PARTIAL` fired, audit TAMPER reported, etc.).
- **`AGENTS.md`** at the repo root — convention-aligned guide for AI
  coding assistants (Claude Code, Cursor, Aider, Zed, Codex). Covers
  operating rules, workflow, and common tasks.
- **`scripts/stress_concurrent.py`** — standalone concurrent
  cap-promote harness (promoted from the v0.8.5.6 ad-hoc audit).
  Runs 2000 threads × 20 peers in ~3s on a laptop; asserts exactly
  one winner per peer, no MAC corruption, correct final baseline.
- **`.github/workflows/stress-nightly.yml`** — runs the stress
  harness nightly on Ubuntu + Windows, Python 3.11 + 3.13. Catches
  concurrency regressions in the trust-store locking contract before
  they reach a release.

### Changed

- **Dashboard PENDING TRUST panel** now sits next to a parallel
  PENDING CAP CHANGE panel under the peers tree. Both auto-refresh
  via the existing WebSocket control channel.
- **`docs/CONFIGURATION.md`** gains "Capability-set binding" and
  "Audit log triage" sections covering every v0.8.5.6 / v0.8.5.7 CLI
  command.

### Fixed

Eight bugs found during release hardening. Four surfaced during live
testing against a multi-node mesh; four during a systematic static +
Hypothesis fuzz audit.

**High:**

- **Observability gap for out-of-process audit events.** CLI and
  MCP-spawned-in-a-separate-process paths fired audit events correctly
  but couldn't bump the daemon's in-memory Prometheus counters.
  Grafana dashboards therefore stayed blind to CLI-initiated operator
  actions. The new audit-log tail scanner closes this end-to-end —
  regardless of which process wrote the event, the counter moves.

**Medium:**

- **CLI `cmd_trust` local `import time` scope.** An `import time`
  placed inside one subcommand branch shadowed `time` as function-local
  for every other branch, breaking the new `cap-status` command with
  `NameError`. Removed redundant local imports (`time` is imported at
  module top).
- **Counter reservation race.** `_reserve_counter_bump` and the
  audit-log scanner raced on a shared reservation dict because the
  mesh-dispatch path calls the bump from a worker thread while the
  scanner runs on the asyncio loop. Added a `threading.Lock`
  serializing the read-modify-write.
- **Trust-state transitions via `set-state trusted`** fire
  `PEER_PROMOTED`, not `PEER_STATE_CHANGED`, and the counter map
  didn't include it — silent undercount. Added `peer_promoted` +
  `peer_blocked` counters plus reservation bumps on the daemon-side
  promote / block paths.
- **MCP `cap_reject_peer` mutated the trust file without firing any
  audit event.** Forensic review was blind to MCP-driven rejects.
  Now fires the appropriate state-transition event with
  `actor: "mcp"` + `reason: "cap-reject"` + `rejected_pending_hash`
  for traceability.
- **Audit-log rotation detection missed the re-grown case.** Scanner
  used `current_size < offset` which failed when post-rotation writes
  had already re-grown the live file past the pre-rotation offset.
  Now tracks file identity via `os.stat().st_ino`; on inode change,
  scans the rotated `.1` file for missed events before resetting.
- **`Budget.from_dict(d)` crashed on non-dict input.** A peer sending
  `{"budget": "0"}` used to raise `AttributeError` on `d.get("...")`.
  Added `isinstance(d, dict)` guard. Caught by a Hypothesis fuzz
  test.
- **MCP `_resolve_node_id(target)` crashed on non-string target.**
  An int or list target used to raise `TypeError` in `len()`. Now
  returns `None` cleanly for any non-string input.

### Verified

- pytest: 726 passed (+4 from v0.8.5.6 for new metric-counter tests
  and rotation regression). Integration-only tests excluded.
- 2000-thread concurrent cap-promote stress via
  `scripts/stress_concurrent.py`: exactly 1 winner per peer, no MAC
  corruption, under 3 s runtime.
- 1000-operation concurrent counter stress (mixed in-process
  reservations + external CLI-like events + log rotation): exactly
  1000 counted, 0 residual reservations, 0 errors.
- 13 816 concurrent trust-store reads + 254 writes over 3 s: 0
  errors; MAC-mismatch latch 100 % activated on rogue-key loads.
- Property fuzz across 8 malformed-input cases for every new MCP
  tool and the `telemetry.emit_event` helper: all handled cleanly.
- MCP tool surface: 25 tools registered.
- `ruff check`: clean across touched files.
- `scripts/leak-scan.sh --all`: clean.
- `scripts/release-smoke.sh`: PASS.
- Live multi-node mesh: cap-binding observed end-to-end through
  dashboard + CLI + MCP, with counter bumps visible in Prometheus
  within one scan interval of every CLI-driven event.

## [0.8.5.6] — Trust binding (capability-set + cross-transport replay)

Patch release on top of v0.8.5.5. No protocol or schema changes;
every v0.8.x peer stays interoperable. Default behavior unchanged for
existing deployments — the new audit events fire when relevant
conditions are met, and existing `known_peers.json` files auto-migrate
on first load.

Closes two security gaps surfaced during external security review:
authenticated peers retaining over-privileged state across reconnects
with changed capability sets, and silent cross-transport replay drops.

### Added

- **Capability-set binding in the pending-trust gate.** New trust-store
  field `capability_hash` (SHA-256 over a canonical serialization of
  the peer's advertised capability set). On reconnect, if the observed
  hash differs from the stored baseline, the peer is auto-demoted to a
  new `pending-cap-change` trust state and inbound messages queue at
  the daemon until an operator re-promotes. See
  `docs/TRUST_BINDING.md`.
- **Cross-transport replay detection.** `DedupCache` gains
  `check_and_add_with_transport(source, msg_id, transport)`. When a
  duplicate arrives via a *different* transport than the original
  (e.g. WebSocket then Reticulum/LoRa), the new
  `MSG_REPLAY_CROSS_TRANSPORT` audit event fires before the drop.
  Operators get a signal where there used to be silence.
- **Four new audit event types** in `audit.py`:
  `PEER_CAP_SET_CHANGED`, `PEER_CAP_BASELINE`, `PEER_CAP_ACCEPTED`,
  `MSG_REPLAY_CROSS_TRANSPORT`. All HMAC-chained with the existing
  audit log.
- **Operator surface (CLI):**
  - `ironmesh trust cap-promote <node_id>` (or `--all`) — accept
    pending capability change and re-promote
  - `ironmesh trust list-cap-pending` — list peers in
    `pending-cap-change` with the cap diff
  - `ironmesh trust cap-diff <node_id>` — show baseline vs pending
    capability sets
  - `ironmesh trust set-state` accepts the new
    `pending-cap-change` value
- **Operator surface (MCP):** two new tools — total grows from 21 to
  23.
  - `ironmesh_pending_cap_changes` — list peers in
    `pending-cap-change` with diff
  - `ironmesh_cap_promote_peer` — accept the change and re-promote
- **Operator surface (programmatic):** `BridgeDaemon.accept_pending_
  cap_change(node_id)` for in-process operator code that bypasses
  CLI/MCP.
- **`docs/TRUST_BINDING.md`** — threat model, what v0.8.5.6 covers,
  operator surface walkthrough.
- **`docs/TRUST_BINDING_WIRE_v0.9.md`** — full design for the
  three wire-protocol extensions queued for v0.9 (deterministic
  session ID, rolling transcript hash, reconnect continuity
  challenge). Backwards-compat strategy + HELLO extension
  negotiation documented.
- **23 new tests** in `tests/test_trust_binding.py`. Includes
  Hypothesis fuzz tests proving the canonical capability hash is
  stable across reordering and duplication for any sequence of
  capability tokens.

### Changed

- **`TrustStore.set_trust_state`** and **`pin_peer`** now accept
  `pending-cap-change` as a valid state.
- **`TrustStore.list_by_trust_state`** rows now include
  `capability_hash` and `capability_set` fields.
- **Bridge `_handle_message` / `_handle_binary_frame` /
  `_handle_json_message` / `_dispatch_message`** thread a
  `transport` string through the dispatch chain so the dedup cache
  can tag inbound frames with their originating transport
  (`"ws"` or `"rns"`).
- **`MeshRouter.relay_message`** accepts an optional `transport`
  argument; when supplied, uses the new transport-aware dedup path.
  Existing callers that don't pass it are unaffected (legacy dedup
  preserved).

### Migration

Existing `known_peers.json` trust files don't have the
`capability_hash` field. On first load after upgrade, entries
without the field get `capability_hash: null`. The next successful
handshake with each peer records the observed hash as the baseline
(treating this as TOFU-for-capabilities, mirroring the existing
TOFU-for-identity pattern). No operator action is required to
upgrade. Security improvement engages from the next capability
change forward.

### Fixed

The release-preparation audit — static code review, protocol fuzz,
concurrent-operator race, SIGKILL chaos, and an extended live-mesh
soak — identified and fixed nineteen bugs. Most were pre-existing
defects in IronMesh; a few landed with the new cap-binding code and
ship fixed in the same release.

**Critical:**

- Trust store could be silently wiped when the on-disk MAC did not
  verify (e.g. a colliding process on the same host). `TrustStore`
  now latches read-only on MAC mismatch and refuses to save, so a
  foreign writer can no longer cause the production daemon to blow
  away every pinned peer on its next save.
- `save_keys()` is now fully atomic (tmp + `fsync` + rename). The
  prior `open(path, "w")` pattern could leave `keys.json` truncated
  if the process was killed mid-write, making the daemon's identity
  unrecoverable.

**High:**

- Capability-binding wire-in used a stale attribute reference and
  would raise `AttributeError` on every `CAPABILITY_ANNOUNCE` from
  a pinned peer, silently disabling the entire feature. A new
  helper constructs the trust store ad-hoc — matching the pattern
  used elsewhere in the daemon.
- Audit-log HMAC chain could be corrupted when multiple processes
  on the same host shared one audit file. A cross-platform
  sentinel-file exclusive lock now wraps every write, plus a
  chain-tail re-read under the lock in case the cached in-memory
  tail is stale.
- `TrustStore._save()` had no inter-process lock. On Windows,
  concurrent operator actions collided on a shared `<path>.tmp`
  filename (WinError 32) and silently lost writes, while
  `accept_capability_change` returned True regardless of whether
  the save reached disk. Now layered with a thread + flock lock,
  per-pid + per-thread tmp filenames, and `_save()` propagates its
  success bit to callers so mutating methods can roll back and
  report failure honestly.

**Medium:**

- Duplicate `PEER_CAP_SET_CHANGED` audit events fired every ~30s
  while a peer sat in `pending-cap-change` with an unchanged
  pending set; a new `pending-match` status keeps the handler
  silent on re-announce.
- Pending-cap-change stash was not cleared when a peer reverted to
  its accepted baseline, so a later operator acceptance could
  promote stale data.
- CLI `trust cap-promote` accepted pending changes without
  emitting `PEER_CAP_ACCEPTED`. Now fires the event via a shared
  CLI audit helper with an `actor: "cli"` marker.
- Cap-binding handler swallowed stash / demote failures silently
  while still firing `PEER_CAP_SET_CHANGED`, lying about pending
  state. New `PEER_CAP_BINDING_PARTIAL` event distinguishes "change
  detected + applied" from "change detected + persistence failed".
- `DedupCache.cleanup_expired` iterated without holding the cache
  lock, racing with concurrent inbound-frame adders.
- Audit log `_write_entry` lacked `fsync` and leading-newline
  recovery; a SIGKILL between write and flush could leave a torn
  line that the next reader would concatenate onto. Fixed with a
  single `os.write` under the lock, `fsync`, and a leading-newline
  prepend when the prior write didn't terminate.
- `routes.json` and `capabilities.json` saved via non-atomic
  truncate+write; SIGKILL mid-write emptied the files. Both now
  use tmp + `fsync` + rename.
- "Ghost capabilities" after a role change: the bridge called
  `CapabilityRegistry.load()` then `advertise_local()` per config
  cap, producing the union of persisted + configured caps. New
  `set_local(caps)` replaces the entire local set when config is
  authoritative.
- `Frame.from_json_message` lacked the strict type validation that
  `from_dict` received in v0.8.5.2; a peer sending
  `{"msg_id": [1,2,3]}` could crash downstream code.
- `ROUTE_ANNOUNCE` and `CAPABILITY_ANNOUNCE` handlers didn't
  validate that string-typed fields (`destination`, `origin`, cap
  tokens) were actually strings. Both now reject non-string or
  oversized input at the boundary.
- Dashboard `get_history` accepted an unbounded `limit` argument;
  now clamped to `[1, 5000]` and `peer_id` must be a string.
- Trust store lock had no thread granularity (`msvcrt.locking` and
  `fcntl.flock` are process-level); concurrent threads in a single
  daemon process collided. A process-wide `threading.Lock` per
  canonical path now layers over the file lock.

**Low:**

- `websockets.server` ERROR-level "did not receive a valid HTTP
  request" noise from peers' TLS-first dial fallback is now
  filtered (re-emitted at DEBUG for operators who want it).

**Audit-coverage follow-ups:**

- CLI `trust revoke` and `trust set-state` now emit audit events
  (`PEER_REVOKED_LOCAL`, `PEER_STATE_CHANGED`, or the existing
  `PEER_PROMOTED` / `PEER_BLOCKED` for the matching states) via a
  shared helper. Every CLI-driven trust mutation now leaves an
  audit trail with `actor: "cli"`.
- Test-infrastructure isolation: a new autouse session fixture in
  `tests/conftest.py` redirects `HOME`, `USERPROFILE`, and
  `IRONMESH_TRUST_PATH` to a per-session temp directory before any
  test module loads `ironmesh`. Integration tests that spawn real
  `Agent(...)` processes with auto-generated identity keys can no
  longer collide with a developer's or CI host's production trust
  store.

New audit event types introduced by this release (in addition to
the four documented above): `PEER_CAP_BINDING_PARTIAL`,
`PEER_REVOKED_LOCAL`, `PEER_STATE_CHANGED`.

### Verified

- pytest: 718 passed, 2 skipped, 1 xpassed (full unit suite;
  integration-only tests excluded because they require a live mesh)
- Property-based fuzz of the binary frame deserializer (5000 random
  / corrupted inputs): zero unhandled exceptions
- Concurrent-operator stress (2000 threads × 20 peers): exactly 1
  winner per peer, no MAC corruption, completes in under 3 seconds
- X25519 small-order-point rejection: all 7 known small-order
  representations rejected by the underlying libsodium binding
- Every MAC / signature comparison uses `hmac.compare_digest`
  (constant-time)
- `ruff check`: clean across all touched files
- `scripts/leak-scan.sh --all`: clean

## [0.8.5.5] — Big-batch quality-of-life patch

Patch release on top of v0.8.5.4. No protocol or schema changes;
every v0.8.x peer stays interoperable. Default behavior unchanged
unless the new optional features are explicitly opted into.

### Added

- **OS keychain integration.** New `ironmesh keys keychain-store` /
  `keychain-clear` / `keychain-check` subcommands plus
  `IRONMESH_PASSPHRASE_KEYCHAIN=true` env var to read the mesh
  passphrase from macOS Keychain / Windows Credential Manager / Linux
  Secret Service. New optional dep group: `pip install ironmesh[keychain]`.
- **CLI named profiles.** `ironmesh run --profile=secure|dev|offline`
  bundles related flag presets. `secure` enables the pending-trust
  gate and warns about insecure flag combinations. `dev` enables the
  localhost-testing shortcuts. `offline` enables the Reticulum
  transport.
- **`ironmesh upgrade`** subcommand. Checks PyPI for a newer release,
  prints the exact `pip install -U` and `docker pull` commands, and
  links to the matching GitHub release notes. `--json` for automation.
- **`ironmesh setup` already shipped in v0.8.5.4** but is now
  documented under the named-profile + keychain workflow.
- **Windows service wrapper.** `scripts/install-windows-service.ps1`
  + `docs/WINDOWS_SERVICE.md`. NSSM-based PowerShell installer with
  log redirection, automatic restart, graceful shutdown.
- **Reverse-proxy-friendly dashboard mode.** New `--gui-bind`
  flag (default `127.0.0.1`) lets the dashboard bind to a non-
  loopback address. Setting it to anything other than loopback
  emits an `INSECURE BIND` warning at startup. Full nginx / Caddy /
  Traefik recipes in `docs/REVERSE_PROXY.md`.
- **OpenTelemetry tracing.** New optional `ironmesh[otel]` extra
  installs the OpenTelemetry SDK and OTLP-HTTP exporter.
  `ironmesh/telemetry.py` is a no-op shim when the SDK is absent or
  `OTEL_EXPORTER_OTLP_ENDPOINT` is unset. First instrumented surface
  is `ironmesh.send_message`; per-stage handshake / routing / MCP
  spans are queued for subsequent releases. Reference Grafana
  dashboard JSON at `docs/grafana/ironmesh-dashboard.json`.
- **TS client graduates out of alpha to 0.2.0.** TOFU pin file
  enforcement (`pinFile` option) is now actually enforced — pin
  mismatch refuses the connection with a clear `PinMismatchError`;
  strict mode (`tofu: "strict"`) refuses first contact with a
  `PinNotFoundError`. New `clients/ts/src/pinstore.ts` module with
  atomic-write persistence (write-to-tmp + fsync + rename). 10 new
  tests in `clients/ts/tests/pinstore.test.ts`.
- **`docs/CONFIGURATION.md`** — complete index of every CLI flag,
  env var, file path, and profile preset. The single page to point
  someone at when they ask "what can I configure?"
- **`docs/NAT_TRAVERSAL.md` already shipped in v0.8.5.4** as the
  operator-recipe doc; complemented now by:
- **`docs/deployments/off-grid.md`** — Heltec V3 + Pi Zero 2 W +
  LoRa reference recipe.
- **`docs/deployments/multi-tenant.md`** — multiple isolated tenant
  daemons on shared hardware with cryptographic + OS-account
  isolation.
- **`docs/OBSERVABILITY.md`** — end-to-end observability guide
  covering Prometheus, structured JSON logs, OpenTelemetry, and
  audit-log inspection.
- **`docs/grafana/ironmesh-dashboard.json`** — importable starter
  dashboard with peer health, RTT, lifetime quantiles, backpressure
  events, and pending-trust gate panels.
- **`.github/workflows/codeql.yml`** — CodeQL scanning on push, PR,
  and weekly. Catches a class of vulnerabilities that ruff and
  bandit don't.
- **`CITATION.cff`** — academic citation file at the repo root.

### Changed

- **`scripts/leak-scan.sh`** exclusion list now supports glob
  patterns (`docs/RELEASE_NOTES_v*.md`, `docs/migration/*.md`) so
  future docs auto-exclude without a code change.
- **`.github/RELEASE_CHECKLIST.md`** Section 5 now requires running
  `ruff check` locally before tagging — closes the gap that landed a
  red tag-CI on v0.8.5.4.
- **README** gains the Codecov badge wired up in v0.8.5.4 (now
  active once Codecov is authorized) and an updated install line
  that mentions the new optional dep groups (`[keychain]`, `[otel]`).

### Documentation

- New `docs/RELEASE_NOTES_v0.8.5.5.md`.
- README current-version references updated to `v0.8.5.5`.
- `pyproject.toml` gains two new optional dep groups: `keychain` and
  `otel`.

### Verified

- pytest: 700+ passed across 10+ affected modules
- scripts/leak-scan.sh --all: clean
- scripts/release-smoke.sh: PASS, version reads as 0.8.5.5
- ironmesh demo: works
- ironmesh upgrade: live PyPI check works
- ironmesh keys keychain-check: AVAILABLE on Windows
- ironmesh setup --non-interactive: writes files + prints run cmd
- TS client: 61 tests pass including 10 new pinstore tests
- ruff check: clean across all touched files

## [0.8.5.4] — Repo hygiene, onboarding, and credibility documentation

Patch release on top of v0.8.5.3. No protocol or schema changes; every
v0.8.x peer stays interoperable. Default behavior unchanged.

### Added

- **Three-layer leak-scan defense.** A pre-commit hook
  (`.githooks/pre-commit`), a pre-push hook (`.githooks/pre-push`),
  and a CI workflow (`.github/workflows/leak-scan.yml`) all share a
  single scanner (`scripts/leak-scan.sh`) that screens for filename
  patterns reserved for internal content (audit reports, plan docs,
  gap analyses, top-level roadmap files) and for content markers that
  should never appear in shipped code (audit hardening codes,
  decision-tree shorthand, personal identifiers, mesh-fleet personal
  names). Run `bash scripts/install-hooks.sh` once after cloning to
  wire it up locally. Documented in `CONTRIBUTING.md`.
- **`ironmesh setup` first-run wizard.** New CLI subcommand walks the
  operator through node name, port, passphrase, key generation, peer
  allowlist, and pending-trust gate. Writes the passphrase file
  (`chmod 600`) and the encrypted keypair, then prints the exact
  `ironmesh run` command to start the daemon. Supports `--non-interactive`
  + `--passphrase-from-env` (`IRONMESH_SETUP_PASSPHRASE`) for CI /
  automation use. Idempotent: re-running detects existing files and
  asks before overwriting (or honors `--force`).
- **`docker-compose.demo.yml`** — two preconfigured nodes (alice +
  bob) on an isolated bridge network with hardcoded demo passphrase.
  `docker compose -f docker-compose.demo.yml up` for an instant
  two-peer mesh demo with both dashboards exposed on localhost.
- **`WHATS_NEW.md`** — one-page narrative of the v0.7.2 → v0.8.5.4
  trajectory plus what's coming on the v1.0 path and beyond.
- **`docs/BENCHMARKS.md`** — published LAN (WebSocket) and LoRa
  (Reticulum/RNode) numbers with delivery rate, p50, p95, goodput,
  resource footprint by hardware class, and reproduction steps.
- **`docs/TESTING.md`** — test-philosophy walkthrough covering all
  four layers (unit, Hypothesis fuzz, concurrency, framework
  integration) and how to add a test in the right one.
- **`docs/NAT_TRAVERSAL.md`** — operator recipes for running IronMesh
  across NATs by layering on Tailscale, Yggdrasil, or Reticulum.
  Three step-by-step setups with trade-offs explicit. Native
  hole-punching is still on the v1.1+ roadmap; this is the
  recommended path until then.
- **`docs/deployments/homelab.md`** — first reference deployment
  recipe: two IronMesh nodes + local Ollama (`llama3.2:3b`) + a
  CrewAI two-agent crew talking over the encrypted mesh. End-to-end
  walkthrough from `pip install` to running the crew.
- **`docs/migration/v0_9_default_deny.md`** — migration walkthrough
  for the pending-trust gate becoming default-on in v0.9. Covers
  prepare-now (opt in early), prepare-later (use the planned
  `--no-message-promotion` legacy flag), wire-protocol stability,
  and operator-visible failure modes to expect.
- **GitHub Sponsors configuration.** New `.github/FUNDING.yml`
  pointing at the maintainer's GitHub Sponsors profile, plus a
  short "Sponsor" section in the README. (Sponsors must be enabled
  by the repo owner before the link resolves.)
- **Coverage badge wired (Codecov).** CI uploads `coverage.xml` from
  every matrix combo; README gains a live coverage-percentage badge
  next to the existing CI / PyPI / Docker badges. (Requires repo
  owner to authorize Codecov and add `CODECOV_TOKEN` secret.)

### Changed

- **Personal identifiers in shipped code and docs replaced with
  generic placeholders.** Personal node names previously used as
  CLI examples in README, ARCHITECTURE.md, QUICKSTART.md,
  SECURITY.md, USE_CASES.md, DASHBOARD.md, OPENCLAW_MCP_SETUP.md,
  PROTOCOL_SPEC.md, examples/README.md, examples/ai_to_ai_dialogue.py,
  cli.py, protocol.py, the TS client README, the ironmesh-status
  skill, and tests/test_mcp.py replaced with the generic alice / bob
  convention. Personal LAN IP examples replaced with TEST-NET-1
  (192.0.2.0/24, RFC 5737) addresses across QUICKSTART.md,
  SECURITY.md, USE_CASES.md, and the mesh_bench harness docstring.
  Test-name prefixes that started with audit-class identifiers
  (`H2:`, `H3:`, `C2:`) in `clients/ts/tests/*.test.ts` renamed to
  plain descriptive labels. The leak-scan workflow keeps the
  baseline clean from this commit forward.
- **Internal milestone reference (`M0 spike`)** in
  `clients/ts/README.md` reworded to plain language.
- **README `Recent changes` section** gets a new v0.8.5.4 paragraph;
  v0.8.5.3 demoted to historical.
- **README test-count claim** updated 686 → 688 to match current
  pytest collection.
- **`docker-compose.yml`** image tag bumped from `0.8.5` to `0.8.5.4`
  (was stale through three patch releases — caught by the release
  checklist's version-sync sweep).
- **`tests/test_cli.py`** fixture name updated `wiz` → `alice` to
  match the rest of the codebase's generic-name convention. Four new
  tests cover the `setup` wizard's non-interactive code paths.

### Removed (from prior commit on main)

- Four internal-only documents (`docs/AUDIT_v0.8.3.md`,
  `docs/BUG-PY310-TIMEOUTERROR-CLASS-SPLIT.md`,
  `docs/BUG-RNS-HANDSHAKE-RACE.md`, `docs/OPENCLAW_WS_API_GAPS.md`)
  removed from the repo and from full git history via
  `git filter-repo`. They were committed in earlier sessions before
  the broader internal-docs ignore patterns existed.
- `IRONMESH_V1_ROADMAP.md` (untracked at the repo root) moved to a
  private location.

### Documentation

- New `docs/RELEASE_NOTES_v0.8.5.4.md`.
- README current-version references (top banner, docker-pull
  commands, `Latest:` line) all updated to `v0.8.5.4`.
- `.gitignore` extended with `docs/AUDIT_*.md`, `docs/BUG-*.md`,
  `docs/*_GAPS.md`, `*_INTERNAL.md`, top-level `*_ROADMAP.md` so
  the leak class cannot recur.

## [0.8.5.3] — Quickstart hardening and onboarding polish

Patch release on top of v0.8.5.2. No protocol or schema changes; every
v0.8.x peer stays interoperable. Default behavior is unchanged for
existing deployments — the new warnings only fire when the relevant
flags or env vars are set (or absent in the deprecation case).

### Added

- **Startup `INSECURE` warning when `--open-discovery` is set.**
  Previously the daemon emitted a warning only when default-deny mode
  was active; the explicit insecure case was silent. Setting the flag
  now logs a clear warning naming the flag, the security implication,
  and the recommended replacement (`--allowed-peers`).
- **Startup `INSECURE` warning when `--allow-plaintext-ws` is set.**
  Same pattern — explicit warning naming the flag, the implication
  (plaintext `ws://` fallback enabled), and the recommended fix
  (generate a TLS cert and pass `--tls-cert`/`--tls-key`).
- **Startup `DEPRECATION` warning when the pending-trust message gate
  is opt-in disabled.** Cites the v0.9 default-on commitment and points
  at the planned `--no-message-promotion` escape hatch and the
  `docs/migration/v0_9_default_deny.md` migration doc (to be written
  ahead of the v0.9 ship).
- **`examples/conv_multiturn.py`** — minimal `ConvEnvelope` walkthrough.
  Two terminals, two roles (`pinger`/`ponger`), no LLM dependency.
  Reference for: open a conversation, exchange bounded turns,
  recognize end-of-conversation, no orphaned state.
- **`examples/persona_debate.py`** — persona-vs-persona debate
  orchestrator. Discovers two peers advertising different
  `role:<persona>` capabilities, seeds a debate motion, relays bounded
  turns. Pair `assistant` vs `devil` for classic debate,
  `security-analyst` vs `ops` for a real-world tradeoff discussion,
  etc.
- **`.github/RELEASE_CHECKLIST.md`** — explicit doc-sync, public-facing
  scrub, smoke-gate, and post-release verification sections so the
  README/version drift that motivated this release cannot recur.
  Section 3 ("Documentation in sync") enumerates every shipped doc
  with the exact sweep command for catching stale current-version
  claims.

### Changed

- **README quickstart restructured.** The `60-second demo` section in
  Quick Start now leads with pointers to the secure deployment path
  (`Running two physical machines`) and to a clearly labeled
  `Advanced / Testing — same-machine localhost demo` subsection. The
  insecure-flag walkthrough still exists in full — it just no longer
  appears in the headline quickstart where a stranger could mistake it
  for the recommended path.
- **README "Recent changes" section** has a new `v0.8.5.3` paragraph
  at the top; the `v0.8.5.2` paragraph is preserved as historical
  context with `(current)` removed.

### Documentation

- New `docs/RELEASE_NOTES_v0.8.5.3.md`.
- README current-version references (top banner, docker-pull commands,
  `Latest:` line) all updated to `v0.8.5.3`.

## [0.8.5.2] — Operator polish and security hardening

Patch release on top of v0.8.5. Operator UX polish for the pending-
trust gate plus a batch of security hardening fixes. No protocol
or schema changes; every v0.8.x peer stays interoperable; default
behavior is unchanged.

### Added

- **HMAC-chained audit events for gate decisions**: `MSG_GATED_QUEUE`,
  `MSG_GATED_DROP`, `PEER_PROMOTED`, `PEER_BLOCKED`. Wired into
  `_gate_inbound_msg`, `promote_pending_peer`, `block_pending_peer`.
  Operators get a tamper-evident forensic trail instead of only
  stderr logs.
- **`ironmesh trust set-state <node_id> <pending|trusted|blocked>`**
  CLI subcommand. Works offline against the trust file. Paired with
  a new `--trust-path` flag on the `trust` subcommand for
  multi-daemon operators.
- **Trust-state column** in `ironmesh trust list` output.
- **`trust_gate_state` in `/api/state`** — dashboard PEERS table now
  surfaces the v0.8.5 trust enum in the main peer row alongside the
  existing TOFU labels.
- **Gate counters in `/api/mesh_stats` + `/metrics` Prometheus**:
  `gate_enabled`, `pending_trust_evicted`, `pending_trust_dropped`,
  `messages_received_blocked`.
- **`ironmesh doctor`** — one-shot diagnostic subcommand. Checks
  identity key, trust store MAC, SQLite schema, pending-trust queue,
  gate env vars, port availability, audit chain integrity. Exit code
  non-zero on failure.

### Fixed (security)

- **Constant-time GUI token comparison.** Both the `?token=`
  query-param and `Authorization: Bearer` header paths in
  `_is_gui_authorized` used variable-time `==`. A LAN attacker
  could have recovered the 256-bit token via response-latency timing
  on `/ws` upgrade. Now uses `hmac.compare_digest`.
- **Atomic trust-file write.** `TrustStore._save` wrote
  non-atomically with `open(path, "w") + json.dump`. SIGKILL or
  power loss mid-write would leave an empty or truncated file, and
  operators would lose every pinned peer on restart. Now writes
  `path.tmp` + `fsync` + `os.replace` (atomic on POSIX and
  same-drive NTFS).
- **Strict `Frame.from_dict` type validation.** Previously accepted
  malformed inputs like `{"type": 123}` and crashed deep in dispatch.
  Now validates `type`, `msg_id`, `source`, `destination`, and
  `sequence` at the deserialization boundary.

### Fixed (observability)

- **Conflated pending-queue counter.** The v0.8.5 trust-gate queue
  eviction was incrementing `self.pending_evicted` on
  `MessageStore`, which is also the offline-queue counter. Operators
  looking at `/metrics` couldn't tell which queue was under
  pressure. Split into separate fields: `pending_trust_evicted` and
  `pending_trust_dropped` for the gate; `pending_evicted` /
  `pending_dropped` remain the offline-queue fields.
- **`/api/mesh_stats` was missing the new gate counters.** Only
  `/metrics` Prometheus carried them. Fixed so both surfaces expose
  `gate_enabled`, `pending_trust_evicted`, `pending_trust_dropped`,
  `messages_received_blocked`.
- **`ironmesh doctor` stdin-closed hang.** The tool previously
  called `getpass.getpass()` unconditionally, blocking forever when
  run from automation or `< /dev/null`. Now tries env + plaintext
  key first and only prompts when `sys.stdin.isatty()`.

### Fixed (operator-facing error messages)

- **Trust integrity-check message.** Upgraded from the generic
  "file may be tampered" to include the stored-vs-expected HMAC
  prefix + file path + explicit pointer to `--trust-path` for the
  multi-daemon collision pattern this release closes in v0.8.5.

### Fixed (additional security hardening)

- **MCP tool resource caps.** `ironmesh_request_service` timeout
  clamped to [1, 300]s and prompt capped at 1 MB;
  `ironmesh_send_message` and `ironmesh_broadcast` payload capped
  at 16 MB; `ironmesh_subscribe_events` limit clamped to
  [1, 1000], cursor must be non-negative, kinds filter capped at
  64 entries. Any of these could previously have been weaponized
  against the MCP handler for resource exhaustion.
- **TypeScript persistence `fsync`.** `PluginState.save` in
  `@wiztheagent/openclaw-ironmesh-channel` now `fsync`s before
  rename. Same class as the Python trust-file atomic-write fix.
- **Framework adapter error leakage.** `langchain_adapter` and
  `autogen_adapter` previously returned raw `str(e)` on exception,
  leaking internal paths and config into the LLM's tool-result
  context. Now returns only the exception class name plus a
  generic category; full trace logs server-side.
- **Federation targeted forwarding.**
  `FederationGateway._forward_handler` previously broadcast to
  every peer on the destination mesh as long as any peer there
  advertised a policy-allowed capability. Now iterates destination
  peers and forwards only to those whose own advertised
  capabilities pass policy. Closes a cross-mesh data-leakage
  vector.
- **MCP stdio EOF zombie.** When an MCP host closed stdio, the
  MCP server's long-running background tasks kept non-daemon
  threads alive for 20+ seconds (or indefinitely). Now `main()`
  calls `daemon.shutdown()` with a 3 s cap then `os._exit(0)` to
  kill any surviving threads. Exits in 3 s.
- **Audit log bombing rate-limit.** `MSG_GATED_DROP` events
  rate-limited to one per peer per second. A blocked peer sending
  1000 MSGs/sec could previously flood the audit chain at
  ~200 KB/sec, rotating older forensic entries out of the retained
  5-archive window within ~4 minutes. Counter in `/api/mesh_stats`
  still increments on every drop for visibility.
- **Passphrase-file hardening.** `_read_passphrase_file_safe`
  refuses non-regular files (blocks symlinks to `/dev/urandom`
  that would hang reads), caps size at 4096 bytes, rejects empty
  files, warns on world-readable mode on POSIX, validates UTF-8.

### Added documentation

- `SECURITY.md` gained sections: "Storage-at-rest properties"
  (documents ciphertext in SQLite WAL/SHM, metadata plaintext
  by design), "Reticulum (LoRa) transport caveats" (opt-in path,
  known gaps), "TLS and peer authentication" (design choice —
  TOFU+Ed25519 authenticates, TLS for confidentiality only).
- `docs/OPERATOR_TRUST_RUNBOOK.md` gained sections: "Running
  multiple daemons on one host" with the exact multi-daemon
  collision error message, "Audit events you can grep for" with
  the full event-name table + forensic grep recipe,
  "`ironmesh doctor` diagnostic" with the 7-check breakdown.
- `docs/RELEASE_NOTES_v0.8.5.2.md` — complete release notes.
- `tests/test_fuzz_v0852.py` — property-based fuzz tests for
  `Frame.from_dict`, `TrustStore._load`, and
  `MessageStore.queue_pending_trust` against arbitrary inputs
  including unicode, SQL-injection attempts, binary bytes, and
  empty strings.

### Verification

- **656 unit tests and 29 vitest tests green.**
- **Adversarial security review** — findings fixed (see Fixed
  sections above).
- **Cross-version handshake** — v0.8.5.2 daemon interoperates with
  v0.8.4 peers running on Raspberry Pi and NAS (verified on a live
  3-node mesh).
- **Malformed frame fuzz** — 11 payloads (garbage, oversized,
  negative sequence, wrong types) all rejected cleanly. Daemon
  survived.
- **SIGKILL + restart** — trust file intact, SQLite
  `PRAGMA integrity_check` returns `ok`, peers re-handshaken <1s.
- **Trust file deletion mid-run** — daemon survives, file recreated
  on next trust operation.
- **Concurrent promote/block race** — final state consistent, both
  operations captured in audit chain.
- **Real-mesh gate flow** — live MSG blocked at the gate,
  `MSG_GATED_DROP` event fired with the message's msg_id,
  `pending_trust_dropped` counter incremented.

## [0.8.5] — Pending-trust gate + OpenClaw channel

Two themes:

1. **Pending-trust message gate** — opt-in default-deny mode for new
   peers. When enabled, MSG/REQ/RESP frames from peers awaiting
   operator promotion queue at the daemon instead of reaching clients.
   Closes the "any new TOFU-pinned peer can immediately push messages
   into your agents" gap.
2. **OpenClaw channel plugin** — IronMesh peers as a chat surface in
   OpenClaw, complementing the v0.8.4 MCP bridge.

No wire-protocol changes — every v0.8.x peer stays interoperable.

### Added — pending-trust message gate

- **Daemon-side gate** at `bridge.py` `_gate_inbound_msg` — inbound
  user-payload frames (MSG / REQ / RESP) from a peer in trust state
  `pending` are queued in a new SQLite table; `blocked` peers are
  silently dropped; `trusted` peers fall through to the existing
  delivery path. Control frames (HEARTBEAT / REKEY / ROUTE_*) are
  always delivered. Self-loopback bypasses the gate.
- **Trust state machine** in `trust.py` — every pinned peer carries a
  `trust_state` of `pending` | `trusted` | `blocked`. Pre-v0.8.5 stores
  read missing field as `trusted` so existing operators see no
  behavior change on upgrade. New methods: `get_trust_state`,
  `set_trust_state`, `list_by_trust_state`. `pin_peer` accepts an
  initial state (defaults to `trusted`).
- **SQLite schema v3** in `store.py` — `pending_trust_messages` table
  with per-peer FIFO queue (default cap 100/peer with eviction +
  observability counter). New methods: `queue_pending_trust`,
  `drain_pending_trust`, `discard_pending_trust`,
  `list_pending_trust_summary`, `pending_trust_count_for`. Schema
  migrates automatically from v2; existing message + peer data preserved.
- **Operator API** on the daemon: `promote_pending_peer(node_id)` flips
  to trusted and drains the queue back through the normal inbound
  path (history + bus + GUI fanout) in arrival order;
  `block_pending_peer(node_id)` flips to blocked and discards the queue;
  `list_pending_trust()` returns one entry per peer awaiting promotion
  with queued counts and identity metadata.
- **Three new MCP tools** (`ironmesh_mcp/server.py`) — tool count
  18 → 21:
  - `ironmesh_list_pending_trust` — list peers awaiting promotion +
    queued message counts; reports `gate_enabled` so the caller knows
    whether the daemon is actually gating
  - `ironmesh_trust_peer` — promote a pending peer, drain its queued
    messages back through the normal inbound path (idempotent on
    already-trusted peers)
  - `ironmesh_block_peer` — local-only quiet block (requires
    `confirm=true`); distinct from `ironmesh_revoke_peer`, which
    propagates a signed REVOCATION across the mesh
- **`/ws` operator actions** on the dashboard control channel —
  `list_pending_trust`, `promote_peer`, `block_peer` (all guarded by
  the existing GUI session token).
- **Dashboard panel** — new "PENDING TRUST" section under PEERS shows
  the queue at a glance with `PROMOTE` / `BLOCK` action buttons and a
  `gate on` / `gate off` indicator. Auto-refreshes on every gate event.
- **CLI flag** `--require-message-promotion` (env
  `IRONMESH_REQUIRE_MSG_PROMOTION=true`). Default **off** for
  backwards compatibility — opt-in security default for v0.8.5;
  v0.9.0 is the natural place to flip the default with a release of
  operator feedback. Companion knob:
  `--pending-trust-queue-cap N` (default 100).
- **34 hardened tests** in `tests/test_trust_gate.py` — state machine,
  queue admit / cap eviction / drain order / discard / summary,
  schema v2 → v3 migration with data preservation, MCP tool dispatch +
  arg validation, end-to-end gate behavior, concurrent inbound
  serialization, backwards-compat default for pre-v0.8.5 stores.

### Added — OpenClaw channel plugin (alpha)

- **OpenClaw channel plugin** at [`clients/ts-channel/`](clients/ts-channel/),
  package `@wiztheagent/openclaw-ironmesh-channel@0.1.0`.
  OpenClaw agents treat IronMesh peers as a chat channel: incoming
  peer messages arrive as inbound chat, outbound replies go back over
  the encrypted mesh. Adapters implemented: `id`, `meta`,
  `capabilities`, `config`, `lifecycle.start/stop`, `outbound.send`,
  `messaging.subscribe`, `directory.self/listPeers/listPeersLive`,
  `status.describe`. Setup walkthrough:
  [`docs/OPENCLAW_CHANNEL_SETUP.md`](docs/OPENCLAW_CHANNEL_SETUP.md).
- **Persistence layer** (`src/persistence.ts`) — atomic JSON-per-account
  state file under `~/.openclaw/ironmesh-channel/`. Survives gateway
  restart. `PeerRecord` shape: `{nodeId, agentName, lastSeenMs,
  pinnedFingerprint, trust}`. TOFU fingerprint pinned on first
  observation.
- **Peer-mapper** (`src/peer-mapper.ts`) — translates IronMesh node_id
  ↔ OpenClaw `ChannelDirectoryEntry`. Peers seen on the mesh appear in
  OpenClaw's contact list with their agent name + online status.

### Changed

- **TS channel plugin no longer holds its own pending-trust queue.**
  Initial alpha.3 shipped a TS-side gate; in alpha.4 trust gating is
  daemon-authoritative. Pending peers' messages don't reach the plugin
  at all when the daemon gate is on. Operators promote/block via the
  daemon dashboard or the new MCP tools — there is no per-channel
  trust UX. Removes ~400 lines of TS code that would have duplicated
  daemon state.

### Security

- **Pre-release audit caught + fixed**: the gate originally judged
  trust against `frame.source`, an unauthenticated envelope field. A
  pending peer could forge `source = self.node_id` and bypass the
  self-loopback exemption. Trust judgement now keys on `peer_id`, the
  wire-authenticated peer that signed the frame. Regression test
  added (`test_pending_peer_cannot_bypass_via_forged_source`). Trade-
  off: relayed messages now gate on the relay, not the originator —
  documented limitation, may be revisited in v0.9.0.
- **TrustStore failure is fail-closed**: a corrupted or unreadable
  trust file drops gated traffic instead of silently delivering.
- **Multi-daemon trust file collision fixed**: `BridgeDaemon` now
  accepts an explicit `trust_path` (CLI: `--trust-path`). Previously
  every daemon shared `~/.ironmesh/known_peers.json`, causing MAC
  mismatches and silent trust resets when running two daemons on one
  host. The default is unchanged, so single-daemon hosts see no
  difference.

### Notes

- Default behavior unchanged: `--require-message-promotion` is off, so
  upgrading a daemon does not change message delivery for any
  existing peer. Operators opt in; v0.9.0 will revisit defaulting.
- The pending-trust queue is **not encrypted at rest beyond the
  daemon's existing `_encrypt_payload` storage key** — same protection
  as `messages` and `pending_messages` tables.
- The OpenClaw channel plugin remains alpha — single-peer DMs only,
  no setup wizard, no offline replay, no multi-peer routing. Those
  remain on the v0.8.6+ roadmap.
- Python package version remains `0.8.4` until the v0.8.5 cut. The
  channel plugin is npm-only and has its own version (`alpha.4`).

## [0.8.4] — Expanded MCP surface + functional TypeScript client

Incremental release on top of v0.8.3. Lands the MCP-side OpenClaw
integration and a working TypeScript client that speaks the full
IronMesh wire protocol against a live Python daemon. v0.9.0 stays
reserved for when the OpenClaw Channel Plugin also ships. No protocol
changes — every v0.8.x peer stays on the mesh.

### Added

- **OpenClaw integration — MCP bridge.** Ten new tools in
  `ironmesh_mcp/server.py` make agent-to-agent collaboration first-class
  for any MCP host (OpenClaw, Claude Desktop, Claude Code). The existing
  8 tools are unchanged; total is now 18 (8 core + 5 collaboration +
  5 introspection/responder):
  - `ironmesh_discover_capabilities` — fnmatch glob across the mesh
    (`llm:*`, `role:assistant`, etc.)
  - `ironmesh_get_peer_capabilities` — full capability set for one peer
  - `ironmesh_request_service` — REQ/RESP with correlation-id + timeout
    (D5 envelope convention from the integration plan)
  - `ironmesh_broadcast` — send to every online peer, returns
    `{sent_to, failed}` lists. Now uses `asyncio.gather`
    so one slow peer doesn't serialize the whole call N×10 s
  - `ironmesh_subscribe_events` — cursor-based event poll (peer
    connect/disconnect + message arrivals); cursors past
    `high_water_mark` are clamped to keep desynced clients alive
  - `ironmesh_advertise_capability` / `ironmesh_withdraw_capability` —
    declare/retract capabilities mid-session without restarting
  - `ironmesh_get_my_identity` — own `node_id` + name + advertised caps
  - `ironmesh_pending_requests` — observability into in-flight
    REQ/RESP correlation slots
  - `ironmesh_reply_to_request` — first-class responder helper that
    wraps the correlation-id JSON envelope
  Setup walkthrough: [`docs/OPENCLAW_MCP_SETUP.md`](docs/OPENCLAW_MCP_SETUP.md).
  SOUL.md snippet: [`examples/openclaw/soul_mesh_snippet.md`](examples/openclaw/soul_mesh_snippet.md).
- **TypeScript client — functional alpha.** `@wiztheagent/ironmesh-client@0.1.0-alpha.2`
  in [`clients/ts/`](clients/ts/) implements the full wire protocol:
  3-stage passphrase + ECDH + signed-HELLO handshake, binary frame v4
  encode/decode, SecretBox + Ed25519 signing, WebSocket client with
  reconnect (real exponential backoff + jitter, capped at 30 s).
  51 vitest tests including a live e2e that spawns a real Python
  `BridgeDaemon` and exchanges a MSG round-trip (~6 s), plus
  parallel-send and large-payload (256 KiB) e2e coverage.
- **WS API gap analysis** at `docs/OPENCLAW_WS_API_GAPS.md` (kept
  internal — five-gap audit concluding the channel plugin is feasible with
  ~120 LOC of new daemon code (under the spike's 200-LOC ceiling).
- **`__main__.py`** so `python -m ironmesh` works from a checkout (the
  installed `ironmesh` script entry already worked).

### Fixed

- **`agent.py`: catch `concurrent.futures.TimeoutError` explicitly in
  `Agent.stop()`.** PEP 616 unified `concurrent.futures.TimeoutError`
  with `builtins.TimeoutError` in Python 3.11; on 3.10 they are
  distinct classes, so a bare `except TimeoutError` missed the timeout
  raised by `fut.result(timeout=5)` when daemon shutdown took longer
  than 5 s on a slow runner. The exception leaked out of the
  `finally:` block in `tests/test_concurrency_audit.py::
  test_100_parallel_sends_no_drops` even though the test body had
  already passed. Same widening applied defensively to `bridge.py`'s
  handshake-failure handler. Documented internally as a maintainer-only
  bug post-mortem.
- **CI: collapsed dual pytest runs + `scripts/ci-pytest.sh` wrapper.**
  Every job since 04-17 was hitting the 20-min cap because the second
  "Check coverage threshold" step silently re-ran the entire suite
  under `-q`, and pytest itself sometimes hung in atexit cleanup on
  hosted runners despite reporting all tests passing. Now a single
  pytest invocation handles both report + 60% floor, and the wrapper
  exits 0 the moment a green-summary line appears (10 s grace then
  SIGKILL on the hung interpreter).
- **MCP server peer-dict thread safety.** Wrapped every
  `daemon.peers.items()` iteration in `list(...)` so concurrent
  peer connect/disconnect on the daemon's loop thread can't raise
  `RuntimeError: dictionary changed size during iteration` against
  an in-flight MCP tool handler.
- **TS client no longer drops mesh-relayed binary frames.**
  Previously the outer Ed25519 verification used the handshake peer's
  identity key; for relayed frames the outer sig is the relayer's
  identity, so every relayed frame raised "verification failed" and
  was dropped. Now treated as a soft warning — frame is dispatched on
  AEAD authenticity alone (the inner end-to-end source signature,
  when present, remains the originator's trust anchor).
- **MCP correlation-id slots are peer-keyed.**
  `ironmesh_request_service` now records the addressed peer and rejects
  responses from any other peer that knows the cid, recording the spoof
  as a `request_service:cross_peer_echo` observability event.
- **TS client resets `state.sequence` on each `connect()`.**
  Each session has its own sequence space; carrying a counter across
  reconnect would tag the first frame of a new `session_key` with a
  sequence number that has no meaning to the new session.
- **TS client real exponential backoff with jitter.** Was
  a fixed 500 ms delay despite types.ts advertising "doubles up to
  30 s cap." Now `min(initial × 2^attempt, 30000)` ± 20% jitter,
  reset to 0 on successful connect.
- **`tool_get_mesh_stats` errors on a non-started daemon.**
  Was returning a misleading partial snapshot.
- **`tool_get_audit_log` opens with `encoding="utf-8"`.**
  Windows cp1252 default would corrupt non-ASCII fields.
- **TS client drops frames with `sequence == 0`.** Daemon
  already enforces; this catches buggy/malicious peers at the
  application layer.
- **TS `canonicalJson` ASCII-escapes non-BMP chars (audit follow-up).**
  Matches Python's `json.dumps(ensure_ascii=True)` default; without
  this, an agent named `Zoë` or carrying an emoji in a HELLO field
  would fail signature verification.
- **MCP `SERVER_INFO` reads version dynamically** from
  `ironmesh.__version__` so future bumps can't leave it stale.
- **Eleven inline doc / version-bump fixes** — README, Dockerfile,
  docker-compose, dashboard pill, OpenClaw setup doc: all 0.8.3 →
  0.8.4 references corrected.

## [0.8.3] — Operator console redesign, capability GUI fix, E2E audit

Polish release on top of v0.8.2. The dashboard is rebuilt from scratch
to match the ironmesh.org visual identity — a monospace operator
console with the site's 3-stage handshake diagram baked in, a TOFU
trust tri-state column, concurrent WS/RNS transport view, stat-strip
sparklines, regex-capable message feed with pause/export, bearer-token
masked reveal, and a CSP meta tag that locks the page to same-origin
so `pull the plug on your router` still renders. Two latent backend
serialization bugs that kept capabilities and peer names invisible in
`/api/state` are fixed. Plus the full v0.8.3 E2E audit:
Hypothesis fuzzing, concurrency tests, crash matrix, macOS added to CI.
No wire-protocol changes — any v0.8.2 peer stays on the mesh.
Full write-up: [`docs/RELEASE_NOTES_v0.8.3.md`](docs/RELEASE_NOTES_v0.8.3.md).

### Changed

- **Dashboard rebuild.** `bridge.GUI_HTML` replaced end-to-end. New
  layout: IRONMESH wordmark + `v0.8.3 · PRE-1.0` pill, truncated node
  fingerprint (click-to-copy), mesh state pill (OPERATIONAL /
  DEGRADED / ISOLATED), `OFFLINE-FIRST` badge, masked bearer token
  with reveal / copy-URL / rotate icons. Six stat cards with inline
  SVG sparklines rendered from a rolling client-side buffer (zero
  charting libs). Peer table gains Transport (WS/RNS/BOTH), Trust
  (`✓ TOFU-PINNED` / `… HANDSHAKING` / `✗ MISMATCH`), Last-contact
  relative, Capabilities pills. Selecting a peer lights the stages
  of the site's canonical ASCII handshake diagram. Transport panel
  shows live WS LAN throughput + Reticulum status (disabled with
  "install ironmesh[rns] to enable" hint when RNS is absent).
  Hardened terminal-style feed: per-line severity gutter, pause-tail,
  regex or substring search, CSV export, chatter-toggle for
  PING/PONG. Footer ops row: Audit Log / Rotate Keys / Session Rekey
  / Panic Wipe (2-step confirm). System fonts only — no Google Fonts
  or CDN icons; all SVGs inlined as `<symbol>` sprites.
- **Dashboard feed (pre-audit fix, carried forward from the
  unreleased v0.8.2.1 branch):** CONV envelopes render as
  `[response turn N/M] <body>`; peer name resolved from `state.peers`
  rather than raw node_id; PING/PONG/ROUTE_ANNOUNCE/CAPABILITY_ANNOUNCE
  filtered from the operator view by default, behind a chatter
  toggle.
- **Sent-message UX:** Enter-to-send (Shift+Enter for newline, chat
  convention); `ws.send` failures now surface as an alarm row + red
  statusline instead of vanishing. Empty-feed copy disambiguates
  "cleared · waiting for traffic" from "no matching events".

### Fixed

- **`PeerState.to_dict()` never serialized `agent_name`.** v0.8.1
  populated `peer_state.agent_name` from the HELLO exchange, but the
  GUI serializer dropped it. Every peer in `/api/state` showed
  `name: null`, so the dashboard rendered truncated hashes everywhere
  a human name belonged. Now emitted as `"name"`.
- **`_build_full_state()` never serialized the capability registry.**
  Dashboard JS read `state.capabilities` for the A2A dropdown filter
  and per-peer capability pills; the backend never set the key, so
  the filter silently matched zero peers and pills were always empty.
  Now inverted to `{capability -> [node_ids]}` — the shape every
  consumer actually wants.
- **`DedupCache` TOCTOU race.** `is_duplicate()` and `add()` were
  separate lock acquisitions, leaving a window where two concurrent
  handlers could both decide a message was novel and process it
  twice. Replaced with atomic `check_and_add()`. Regression test
  in `tests/test_concurrency.py`.
- **Dashboard `<img>` tag was live with no file at the referenced
  path**, producing a broken image icon on GitHub rendering. The tag
  is now active and points at `docs/assets/dashboard.png`.
- **Docker image was missing `adapters/`, `ironmesh_mcp/`,
  `examples/`**, so `import ironmesh.adapters.langchain_adapter`
  failed inside the container. `pyproject.toml` `[tool.setuptools]
  package-dir` / `packages` re-declared to include every subpackage.
- **User-Agent header leak in `reticulum_transport.py` HTTP probes.**
  Replaced `urllib`'s default `Python-urllib/3.x` with
  `ironmesh/<version>` so passive observers can't fingerprint the
  Python version.
- **Stale `LICENSE` year + author**, missing `NOTICE` file.

### Added

- **v0.8.3 E2E debugging audit.** Nine Hypothesis properties × 400
  inputs on `ConvEnvelope` round-trip + invariants; 6 new concurrency
  tests (`ReplayGuard`, `TokenBucket`, `DedupCache`); a 4-scenario
  crash matrix (SIGKILL mid-handshake, corrupt trust store, corrupt
  routes.json, disk-full on audit.log); 7 pathological payloads
  fired at the dashboard. `pip-audit` + `bandit` clean. Full matrix
  and findings retained internally as the v0.8.3 audit record.
- **Real-adapter integration tests.** `tests/integration/` exercises
  `adapters/langchain_adapter.py`, `crewai_adapter.py`,
  `autogen_adapter.py` against a `fake_ollama` stub so the adapters
  can't silently drift.
- **macOS in CI matrix** — now 12 jobs: Ubuntu / Windows / macOS ×
  Python 3.10 / 3.11 / 3.12 / 3.13.
- **Roadmap** at [`docs/ROADMAP.md`](docs/ROADMAP.md) (NAT traversal,
  Android native, Rust port, plugin sandbox).
- **NAT traversal design doc** at
  [`docs/NAT_TRAVERSAL_DESIGN.md`](docs/NAT_TRAVERSAL_DESIGN.md)
  (accepted, implementation deferred to v0.9).
- **`docs/assets/dashboard.png`** — live 3-node mesh screenshot used
  as the README hero.
- **`NOTICE`** file with third-party attribution.

### Verification

582 tests pass (+3 GUI assertion tests for the redesign —
`test_html_has_handshake_diagram`, `test_html_has_csp`,
`test_html_has_trust_tri_state`), +9 Hypothesis fuzz properties,
+6 concurrency tests. ruff clean, mypy clean, bandit clean,
pip-audit clean on Ubuntu + Windows + macOS across Python 3.10–3.13.

## [0.8.2] — Multi-turn AI dialogue, personas, tools, A2A dashboard

Feature release on top of v0.8.1. Adds structured multi-turn
conversations, seven persona presets, byte/time budgets + smart
termination, a one-click AI-to-AI panel in the dashboard, and an
opt-in tool-use registry. No wire-protocol version bump — the new
`CONV` frame is additive. Full write-up:
[`docs/RELEASE_NOTES_v0.8.2.md`](docs/RELEASE_NOTES_v0.8.2.md).

### Added

- `MessageType.CONV` and `ironmesh.conversation` (`ConvEnvelope`,
  `Budget`, `make_reply`, `is_terminal`) for multi-turn agent
  dialogue with turn caps and budgets. Documented in
  [`docs/PROTOCOL_SPEC.md §4.1`](docs/PROTOCOL_SPEC.md).
- `ironmesh.roles` with 7 persona presets; `--role` on
  `examples/llm_bridge.py`. Also advertised as `role:<name>` capability.
- Budgets + `[DONE] <reason>` smart termination in `llm_bridge.py`.
- Dashboard `start_dialogue` GUI WS action + "Start A2A" panel.
- `ironmesh.tools` registry with `echo` / `http-get` / `file-read`
  tools; `--tools` + `--file-read-allow` on `llm_bridge.py`.

### Fixed

- **GUI `message_event` emitted empty `peer_id` and `payload`.**
  `MessageBus.publish` wraps dict payloads in `MappingProxyType`
  which is not a `dict` subclass; the old `isinstance(data, dict)`
  check silently dropped the fields. Now uses
  `collections.abc.Mapping`. Regression in
  `tests/test_hardening.py::TestGUIBroadcastMappingProxy`.

### Verification

559 tests pass (+45 new), ruff/mypy/bandit clean.

## [0.8.1] — Mesh stability: duplicate-handshake race fix

Bug-fix release on top of v0.8.0. No wire-protocol changes.

### Fixed

- **Duplicate-handshake race.** When two peers dial each other at
  nearly the same time, the losing handshake's `finally` block in
  `_handle_connection` used to unconditionally pop
  `ws_clients[peer_id]`, transition the peer to `OFFLINE`, and clear
  the session key — clobbering the winning handshake's still-live
  connection. Symptoms: peers appearing online then immediately
  offline in the dashboard, streams of `No session key for peer X —
  dropping message` warnings, and a mesh that could only keep one
  peer online at a time. The teardown is now scoped to the
  *owning* websocket: `self.ws_clients.get(peer_id) is websocket`.
- **Client-side message-loop cleanup.** The mirror path in
  `_do_client_handshake` previously had no cleanup at all when the
  connection died, leaving stale `ONLINE` state that blocked the
  reconnect loop from ever re-dialing. Same scoped teardown applied.
- **Windows proactor shutdown noise.** Installed a scoped exception
  handler on the daemon's event loop that silences only the known
  CPython `AssertionError` from `proactor_events._start_serving` that
  fires when an `accept()` completes between `server.close()` and
  socket shutdown. Every other exception still surfaces normally.
- **`Agent.peer_by_name()` always returned `None`.** `PeerState.agent_name`
  was never populated during the handshake, so the SDK's friendly-name
  lookup (and the `name` field in `Agent.peers`) didn't work. The
  HELLO-advertised name is now stored on `PeerState` in both the
  server and client handshake paths.

### Added

- **`ironmesh demo` subcommand.** One command spawns two temporary
  agents on `127.0.0.1`, does the full mutual-auth + ECDH handshake,
  sends an encrypted ping, prints the round-trip latency, and exits.
  No keys, ports, or state written to `~/.ironmesh`. Use it as a
  10-second smoke test after `pip install ironmesh`. Pass `--gui` to
  keep both agents up with the dashboard enabled on `alice`'s port+1
  (handy for screenshots and poking around the state endpoints).
- **`docs/USE_CASES.md`.** Five concrete deployment patterns with
  runnable commands: home AI mesh, offline LLM swarm, robotics
  coordination, air-gapped lab, off-grid LoRa comms.
- **`examples/ollama_swarm.py`.** Two local-LLM agents talking over
  an encrypted IronMesh session — the flagship "multiple AI agents
  on your home network, no cloud" demo.
- **`docs/assets/`.** Slot for the README dashboard screenshot.

### Docs + positioning

- README now leads with a stack diagram showing IronMesh *under*
  MCP / LangChain / CrewAI rather than competing with them. Four
  Q&A cards address the common "but doesn't X already do this?"
  objections (MCP, LangGraph, Tailscale, Reticulum).
- Feature comparison table retitled to acknowledge it's one axis
  (offline-first), not a universal ranking.
- Site (ironmesh.org) mirrors the same reframing.

### Regression tests

Two new tests in `tests/test_hardening.py::TestDuplicateHandshakeTeardown`
cover both branches of the fix (loser must not clobber winner; winner
still cleans up its own state). Total: 514 tests, ruff clean, mypy
clean, bandit clean on Ubuntu + Windows across Python 3.10–3.13.

## [0.8.0] — Agent SDK, framework adapters, federation, Go client

First release above the "transport" layer. Turns IronMesh from a
protocol you integrate by hand into a platform you build on.

### Added

- **Agent SDK** (`ironmesh.Agent`) — high-level wrapper over
  `BridgeDaemon` with decorator handlers, sync+async send, capability
  discovery. Joins the mesh in 3 lines.
- **Framework adapters** for LangChain (`create_ironmesh_toolkit`),
  CrewAI (`create_mesh_crew_agent`), and AutoGen (`register_ironmesh`).
- **Federation gateway** (`FederationGateway`, `FederationPolicy`) —
  bridges two independent meshes with allow/deny glob rules on
  capabilities. Runs two Agent instances, one per mesh.
- **Go reference client** (`clients/go/`) — full wire-protocol
  implementation: frame serialization, X25519 ECDH, XSalsa20-Poly1305,
  Ed25519 detached signatures, 3-stage handshake. Crypto primitives
  verified against the Python reference.
- **Docker + PyPI + GitHub release** — `pip install ironmesh`,
  `docker pull wiztheagent/ironmesh:0.8.0`, GitHub release with
  wheel + sdist attached.

### Changed

- Default keys path migrated from a legacy vendor-prefixed location
  to `~/.ironmesh/keys.json`.
- Python minimum: 3.10 (3.9 was already dropped in 0.7.2).

### Fixed (security)

- Tarfile path-traversal guard in `backup.py` (rejects `..`,
  absolute paths, backslash).
- Narrowed bare `except` clauses in `agent.py` and `crypto.secure_wipe`.

## [0.7.2] — Mesh stability, observability, and backpressure

Focused on production-readiness for multi-node deployments. Closes
Wiz's hardening checklist (per-hop RTT + retries + message lifetime,
queue backpressure, peer-drop alerting, per-peer bandwidth throttle).
All 5 critical and 11/11 high-severity items from the prior audit now
fixed. 472 tests passing, zero regressions.

### Distribution (post-0.7.2 initial commit)

- **PyPI** — `pip install ironmesh` live at
  https://pypi.org/project/ironmesh/0.7.2/ . The wheel ships both
  `ironmesh` and `ironmesh-mcp` console scripts.
- **Docker Hub** — `docker pull wiztheagent/ironmesh:0.7.2` (also
  `:0.7.2-beta` and `:latest`) at
  https://hub.docker.com/r/wiztheagent/ironmesh .
  Dockerfile now copies the `ironmesh_mcp/` subpackage so the MCP
  server is included in the image.
- **GitHub** — public at https://github.com/WizTheAgent/IronMesh
  with v0.7.2-beta tagged as a pre-release.
- **Website** — public at https://ironmesh.org .

### CI + polish (post-0.7.2 initial commit)

- Ruff config tightened: `known-first-party = ["ironmesh", "ironmesh_mcp"]`
  and `combine-as-imports = true` so lint results are reproducible
  between local and GitHub Actions (the env-dependent heuristic was
  firing I001 only on CI).
- Ignore `E501` (line-too-long) and `E402` (import-not-at-top) — both
  were triggering on legitimate patterns (long URLs in docstrings,
  conditional imports).
- Bandit threshold in CI raised to `-lll` (HIGH only). The 5 Medium
  findings are all `B104` (bind to `0.0.0.0`) — intentional for a
  mesh daemon, not a vulnerability. Zero HIGH findings.
- Added `hypothesis>=6.0` to `[dev]` deps so `test_fuzz_protocol.py`
  runs on fresh CI.
- Removed `scripts/sanitize.py` — it was a private→public migration
  tool that itself contained the identifiers it was designed to
  redact.
- `test_refills_over_time` sleep extended to 100 ms to avoid flaky
  failures on Windows (~15.6 ms scheduler granularity).
- GitHub repo metadata set: description, homepage
  (https://ironmesh.org), README BETA banner, Contact section.
- `SECURITY.md` / disclosure email: `info@ironmesh.org`.

### Breaking: Python 3.10+ required

`requires-python` bumped from `>=3.9` to `>=3.10`. Python 3.9 went
EOL in October 2025. The codebase relies on `asyncio.Lock()` being
constructible outside a running loop (a 3.10 change) — keeping the
3.9 compat shim is more complexity than the shrinking 3.9 user base
justifies. If you're on 3.9, pin to `ironmesh==0.7.1` until you
upgrade.

### Breaking: Python 3.10+ required

`requires-python` bumped from `>=3.9` to `>=3.10`. Python 3.9 went
EOL in October 2025. The codebase relies on `asyncio.Lock()` being
constructible outside a running loop (a 3.10 change) — keeping the
3.9 compat shim is more complexity than the shrinking 3.9 user base
justifies. If you're on 3.9, pin to `ironmesh==0.7.1` until you
upgrade.

### Major protocol bugs fixed

- **Event loop not started on `BridgeDaemon.run(background=True)`** —
  `loop.run_forever()` was never called, so every scheduled coroutine
  (mDNS auto-connect, server handshakes, LXMF→IronMesh forwarding)
  was a dead letter. The LXMF gateway couldn't forward messages until
  this was fixed. The daemon now spawns a `run_forever()` thread
  before returning the loop to the caller.
- **Simultaneous-dial collision storm** — both ends of an mDNS pair
  dialed each other at the same tick, creating duplicate sessions
  that both sides tore down, producing a rapid online→offline flap.
  Added a deterministic agent-name tie-breaker: the lexicographically
  smaller name dials; the larger waits for incoming. Applied uniformly
  in `_on_peer_discovered`, `_discover_loop`, and `_reconnect_loop`.
- **`_local_ip()` returned the wrong NIC on multi-homed hosts** —
  `getaddrinfo(hostname)` picked up VirtualBox/WSL/Docker bridge IPs
  ahead of the real LAN adapter. Reordered to prefer route-based
  detection (UDP-connect to common RFC1918 gateways).
- **Zeroconf responded on every interface** — when operator sets an
  explicit `--bind`, Zeroconf now binds only to that interface.
- **Single-peer mDNS auto-connect gate** — `any(peer.is_online)`
  globally skipped auto-dial of *any* new peer once *any* peer was
  online. Broke 3+ node meshes. Changed to per-peer check.
- **Session-key race after connect_to_peer** — harness and normal
  client callers could send their first message on a connection the
  tie-breaker was about to tear down. Added `wait_peer_online(stability_seconds)`
  that waits for session_key to stay unchanged for ≥2s before returning.

### Observability — Wiz's hardening checklist

- **Per-peer metrics**: `ironmesh_peer_{online,rtt_ms,retries_total,
  bytes_sent_total,bytes_received_total}{peer="…",name="…"}` — Prometheus-labelled
  per-peer gauges/counters. Retries tagged by reason (`direct_send_failed`,
  `routed_send_failed`, `queued_offline`, `queue_full_dropped`,
  `bandwidth_throttled`, `rekey_failed`).
- **Message lifetime summary**: `ironmesh_message_lifetime_seconds`
  sampled from inbound frame timestamps — p50/p90/p99 quantiles
  populated from a bounded rolling window (512 samples).
- **`/api/mesh_stats` endpoint**: compact JSON snapshot optimized for
  harness/dashboard polling. Stable schema — additive across releases.
- **Dashboard**: peer table now shows Bytes (sent/received), RTT, and
  retry count with hover tooltip listing per-reason breakdown.

### DoS guard: backpressure on queues

- **Offline queue cap** (`MessageStore(max_pending_per_peer=1000)`) —
  prevents a perpetually-offline peer from consuming unbounded disk.
  Priority-aware eviction: CRITICAL/HIGH displace oldest LOW/NORMAL;
  a queue full of CRITICAL refuses new LOW admits.
- **Per-peer bandwidth throttle** — `TokenBucket` in bytes/sec
  (default 1 MB/s sustained, 1 MB burst). If required wait exceeds
  5s, the frame is dropped with `record_retry("bandwidth_throttled")`.
  Prevents one noisy peer from starving mesh bandwidth.
- New metrics: `ironmesh_pending_queue_dropped_total`,
  `ironmesh_pending_queue_evicted_total`,
  `ironmesh_peer_bandwidth_drops_total`.

### Peer-drop alerting

- `PeerState.offline_since` stamped on transition (preserved across
  rapid flaps — not reset per event).
- New `_long_drop_watchdog` task emits `EVENT_PEER_DROPPED_LONG` to the
  audit log exactly once per drop when a peer stays offline past
  `_long_drop_threshold_seconds` (default 300s). Metric:
  `ironmesh_peer_long_drops_total`.

### Bandwidth: RNS transport hardening

- Outbound `send()` now enforces `MAX_RNS_MSG` (1 MB) matching the
  inbound deframe bound — closes an asymmetric bounds-check gap.

### Operations

- **`scripts/startup-capture.sh`** — systemd-friendly wrapper that
  extracts the GUI token from daemon stdout and appends it to
  `/var/log/ironmesh-token.log` (mode 0600) so operators can retrieve
  dashboard access without grep'ing the journal.
- **`docs/REPIN.md`** — complete playbook for compromised-peer
  revocation, legitimate key rotation, corrupted trust store, offline
  pubkey backup, and reinstall recovery.
- **`scripts/chaos-netem.sh`** — `tc netem` wrapper for injecting
  packet loss, delay, jitter, or corruption into the mesh for
  resilience testing.

### Benchmark harness

- New `tests/harness/mesh_bench.py` — parametric RTT/goodput
  measurement tool. Sweeps payload sizes, supports `--chaos <rate>`
  for drop injection, writes CSV for trend analysis.
- New `tests/harness/bench_responder.py` — companion BENCH echo
  responder (also usable as a library via `attach_responder()`).
- Baseline measured live on a 3-node LAN mesh: 100% delivery at 64B/256B/1024B,
  p50 ≈ 12-14 ms, goodput 38-77 KB/s. Chaos 25% drop → 78% delivered
  (matches injection rate within 2%).

### Test suite

- 430 → 456 tests (+26 new covering discovery multi-NIC, queue
  bounds, bandwidth throttle, long-drop alerts, TokenBucket.wait_time,
  mesh_stats schema, TOFU test fixture repair).
- Four pre-existing failures and 16 errors from v0.5/v0.6 feature
  changes all repaired — test suite is now clean (zero failures,
  zero errors).

### Deferred to v0.8

- Signed capability announcements (schema change; needs v0.8 wire version)
- Circuit-breaker persistence across restarts
- Adaptive LoRa message sizing (RNS already fragments at its layer)
- Native Android client (Sideband + LXMF gateway covers the Android
  use case for v0.7)

---

## [0.7.1] — Security audit fixes (53/62 items)

Addresses a 62-item security/code-quality audit. This release closes
all 5 critical and 10 of 11 high-severity findings, plus 14 medium and
13 low-severity items. The remaining 9 items (signed capability
announcements, circuit-breaker persistence, rate-limiting future
frames, two new test suites, mypy-blocking in CI) are deferred to
v0.7.2 — each requires more scope than this release permits.

### Security fixes — Critical

- **C-01** Peer state race condition — added `asyncio.Lock` covering
  the duplicate-detection check, peer-state assignment, and
  `_handle_connection` finally cleanup. Fixes identity hijacking when
  two connections race to the same peer_id.
- **C-02** `secure_wipe` rewritten — the old implementation used
  CPython-specific ctypes offsets that silently failed. The new
  version uses `nacl.bindings.sodium_memzero` when available and
  refuses silently on immutable `bytes`, logging honestly about its
  limits.
- **C-03** Trust store MAC is now bound to the agent's identity key
  (required parameter). The old machine-home-derived key is kept only
  as a one-shot migration detector. `ironmesh trust` CLI now loads the
  identity key before constructing the store.
- **C-04** Replay-guard monotonic check verified already in place
  (`protocol.py:522` rejects `seq <= last_seq` before window lookup).
  Comment added.
- **C-05** Bound the 4-byte length field in the RNS Buffer deframe
  loop to `MAX_RNS_MSG = 1_048_576` — prevents memory exhaustion from
  a malformed prefix.

### Security fixes — High

- **H-01** `_handle_connection` always closes the websocket in its
  finally block, even on early handshake failure.
- **H-02** `_is_ip_blocked` / `_record_auth_failure` made async and
  serialized under `asyncio.Lock` to prevent rate-limit bypass.
- **H-03** Audit log emits `logger.critical(...)` when initialized
  without an HMAC key — never silently disabled.
- **H-04** `MeshRouter.__init__` raises `RuntimeError` if the daemon
  has no keypair (routes are HMAC-protected using that key).
- **H-05** `store._encrypt_payload` no longer falls back to plaintext
  on encryption failure — errors propagate.
- **H-06** `transport.recv` takes a `timeout: float = 300.0` parameter
  and uses `asyncio.wait_for` — prevents stalled peers from blocking.
- **H-07** `reticulum_transport._active_adapters` now protected by
  `threading.Lock`.
- **H-08** mDNS property decoding validates length, UTF-8 strictness,
  charset (alnum + `-_.`), port range, and idhash hex format.
- **H-09** `ed25519_to_curve25519_secret` uses a `bytearray` for the
  intermediate buffer and zeroes it in `finally`.
- **H-10** `AsyncMessageStore.open` serialized under `asyncio.Lock`
  with an `_opened` idempotency flag.
- **H-11** Created 4 missing test files: `test_cli.py` (11 tests),
  `test_hooks.py` (8), `test_config.py` (10), `test_backup.py` (6).

### Security fixes — Medium

M-01, M-03, M-04, M-05 (partial), M-06, M-07, M-09, M-10, M-12, M-13,
M-15, M-16, M-19.

### Security fixes — Low

L-01, L-02, L-03, L-04, L-05, L-06, L-07, L-08, L-09, L-11, L-12, L-13, L-14.

### Deferred (v0.7.2 candidates)

- **M-02** Rate-limit future-timestamped frames per peer.
- **M-08** Sign capability announcements with Ed25519.
- **M-11** Persist circuit-breaker state to HMAC-protected file.
- **M-14** Two-daemon integration test suite.
- **M-17** Concurrency test suite with `asyncio.gather`.
- **M-18** Separate `revoked_peers` set (today tracked inside
  `_revoked` dict; the race is theoretical, not yet observed).
- **L-10** Replace `time.sleep(0.01)` in rate-limit test with
  `freezegun` time mocking.
- **M-16** Make mypy blocking in CI (needs existing type errors fixed
  first; kept non-blocking to avoid breaking CI in the same commit).

### Test results
- 410 tests pass (up from 375 pre-v0.7.1; +35 from new test files +
  C-03 migration fixtures).
- 4 pre-existing failures unchanged (v0.5.1 TOFU address-change and
  v0.6 revocation — these tests need updating, not core code).
- 16 pre-existing `test_reticulum_transport.py` errors unchanged
  (from v0.5.1 RNS adapter rewrite).

## [0.7.0] — Ecosystem release: Docker, LXMF bridge, conformance suite

This release focuses on making IronMesh publish-ready and easier to
interoperate with. No wire-protocol changes — v0.7 interoperates with
v0.3–0.6 peers.

### Added

**Deployment**
- `Dockerfile` (multi-stage, non-root UID 1000) + `docker-compose.yml`
  with sensible defaults, healthcheck, and optional paired-peer profile.
- `scripts/install.sh` — one-line installer. Detects OS, installs
  Python if missing, creates a venv, prompts for a passphrase, and
  optionally installs the systemd user unit.
- `scripts/ironmesh.service` — hardened systemd user unit with
  `PrivateTmp`, `ProtectSystem=strict`, `ReadWritePaths`,
  `SystemCallFilter=@system-service`, etc.

**Mobile / Web**
- GUI dashboard is now mobile-responsive: new `@media (max-width: 600px)`
  breakpoint with touch-friendly form controls (44px min-height), 2-col
  cards grid, compressed tables.
- PWA manifest served at `/manifest.json` — Chrome "Install app" works.
- Theme colour, apple-mobile-web-app-capable meta tags.

**LXMF gateway** — `examples/lxmf_gateway.py`
- Bidirectional bridge between IronMesh and Reticulum LXMF.
- Anyone on [Sideband](https://unsigned.io/sideband) (iOS/Android) or
  NomadNet can message IronMesh peers and receive replies, without
  running IronMesh themselves.
- JSON config file maps LXMF destination hashes to IronMesh peer_ids.
- Loop-prevention via `[LXMF] ` / `[IM] ` prefixes.
- Thread-safe bridging from RNS delivery callback to the asyncio loop.

**Specification**
- `docs/PROTOCOL.md` — added formal header with protocol identifier
  `ironmesh/0.6`, version / compatibility matrix, conformance section.
- `tests/test_conformance.py` — 28 invariant tests covering wire
  format, replay guard, handshake, signatures, TOFU, version
  negotiation, and message type catalog. Usable as a reference by
  future ports (Rust, Go).

**Docs**
- `GETTING_STARTED.md` — 5-minute quickstart separate from the
  feature-heavy README.
- `docs/TERMUX.md` — Android/Termux install guide.
- README additions: examples table, mobile section, Docker/installer
  options.

### Changed
- Version bumped to 0.7.0 in `__init__.py` and `pyproject.toml`.
- Roadmap in README reflects completed v0.5/0.6/0.7 milestones and
  sets v1.0 as the next major target (after 10-20 real-world deployments).

### Strategy
Per open-source-first guidance:
- Core stays MIT (see `LICENSE`).
- Future commercial surface (hardware kits, managed dashboards, custom
  transport adapters, deployment services) will sit on top of the open
  core without wrapping key management.

## [0.6.1] — Connection stability + LLM bridge example

### Fixed
- **Connection churn**: Native WebSocket ping/pong is now enabled on both
  server and client (`ping_interval=20, ping_timeout=10`). Previously
  disabled, which meant dead connections weren't detected until the
  app-level heartbeat tried to send (up to 15 s) and then spammed
  `Failed to send frame` until the next reconnect cycle. The websockets
  library now detects dead peers within ~30 s and fires the normal
  `ConnectionClosed` path cleanly.
- **Send timeout in `_send_frame`**: wraps `ws.send()` with a 5-second
  `asyncio.wait_for`. On timeout or send error, the peer is marked
  OFFLINE immediately and the stale ws is closed — no more "Failed to
  send frame" loops on half-dead connections.
- **Reconnect race**: four reconnect paths (`_reconnect_loop`,
  `_try_transport_failover`, `_discover_loop`, `_on_peer_discovered`)
  could race when a peer dropped. Added a `_reconnecting` gate keyed by
  peer_id/agent_name with 60 s staleness timeout — at most one
  reconnect attempt in flight per peer.

### Added
- **`examples/llm_bridge.py`** — a ~200-line standalone example that
  turns any IronMesh node into an encrypted LLM agent:
  - Subscribes to `MSG` on the bus.
  - For each prompt, calls the Ollama HTTP API (`/api/generate`).
  - Sends the response back to the original sender, prefixed with
    `[LLM] ` so this code does not loop on the local replies.
  - Configurable model, system prompt, timeout, max prompt size.
  - Error responses are prefixed with `[LLM-ERR] `.
  - Uses only stdlib `urllib.request` (no extra deps) + `asyncio.to_thread`.

  This is the canonical use case for IronMesh: end-to-end encrypted LLM
  agents that work fully offline over LoRa.

## [0.6.0] — Hardening release: backup, revocation, version floor, fuzzing

This release focuses on operational readiness and long-term trust
management.  No wire-protocol breaking changes — v0.6 interoperates with
v0.3–0.5 peers.

### Added

**Operational tooling**
- `ironmesh backup --out <file>` and `ironmesh restore --in <file>`
  produce encrypted archives of keys + trust store + audit log tail
  (Argon2id + SecretBox, same crypto as identity key files).
- `ironmesh audit verify [--archives]` walks the HMAC chain and
  reports tamper/integrity.
- `ironmesh audit export --out <file>` produces an Ed25519-signed JSON
  bundle of audit entries; `ironmesh audit verify-export <file>` checks it.
- `ironmesh session rotate <peer_id> --token <t>` forces an immediate
  session key rotation with a peer via the local GUI WebSocket.
- `ironmesh trust list-revoked` shows currently revoked peers.
- GUI WebSocket actions: `rotate_session`, `broadcast_revocation`.

**Protocol hardening**
- `--min-protocol-version` flag (default `ironmesh/0.3`): refuses peers
  below the floor. Raise to `ironmesh/0.5` once all nodes are upgraded.
- Jittered exponential backoff for reconnection (5 s → 300 s cap, ±2 s
  jitter). Prevents reconnect storms after network partition.
- mDNS `idhash`: 8-byte SHA-256 prefix of identity public key in TXT
  records. Non-identifying but lets peers correlate announcements to
  pinned identities before handshake.

**Security features**
- `REVOCATION` message type: Ed25519-signed broadcast to mark a peer as
  revoked. Receivers verify the signature came from a pinned peer, then
  add the target to `revoked_peers` in the trust store. Revoked peers
  are refused at TOFU check.
- Fuzzing harness (`tests/test_fuzz_protocol.py`) using `hypothesis`:
  500+ random inputs per test, verifies frame parser and version
  parser raise only known exception classes on malformed input.

**Documentation**
- `docs/THREAT_MODEL.md`: full STRIDE analysis with assets, mitigations,
  residual risks, and out-of-scope items.
- `docs/ARCHITECTURE.md`: version compatibility matrix (v0.3 → v0.6)
  and upgrade path.

### Changed
- Protocol version bumped to `ironmesh/0.6` in HELLO messages.
- Trust store file format gains a `revoked` section (backward-compatible
  — old stores without it still load cleanly).
- mDNS `idhash` is an additional TXT field (older peers ignore unknown
  fields).

### Fixed
- Simultaneous-rekey race (both peers initiate at the same interval): now
  the node with the lexicographically-smaller `node_id` initiates; the
  other responds.
- Protocol version was stuck at `ironmesh/0.4` in v0.5.x — rekey path
  checks `>= 0.5` so v0.5 peers never rekeyed with each other. Fixed as
  part of the v0.6 version bump.

### Deferred to future releases
- Shamir's Secret Sharing for key recovery (v0.7 candidate).
- Full HTTPS GUI with auto-generated certificates.
- C/Rust SDK for embedded firmware.
- Message batching and large-payload fragmentation over LoRa.
- Ephemeral mDNS aliases.

## [0.5.2] — Metrics, session rotation, LoRa QoS, and test harness

### Added
- **Per-hop RTT measurement**: Heartbeat PING/PONG now measures actual
  round-trip time and populates `PeerState.latency_ms` (previously always
  `null`). Dashboard and `/api/state` show live RTT per peer.
- **Delivery metrics**: `messages_delivered` (real-time) and `messages_failed`
  (fell back to offline queue) counters in Metrics class and Prometheus.
- **`avg_rtt_ms`**: New Prometheus gauge showing average RTT across online peers.
- **Session key rotation** (`REKEY_REQUEST`/`REKEY_RESPONSE`): Periodic
  re-derivation of ECDH session keys without full re-handshake. Configurable
  via `--rekey-interval` (default 30 min, 0 to disable). Only activates with
  v0.5+ peers. Forward secrecy maintained — ephemeral keys wiped after each
  rotation.
- **LoRa QoS / adaptive sizing**: `--lora-max-payload` flag (default 128 bytes).
  Messages to RNS peers exceeding the limit are automatically gzip-compressed.
  `routing["compressed"]` flag signals the receiver to decompress. WebSocket
  peers are unaffected.
- **Test harness** (`scripts/test_harness.py`): Standalone tool that sends
  incremental payload sizes through the bridge, measures latency per size, and
  outputs a CSV with per-size min/max/avg/p95 statistics.

### Changed
- Prometheus endpoint now exposes 26 metrics (was 21), including delivery,
  RTT, rekey, and LoRa QoS counters.

## [0.5.1] — Transport resilience and RNS bug fixes

### Fixed
- **RNS handshake race condition**: Outbound `RNSLinkAdapter` callbacks were
  registered after the link went ACTIVE, causing the server's
  `PASSPHRASE_CHALLENGE` to be silently dropped.  Rewrote adapter to use
  `RNS.Buffer.create_bidirectional_buffer()` over the link's Channel API
  with length-prefixed message framing — handles fragmentation and delivery
  automatically.
- **RNS incoming link callback**: `_on_incoming_link` exceptions were silently
  swallowed by the RNS thread.  Added try/except with `logger.exception()`.
- **TOFU address pinning too strict**: mDNS address changes (e.g. port change
  after restart) were hard-rejected, blocking all reconnection.  Now accepts
  address changes and updates the pin — identity is verified via Ed25519 key
  during the handshake.
- **RNS configdir default**: `--rns-configdir` defaulted to `None` instead of
  `~/.reticulum`, causing the RNS identity file to not persist and the
  destination hash to change on every restart.

### Added
- **Transport failover**: When a WebSocket connection drops, the bridge
  automatically attempts reconnection over RNS if a destination hash is known
  (and vice versa).  2-second cooldown prevents tight reconnect loops.
- **Transport-aware duplicate guard**: If a peer is connected via RNS and a
  WebSocket connection becomes available, the bridge upgrades to WebSocket
  (preferred, faster) and tears down the RNS link.  Same-transport duplicates
  are still dropped.
- **RNS reconnection**: `_reconnect_loop` now tries RNS destinations for
  offline peers when no WebSocket address is available.
- **Transport tracking**: `PeerState` gained `transport_type` (`"websocket"` or
  `"rns"`), `rns_dest_hash`, and `ws_address` fields.  Dashboard API exposes
  these in `/api/state`.
- **`_known_rns_hashes` dict**: Remembers RNS destination hashes for peers
  across reconnections.

### Changed
- `RNSLinkAdapter` now uses `RNS.Buffer` (bidirectional buffered stream over
  Channel) instead of raw `RNS.Packet` / `RNS.Resource`.  Messages are framed
  with 4-byte big-endian length prefixes.  Server uses stream IDs (recv=0,
  send=1), client uses (recv=1, send=0).

## [0.5.0] — Reticulum (LoRa) transport release

IronMesh goes radio. v0.5 adds Reticulum as an optional second transport
layer so agents can communicate over LoRa (915 MHz) with no internet and no
LAN — just RNode hardware. Both WebSocket and Reticulum transports run
simultaneously.

### Added

#### Reticulum / LoRa transport
- New `reticulum_transport.py` module with `RNSLinkAdapter` (duck-typed
  WebSocket interface over an RNS Link) and `ReticulumTransport` (lifecycle
  manager: init, announce, incoming links, outbound connections, shutdown).
- `RNSLinkAdapter` implements `send()`, `recv()`, `async for`, `async with`,
  `remote_address`, `open`, and `close()` — slots into `ws_clients` alongside
  real WebSockets with zero changes to the handshake or message loop.
- Small payloads (≤ 400 bytes) sent via `RNS.Packet`; larger payloads via
  `RNS.Resource` (automatic chunking over LoRa).
- Thread-safe bridging from RNS callbacks to asyncio via
  `loop.call_soon_threadsafe()` + `asyncio.Queue`.
- Periodic RNS announces with agent name as `app_data`.
- Double encryption by design: IronMesh NaCl crypto on top of Reticulum's
  own link-level encryption (defense in depth).

#### Bridge integration
- Extracted `_do_client_handshake(ws, label)` from `connect_to_peer` — the
  transport-agnostic core of the outbound handshake. Both `connect_to_peer`
  (WebSocket) and `_connect_rns_peer` (Reticulum) use it.
- New `_connect_rns_peer(dest_hash)` method: resolves destination, creates
  RNS link, wraps in adapter, runs standard IronMesh handshake.
- `_start()` conditionally initializes `ReticulumTransport` and connects to
  startup destinations from `--rns-connect`.
- `shutdown()` tears down Reticulum transport before mDNS cleanup.

### CLI
- `--reticulum` — enable Reticulum transport.
- `--rns-configdir PATH` — Reticulum config directory.
- `--rns-announce-interval SECONDS` — announce interval (default: 300).
- `--rns-connect HASHES` — comma-separated destination hashes for startup.

### Configuration
- New `IronMeshConfig` fields: `rns_enabled`, `rns_configdir`,
  `rns_announce_interval`.
- Environment variables: `IRONMESH_RNS_ENABLED`, `IRONMESH_RNS_CONFIGDIR`.

### Dependencies
- `rns>=0.9.0` added as optional dependency group (`pip install ironmesh[rns]`).
- Keywords updated to include `lora`, `reticulum`.

### Migration notes from 0.4.x
- No breaking changes. The `--reticulum` flag is off by default; existing
  WebSocket-only deployments are unaffected.
- The `connect_to_peer` method was refactored to use `_do_client_handshake`
  internally — behavior is identical, but the handshake logic is now shared.

---

## [0.4.0] — Mesh routing release

This is a major release. v0.3 was a working A2A protocol with WebSocket + mDNS
+ per-pair encrypted sessions; v0.4 makes the "mesh" in IronMesh real.

### Added

#### Multi-hop mesh routing
- New `mesh.py` module with `RoutingTable`, `DedupCache`, `CircuitBreaker`,
  and `MeshRouter` (announce loop, cleanup loop, relay, partition detection).
- Proactive distance-vector routing with split horizon + poisoned reverse.
- New message types: `ROUTE_ANNOUNCE`, `ROUTE_UNREACHABLE`,
  `CAPABILITY_ANNOUNCE`, `CAPABILITY_QUERY`.
- TTL-based loop prevention plus explicit hop-list inspection.
- Per-source-sharded dedup cache (`128` sources × `1024` entries × `5min` TTL
  by default) to bound memory under flooding.
- Routing table persistence at `~/.ironmesh/routes.json`, HMAC-protected with
  a key derived from the node identity.
- Circuit breaker that opens after 3 failures within a 60s window and is
  consulted before every route lookup.
- Mesh partition detection with `EVENT_MESH_PARTITION_SUSPECTED` audit event.
- `BridgeDaemon.send_message()` now falls back to mesh routing when no direct
  WebSocket session exists; the offline queue remains the final fallback.

#### End-to-end encryption
- New `mesh_crypto.py` wrapping NaCl `SealedBox` over X25519 keys derived
  from each node's existing Ed25519 identity (`keys.ed25519_to_curve25519_*`).
- `seal_to_destination(plaintext, dest_ed25519_pub)` and
  `unseal_from_source(sealed, my_ed25519_secret)` provide forward-secret per-
  message ephemeral encryption that relays cannot read.
- E2E payloads carried in the new `Frame.e2e_payload` field, untouched by per-
  hop re-encryption.
- Inner Ed25519 source signature (`Frame.source_signature`) over the
  *plaintext* survives per-hop re-encryption and provides end-to-end
  authenticity in addition to the existing per-hop outer signature.

#### Capability discovery
- New `capabilities.py` module with `CapabilityRegistry`: local advertisement,
  remote learning, glob-pattern lookup (`find("llm:*")`), HMAC-protected
  persistence.
- New CLI flag: `--capability llm:llama3` (repeatable).
- Public API: `daemon.advertise_capability(cap)` and
  `daemon.find_capability(pattern)`.
- `_capability_announce_loop` propagates the local capability set to direct
  neighbors every 60 seconds; remote nodes are reachable via mesh routing.

#### Wire format v0.4
- `Frame.VERSION` bumped from 3 to 4.
- New optional fields: `source_signature`, `e2e_payload`.
- Protocol version negotiated in HELLO; v0.3 peers remain interoperable as
  direct-only nodes (mesh forwarding is refused for them with no silent
  degradation).

#### Observability
- `/metrics` endpoint now serves Prometheus exposition format by default.
  JSON format remains available via `?format=json` or
  `--metrics-format=json`.
- New mesh metrics: `ironmesh_routes_known`,
  `ironmesh_messages_relayed_total`, `ironmesh_route_lookup_failures_total`,
  `ironmesh_dedup_cache_size`, `ironmesh_dedup_sources`,
  `ironmesh_capabilities_known`, `ironmesh_circuit_breakers_open`,
  `ironmesh_e2e_decrypt_failures_total`.
- New `--log-format json` flag uses a structured `JsonFormatter` that emits
  one JSON object per log record.
- New audit events: `EVENT_ROUTE_ANNOUNCED`, `EVENT_ROUTE_LEARNED`,
  `EVENT_ROUTE_EXPIRED`, `EVENT_MESSAGE_RELAYED`, `EVENT_TTL_EXPIRED`,
  `EVENT_ROUTE_LOOP`, `EVENT_NO_ROUTE`, `EVENT_DUPLICATE_DROPPED`,
  `EVENT_MESH_PARTITION_SUSPECTED`, `EVENT_CIRCUIT_BREAKER_TRIPPED`,
  `EVENT_CAPABILITY_LEARNED`, `EVENT_E2E_DECRYPT_FAILURE`,
  `EVENT_LOG_ROTATED`.

#### Reliability
- Audit log rotation: when the live log exceeds `audit_log_max_bytes`
  (default 10 MB), the file is rotated to `audit.log.1` (older archives shift
  to `.2`, `.3`, … up to `.5`) and a fresh `EVENT_LOG_ROTATED` entry is
  written whose `previous_tail_hmac` field anchors the chain across the
  rotation boundary.
- `AuditLog.verify_chain_across_archives()` walks every archive plus the live
  log, validating the per-file HMAC chain *and* the rotation anchors.

### Changed
- `BridgeDaemon._dispatch_message` now takes a full `Frame` object so it can
  inspect `destination`, `ttl`, `hops`, `source_signature`, and
  `e2e_payload`. Both call sites (`_handle_binary_frame` and
  `_handle_json_message`) were updated and a new
  `Frame.from_json_message` classmethod synthesizes a Frame from the legacy
  JSON path.
- `BridgeDaemon._send_frame` now passes the source signing key only when
  the daemon is the original source, so relays do not overwrite the inner
  source signature.

### CLI
- `--mesh-routing {off,passive,relay}` (default: `relay`)
- `--max-hops N` (default: 5)
- `--route-announce-interval SECONDS`
- `--route-ttl SECONDS`
- `--routes-path PATH`
- `--capability NAME` (repeatable)
- `--capabilities-path PATH`
- `--metrics-format {prometheus,json}`
- `--log-format {text,json}`

### Migration notes from 0.3.x
- The default routing mode is `relay`. Operators who do not want their node
  to forward traffic for others should run with `--mesh-routing=passive` (or
  `off` to disable the routing subsystem entirely). The trust implications of
  relaying are documented in `docs/MESH.md` and `docs/SECURITY.md`.
- The `/metrics` endpoint default format changed from JSON to Prometheus.
  Existing JSON consumers should append `?format=json` to their scrape URL or
  pass `--metrics-format=json` on the daemon.
- Wire version is now 4. v0.4 daemons happily interoperate with v0.3 peers
  for direct messaging but will not relay through them.

## [0.3.0] — Hardened bilateral release

The first release deployed in production between two nodes.
This entry is reconstructed retroactively for completeness.

### Added
- WebSocket transport with mDNS auto-discovery.
- Per-pair NaCl SecretBox session encryption with X25519 ECDH key agreement
  bound to the long-term Ed25519 identity.
- TOFU peer pinning with HMAC-protected trust store.
- HMAC-chained tamper-evident audit log.
- GUI dashboard at `/` with token-gated WebSocket telemetry feed.
- 18 specific security findings addressed in `tests/test_audit_fixes.py`
  (replay guard, signature canonicalization, GUI auth, SQL parameterization,
  passphrase-from-file, mDNS allowlist, hook circuit breaker, etc.).
- Offline message queue per peer.
- 268 passing tests across 11 modules.
