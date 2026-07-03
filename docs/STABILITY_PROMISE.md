# IronMesh Stability Promise — v1.0

This document defines what IronMesh commits to keeping stable from
v1.0 forward. It is the contract between the project and its
integrators: if it's listed here, you can build on it and expect it
to still work on the next minor release.

The headline rule: **no breaking change without a minimum of one
minor release of deprecation warnings and a documented migration
path.**

## 1. Scope: what this promise covers

### Wire protocol

| Surface | Stability | Notes |
|---|---|---|
| `ironmesh/0.8` wire format | **Stable** | Additive fields only; existing field semantics frozen |
| Announce app_data schema (`n`, `v`, `i`, `c`, `f`) | **Stable** | New keys may be added; existing keys will not be renamed or removed |
| Feature flag vocabulary (`mesh`, `resource`, `lxmf`, `hskip`, `group`) | **Stable** | New flags may be added; existing flags are permanent |
| Handshake stage 1/2 message shapes | **Stable** | Including the `hskip` channel-binding sentinel |
| Stage 1 skip channel-binding sentinel | **Stable** | Value is fixed; see `PROTOCOL_SPEC.md §2` |
| Message type numeric codes | **Stable** | New codes may be assigned; existing codes permanent |
| Mesh route announce payload | **Stable** | Additive fields only |
| Trust-binding wire format (v0.9) | **Stable** | |

### Python API

| Surface | Stability | Notes |
|---|---|---|
| `ironmesh.Agent` public methods | **Stable** | `send_to`, `send_to_name`, `send_to_capability`, `unified_peers`, `on_message`, etc. |
| `ironmesh.BridgeDaemon.__init__` kwargs | **Stable** | New kwargs may be added; existing kwargs keep their names, types, and default values |
| `ironmesh.protocol.Frame` / `MessageType` | **Stable** | |
| `ironmesh.protocol.Handshake.skip_channel_binding()` | **Stable** | |
| `ironmesh.capabilities.CapabilityRegistry` public API | **Stable** | |
| `ironmesh.federation.FederationGateway` / `FederationPolicy` | **Stable** | Per-source policy matchers are additive |
| `ironmesh.mesh.MeshRouter` / `RoutingTable` / `DedupCache` public methods | **Stable** | |
| Private `_underscore_prefixed` methods and attributes | **NOT stable** | Internal; may change without notice |

### CLI flags

| Surface | Stability | Notes |
|---|---|---|
| Top-level command names (`ironmesh`, `ironmesh trust`, `ironmesh keys`, etc.) | **Stable** | |
| `--passphrase`, `--passphrase-file`, `--keys-path`, `--port`, `--bind`, `--log-level` | **Stable** | |
| `--mesh-routing`, `--max-hops`, `--route-announce-interval`, `--route-ttl` | **Stable** | |
| `--reticulum`, `--rns-*` family | **Stable** | Including `--rns-skip-handshake` and `--rns-group-broadcast` added in v0.9.2 |
| `--lxmf`, `--lxmf-*` family | **Stable** | |
| `--strict-tls`, `--pinned-ca`, `--max-msgs-per-sec` | **Stable** | Added in v0.9.3. Default behaviors of all three are off / preserve historical posture. |
| `capability_announce_max_age` (config field) | **Stable** | Added in v0.9.4 with signed capability advertisements. Default 300 s. Bounds the replay window for stolen origin signatures on CAPABILITY_ANNOUNCE. |
| `CAPABILITY_ANNOUNCE_BAD_SIG` audit event name | **Stable** | Added in v0.9.4 with signed capability advertisements. Reasons field carries `missing-sig`, `unknown-origin`, `stale`, or `bad-sig`. |
| `capability_announce_bad_signature_total` Prometheus metric | **Stable** | Added in v0.9.4 with signed capability advertisements. |
| `SIG_CTX_*` Ed25519 domain-separation context labels (`crypto`) | **Stable** | Added in v0.9.4. Labels are wire-stable; the loader rejects label changes via the NUL terminator + exact-bytes match. v0.9.4 adds `SIG_CTX_X25519_BINDING`. |
| HELLO `x25519_public_b64` field | **Stable** | Added in v0.9.4 (Phase 2). Field name formally reserved by `PROTOCOL_SPEC.md` §2.2. Future versions MUST NOT repurpose. Sits outside the signed HELLO canonical body — adding it does not affect HELLO signature verification. |
| HELLO `x25519_binding_signature_b64` field | **Stable** | Added in v0.9.4 (Phase 2). Field name formally reserved. Carries an Ed25519 detached signature of the X25519 public under `SIG_CTX_X25519_BINDING`. |
| Environment variables documented in `CONFIGURATION.md` | **Stable** | |

### Config file

| Surface | Stability | Notes |
|---|---|---|
| `~/.ironmesh/config.json` schema (`IronMeshConfig` dataclass) | **Stable** | New fields additive with safe defaults |
| `~/.ironmesh/keys.json` format | **Stable** | Versions 1, 2, and 3 all readable. v3 (`format: "master-seed-v1"`, added v0.9.4) carries an additional HKDF-derived X25519 subkey; legacy v1/v2 keep working unchanged. The loader continues to accept all prior versions. `ironmesh keys migrate` converts v1/v2 to v3 in place + preserves `.legacy.bak`. |
| `~/.ironmesh/known_peers.json` envelope versions | **Stable** | v1 (legacy plaintext) and v2 (encrypted v0.9.3+) both readable. New envelope versions roll forward additively; the loader continues to accept all prior versions. |
| `~/.ironmesh/routes.json` format | **Stable** | |
| `~/.ironmesh/data.db` SQLite schema | **Stable** | Migrations ship in release notes when schema evolves |
| Audit log line format | **Stable** | Append-only chained HMAC record; format frozen |

### Observability

| Surface | Stability | Notes |
|---|---|---|
| Prometheus metric names | **Stable** | Canonical catalog: `docs/METRICS_REFERENCE.md`. New counters may be added in a minor; existing names are never renamed without a deprecation cycle. |
| Prometheus metric label keys | **Stable** | Label *values* may grow over time |
| JSON metric shape from `--metrics-format json` | **Stable** | Field names mirror Prometheus counter stems (e.g., `handshake_skips_offered`); same add/never-rename rule applies |
| OpenTelemetry span names for public Agent surfaces | **Stable** | |
| `/im/info`, `/im/cap/list`, `/im/cap/find` RNS RPC paths | **Stable** | |
| Audit event type names | **Stable** | New event types may be added; existing event-type strings (e.g. `TOFU_NEW_PEER`, `STRICT_TLS_ENABLED`, `GLOBAL_RATE_LIMIT_TRIGGERED`, `TRUST_STORE_ENCRYPTED`) will not be renamed without a deprecation cycle so external tooling can alert on them safely. |

## 2. Scope: what this promise does NOT cover

* **Internal module layout.** Non-`__all__` symbols, private modules, implementation helpers. If it's not listed in §1, assume it can change.
* **Upstream dependencies.** RNS, LXMF, websockets — we follow their semver. Pin the versions you care about.
* **Log messages and warning text.** Human-facing, subject to rewording.
* **Performance characteristics.** Best-effort; not contractual. If a release regresses a documented benchmark, that is a bug to fix, but the numbers themselves are not frozen.
* **Internal documentation and PR process.** `CONTRIBUTING.md`, the release checklist, and internal audit docs may change at any time.

## 3. Deprecation procedure

When a stable surface must change, we commit to the following:

1. **Warning window.** At least one minor release ships the new behavior alongside the old, with a `DeprecationWarning` on the old path. The warning message names the replacement.
2. **Migration guide.** A dedicated doc under `docs/migration/` explains the change and the mechanical rewrite path.
3. **Release-notes call-out.** Every deprecation is called out in `RELEASE_NOTES_v*.md` under a `### Deprecated` heading.
4. **Removal in the next major.** The old path is removed in the next major release (e.g., deprecated in v1.4 → removed in v2.0). Never removed in a minor release.

## 4. Security backports

Security fixes are backported to the **previous minor** of v1.x for at least 6 months after the minor was superseded. A 1.0 security fix lands on:

* the current minor (e.g. 1.3 if that's current)
* the previous minor (e.g. 1.2)

Older minors get a best-effort backport at the maintainers' discretion.

CVEs are advised via a GitHub Security Advisory on the repo, an entry in `SECURITY.md`, and an explicit section in the release notes.

## 5. Wire-protocol version bumps

The wire protocol itself only bumps when the on-wire bytes change incompatibly. New features ride feature flags in the announce (`f:` list) without bumping the wire version — the version advertised by an old peer tells the new peer what fallback path to take.

| Version | Introduced | Promises |
|---|---|---|
| `ironmesh/0.3` | v0.3 | Baseline WS + mDNS + SecretBox |
| `ironmesh/0.4` | v0.4 | Multi-hop routing + SealedBox + capability discovery |
| `ironmesh/0.6` | v0.6 | Hardening pass: length caps, nonce windows |
| `ironmesh/0.7` | v0.7 | Rekey, QoS, LoRa payload negotiation |
| `ironmesh/0.8` | v0.9.2 | Feature flags, handshake skip, group broadcast, capability routing |
| `ironmesh/0.9` | unreleased (main) | Domain-separated HELLO signature (`SIG_CTX_HELLO`) + RNS link binding; legacy fallback for pre-0.9 peers |

Peers negotiate the highest version both sides advertise. A v0.8 peer talking to a v0.3 peer downgrades cleanly; unknown feature flags are ignored.

## 6. What changes in v1.0

Nothing on the wire, nothing in the Python API, nothing in the CLI. v1.0 is the commitment to §1 — not a new feature drop. Every v0.9.2 feature ships as-is with the label now attached.

## 7. Enforcement

CI runs the conformance vector suite (`tests/test_conformance_vectors.py`) on every commit. The golden vectors in `tests/conformance/vectors/` are the machine-readable version of this document: if a change breaks one, it must also update this doc and the deprecation window starts.

## 8. Reporting stability issues

If a release appears to break a surface listed in §1, file an issue titled `stability regression: <surface>` with:

* the release that introduced the break
* the old behavior (with a snippet)
* the new behavior (with the error or observed divergence)

Stability regressions are treated as bugs, not features, and are backported under §4.
