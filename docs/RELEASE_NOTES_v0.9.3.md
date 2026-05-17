# IronMesh v0.9.3 — Release Notes

## Headline

A security + observability point release on the road to v1.0. Wire
protocol unchanged at `ironmesh/0.8` — every v0.8.x and v0.9.x peer
stays interoperable. No migration required for operators on a stock
deployment; existing trust stores migrate forward silently on the
next save.

## Highlights

### Trust store encrypted at rest

`known_peers.json` is now SecretBox-encrypted with a key derived from
the daemon's identity secret. A host-disk leak no longer exposes the
peer graph (node IDs, fingerprints, capability sets). HMAC-SHA256
over the ciphertext keeps tamper evidence and the existing
multi-daemon collision detection. Pre-v0.9.3 plaintext stores load
through the legacy v1 path and migrate forward automatically on the
next save — no operator action required.

Operators who want the migration to land immediately rather than on
the next routine save can run:

```
ironmesh trust migrate
```

The command is idempotent. A `--dry-run` flag previews the action
without writing.

### `--strict-tls` for outbound WebSocket connections

Default mesh mode keeps the historical `CERT_NONE` +
`check_hostname=False` behavior — TLS provides line-level
confidentiality and peer authentication runs at the application
layer (passphrase HMAC + Ed25519 + TOFU). This preserves
interoperability with self-signed mesh certs.

For deployments where WSS endpoints are issued real certificates
(operator CA, internal Let's Encrypt, public ACME), the new
`--strict-tls` flag opts into transport-layer authentication on top:
hostname check + `CERT_REQUIRED`. Pair with `--pinned-ca <path>` to
use a private CA bundle as the trust anchor; the system trust store
is used otherwise.

When `--strict-tls` is set, the daemon emits a `STRICT_TLS_ENABLED`
audit event at startup and exposes `ironmesh_strict_tls_enabled=1`
on `/metrics` so monitoring can confirm the posture.

### `--max-msgs-per-sec` global daemon-wide cap

A new defense-in-depth lever on top of the existing per-peer caps.
Off by default — per-peer limits remain sufficient when peers are
mutually trusted. Enable when the mesh may be exposed to
potentially-hostile peers:

```
ironmesh run ... --max-msgs-per-sec 100
```

Burst capacity equals `ceil(rate)` so short legitimate spikes don't
trip the limiter. Rejected messages bump
`ironmesh_global_msg_rate_limit_total` and emit a sampled
`GLOBAL_RATE_LIMIT_TRIGGERED` audit event (at most one per ten
seconds, so a flood does not dominate the chain).

### `ironmesh trust verify <node-id> <expected-fp>`

Point-and-shoot fingerprint verification helper. Operators paste the
fingerprint they got out-of-band (phone call, signed message, QR
code) and the CLI returns a concrete `match` / `mismatch` /
`unknown` verdict instead of asking them to eyeball
`ironmesh trust list`. Accepts colon- or whitespace-separated input
and matches a leading prefix of at least 8 hex characters so a
shorter fingerprint read aloud still works. `--json` available for
scripts.

### `ironmesh doctor` v0.9.3 surface

`doctor` grows an eighth check that surfaces the on-disk trust-store
envelope version (1 = legacy plaintext, 2 = encrypted at rest) and
notes that strict-TLS / global-cap state belongs to the running
daemon and is reported via `/metrics` rather than `doctor`.

### Dependency upper bounds

`pyproject.toml` now caps every runtime, optional, and dev dependency
at the next major version. A breaking upstream major bump will
surface as a resolver error rather than silently shipping into
`pip install ironmesh` mid-release. Patch and minor bumps continue
to flow through automatically.

## Operator-visible behavior change

After upgrade, the next routine save of `known_peers.json` rewrites
it as the encrypted v2 envelope. Tools that parse the trust store
directly (third-party scripts that read raw JSON) need to stop doing
that and instead use `ironmesh trust list [--show-caps]`,
`ironmesh trust cap-status <node-id>`, or
`ironmesh trust verify <node-id> <fp>`. Daemons and the bundled CLI
read both envelope versions transparently.

## Threat model + documentation updates

- `SECURITY.md` — TLS section now describes both default and strict
  modes; new "LAN discovery (mDNS) caveats" subsection enumerates
  what mDNS spoofing can and cannot do (it cannot bypass the
  application-layer handshake); new "Threat-model assumption — peer
  set" subsection makes the per-peer-cap assumption explicit.
- `docs/QUICKSTART.md` — trust-management section points operators
  at out-of-band fingerprint verification before exchanging
  sensitive traffic with a new peer.
- `docs/migration/v0_9_3_trust_store_encryption.md` — a one-page
  migration guide covering rollback, downgrade, and verification.

## Upgrade

```
pip install --upgrade ironmesh
# or
docker pull wiztheagent/ironmesh:0.9.3
```

Rolling upgrade across a mesh is safe — no protocol changes. Restart
peers one at a time. Each peer's first save after upgrade rewrites
its trust store as v2; verify with:

```
ironmesh doctor
# look for: "Trust-store envelope: v2 (encrypted at rest)"
```

## Testing

- Unit + integration suites green on the touched surfaces (trust,
  TLS, global rate cap, metrics, audit events).
- Live-mesh validation against a 3-node test mesh: trust-store
  migration v1 → v2, strict-TLS handshake against a CA-issued cert,
  global-cap rejection visible in `/metrics`.

## Thanks

To everyone running IronMesh in production and surfacing the
operational rough edges that motivate these hardening releases.
