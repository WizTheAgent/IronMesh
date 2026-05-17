# Migration to the v0.9.4 master-seed key format

**Applies to:** operators upgrading from any v0.9.x release to v0.9.4 or
later. v0.9.4 introduces a master-seed envelope (v3) for
`~/.ironmesh/keys.json` that adds an HKDF-derived X25519 subkey and a
binding signature alongside the existing Ed25519 identity seed.

## What changes on disk

Before (legacy v1/v2 envelope):

```json
{
  "version": 2,
  "agent_name": "...",
  "ed25519_public": "<base64>",
  "encrypted": true,
  "salt": "<base64>",
  "ed25519_secret_encrypted": "<base64>"
}
```

After (v0.9.4 master-seed v3 envelope):

```json
{
  "version": 3,
  "format": "master-seed-v1",
  "agent_name": "...",
  "ed25519_public": "<base64>",
  "encrypted": true,
  "salt": "<base64>",
  "ed25519_secret_encrypted": "<base64>",
  "x25519_seed_encrypted": "<base64>",
  "hkdf_salt": "<base64>",
  "x25519_public": "<base64>",
  "x25519_binding_signature": "<base64>"
}
```

The Ed25519 seed itself is unchanged — every existing TOFU pin remains
valid because your node fingerprint (derived from `ed25519_public`)
does not change.

## What changes on the wire

v0.9.4 HELLO frames optionally advertise the X25519 public + an
Ed25519-signed binding under the `SIG_CTX_X25519_BINDING` context.
Pre-v0.9.4 receivers ignore the new fields. v0.9.4 receivers verify
the binding under the peer's pinned Ed25519 identity and, when valid,
use the advertised X25519 directly for E2E SealedBox sealing. When
either the field or the binding is absent or invalid, the receiver
falls back to the historical `ed25519_to_curve25519(identity_public)`
derivation. Mixed v0.9.3 ↔ v0.9.4 meshes interoperate cleanly.

## How the migration runs

### Auto-migration on first start

When a v0.9.4 daemon loads a legacy v1/v2 keystore for the first time
it:

1. Generates a fresh 16-byte random `hkdf_salt`.
2. Derives `x25519_seed = HKDF-SHA256(ed25519_secret, hkdf_salt,
   info=b"ironmesh-identity-x25519-v1\x00", length=32)`.
3. Derives `x25519_public = scalar_base_mult(x25519_seed)`.
4. Signs `x25519_public` under the Ed25519 identity with the
   `SIG_CTX_X25519_BINDING` context label.
5. Writes the v3 envelope atomically.
6. Preserves the pre-migration file as `<keys.json>.legacy.bak`.

You'll see a one-time `WARNING` in the daemon log:

```
v0.9.4 Phase 2 auto-migration: legacy keys rewritten to master-seed
envelope (~/.ironmesh/keys.json). Legacy backup at
~/.ironmesh/keys.json.legacy.bak. Ed25519 identity unchanged — every
TOFU pin remains valid.
```

If auto-migration fails for any reason (disk full, permissions
issue, transient filesystem error) the daemon still starts on the
legacy keys without the new HELLO advertisement, and logs a second
`WARNING` explaining why. Operator action: fix the underlying
condition, then run the manual migration command below.

### Manual migration

If you prefer explicit control, run:

```bash
ironmesh keys migrate --path ~/.ironmesh/keys.json
```

Sample output:

```
Migrated to master-seed format -> ~/.ironmesh/keys.json
Legacy backup preserved at:      ~/.ironmesh/keys.json.legacy.bak
Fingerprint:                     b324ff19...
Ed25519 identity unchanged — every TOFU pin remains valid.
```

The command is idempotent in the sense that re-running it on a
file already in v3 format raises a clear error rather than re-
generating the X25519 subkey. To re-migrate (rare — e.g. recovering
from a tampered file) restore the `.legacy.bak` first.

## What survives migration

- **Ed25519 secret + public.** Byte-identical before and after.
- **Node fingerprint.** SHA-256 of the Ed25519 public — unchanged.
- **All TOFU pins** that peers have recorded for this node.
- **Passphrase + Argon2id parameters.** The envelope is re-encrypted
  with the same passphrase you used previously.

## What's new on disk

- 32-byte `x25519_seed` (encrypted with the same passphrase).
- 16-byte `hkdf_salt` (cleartext — non-secret).
- 32-byte `x25519_public` (cleartext — non-secret).
- 64-byte `x25519_binding_signature` (cleartext — non-secret).

## Rollback

If you need to revert to a pre-v0.9.4 daemon:

```bash
# Stop the v0.9.4 daemon.
systemctl stop ironmesh         # or your equivalent

# Restore the pre-migration file.
cp ~/.ironmesh/keys.json.legacy.bak ~/.ironmesh/keys.json

# Install the prior release.
pip install ironmesh==0.9.3

# Start the daemon. It will read the v1/v2 envelope as before.
systemctl start ironmesh
```

The `.legacy.bak` is retained for **one full release cycle** (through
v0.9.5). After that an upgrade cycle removes the file. If you intend
to stay on v0.9.4+ permanently, the backup can be deleted at any
time.

## Integrity guarantees

- The on-disk `x25519_seed` is verified at load time against
  `HKDF-SHA256(ed25519_secret, hkdf_salt, INFO_X25519)`. A tampered
  subkey is rejected with `ValueError("master-seed x25519_seed does
  not match HKDF derivation from ed25519_secret + hkdf_salt")` even
  when the operator's passphrase decrypts the envelope cleanly.
- The on-disk `x25519_binding_signature` is verified at load time
  against the daemon's own Ed25519 identity. A tampered binding is
  rejected with `ValueError("x25519_binding_signature failed to
  verify")`.

## Concurrent-daemon-startup safety

Two daemons starting against the same keystore file concurrently
converge to a single consistent envelope: per-process+thread tmp
filenames plus atomic `os.replace` ensure no partial blend or split-
brain. Whichever rename lands last wins; the other gets a clean
read-back on the next load.

See `tests/test_master_seed_format.py::TestConcurrentMigrationRace`
for the empirical verification.
