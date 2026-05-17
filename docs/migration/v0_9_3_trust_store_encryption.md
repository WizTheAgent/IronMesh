# Migrating to v0.9.3 — trust-store at-rest encryption

## TL;DR

`known_peers.json` is now SecretBox-encrypted with a key derived from
the daemon's identity secret. **Existing operators do nothing.** The
first time the daemon saves the trust store after upgrade, it
rewrites the file in the new v2 envelope format. Reads accept both
formats.

## What changes on disk

Pre-v0.9.3:

```json
{
  "peers": { "<node-id>": { "pubkey": ..., "fingerprint": ..., ... } },
  "revoked": { ... },
  "_mac": "<HMAC-SHA256>"
}
```

v0.9.3+:

```json
{
  "version": 2,
  "ciphertext": "<base64 SecretBox(nonce || encrypted-peers-and-revoked)>",
  "_mac": "<HMAC-SHA256 over 'v=2|c=<ciphertext>'>"
}
```

The inner JSON inside the SecretBox payload has the same shape as
the old plaintext file: `{"peers": ..., "revoked": ...}`.

## What you need to do

For a stock `~/.ironmesh/known_peers.json`: nothing. The first save
after upgrade rewrites the file. You can verify with:

```bash
ironmesh doctor
# look for: "Trust-store envelope: v2 (encrypted at rest)"
```

For deployments that script against the trust file directly: switch
to the CLI surface, which reads either envelope version
transparently.

```bash
ironmesh trust list
ironmesh trust list --show-caps
ironmesh trust cap-status <node-id>
ironmesh trust verify <node-id> <expected-fp>
```

## Force the migration immediately

If you don't want to wait for the next routine save, run:

```bash
ironmesh trust migrate
```

The command is idempotent — safe to re-run, no-ops when the file is
already v2. A `--dry-run` flag previews the action.

## Rollback to v0.9.2

A v0.9.3 daemon can still read v1 envelopes. A v0.9.2 daemon
**cannot** read v2 envelopes — it will fail integrity check and
read-only-latch the file.

If you must roll back:

1. Stop the v0.9.3 daemon.
2. Restore the pre-upgrade `known_peers.json` from your backup
   (`ironmesh backup` taken before upgrade, or filesystem snapshot).
3. Start the v0.9.2 daemon.

If you don't have a backup, peers will need to re-TOFU on the
v0.9.2 side. Use `ironmesh trust verify` on the v0.9.3 daemon
beforehand to record fingerprints out-of-band so you can re-pin them
manually after the rollback.

## Verifying the migration ran

```bash
# 1. Check the on-disk envelope version.
ironmesh doctor | grep "Trust-store envelope"
# Expected: Trust-store envelope: v2 (encrypted at rest)

# 2. Confirm the file is not human-readable.
head -c 200 ~/.ironmesh/known_peers.json
# Expected: a JSON envelope with "version": 2 and a "ciphertext" field.
# If you can read peer pubkeys, fingerprints, or node-ids in the file,
# the migration did not run — check the daemon log for "_save() did
# not persist" lines.

# 3. Confirm the daemon can still open it.
ironmesh trust list
# Expected: lists pinned peers as before.
```

## Multi-daemon hosts

The integrity-MAC + read-only-latch behavior from earlier releases
still applies. Two daemons on one host that share a trust-store path
but use different identity keys will trigger the read-only latch on
whichever daemon loses the race, just like before. The fix remains
giving each daemon its own `--trust-path`.

## Audit-log evidence

When the migration runs explicitly via `ironmesh trust migrate`, an
audit event of type `TRUST_STORE_ENCRYPTED` is appended to the
audit log. The auto-migration on the first daemon save does not
emit a dedicated audit event (it logs at INFO level — "migrating to
encrypted v2 envelope on next save").
