# Security Advisory: at-rest storage key derived without a salt or KDF stretching

> This advisory is published as a GitHub Security Advisory in lockstep with the
> v0.9.5 release and is linked from the v0.9.5 release notes.

- **Severity:** Moderate
- **CVSS v3.1:** `6.2` — `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVE:** requested via the GitHub CNA at publication
- **Weakness:** CWE-759 (use of a one-way hash without a salt) / CWE-916 (use of a password hash with insufficient computational effort)
- **Affected:** IronMesh `v0.7.2-beta` through `v0.9.4.2` (all releases prior to `v0.9.5` that write an encrypted at-rest message store)
- **Fixed in:** `v0.9.5`
- **Reporter:** found during internal security review prior to the v0.9.5 release

## Summary

Before v0.9.5, the key that encrypts the at-rest SQLite message store
(`~/.ironmesh/data.db` — message history and the offline queue) was derived from
the mesh passphrase with a **single, unsalted SHA-256**:

```
storage_key = SHA-256(passphrase + "ironmesh-storage-v1")
```

SHA-256 is fast by design and there is no per-database salt, so an attacker who
obtains a copy of the encrypted database (a stolen disk image, a backup, a
copied VM volume) can mount an **offline dictionary / brute-force attack against
the mesh passphrase at hashing speed**, and can precompute/reuse work across
targets because the derivation is not salted. Recovering the passphrase yields
the storage key and decrypts all at-rest message content; because the same
passphrase also drives the mesh authentication handshake, its recovery has
impact beyond the stored data.

This is an **at-rest** weakness. It does not permit remote code execution or
network compromise on its own, and it requires local access to the database
file, which is written owner-only.

## Impact & preconditions (why the CVSS vector)

- **AV:L** — the attacker needs local access to the encrypted `data.db` (or a
  copy of it). There is no network vector.
- **AC:L** — the offline attack is a straightforward unsalted-hash dictionary
  attack; no special conditions.
- **PR:N** — scored for the **stolen-disk / captured-backup** model: once an
  attacker holds a copy of the bytes (a stolen disk image, a backup, a copied
  VM volume), no privileges on the running system are required to mount the
  offline attack, and that offline-media scenario is exactly where this
  weakness bites. (On a **live host** the database file is created owner-only —
  `keys.restrict_file_to_owner` → mode `0600` on POSIX, an owner-only ACL on
  Windows — so reading it in place requires the daemon user's privileges or
  root; under that narrower `PR:L` model the base score would be 5.5.)
- **UI:N**, **S:U**.
- **C:H** — passphrase recovery decrypts all stored message content (and, since
  the mesh passphrase is shared, undermines mesh auth). **I:N / A:N** — no
  integrity or availability impact from this weakness.

## The fix in v0.9.5 (verified from code)

`v0.9.5` replaces the derivation with a salted, memory-hard KDF plus an HKDF
expansion, implemented in `store.py` (`MessageStore._derive_storage_key`):

1. A per-database 16-byte salt (`nacl.pwhash.argon2id.SALTBYTES`) is generated
   with `os.urandom` on first open and persisted, base64-encoded, in the SQLite
   `_meta` table under key `storage_salt`.
2. Intermediate key material:
   `ikm = argon2id.kdf(32, passphrase, salt, opslimit=OPSLIMIT_MODERATE,
   memlimit=MEMLIMIT_MODERATE)` — the same Argon2id cost parameters that protect
   the identity key file.
3. Storage key:
   `storage_key = HKDF-SHA256(ikm, salt=salt, info=b"ironmesh-storage-key-v2\x00",
   L=32)` (`HKDF_INFO_STORAGE`).
4. Ciphertext written under the new key carries the format prefix
   `b"IMSTOREv2\x00"` (`STORAGE_V2_MAGIC`) followed by an XSalsa20-Poly1305
   `SecretBox` blob, so the reader can distinguish new-format from legacy blobs
   without trial decryption.

Argon2id's memory-hardness and the per-database salt remove the fast,
precomputable offline attack.

## Remediation

**Upgrade to v0.9.5 and start the daemon.** There is **no separate storage-key
rotation command** — migration is automatic and forward-only:

- On the first `MessageStore.open` under v0.9.5, `_derive_storage_key` creates
  and persists the salt and derives the Argon2id+HKDF key, then
  `_upgrade_storage_format` re-encrypts every payload that was written under the
  legacy unsalted key to the new key and stamps the `_meta` marker
  `storage_format = "aead-v2"`.
- A first open under the **wrong** passphrase does **not** stamp completion, so
  legacy rows are not stranded and still migrate on a later correct open
  (regression-tested).
- **Honest caveat (verified by test):** rows written *before at-rest encryption
  was active* — i.e. plaintext-era rows — are left **byte-for-byte untouched**
  (they are served as-is and are not retroactively encrypted). The migration
  re-encrypts data that was under the weak key; it does not encrypt data that
  was never encrypted. Operators who ran early releases with plaintext history
  should treat that history as unprotected regardless of this fix.
- **A pre-upgrade disk image already in an attacker's hands remains attackable
  offline.** Upgrading protects data going forward; it cannot un-capture bytes
  an attacker copied while the weak derivation was in use. If you suspect the
  database was exposed, rotate the mesh passphrase after upgrading.

## Scope

This advisory is scoped **only** to the at-rest storage-key derivation. The
other v0.9.5 security hardening — HELLO signature domain separation, the RNS
link binding, and receive-side end-to-end inner-source-signature verification —
are release-notes items, **not** part of this advisory.

## Timeline

- Weakness present since the initial release (`v0.7.2-beta`, commit `f9b1215`).
- Replaced by Argon2id + HKDF in `v0.9.5` (commit `a0c3143`,
  "fix(store): derive the at-rest storage key with Argon2id + HKDF").
- Advisory published in lockstep with the `v0.9.5` release.
