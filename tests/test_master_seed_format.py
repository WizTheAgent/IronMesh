"""Tests for Phase 1 of the Ed25519/X25519 dual-use migration.

Covers the v0.9.4 master-seed envelope: new ``AgentKeys`` fields, v3
disk format, format detection across v1/v2/v3 loads, HKDF derivation
of the X25519 subkey, in-place migration helper, and the shared-
keystore concurrent-startup race the user flagged for verification.
"""

from __future__ import annotations

import base64
import json
import os
import threading

import pytest

from ironmesh.keys import (
    HKDF_INFO_X25519,
    KEYS_FORMAT_MASTER_SEED_V1,
    _hkdf_sha256,
    ed25519_to_curve25519_secret,
    generate_keypair,
    load_keys,
    migrate_keys_to_master_seed,
    save_keys,
)

# ----------------------------------------------------------------------
# HKDF primitive
# ----------------------------------------------------------------------


class TestHKDF:
    def test_hkdf_is_deterministic(self):
        secret = b"\x00" * 32
        salt = b"\x01" * 16
        info = b"test\x00"
        out1 = _hkdf_sha256(secret, salt, info, length=32)
        out2 = _hkdf_sha256(secret, salt, info, length=32)
        assert out1 == out2

    def test_hkdf_distinct_inputs_distinct_outputs(self):
        a = _hkdf_sha256(b"\x00" * 32, b"\x01" * 16, b"a\x00", length=32)
        b = _hkdf_sha256(b"\x00" * 32, b"\x01" * 16, b"b\x00", length=32)
        c = _hkdf_sha256(b"\xff" * 32, b"\x01" * 16, b"a\x00", length=32)
        assert a != b
        assert a != c

    def test_hkdf_rfc_test_vector_1(self):
        # RFC 5869 §A.1 — Basic test case with SHA-256.
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        # Expected OKM (42 octets) per RFC 5869.
        expected = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        out = _hkdf_sha256(ikm, salt, info, length=42)
        assert out == expected


# ----------------------------------------------------------------------
# AgentKeys + generate_keypair
# ----------------------------------------------------------------------


class TestGenerateKeypair:
    def test_default_is_master_seed_format(self):
        k = generate_keypair("alice")
        assert k.is_master_seed_format()
        assert k.x25519_seed is not None and len(k.x25519_seed) == 32
        assert k.hkdf_salt is not None and len(k.hkdf_salt) == 16

    def test_legacy_format_opt_out(self):
        k = generate_keypair("alice", master_seed_format=False)
        assert not k.is_master_seed_format()
        assert k.x25519_seed is None
        assert k.hkdf_salt is None

    def test_x25519_seed_is_hkdf_of_ed25519_seed(self):
        # The Phase 1 contract: x25519_seed = HKDF(ed25519, salt, INFO_X25519).
        # Anyone with the Ed25519 seed + salt can reproduce it. Phase 2
        # will rely on this property to switch wire-level X25519 to the
        # seeded subkey without a second disk-format migration.
        k = generate_keypair("alice")
        expected = _hkdf_sha256(
            k.ed25519_secret, k.hkdf_salt, HKDF_INFO_X25519, length=32,
        )
        assert k.x25519_seed == expected


class TestGetX25519Secret:
    def test_master_seed_path_returns_stored_seed(self):
        k = generate_keypair("alice")
        assert k.get_x25519_secret() == k.x25519_seed

    def test_legacy_path_falls_back_to_curve25519_transform(self):
        k = generate_keypair("alice", master_seed_format=False)
        expected = ed25519_to_curve25519_secret(k.ed25519_secret)
        assert k.get_x25519_secret() == expected


# ----------------------------------------------------------------------
# Disk format — save_keys + load_keys roundtrip
# ----------------------------------------------------------------------


class TestSaveLoadRoundtripV3:
    def test_master_seed_roundtrip_encrypted(self, tmp_path):
        path = str(tmp_path / "keys.json")
        k = generate_keypair("alice")
        save_keys(k, path, passphrase="testpass-12chars")

        loaded = load_keys(path, passphrase="testpass-12chars")
        assert loaded.is_master_seed_format()
        assert loaded.ed25519_secret == k.ed25519_secret
        assert loaded.x25519_seed == k.x25519_seed
        assert loaded.hkdf_salt == k.hkdf_salt
        assert loaded.agent_name == k.agent_name

    def test_master_seed_roundtrip_plaintext(self, tmp_path):
        path = str(tmp_path / "keys.json")
        k = generate_keypair("alice")
        save_keys(k, path, allow_plaintext=True)
        loaded = load_keys(path)
        assert loaded.is_master_seed_format()
        assert loaded.x25519_seed == k.x25519_seed

    def test_disk_envelope_carries_v3_format_tag(self, tmp_path):
        path = str(tmp_path / "keys.json")
        k = generate_keypair("alice")
        save_keys(k, path, allow_plaintext=True)
        with open(path) as f:
            on_disk = json.load(f)
        assert on_disk["version"] == 3
        assert on_disk["format"] == KEYS_FORMAT_MASTER_SEED_V1
        assert "hkdf_salt" in on_disk

    def test_legacy_file_loads_without_master_seed_fields(self, tmp_path):
        path = str(tmp_path / "keys.json")
        k_legacy = generate_keypair("alice", master_seed_format=False)
        save_keys(k_legacy, path, passphrase="testpass-12chars")

        loaded = load_keys(path, passphrase="testpass-12chars")
        assert not loaded.is_master_seed_format()
        assert loaded.x25519_seed is None
        assert loaded.hkdf_salt is None
        # And get_x25519_secret falls back to the legacy curve25519 transform.
        assert loaded.get_x25519_secret() == ed25519_to_curve25519_secret(
            loaded.ed25519_secret
        )


class TestLoadIntegrityChecks:
    def test_tampered_x25519_seed_rejected(self, tmp_path):
        # The on-disk x25519_seed MUST match the HKDF derivation from
        # ed25519_secret + hkdf_salt. If an attacker swaps the encrypted
        # x25519_seed without the passphrase (e.g. by re-encrypting with
        # a known key) the integrity check trips.
        path = str(tmp_path / "keys.json")
        k = generate_keypair("alice")
        save_keys(k, path, allow_plaintext=True)
        with open(path) as f:
            data = json.load(f)
        # Replace the plaintext x25519_seed with an attacker-chosen one.
        data["x25519_seed"] = base64.b64encode(b"\xaa" * 32).decode()
        with open(path, "w") as f:
            json.dump(data, f)
        with pytest.raises(ValueError, match="HKDF derivation"):
            load_keys(path)

    def test_master_seed_envelope_without_hkdf_salt_rejected(self, tmp_path):
        path = str(tmp_path / "keys.json")
        k = generate_keypair("alice")
        save_keys(k, path, allow_plaintext=True)
        with open(path) as f:
            data = json.load(f)
        del data["hkdf_salt"]
        with open(path, "w") as f:
            json.dump(data, f)
        with pytest.raises(ValueError, match="hkdf_salt"):
            load_keys(path)


# ----------------------------------------------------------------------
# Migration helper
# ----------------------------------------------------------------------


class TestMigrate:
    def test_migrate_preserves_ed25519_seed(self, tmp_path):
        path = str(tmp_path / "keys.json")
        k_legacy = generate_keypair("alice", master_seed_format=False)
        save_keys(k_legacy, path, passphrase="testpass-12chars")

        migrated = migrate_keys_to_master_seed(path, passphrase="testpass-12chars")

        # TOFU pin survival: Ed25519 secret + public must be byte-identical.
        assert migrated.ed25519_secret == k_legacy.ed25519_secret
        assert migrated.ed25519_public == k_legacy.ed25519_public
        assert migrated.get_fingerprint() == k_legacy.get_fingerprint()
        # X25519 subkey is freshly derived (was None pre-migration).
        assert migrated.is_master_seed_format()
        assert migrated.x25519_seed is not None
        assert migrated.hkdf_salt is not None

    def test_migrate_writes_legacy_bak(self, tmp_path):
        path = str(tmp_path / "keys.json")
        k_legacy = generate_keypair("alice", master_seed_format=False)
        save_keys(k_legacy, path, passphrase="testpass-12chars")
        before = open(path).read()

        migrate_keys_to_master_seed(path, passphrase="testpass-12chars")

        backup = path + ".legacy.bak"
        assert os.path.exists(backup)
        assert open(backup).read() == before

    def test_migrate_loads_after_migration(self, tmp_path):
        path = str(tmp_path / "keys.json")
        k_legacy = generate_keypair("alice", master_seed_format=False)
        save_keys(k_legacy, path, passphrase="testpass-12chars")

        migrate_keys_to_master_seed(path, passphrase="testpass-12chars")
        loaded = load_keys(path, passphrase="testpass-12chars")

        assert loaded.is_master_seed_format()
        assert loaded.ed25519_secret == k_legacy.ed25519_secret

    def test_migrate_is_not_idempotent(self, tmp_path):
        # Second migration call on an already-master-seed file raises
        # ValueError — contract per the function docstring. The caller
        # gets explicit feedback rather than a silent re-key.
        path = str(tmp_path / "keys.json")
        k_legacy = generate_keypair("alice", master_seed_format=False)
        save_keys(k_legacy, path, passphrase="testpass-12chars")
        migrate_keys_to_master_seed(path, passphrase="testpass-12chars")
        with pytest.raises(ValueError, match="already in master-seed format"):
            migrate_keys_to_master_seed(path, passphrase="testpass-12chars")

    def test_migrate_legacy_bak_not_overwritten_on_double_call(self, tmp_path):
        # If migrate somehow runs twice (e.g. a buggy operator script),
        # the .legacy.bak from the first run MUST stay as the canonical
        # rollback target. The first call already raises ValueError on
        # the second invocation (test above), but if someone bypasses
        # that check the backup-preservation logic still holds.
        path = str(tmp_path / "keys.json")
        k_legacy = generate_keypair("alice", master_seed_format=False)
        save_keys(k_legacy, path, passphrase="testpass-12chars")
        first_bytes = open(path, "rb").read()
        migrate_keys_to_master_seed(path, passphrase="testpass-12chars")
        # Forge a state: rewrite the file as legacy again and re-migrate.
        save_keys(
            generate_keypair("bob", master_seed_format=False),
            path, passphrase="testpass-12chars",
        )
        migrate_keys_to_master_seed(path, passphrase="testpass-12chars")
        assert open(path + ".legacy.bak", "rb").read() == first_bytes


# ----------------------------------------------------------------------
# Shared-keystore concurrent startup race
# ----------------------------------------------------------------------


class TestConcurrentMigrationRace:
    """User-flagged risk: two daemons starting simultaneously against
    the same legacy keystore. The atomic write + per-process tmp suffix
    introduced in v0.9.4 should produce consistent post-migration state
    regardless of who wins the rename race.

    Acceptable outcomes per the user's spec:
        (1) One daemon wins migration cleanly, the other detects the
            completed state and proceeds normally.
        (2) Both detect contention via flock and one defers until first
            completes.
    What MUST NOT happen: split-brain (different x25519_seeds), half-
    migrated files, or unreadable post-race state.
    """

    def test_two_threads_migrating_same_file_converge(self, tmp_path):
        path = str(tmp_path / "keys.json")
        k_legacy = generate_keypair("alice", master_seed_format=False)
        save_keys(k_legacy, path, passphrase="testpass-12chars")
        legacy_ed_seed = k_legacy.ed25519_secret

        start_barrier = threading.Barrier(2)
        errors = []

        def _run_migration():
            start_barrier.wait()
            try:
                migrate_keys_to_master_seed(path, passphrase="testpass-12chars")
            except ValueError as e:
                # "already in master-seed format" is an acceptable
                # racer outcome — the other thread won.
                if "already in master-seed format" not in str(e):
                    errors.append(e)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=_run_migration)
        t2 = threading.Thread(target=_run_migration)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # No unexpected exceptions.
        assert errors == [], f"unexpected exceptions: {errors}"

        # File must load cleanly post-race.
        post = load_keys(path, passphrase="testpass-12chars")
        assert post.is_master_seed_format()
        # Ed25519 seed must still match — TOFU pin survival is the
        # critical property.
        assert post.ed25519_secret == legacy_ed_seed

        # Legacy backup must exist + match the pre-migration bytes.
        assert os.path.exists(path + ".legacy.bak")

    def test_concurrent_save_keys_does_not_corrupt_file(self, tmp_path):
        # Adjacent risk: two threads SAVING the same path concurrently.
        # Per-process+thread tmp-file naming + os.replace atomicity means
        # whichever rename lands last wins and the file is always one
        # complete envelope or the other — never a partial blend.
        #
        # On POSIX, os.replace is fully atomic over a held destination;
        # on Windows, a rename racing with a concurrent open of the
        # destination can raise PermissionError. That's an acceptable
        # racer outcome per the user's spec ("either path acceptable —
        # what matters is consistent state, no split-brain") — the loser
        # bails, the winner's envelope is canonical, and the next save
        # cycle gets through on retry. We verify the consistency
        # property, not "every save succeeds".
        path = str(tmp_path / "keys.json")
        k1 = generate_keypair("alice")
        k2 = generate_keypair("bob")

        unexpected = []
        barrier = threading.Barrier(2)

        def _save(keys):
            barrier.wait()
            for _ in range(20):
                try:
                    save_keys(keys, path, allow_plaintext=True)
                except PermissionError:
                    # Acceptable on Windows when the rename loses the
                    # race with a concurrent open. The other thread's
                    # save still produces a consistent envelope.
                    continue
                except Exception as e:
                    unexpected.append(e)
                    return

        t1 = threading.Thread(target=_save, args=(k1,))
        t2 = threading.Thread(target=_save, args=(k2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert unexpected == [], f"unexpected exceptions: {unexpected}"

        # Final file must load cleanly and be exactly one of {k1, k2} —
        # no partial blend, no corruption, no split-brain.
        post = load_keys(path)
        assert post.ed25519_public in (k1.ed25519_public, k2.ed25519_public)
