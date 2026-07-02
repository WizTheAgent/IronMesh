"""Tests for the at-rest storage-key derivation and format migration.

The storage key that encrypts SQLite payloads is derived from the
daemon passphrase via Argon2id (with a per-database persisted salt)
plus an HKDF-SHA256 storage subkey. Databases written by earlier
releases used a fast unsalted SHA-256 of the passphrase; those decrypt
through a legacy fallback and are re-encrypted forward on first open.
"""

import base64

import aiosqlite
import pytest
from nacl.pwhash import argon2id
from nacl.secret import SecretBox

from ironmesh.keys import _hkdf_sha256
from ironmesh.store import (
    HKDF_INFO_STORAGE,
    STORAGE_FORMAT_AEAD_V2,
    STORAGE_V2_MAGIC,
    MessageStore,
    _derive_legacy_storage_key,
)

PASSPHRASE = "storage-kdf-test-passphrase"


async def _raw_payload(db_path: str, msg_id: str) -> bytes:
    """Read a message payload straight from SQLite, bypassing the store."""
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "SELECT payload FROM messages WHERE msg_id = ?", (msg_id,)
        )
        row = await cursor.fetchone()
    assert row is not None
    return bytes(row[0])


async def _meta_value(db_path: str, key: str):
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "SELECT value FROM _meta WHERE key = ?", (key,)
        )
        row = await cursor.fetchone()
    return row[0] if row else None


class TestKdfDerivedKey:
    async def test_new_store_encrypts_under_kdf_derived_key(self, db_path):
        """New databases must use the Argon2id+HKDF key, not the legacy hash."""
        store = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store.open()
        await store.store_message("m1", "alice", "Alice", "bob", "MSG",
                                  b"confidential body", "out")
        await store.close()

        raw = await _raw_payload(db_path, "m1")
        assert raw.startswith(STORAGE_V2_MAGIC)
        assert b"confidential body" not in raw

        # The blob must NOT decrypt under the legacy unsalted-SHA-256 key.
        legacy_box = SecretBox(_derive_legacy_storage_key(PASSPHRASE))
        with pytest.raises(Exception):
            legacy_box.decrypt(raw[len(STORAGE_V2_MAGIC):])

        # It MUST decrypt under an independent recomputation of the
        # documented derivation: Argon2id over the passphrase with the
        # persisted salt, then the HKDF storage subkey.
        salt = base64.b64decode(await _meta_value(db_path, "storage_salt"))
        ikm = argon2id.kdf(
            32, PASSPHRASE.encode(), salt,
            opslimit=argon2id.OPSLIMIT_MODERATE,
            memlimit=argon2id.MEMLIMIT_MODERATE,
        )
        expected_key = _hkdf_sha256(ikm, salt, HKDF_INFO_STORAGE, length=32)
        plaintext = SecretBox(expected_key).decrypt(raw[len(STORAGE_V2_MAGIC):])
        assert plaintext == b"confidential body"

    async def test_salt_persists_across_reopen(self, db_path):
        """The per-database salt must survive restarts so the key is stable."""
        store1 = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store1.open()
        await store1.store_message("m1", "alice", "Alice", "bob", "MSG",
                                   b"survives restart", "out")
        salt_before = await _meta_value(db_path, "storage_salt")
        await store1.close()

        store2 = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store2.open()
        assert await _meta_value(db_path, "storage_salt") == salt_before
        msgs = await store2.get_messages()
        assert msgs[0]["payload"] == b"survives restart"
        await store2.close()


class TestLegacyMigration:
    async def _write_legacy_database(self, db_path: str, payload: bytes):
        """Create a database exactly as pre-v0.9.5 releases wrote it:
        SecretBox ciphertext under the unsalted-SHA-256 key, no format
        prefix, no persisted salt."""
        store = MessageStore(db_path)  # schema only, no encryption
        await store.open()
        await store.close()
        legacy_blob = bytes(
            SecretBox(_derive_legacy_storage_key(PASSPHRASE)).encrypt(payload)
        )
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                """INSERT INTO messages
                   (msg_id, source, source_display, destination, msg_type,
                    payload, timestamp, priority, direction)
                   VALUES ('legacy1', 'alice', 'Alice', 'bob', 'MSG', ?,
                           1.0, 'NORMAL', 'out')""",
                (legacy_blob,),
            )
            await db.commit()

    async def test_legacy_ciphertext_readable(self, db_path):
        """Payloads written under the legacy key must decrypt after upgrade."""
        await self._write_legacy_database(db_path, b"pre-upgrade message")

        store = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store.open()
        msgs = await store.get_messages()
        assert len(msgs) == 1
        assert msgs[0]["payload"] == b"pre-upgrade message"
        await store.close()

    async def test_legacy_rows_reencrypted_on_open(self, db_path):
        """First open re-encrypts legacy blobs under the KDF-derived key."""
        await self._write_legacy_database(db_path, b"pre-upgrade message")

        store = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store.open()
        await store.close()

        raw = await _raw_payload(db_path, "legacy1")
        assert raw.startswith(STORAGE_V2_MAGIC)
        # Legacy key no longer decrypts the stored blob.
        with pytest.raises(Exception):
            SecretBox(_derive_legacy_storage_key(PASSPHRASE)).decrypt(
                raw[len(STORAGE_V2_MAGIC):]
            )
        assert await _meta_value(db_path, "storage_format") == STORAGE_FORMAT_AEAD_V2

        # Round-trip after migration: reopen and read back.
        store2 = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store2.open()
        msgs = await store2.get_messages()
        assert msgs[0]["payload"] == b"pre-upgrade message"
        await store2.close()

    async def test_plaintext_era_rows_left_untouched(self, db_path):
        """Rows written before at-rest encryption existed stay readable
        and are not blindly wrapped in ciphertext they never had."""
        store1 = MessageStore(db_path)
        await store1.open()
        await store1.store_message("old1", "alice", "Alice", "bob", "MSG",
                                   b"plaintext era", "out")
        await store1.close()

        store2 = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store2.open()
        msgs = await store2.get_messages()
        assert msgs[0]["payload"] == b"plaintext era"
        await store2.close()
        raw = await _raw_payload(db_path, "old1")
        assert raw == b"plaintext era"

    async def test_wrong_passphrase_first_open_defers_migration(self, db_path):
        """A first open under the wrong passphrase must not stamp the
        upgrade complete — the legacy rows haven't migrated, and stamping
        would strand them under the fast unsalted-SHA-256 key forever."""
        await self._write_legacy_database(db_path, b"pre-upgrade message")

        wrong = MessageStore(db_path, storage_passphrase="not-the-passphrase")
        await wrong.open()
        await wrong.close()

        # No completion marker, and the legacy blob is byte-untouched.
        assert await _meta_value(db_path, "storage_format") is None
        raw = await _raw_payload(db_path, "legacy1")
        assert not raw.startswith(STORAGE_V2_MAGIC)
        plaintext = SecretBox(_derive_legacy_storage_key(PASSPHRASE)).decrypt(raw)
        assert plaintext == b"pre-upgrade message"

        # A later open with the right passphrase still migrates.
        store = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store.open()
        msgs = await store.get_messages()
        assert msgs[0]["payload"] == b"pre-upgrade message"
        await store.close()
        assert await _meta_value(db_path, "storage_format") == STORAGE_FORMAT_AEAD_V2
        raw = await _raw_payload(db_path, "legacy1")
        assert raw.startswith(STORAGE_V2_MAGIC)

        # Round-trip after migration: reopen and read back.
        store2 = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store2.open()
        msgs = await store2.get_messages()
        assert msgs[0]["payload"] == b"pre-upgrade message"
        await store2.close()

    async def test_plaintext_era_only_store_rescans_without_marker(self, db_path):
        """A store whose only unprefixed rows never decrypt (written
        before at-rest encryption existed) can't be told apart from a
        wrong-passphrase open, so the marker stays unset and the sweep
        re-runs each open — leaving the rows byte-identical each time."""
        store1 = MessageStore(db_path)
        await store1.open()
        await store1.store_message("old1", "alice", "Alice", "bob", "MSG",
                                   b"plaintext era", "out")
        await store1.close()

        for _ in range(2):
            store = MessageStore(db_path, storage_passphrase=PASSPHRASE)
            await store.open()
            msgs = await store.get_messages()
            assert msgs[0]["payload"] == b"plaintext era"
            await store.close()
            assert await _meta_value(db_path, "storage_format") is None
            raw = await _raw_payload(db_path, "old1")
            assert raw == b"plaintext era"

    async def test_fresh_store_sets_marker_immediately(self, db_path):
        """A brand-new database has no unprefixed candidates, so the
        completion marker is recorded on the very first open."""
        store = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store.open()
        await store.close()
        assert await _meta_value(db_path, "storage_format") == STORAGE_FORMAT_AEAD_V2

    async def test_legacy_pending_queue_reencrypted(self, db_path):
        """The offline queue upgrades alongside message history."""
        store = MessageStore(db_path)
        await store.open()
        await store.close()
        legacy_blob = bytes(
            SecretBox(_derive_legacy_storage_key(PASSPHRASE)).encrypt(b"queued legacy")
        )
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                """INSERT INTO pending_messages
                   (peer_node_id, msg_id, source, msg_type, payload,
                    priority, created_at)
                   VALUES ('bob', 'q1', 'alice', 'MSG', ?, 'NORMAL', 1.0)""",
                (legacy_blob,),
            )
            await db.commit()

        store2 = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store2.open()
        pending = await store2.get_pending_for_peer("bob")
        assert len(pending) == 1
        assert pending[0]["payload"] == b"queued legacy"
        await store2.close()


class TestAeadProperty:
    async def test_tampered_ciphertext_does_not_decrypt(self, db_path):
        """Flipping a ciphertext byte must never yield the plaintext —
        the Poly1305 authenticator rejects the modified blob."""
        store = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store.open()
        await store.store_message("m1", "alice", "Alice", "bob", "MSG",
                                  b"integrity protected", "out")
        await store.close()

        raw = await _raw_payload(db_path, "m1")
        tampered = bytearray(raw)
        tampered[-1] ^= 0x01
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "UPDATE messages SET payload = ? WHERE msg_id = 'm1'",
                (bytes(tampered),),
            )
            await db.commit()

        store2 = MessageStore(db_path, storage_passphrase=PASSPHRASE)
        await store2.open()
        msgs = await store2.get_messages()
        assert msgs[0]["payload"] != b"integrity protected"
        assert b"integrity protected" not in msgs[0]["payload"]
        await store2.close()

    async def test_explicit_key_round_trip_and_prefix(self, db_path):
        """Explicit-key stores use the same prefixed AEAD format."""
        key = b"\x42" * 32
        store = MessageStore(db_path, storage_key=key)
        await store.open()
        await store.store_message("m1", "alice", "Alice", "bob", "MSG",
                                  b"explicit key body", "out")
        msgs = await store.get_messages()
        assert msgs[0]["payload"] == b"explicit key body"
        await store.close()
        raw = await _raw_payload(db_path, "m1")
        assert raw.startswith(STORAGE_V2_MAGIC)

    def test_key_and_passphrase_mutually_exclusive(self, db_path):
        with pytest.raises(ValueError):
            MessageStore(db_path, storage_key=b"\x01" * 32,
                         storage_passphrase=PASSPHRASE)
