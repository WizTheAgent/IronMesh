"""IronMesh async SQLite message store with migrations.

Single source of truth for message persistence, offline queue, and peer metadata.
Replaces the old database.py (sync) and MessageStore embedded in bridge.py.
"""

import asyncio
import base64
import hashlib
import logging
import os
import time
from typing import List, Optional

import aiosqlite

logger = logging.getLogger("ironmesh.store")

SCHEMA_VERSION = 3

# ---------------------------------------------------------------------------
# At-rest storage-key derivation (v0.9.5)
# ---------------------------------------------------------------------------
# Payload ciphertext written by the current format carries this magic
# prefix so the reader can dispatch between the current key and the
# legacy key without trial decryption. A legacy SecretBox blob starts
# with a 24-byte random nonce, so an accidental prefix collision is
# negligible (2^-80).
STORAGE_V2_MAGIC = b"IMSTOREv2\x00"

# HKDF-SHA256 info label for the storage subkey. NUL-terminated to
# avoid any future label being a prefix of another label (mirrors the
# HKDF_INFO_* convention in keys.py).
HKDF_INFO_STORAGE = b"ironmesh-storage-key-v2\x00"

# The pre-v0.9.5 storage key was a single unsalted SHA-256 of the
# daemon passphrase plus this constant. Kept only so existing
# databases can be read and re-encrypted forward; never used for new
# ciphertext.
_LEGACY_KEY_SUFFIX = "ironmesh-storage-v1"

# _meta keys for the persisted per-database KDF salt and the
# storage-format upgrade marker.
_META_STORAGE_SALT = "storage_salt"
_META_STORAGE_FORMAT = "storage_format"
STORAGE_FORMAT_AEAD_V2 = "aead-v2"


def _derive_legacy_storage_key(passphrase: str) -> bytes:
    """The pre-v0.9.5 storage key: unsalted SHA-256 of the passphrase.

    Fast to compute by design of SHA-256, which is exactly why it was
    replaced — a leaked disk image allowed an offline dictionary attack
    on the passphrase. Retained solely for reading (and migrating)
    databases written by earlier releases.
    """
    return hashlib.sha256((passphrase + _LEGACY_KEY_SUFFIX).encode()).digest()


# v0.7.2 Wiz hardening: bound the offline queue so a perpetually-offline
# peer can't consume unbounded disk. When at cap, the oldest LOW/NORMAL
# message is evicted to make room. CRITICAL/HIGH priority messages always
# get admitted (evicting NORMAL/LOW first if needed).
DEFAULT_MAX_PENDING_PER_PEER = 1000


class MessageStore:
    """Async SQLite-backed persistent store for messages, offline queue, and peer metadata."""

    def __init__(self, db_path: str = "~/.ironmesh/data.db",
                 storage_key: Optional[bytes] = None,
                 max_pending_per_peer: int = DEFAULT_MAX_PENDING_PER_PEER,
                 storage_passphrase: Optional[str] = None):
        """
        Args:
            db_path: Path to SQLite database file.
            storage_key: Optional explicit 32-byte key for encrypting payloads
                at rest. Mutually exclusive with ``storage_passphrase``.
            max_pending_per_peer: Cap on undelivered messages per peer. 0 disables
                the cap (legacy behavior). Over cap, the oldest LOW/NORMAL is
                evicted; CRITICAL/HIGH always admitted, evicting lower priority
                first.
            storage_passphrase: Passphrase from which the at-rest storage key
                is derived during ``open()``: Argon2id (moderate limits,
                matching the identity-key envelope in keys.py) over the
                passphrase with a per-database random salt persisted in the
                ``_meta`` table, then an HKDF-SHA256 expand with a
                domain-separated info label. Databases written by earlier
                releases with the legacy unsalted-SHA-256 key are read via a
                legacy fallback and re-encrypted forward on first open.
        """
        if storage_key is not None and storage_passphrase is not None:
            raise ValueError(
                "storage_key and storage_passphrase are mutually exclusive"
            )
        self.db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._db: Optional[aiosqlite.Connection] = None
        self._storage_key: Optional[bytes] = storage_key
        self._storage_passphrase: Optional[str] = storage_passphrase
        # Key used only to READ (and migrate forward) payloads written by
        # earlier releases. In explicit-key mode the caller's key doubles
        # as the legacy key: pre-upgrade databases written by explicit-key
        # callers used the same key without the format prefix.
        self._legacy_storage_key: Optional[bytes] = storage_key
        self._max_pending_per_peer = max_pending_per_peer
        # Observability: evictions + refused admits, keyed by reason.
        self.pending_dropped = 0  # offline queue: total dropped (never queued)
        self.pending_evicted = 0  # offline queue: displaced by higher-priority admit
        # v0.8.5.2: separate counters for the pending-trust queue (v0.8.5 gate).
        # Conflating them with the offline-queue counters above hides which queue
        # is under pressure — operators need different responses (promote vs.
        # peer-online).
        self.pending_trust_evicted = 0  # trust gate: cap eviction (oldest dropped)
        self.pending_trust_dropped = 0  # trust gate: blocked-peer MSGs dropped at gate
        # Serialize open() against concurrent callers so migrations
        # don't race.
        self._open_lock = asyncio.Lock()
        self._opened = False

    async def open(self):
        """Open the database and run migrations. Idempotent."""
        async with self._open_lock:
            if self._opened:
                return
            self._db = await aiosqlite.connect(self.db_path)
            await self._db.execute("PRAGMA journal_mode=WAL")
            await self._db.execute("PRAGMA foreign_keys=ON")
            await self._migrate()
            if self._storage_passphrase is not None:
                await self._derive_storage_key()
            if self._storage_key is not None:
                await self._upgrade_storage_format()
            self._opened = True
            logger.info("Database opened: %s (schema v%d)", self.db_path, SCHEMA_VERSION)

    async def close(self):
        if self._db:
            await self._db.close()
            self._db = None

    # ------------------------------------------------------------------
    # Migrations
    # ------------------------------------------------------------------

    async def _migrate(self):
        """Run schema migrations to bring DB up to current version."""
        # Create meta table if it doesn't exist
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS _meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        await self._db.commit()

        current = await self._get_schema_version()

        if current < 1:
            await self._migrate_v1()
        if current < 2:
            await self._migrate_v2()
        if current < 3:
            await self._migrate_v3()

        await self._set_schema_version(SCHEMA_VERSION)

    async def _get_schema_version(self) -> int:
        cursor = await self._db.execute(
            "SELECT value FROM _meta WHERE key = 'schema_version'"
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def _set_schema_version(self, version: int):
        await self._db.execute(
            "INSERT OR REPLACE INTO _meta (key, value) VALUES ('schema_version', ?)",
            (str(version),),
        )
        await self._db.commit()

    async def _migrate_v1(self):
        """V1: Core tables for messages, pending queue, peers."""
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                msg_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                source_display TEXT,
                destination TEXT NOT NULL,
                msg_type TEXT NOT NULL,
                payload BLOB,
                timestamp REAL NOT NULL,
                priority TEXT DEFAULT 'NORMAL',
                direction TEXT NOT NULL,
                status TEXT DEFAULT 'delivered',
                retries INTEGER DEFAULT 0
            )
        """)
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)
        """)
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_source ON messages(source)
        """)
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_destination ON messages(destination)
        """)

        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS pending_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_node_id TEXT NOT NULL,
                msg_id TEXT NOT NULL,
                source TEXT NOT NULL,
                msg_type TEXT NOT NULL,
                payload BLOB,
                priority TEXT DEFAULT 'NORMAL',
                created_at REAL NOT NULL,
                delivered INTEGER DEFAULT 0,
                delivered_at REAL,
                retries INTEGER DEFAULT 0,
                UNIQUE(peer_node_id, msg_id)
            )
        """)
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_pending_peer ON pending_messages(peer_node_id, delivered)
        """)

        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS peers (
                node_id TEXT PRIMARY KEY,
                identity_public_b64 TEXT,
                fingerprint TEXT,
                first_seen REAL,
                last_seen REAL,
                last_address TEXT
            )
        """)
        await self._db.commit()

    async def _migrate_v2(self):
        """V2: Add trust/TOFU columns to peers table."""
        try:
            await self._db.execute(
                "ALTER TABLE peers ADD COLUMN trusted INTEGER DEFAULT 0"
            )
        except Exception:
            pass  # Column may already exist
        try:
            await self._db.execute(
                "ALTER TABLE peers ADD COLUMN trust_first_seen REAL"
            )
        except Exception:
            pass
        await self._db.commit()

    async def _migrate_v3(self):
        """V3: Pending-trust message queue (v0.8.5).

        Holds inbound MSG/REQ/RESP frames from peers that haven't been
        promoted to "trusted" yet. Operator promotes via the GUI / MCP
        and the queue drains in arrival order.
        """
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS pending_trust_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_node_id TEXT NOT NULL,
                msg_id TEXT NOT NULL,
                msg_type TEXT NOT NULL,
                payload BLOB,
                priority TEXT DEFAULT 'NORMAL',
                queued_at REAL NOT NULL,
                UNIQUE(source_node_id, msg_id)
            )
        """)
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_pending_trust_source
            ON pending_trust_messages(source_node_id, queued_at)
        """)
        await self._db.commit()

    # ------------------------------------------------------------------
    # v0.8.5: pending-trust message queue
    # ------------------------------------------------------------------

    async def queue_pending_trust(self, source_node_id: str, msg_id: str,
                                   msg_type: str, payload: bytes,
                                   priority: str = "NORMAL",
                                   cap: int = 100) -> bool:
        """Queue a MSG from a peer awaiting trust promotion.

        Enforces a per-peer cap with FIFO eviction (oldest evicted on
        overflow). Returns True if the new message is now in the queue.
        Increments ``pending_dropped`` on eviction (counter is shared
        with the offline-queue, named for observability).
        """
        if cap and cap > 0:
            cursor = await self._db.execute(
                "SELECT COUNT(*) FROM pending_trust_messages WHERE source_node_id = ?",
                (source_node_id,),
            )
            row = await cursor.fetchone()
            current = int(row[0]) if row else 0
            if current >= cap:
                # Evict the oldest (FIFO).
                await self._db.execute(
                    """DELETE FROM pending_trust_messages
                       WHERE id = (
                         SELECT id FROM pending_trust_messages
                         WHERE source_node_id = ?
                         ORDER BY queued_at ASC, id ASC LIMIT 1
                       )""",
                    (source_node_id,),
                )
                self.pending_trust_evicted += 1
                logger.warning(
                    "Pending-trust queue for %s at cap (%d); evicted oldest to admit %s",
                    source_node_id, cap, msg_id,
                )
        encrypted = self._encrypt_payload(payload)
        try:
            await self._db.execute(
                """INSERT INTO pending_trust_messages
                   (source_node_id, msg_id, msg_type, payload, priority, queued_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (source_node_id, msg_id, msg_type, encrypted, priority, time.time()),
            )
            await self._db.commit()
        except aiosqlite.IntegrityError:
            # Duplicate (source, msg_id) — same wire MSG arrived twice. Idempotent no-op.
            return False
        return True

    async def drain_pending_trust(self, source_node_id: str) -> List[dict]:
        """Return + remove all queued pending-trust messages for a peer,
        in arrival order. Caller is responsible for re-publishing to the
        bus + storing in history."""
        cursor = await self._db.execute(
            """SELECT id, msg_id, msg_type, payload, priority, queued_at
               FROM pending_trust_messages
               WHERE source_node_id = ?
               ORDER BY queued_at ASC, id ASC""",
            (source_node_id,),
        )
        rows = await cursor.fetchall()
        out = []
        for row in rows:
            raw = row[3] if isinstance(row[3], (bytes, bytearray)) else (row[3].encode() if row[3] else b"")
            out.append({
                "id": row[0],
                "msg_id": row[1],
                "msg_type": row[2],
                "payload": self._decrypt_payload(raw),
                "priority": row[4],
                "queued_at": row[5],
            })
        if out:
            await self._db.execute(
                "DELETE FROM pending_trust_messages WHERE source_node_id = ?",
                (source_node_id,),
            )
            await self._db.commit()
        return out

    async def discard_pending_trust(self, source_node_id: str) -> int:
        """Drop all queued pending-trust messages for a peer (used on block).
        Returns the number discarded."""
        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM pending_trust_messages WHERE source_node_id = ?",
            (source_node_id,),
        )
        n = int((await cursor.fetchone())[0])
        if n:
            await self._db.execute(
                "DELETE FROM pending_trust_messages WHERE source_node_id = ?",
                (source_node_id,),
            )
            await self._db.commit()
        return n

    async def list_pending_trust_summary(self) -> List[dict]:
        """One row per peer with at least one queued pending-trust msg,
        with the count and the oldest queued_at."""
        cursor = await self._db.execute(
            """SELECT source_node_id, COUNT(*), MIN(queued_at), MAX(queued_at)
               FROM pending_trust_messages
               GROUP BY source_node_id
               ORDER BY MIN(queued_at) ASC"""
        )
        rows = await cursor.fetchall()
        return [
            {
                "source_node_id": r[0],
                "queued_count": int(r[1]),
                "oldest_queued_at": r[2],
                "newest_queued_at": r[3],
            }
            for r in rows
        ]

    async def pending_trust_count_for(self, source_node_id: str) -> int:
        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM pending_trust_messages WHERE source_node_id = ?",
            (source_node_id,),
        )
        return int((await cursor.fetchone())[0])

    # ------------------------------------------------------------------
    # Payload encryption at rest (#8)
    # ------------------------------------------------------------------

    async def _derive_storage_key(self):
        """Derive the at-rest storage key from the store passphrase.

        Argon2id (moderate opslimit/memlimit — the same cost parameters
        that protect the identity-key envelope in keys.py) over the
        passphrase with a per-database 16-byte random salt, followed by
        an HKDF-SHA256 expand under a domain-separated info label that
        binds the subkey to its storage role. The salt is generated on
        first open and persisted in the ``_meta`` table (it is not
        secret), so the derivation is stable across restarts and travels
        with the database file.

        The slow KDF is the point: a leaked disk image no longer allows
        a fast offline dictionary attack on the passphrase, matching the
        at-rest strength of the identity key file. The Argon2id pass runs
        in a thread executor so daemon startup doesn't block the event
        loop for its duration.
        """
        from nacl.pwhash import argon2id

        from ironmesh.keys import _hkdf_sha256

        cursor = await self._db.execute(
            "SELECT value FROM _meta WHERE key = ?", (_META_STORAGE_SALT,)
        )
        row = await cursor.fetchone()
        if row:
            salt = base64.b64decode(row[0])
            if len(salt) != argon2id.SALTBYTES:
                raise ValueError(
                    f"Persisted storage salt has wrong length: {len(salt)}"
                )
        else:
            salt = os.urandom(argon2id.SALTBYTES)
            await self._db.execute(
                "INSERT INTO _meta (key, value) VALUES (?, ?)",
                (_META_STORAGE_SALT, base64.b64encode(salt).decode()),
            )
            await self._db.commit()

        passphrase = self._storage_passphrase
        loop = asyncio.get_running_loop()
        ikm = await loop.run_in_executor(
            None,
            lambda: argon2id.kdf(
                32,
                passphrase.encode(),
                salt,
                opslimit=argon2id.OPSLIMIT_MODERATE,
                memlimit=argon2id.MEMLIMIT_MODERATE,
            ),
        )
        self._storage_key = _hkdf_sha256(
            ikm, salt, HKDF_INFO_STORAGE, length=32,
        )
        self._legacy_storage_key = _derive_legacy_storage_key(passphrase)

    async def _upgrade_storage_format(self):
        """One-shot re-encryption of legacy-key payloads to the current key.

        Databases written before v0.9.5 hold SecretBox blobs under the
        fast unsalted-SHA-256 key (or, for explicit-key callers, blobs
        without the format prefix). On the first open with a storage key
        active, every payload that decrypts under the legacy key is
        re-encrypted under the current key and stamped with the format
        prefix. Payloads that don't decrypt (rows written before at-rest
        encryption existed, or under a different credential) are left
        byte-for-byte untouched — they stay exactly as readable as they
        were before the upgrade.

        A ``_meta`` marker records completion so subsequent opens skip
        the table scan. The marker is only written when the sweep
        actually migrated something, or when there were no unprefixed
        candidate rows at all. If unprefixed rows remain and none of
        them decrypted — which is what a first open under the wrong
        passphrase looks like — the marker is withheld so a later open
        with the right passphrase still migrates them off the legacy
        key. The trade-off: a database whose unprefixed rows are all
        plaintext-era (they decrypt under no key) re-runs the sweep on
        every open. That is a single bounded SELECT per payload table,
        accepted so the migration guarantee holds over skipping a scan.
        """
        cursor = await self._db.execute(
            "SELECT value FROM _meta WHERE key = ?", (_META_STORAGE_FORMAT,)
        )
        row = await cursor.fetchone()
        if row and row[0] == STORAGE_FORMAT_AEAD_V2:
            return

        from nacl.secret import SecretBox
        legacy_box = SecretBox(self._legacy_storage_key)
        migrated = 0
        skipped = 0
        # Static table list — every table with an encrypted payload column.
        for table in ("messages", "pending_messages", "pending_trust_messages"):
            cursor = await self._db.execute(
                f"SELECT rowid, payload FROM {table} WHERE payload IS NOT NULL"
            )
            rows = await cursor.fetchall()
            for rowid, payload in rows:
                if isinstance(payload, str):
                    payload = payload.encode()
                if not payload or payload.startswith(STORAGE_V2_MAGIC):
                    continue
                try:
                    plaintext = bytes(legacy_box.decrypt(bytes(payload)))
                except Exception:
                    # Not legacy ciphertext under this credential —
                    # leave untouched (still served as-is on read).
                    skipped += 1
                    continue
                await self._db.execute(
                    f"UPDATE {table} SET payload = ? WHERE rowid = ?",
                    (self._encrypt_payload(plaintext), rowid),
                )
                migrated += 1
        if migrated > 0 or skipped == 0:
            # Sweep did real work, or there were no unprefixed
            # candidates at all: safe to record completion.
            await self._db.execute(
                "INSERT OR REPLACE INTO _meta (key, value) VALUES (?, ?)",
                (_META_STORAGE_FORMAT, STORAGE_FORMAT_AEAD_V2),
            )
            if migrated or skipped:
                logger.info(
                    "Storage-format upgrade: %d payload(s) re-encrypted "
                    "under the KDF-derived key, %d left untouched (not "
                    "legacy ciphertext)", migrated, skipped,
                )
        else:
            # Unprefixed rows exist and NONE decrypted. Either the
            # passphrase is wrong (legacy rows must still migrate on a
            # later open with the right one) or the rows are
            # plaintext-era. We can't tell the difference, so leave the
            # marker unset and re-scan next open rather than strand
            # legacy ciphertext under the fast SHA-256 key forever.
            logger.info(
                "Storage-format upgrade deferred: %d unprefixed payload(s) "
                "did not decrypt under the legacy key; will re-check on "
                "next open", skipped,
            )
        await self._db.commit()

    def _encrypt_payload(self, payload: bytes) -> bytes:
        """Encrypt payload before INSERT if a storage key is set.

        Output is the format-prefix magic followed by a SecretBox blob
        (XSalsa20-Poly1305, random 24-byte nonce). No plaintext
        fallback. Encryption failure is a hard error — silent downgrade
        to plaintext would be a security regression.
        """
        if not self._storage_key or not payload:
            return payload
        from nacl.secret import SecretBox
        box = SecretBox(self._storage_key)
        return STORAGE_V2_MAGIC + bytes(box.encrypt(payload))

    def _decrypt_payload(self, payload) -> bytes:
        """Decrypt payload after SELECT if a storage key is set.

        Dispatches on the format prefix: prefixed blobs decrypt under
        the current KDF-derived key; unprefixed blobs are tried against
        the legacy key (databases written by earlier releases). When
        neither applies, the raw bytes are returned as-is — that
        preserves rows written before at-rest encryption existed, and
        ensures a tampered or wrong-key ciphertext never yields
        plaintext (the Poly1305 authenticator rejects it).
        """
        if not self._storage_key or not payload:
            return payload if isinstance(payload, bytes) else (payload.encode() if payload else b"")
        if isinstance(payload, str):
            payload = payload.encode()
        from nacl.secret import SecretBox
        if payload.startswith(STORAGE_V2_MAGIC):
            try:
                box = SecretBox(self._storage_key)
                return bytes(box.decrypt(payload[len(STORAGE_V2_MAGIC):]))
            except Exception:
                logger.debug("Payload failed AEAD verification under the "
                             "current storage key; returning ciphertext")
                return payload
        if self._legacy_storage_key:
            try:
                box = SecretBox(self._legacy_storage_key)
                return bytes(box.decrypt(payload))
            except Exception:
                pass
        # Rows written before at-rest encryption existed.
        return payload

    # ------------------------------------------------------------------
    # Message history
    # ------------------------------------------------------------------

    async def store_message(self, msg_id: str, source: str, source_display: str,
                           destination: str, msg_type: str, payload: bytes,
                           direction: str = "inbound", priority: str = "NORMAL",
                           source_signature: Optional[bytes] = None):
        """Store a message in history. Payload is encrypted at rest if storage_key is set.

        Audit L-09: ``source_signature`` is accepted for forward-compat.
        Schema v3 (future) will persist it as a separate column; for
        now we log at debug level when one is supplied.
        """
        if source_signature is not None:
            logger.debug("store_message: source_signature supplied (%d bytes) "
                         "for msg_id=%s — not yet persisted", len(source_signature), msg_id)
        encrypted_payload = self._encrypt_payload(payload)
        await self._db.execute(
            """INSERT OR REPLACE INTO messages
               (msg_id, source, source_display, destination, msg_type, payload,
                timestamp, priority, direction)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (msg_id, source, source_display, destination, msg_type, encrypted_payload,
             time.time(), priority, direction),
        )
        await self._db.commit()

    async def get_messages(self, peer_id: Optional[str] = None,
                          since: Optional[float] = None,
                          limit: int = 100) -> List[dict]:
        """Get messages, optionally filtered by peer and/or timestamp.

        #18: Uses conditions list + params list — no string formatting with user data.
        """
        # Build query from safe static fragments + parameterized values
        base = "SELECT * FROM messages"
        conditions: List[str] = []
        params: list = []

        if peer_id:
            conditions.append("(source = ? OR destination = ?)")
            params.extend([peer_id, peer_id])
        if since:
            conditions.append("timestamp > ?")
            params.append(since)

        if conditions:
            base += " WHERE " + " AND ".join(conditions)
        base += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor = await self._db.execute(base, params)
        rows = await cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        results = []
        for row in rows:
            d = dict(zip(columns, row))
            if "payload" in d and d["payload"] is not None:
                d["payload"] = self._decrypt_payload(d["payload"])
            results.append(d)
        return results

    # ------------------------------------------------------------------
    # Offline message queue
    # ------------------------------------------------------------------

    _PRIORITY_RANK = {"CRITICAL": 0, "HIGH": 1, "NORMAL": 2, "LOW": 3}

    async def queue_for_peer(self, peer_node_id: str, msg_id: str, source: str,
                            msg_type: str, payload: bytes,
                            priority: str = "NORMAL") -> bool:
        """Queue a message for an offline peer.

        Returns:
            True if the message was admitted to the queue.
            False if the queue was at capacity and this message was dropped
            (either because it's lower priority than everything already queued,
            or because capacity could not be freed).

        Side-effects (v0.7.2 bounds enforcement):
            - Counts undelivered messages for this peer.
            - If over cap, attempts to evict the oldest message with LOWER
              priority rank than the incoming one. Equal-priority tie-break:
              oldest existing is evicted (FIFO at the same priority).
            - Increments ``self.pending_evicted`` on successful displacement,
              ``self.pending_dropped`` when admission is refused.
        """
        # Capacity check — done before encrypting to avoid wasted work on drop.
        admitted = True
        if self._max_pending_per_peer and self._max_pending_per_peer > 0:
            cursor = await self._db.execute(
                "SELECT COUNT(*) FROM pending_messages "
                "WHERE peer_node_id = ? AND delivered = 0",
                (peer_node_id,),
            )
            row = await cursor.fetchone()
            current = int(row[0]) if row else 0
            if current >= self._max_pending_per_peer:
                admitted = await self._evict_to_make_room(peer_node_id, priority)
                if not admitted:
                    self.pending_dropped += 1
                    logger.warning(
                        "Offline queue for %s at cap (%d); dropping %s "
                        "priority=%s (all existing are >= priority)",
                        peer_node_id, self._max_pending_per_peer,
                        msg_id, priority,
                    )
                    return False

        encrypted_payload = self._encrypt_payload(payload)
        await self._db.execute(
            """INSERT OR REPLACE INTO pending_messages
               (peer_node_id, msg_id, source, msg_type, payload, priority, created_at, retries)
               VALUES (?, ?, ?, ?, ?, ?, ?, 0)""",
            (peer_node_id, msg_id, source, msg_type, encrypted_payload, priority, time.time()),
        )
        await self._db.commit()
        logger.info("Message %s queued for offline peer %s", msg_id, peer_node_id)
        return True

    async def _evict_to_make_room(self, peer_node_id: str,
                                   incoming_priority: str) -> bool:
        """Displace the oldest lower-or-equal-priority message.

        Returns True if room was made (something was evicted).
        Returns False if every existing message has strictly higher priority
        than the incoming one — in that case the caller must drop.
        """
        incoming_rank = self._PRIORITY_RANK.get(incoming_priority, 2)
        cursor = await self._db.execute(
            """SELECT msg_id, priority FROM pending_messages
               WHERE peer_node_id = ? AND delivered = 0
               ORDER BY
                 CASE priority
                   WHEN 'CRITICAL' THEN 0
                   WHEN 'HIGH' THEN 1
                   WHEN 'NORMAL' THEN 2
                   WHEN 'LOW' THEN 3
                 END DESC,
                 created_at ASC
               LIMIT 1""",
            (peer_node_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return False
        victim_id, victim_priority = row[0], row[1]
        victim_rank = self._PRIORITY_RANK.get(victim_priority, 2)
        # Evict only if the victim's priority is equal or lower than incoming.
        # (Lower priority = higher rank number in our mapping.)
        if victim_rank < incoming_rank:
            # Everything queued is higher priority; do not displace.
            return False
        await self._db.execute(
            "DELETE FROM pending_messages WHERE peer_node_id = ? AND msg_id = ?",
            (peer_node_id, victim_id),
        )
        self.pending_evicted += 1
        logger.info(
            "Evicted %s (priority=%s) from %s's queue to admit new %s-priority msg",
            victim_id, victim_priority, peer_node_id, incoming_priority,
        )
        return True

    async def get_pending_for_peer(self, peer_node_id: str) -> List[dict]:
        """Get all undelivered pending messages for a peer."""
        cursor = await self._db.execute(
            """SELECT msg_id, source, msg_type, payload, priority, created_at, retries
               FROM pending_messages
               WHERE peer_node_id = ? AND delivered = 0
               ORDER BY
                 CASE priority
                   WHEN 'CRITICAL' THEN 0
                   WHEN 'HIGH' THEN 1
                   WHEN 'NORMAL' THEN 2
                   WHEN 'LOW' THEN 3
                 END,
                 created_at ASC""",
            (peer_node_id,),
        )
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            raw_payload = row[3] if isinstance(row[3], bytes) else (row[3].encode() if row[3] else b"")
            results.append({
                "msg_id": row[0],
                "source": row[1],
                "msg_type": row[2],
                "payload": self._decrypt_payload(raw_payload),
                "priority": row[4],
                "created_at": row[5],
                "retries": row[6],
            })
        return results

    async def mark_delivered(self, peer_node_id: str, msg_id: str):
        """Mark a queued message as delivered."""
        await self._db.execute(
            """UPDATE pending_messages SET delivered = 1, delivered_at = ?
               WHERE peer_node_id = ? AND msg_id = ?""",
            (time.time(), peer_node_id, msg_id),
        )
        await self._db.commit()

    async def cleanup_old_pending(self, max_age: float = 86400.0) -> int:
        """Remove pending messages older than max_age seconds."""
        cutoff = time.time() - max_age
        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM pending_messages WHERE created_at < ? AND delivered = 0",
            (cutoff,),
        )
        count = (await cursor.fetchone())[0]
        await self._db.execute(
            "DELETE FROM pending_messages WHERE created_at < ? AND delivered = 0",
            (cutoff,),
        )
        # Also clean up delivered messages older than max_age
        await self._db.execute(
            "DELETE FROM pending_messages WHERE delivered = 1 AND delivered_at < ?",
            (cutoff,),
        )
        await self._db.commit()
        if count:
            logger.info("Cleaned up %d expired pending messages", count)
        return count

    async def prune_old(self, days: int = 30) -> int:
        """Remove messages older than N days from history."""
        cutoff = time.time() - (days * 86400)
        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM messages WHERE timestamp < ?", (cutoff,)
        )
        count = (await cursor.fetchone())[0]
        await self._db.execute("DELETE FROM messages WHERE timestamp < ?", (cutoff,))
        await self._db.commit()
        if count:
            logger.info("Pruned %d old messages (>%d days)", count, days)
        return count

    # ------------------------------------------------------------------
    # Peer metadata
    # ------------------------------------------------------------------

    async def upsert_peer(self, node_id: str, identity_public_b64: Optional[str] = None,
                         address: Optional[str] = None, fingerprint: Optional[str] = None):
        """Update or insert a peer record."""
        await self._db.execute(
            """INSERT INTO peers (node_id, identity_public_b64, fingerprint, first_seen, last_seen, last_address)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(node_id) DO UPDATE SET
                 identity_public_b64 = COALESCE(?, identity_public_b64),
                 fingerprint = COALESCE(?, fingerprint),
                 last_seen = ?,
                 last_address = COALESCE(?, last_address)""",
            (node_id, identity_public_b64, fingerprint, time.time(), time.time(), address,
             identity_public_b64, fingerprint, time.time(), address),
        )
        await self._db.commit()

    async def get_peer(self, node_id: str) -> Optional[dict]:
        """Get a peer record by node_id."""
        cursor = await self._db.execute(
            "SELECT * FROM peers WHERE node_id = ?", (node_id,)
        )
        row = await cursor.fetchone()
        if row:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))
        return None

    async def get_all_peers(self) -> List[dict]:
        """Get all known peers."""
        cursor = await self._db.execute("SELECT * FROM peers ORDER BY last_seen DESC")
        rows = await cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]

    async def get_peer_count(self) -> int:
        cursor = await self._db.execute("SELECT COUNT(*) FROM peers")
        return (await cursor.fetchone())[0]
