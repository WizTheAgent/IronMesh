"""IronMesh async SQLite message store with migrations.

Single source of truth for message persistence, offline queue, and peer metadata.
Replaces the old database.py (sync) and MessageStore embedded in bridge.py.
"""

import asyncio
import logging
import os
import time
from typing import List, Optional

import aiosqlite

logger = logging.getLogger("ironmesh.store")

SCHEMA_VERSION = 2

# v0.7.2 Wiz hardening: bound the offline queue so a perpetually-offline
# peer can't consume unbounded disk. When at cap, the oldest LOW/NORMAL
# message is evicted to make room. CRITICAL/HIGH priority messages always
# get admitted (evicting NORMAL/LOW first if needed).
DEFAULT_MAX_PENDING_PER_PEER = 1000


class MessageStore:
    """Async SQLite-backed persistent store for messages, offline queue, and peer metadata."""

    def __init__(self, db_path: str = "~/.ironmesh/data.db",
                 storage_key: Optional[bytes] = None,
                 max_pending_per_peer: int = DEFAULT_MAX_PENDING_PER_PEER):
        """
        Args:
            db_path: Path to SQLite database file.
            storage_key: Optional 32-byte key for encrypting payloads at rest (#8).
                         Derive from passphrase via SHA-256(passphrase + salt).
            max_pending_per_peer: Cap on undelivered messages per peer. 0 disables
                the cap (legacy behavior). Over cap, the oldest LOW/NORMAL is
                evicted; CRITICAL/HIGH always admitted, evicting lower priority
                first.
        """
        self.db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._db: Optional[aiosqlite.Connection] = None
        self._storage_key: Optional[bytes] = storage_key
        self._max_pending_per_peer = max_pending_per_peer
        # Observability: evictions + refused admits, keyed by reason.
        self.pending_dropped = 0  # total dropped (never queued)
        self.pending_evicted = 0  # displaced by higher-priority admit
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

    # ------------------------------------------------------------------
    # Payload encryption at rest (#8)
    # ------------------------------------------------------------------

    def _encrypt_payload(self, payload: bytes) -> bytes:
        """Encrypt payload before INSERT if storage_key is set.

        No plaintext fallback. Encryption failure is a hard error —
        silent downgrade to plaintext would be a security regression.
        """
        if not self._storage_key or not payload:
            return payload
        from nacl.secret import SecretBox
        box = SecretBox(self._storage_key)
        return bytes(box.encrypt(payload))

    def _decrypt_payload(self, payload) -> bytes:
        """Decrypt payload after SELECT if storage_key is set."""
        if not self._storage_key or not payload:
            return payload if isinstance(payload, bytes) else (payload.encode() if payload else b"")
        if isinstance(payload, str):
            payload = payload.encode()
        try:
            from nacl.secret import SecretBox
            box = SecretBox(self._storage_key)
            return bytes(box.decrypt(payload))
        except Exception:
            # Migration: if decrypt fails, return as-is (existing plaintext data)
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
