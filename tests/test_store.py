"""Tests for ironmesh.store — async SQLite message store."""

import pytest
import pytest_asyncio

from ironmesh.store import MessageStore


@pytest_asyncio.fixture
async def store(db_path):
    s = MessageStore(db_path)
    await s.open()
    yield s
    await s.close()


@pytest.mark.asyncio
class TestMessageStore:
    async def test_store_and_retrieve_message(self, store):
        await store.store_message(
            msg_id="m1", source="alice", source_display="Alice",
            destination="bob", msg_type="MSG", payload=b"hello",
            direction="outbound",
        )
        messages = await store.get_messages()
        assert len(messages) == 1
        assert messages[0]["msg_id"] == "m1"
        assert messages[0]["source"] == "alice"

    async def test_get_messages_filtered_by_peer(self, store):
        await store.store_message("m1", "alice", "Alice", "bob", "MSG", b"1", "outbound")
        await store.store_message("m2", "charlie", "Charlie", "bob", "MSG", b"2", "inbound")
        messages = await store.get_messages(peer_id="alice")
        assert len(messages) == 1
        assert messages[0]["source"] == "alice"

    async def test_get_messages_since_timestamp(self, store):
        import time
        t1 = time.time()
        await store.store_message("m1", "a", "A", "b", "MSG", b"old", "in")
        t2 = time.time()
        await store.store_message("m2", "a", "A", "b", "MSG", b"new", "in")
        messages = await store.get_messages(since=t2 - 0.001)
        assert len(messages) >= 1

    async def test_queue_and_retrieve_pending(self, store):
        await store.queue_for_peer("bob", "q1", "alice", "MSG", b"queued", "NORMAL")
        pending = await store.get_pending_for_peer("bob")
        assert len(pending) == 1
        assert pending[0]["msg_id"] == "q1"

    async def test_mark_delivered(self, store):
        await store.queue_for_peer("bob", "q1", "alice", "MSG", b"msg", "NORMAL")
        await store.mark_delivered("bob", "q1")
        pending = await store.get_pending_for_peer("bob")
        assert len(pending) == 0

    async def test_pending_priority_ordering(self, store):
        await store.queue_for_peer("bob", "q1", "alice", "MSG", b"low", "LOW")
        await store.queue_for_peer("bob", "q2", "alice", "MSG", b"crit", "CRITICAL")
        await store.queue_for_peer("bob", "q3", "alice", "MSG", b"high", "HIGH")
        pending = await store.get_pending_for_peer("bob")
        assert pending[0]["priority"] == "CRITICAL"
        assert pending[1]["priority"] == "HIGH"
        assert pending[2]["priority"] == "LOW"

    # v0.7.2 bounds: backpressure on offline queue

    async def test_queue_admits_up_to_cap(self, db_path):
        s = MessageStore(db_path, max_pending_per_peer=3)
        await s.open()
        try:
            for i in range(3):
                ok = await s.queue_for_peer("bob", f"q{i}", "alice", "MSG", b"x", "NORMAL")
                assert ok is True
            assert s.pending_dropped == 0
        finally:
            await s.close()

    async def test_queue_evicts_oldest_same_priority(self, db_path):
        """At cap, incoming NORMAL displaces the oldest NORMAL (FIFO tie-break)."""
        s = MessageStore(db_path, max_pending_per_peer=2)
        await s.open()
        try:
            await s.queue_for_peer("bob", "q1", "alice", "MSG", b"1", "NORMAL")
            await s.queue_for_peer("bob", "q2", "alice", "MSG", b"2", "NORMAL")
            # Cap hit — next NORMAL should evict q1 (oldest) and admit q3
            admitted = await s.queue_for_peer("bob", "q3", "alice", "MSG", b"3", "NORMAL")
            assert admitted is True
            assert s.pending_evicted == 1

            pending = await s.get_pending_for_peer("bob")
            msg_ids = {p["msg_id"] for p in pending}
            assert msg_ids == {"q2", "q3"}
        finally:
            await s.close()

    async def test_critical_displaces_lower(self, db_path):
        """CRITICAL incoming evicts lowest-priority existing."""
        s = MessageStore(db_path, max_pending_per_peer=2)
        await s.open()
        try:
            await s.queue_for_peer("bob", "q1", "alice", "MSG", b"n", "NORMAL")
            await s.queue_for_peer("bob", "q2", "alice", "MSG", b"h", "HIGH")
            # At cap. CRITICAL comes in — evict q1 (the LOW/NORMAL victim)
            admitted = await s.queue_for_peer("bob", "q3", "alice", "MSG", b"c", "CRITICAL")
            assert admitted is True
            pending = await s.get_pending_for_peer("bob")
            msg_ids = {p["msg_id"] for p in pending}
            assert msg_ids == {"q2", "q3"}

            # The HIGH one still there
            priorities = {p["priority"] for p in pending}
            assert priorities == {"HIGH", "CRITICAL"}
        finally:
            await s.close()

    async def test_dropped_when_all_higher_priority(self, db_path):
        """Incoming NORMAL is refused when queue is full of CRITICAL."""
        s = MessageStore(db_path, max_pending_per_peer=2)
        await s.open()
        try:
            await s.queue_for_peer("bob", "q1", "alice", "MSG", b"c1", "CRITICAL")
            await s.queue_for_peer("bob", "q2", "alice", "MSG", b"c2", "CRITICAL")
            admitted = await s.queue_for_peer("bob", "q3", "alice", "MSG", b"low", "LOW")
            assert admitted is False
            assert s.pending_dropped == 1

            pending = await s.get_pending_for_peer("bob")
            assert len(pending) == 2
            # Only the original two CRITICALs remain
            msg_ids = {p["msg_id"] for p in pending}
            assert msg_ids == {"q1", "q2"}
        finally:
            await s.close()

    async def test_cap_is_per_peer_not_global(self, db_path):
        """Other peers' queues are not affected by one peer hitting cap."""
        s = MessageStore(db_path, max_pending_per_peer=2)
        await s.open()
        try:
            await s.queue_for_peer("bob", "b1", "alice", "MSG", b"x", "NORMAL")
            await s.queue_for_peer("bob", "b2", "alice", "MSG", b"x", "NORMAL")
            # Carol has her own cap
            ok = await s.queue_for_peer("carol", "c1", "alice", "MSG", b"x", "NORMAL")
            assert ok is True
            assert s.pending_dropped == 0
        finally:
            await s.close()

    async def test_cap_of_zero_disables_limit(self, db_path):
        """max_pending_per_peer=0 means unlimited — legacy behavior."""
        s = MessageStore(db_path, max_pending_per_peer=0)
        await s.open()
        try:
            for i in range(50):
                ok = await s.queue_for_peer("bob", f"q{i}", "alice", "MSG", b"x", "NORMAL")
                assert ok is True
            pending = await s.get_pending_for_peer("bob")
            assert len(pending) == 50
        finally:
            await s.close()

    async def test_cleanup_old_pending(self, store):
        import time
        await store.queue_for_peer("bob", "q1", "alice", "MSG", b"old", "NORMAL")
        # Manually set created_at to old time
        await store._db.execute(
            "UPDATE pending_messages SET created_at = ?",
            (time.time() - 100000,),
        )
        await store._db.commit()
        count = await store.cleanup_old_pending(max_age=1.0)
        assert count == 1

    async def test_prune_old_messages(self, store):
        import time
        await store.store_message("m1", "a", "A", "b", "MSG", b"old", "in")
        await store._db.execute(
            "UPDATE messages SET timestamp = ?",
            (time.time() - 100 * 86400,),
        )
        await store._db.commit()
        count = await store.prune_old(days=30)
        assert count == 1

    async def test_upsert_and_get_peer(self, store):
        await store.upsert_peer("node1", identity_public_b64="AAAA", address="1.2.3.4:8765")
        peer = await store.get_peer("node1")
        assert peer is not None
        assert peer["identity_public_b64"] == "AAAA"

    async def test_get_peer_count(self, store):
        await store.upsert_peer("node1")
        await store.upsert_peer("node2")
        count = await store.get_peer_count()
        assert count == 2

    async def test_get_all_peers(self, store):
        await store.upsert_peer("node1")
        await store.upsert_peer("node2")
        peers = await store.get_all_peers()
        assert len(peers) == 2

    async def test_migration_idempotent(self, db_path):
        """Opening DB twice should not fail (migrations are idempotent)."""
        s1 = MessageStore(db_path)
        await s1.open()
        await s1.close()
        s2 = MessageStore(db_path)
        await s2.open()
        await s2.close()
