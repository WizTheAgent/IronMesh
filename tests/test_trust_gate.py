"""Tests for the v0.8.5 pending-trust message gate.

Covers:
  - TrustStore trust_state state machine (backwards-compatible defaults)
  - MessageStore pending_trust_messages queue (cap, FIFO eviction, drain)
  - SQLite schema v2 -> v3 migration
  - MCP tool dispatch + arg validation
  - End-to-end gate behavior via _gate_inbound_msg + promote/block helpers
"""

import asyncio
import json
import os
import sqlite3
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import pytest_asyncio

from ironmesh.store import MessageStore
from ironmesh.trust import TrustStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def trust_path(tmp_path):
    return str(tmp_path / "known_peers.json")


@pytest.fixture
def agent_key():
    return b"\x42" * 32  # 32 bytes is enough for HMAC


@pytest.fixture
def trust_store(agent_key, trust_path):
    return TrustStore(agent_key=agent_key, path=trust_path)


@pytest_asyncio.fixture
async def gate_store(tmp_path):
    s = MessageStore(str(tmp_path / "data.db"))
    await s.open()
    yield s
    await s.close()


# ---------------------------------------------------------------------------
# TrustStore — trust_state state machine
# ---------------------------------------------------------------------------

class TestTrustStateMachine:
    def test_unknown_peer_reads_as_pending(self, trust_store):
        assert trust_store.get_trust_state("nope") == "pending"

    def test_pin_peer_defaults_to_trusted(self, trust_store):
        trust_store.pin_peer("alice", "AAAA" * 16)
        assert trust_store.get_trust_state("alice") == "trusted"

    def test_pin_peer_can_pin_as_pending(self, trust_store):
        trust_store.pin_peer("bob", "BBBB" * 16, trust_state="pending")
        assert trust_store.get_trust_state("bob") == "pending"

    def test_pin_peer_rejects_invalid_state(self, trust_store):
        with pytest.raises(ValueError):
            trust_store.pin_peer("eve", "EEEE" * 16, trust_state="elevated")

    def test_set_trust_state_promotes(self, trust_store):
        trust_store.pin_peer("carol", "CCCC" * 16, trust_state="pending")
        assert trust_store.set_trust_state("carol", "trusted") is True
        assert trust_store.get_trust_state("carol") == "trusted"

    def test_set_trust_state_unknown_peer_returns_false(self, trust_store):
        assert trust_store.set_trust_state("ghost", "trusted") is False

    def test_set_trust_state_rejects_invalid_state(self, trust_store):
        trust_store.pin_peer("dan", "DDDD" * 16)
        with pytest.raises(ValueError):
            trust_store.set_trust_state("dan", "elevated")

    def test_revoked_peer_reads_as_blocked(self, trust_store):
        trust_store.pin_peer("evil", "EE11" * 16)
        trust_store.mark_revoked("evil", "self", time.time(), "spam")
        assert trust_store.get_trust_state("evil") == "blocked"

    def test_list_by_trust_state_filters(self, trust_store):
        trust_store.pin_peer("a", "1111" * 16, trust_state="trusted")
        trust_store.pin_peer("b", "2222" * 16, trust_state="pending")
        trust_store.pin_peer("c", "3333" * 16, trust_state="pending")
        pending = trust_store.list_by_trust_state("pending")
        assert {p["node_id"] for p in pending} == {"b", "c"}

    def test_pre_v085_pin_reads_as_trusted(self, agent_key, trust_path):
        """Backwards compat: a pin written without trust_state field
        defaults to 'trusted' so existing operators see no change on upgrade."""
        # Hand-craft a pre-v0.8.5 trust file (no trust_state field, but proper MAC).
        ts = TrustStore(agent_key=agent_key, path=trust_path)
        ts._peers["legacy"] = {
            "pubkey": "LEGACY-KEY-B64",
            "fingerprint": "abcd",
            "first_seen": 1.0,
            "last_seen": 2.0,
            # NB: no trust_state
        }
        ts._save()
        # Re-open to force a fresh load from disk.
        reopened = TrustStore(agent_key=agent_key, path=trust_path)
        assert reopened.get_peer("legacy") is not None
        assert reopened.get_trust_state("legacy") == "trusted"


# ---------------------------------------------------------------------------
# MessageStore — pending_trust_messages queue + schema v3 migration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestPendingTrustQueue:
    async def test_queue_admit_one(self, gate_store):
        ok = await gate_store.queue_pending_trust(
            "alice", "msg-1", "MSG", b"hello", priority="NORMAL", cap=10,
        )
        assert ok is True
        assert await gate_store.pending_trust_count_for("alice") == 1

    async def test_queue_idempotent_on_duplicate_msg_id(self, gate_store):
        await gate_store.queue_pending_trust("alice", "dup", "MSG", b"a", cap=10)
        ok = await gate_store.queue_pending_trust("alice", "dup", "MSG", b"a", cap=10)
        assert ok is False
        assert await gate_store.pending_trust_count_for("alice") == 1

    async def test_queue_cap_evicts_oldest(self, gate_store):
        for i in range(5):
            await gate_store.queue_pending_trust(
                "alice", f"m{i}", "MSG", f"body-{i}".encode(), cap=3,
            )
        # cap=3 => after 5 admits, only the last 3 remain (FIFO eviction)
        assert await gate_store.pending_trust_count_for("alice") == 3
        drained = await gate_store.drain_pending_trust("alice")
        ids = [d["msg_id"] for d in drained]
        assert ids == ["m2", "m3", "m4"]

    async def test_drain_returns_arrival_order(self, gate_store):
        await gate_store.queue_pending_trust("bob", "first", "MSG", b"1", cap=10)
        await asyncio.sleep(0.001)  # ensure distinct queued_at
        await gate_store.queue_pending_trust("bob", "second", "MSG", b"2", cap=10)
        await asyncio.sleep(0.001)
        await gate_store.queue_pending_trust("bob", "third", "MSG", b"3", cap=10)
        drained = await gate_store.drain_pending_trust("bob")
        assert [d["msg_id"] for d in drained] == ["first", "second", "third"]
        assert await gate_store.pending_trust_count_for("bob") == 0

    async def test_discard_clears_queue(self, gate_store):
        await gate_store.queue_pending_trust("eve", "m1", "MSG", b"x", cap=10)
        await gate_store.queue_pending_trust("eve", "m2", "MSG", b"y", cap=10)
        n = await gate_store.discard_pending_trust("eve")
        assert n == 2
        assert await gate_store.pending_trust_count_for("eve") == 0

    async def test_summary_groups_by_peer(self, gate_store):
        await gate_store.queue_pending_trust("a", "1", "MSG", b"x", cap=10)
        await gate_store.queue_pending_trust("a", "2", "MSG", b"y", cap=10)
        await gate_store.queue_pending_trust("b", "3", "MSG", b"z", cap=10)
        summary = await gate_store.list_pending_trust_summary()
        by_peer = {s["source_node_id"]: s["queued_count"] for s in summary}
        assert by_peer == {"a": 2, "b": 1}

    async def test_payload_round_trips_through_drain(self, gate_store):
        await gate_store.queue_pending_trust("p", "k", "MSG", b"binary\x00\xff", cap=10)
        drained = await gate_store.drain_pending_trust("p")
        assert drained[0]["payload"] == b"binary\x00\xff"


@pytest.mark.asyncio
class TestSchemaMigration:
    async def test_v2_db_migrates_to_v3_with_pending_table(self, tmp_path, monkeypatch):
        """A v2 DB on disk should migrate cleanly to v3 — adding the
        pending_trust_messages table without losing any v1/v2 data."""
        db_path = str(tmp_path / "legacy.db")
        # Hand-build a v2 DB.
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE _meta (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO _meta VALUES ('schema_version', '2')")
        conn.execute("""CREATE TABLE messages (msg_id TEXT PRIMARY KEY,
                        source TEXT, source_display TEXT, destination TEXT,
                        msg_type TEXT, payload BLOB, timestamp REAL,
                        priority TEXT, direction TEXT, status TEXT,
                        retries INTEGER)""")
        conn.execute(
            "INSERT INTO messages VALUES "
            "('legacy-1','alice','Alice','bob','MSG',NULL,1.0,'NORMAL','inbound','delivered',0)"
        )
        conn.execute("""CREATE TABLE pending_messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        peer_node_id TEXT, msg_id TEXT, source TEXT,
                        msg_type TEXT, payload BLOB, priority TEXT,
                        created_at REAL, delivered INTEGER, delivered_at REAL,
                        retries INTEGER)""")
        conn.execute("""CREATE TABLE peers (node_id TEXT PRIMARY KEY,
                        identity_public_b64 TEXT, fingerprint TEXT,
                        first_seen REAL, last_seen REAL, last_address TEXT,
                        trusted INTEGER DEFAULT 0, trust_first_seen REAL)""")
        conn.commit()
        conn.close()

        # Open via MessageStore — should auto-migrate.
        store = MessageStore(db_path)
        await store.open()
        try:
            # Existing data preserved.
            msgs = await store.get_messages()
            assert any(m["msg_id"] == "legacy-1" for m in msgs)
            # New table exists and is usable.
            ok = await store.queue_pending_trust(
                "newpeer", "m1", "MSG", b"x", cap=10,
            )
            assert ok is True
        finally:
            await store.close()


# ---------------------------------------------------------------------------
# MCP tool dispatch + arg validation
# ---------------------------------------------------------------------------

class TestMCPTrustTools:
    def _build_mcp(self):
        from ironmesh_mcp.server import IronMeshMCP, TOOL_SPECS
        # Stub daemon: provides config + an event loop the futures can run on.
        loop = asyncio.new_event_loop()
        daemon = SimpleNamespace(
            config=SimpleNamespace(require_message_promotion=True),
            peers={},
        )
        # Wrap async-returning mocks so run_coroutine_threadsafe accepts them.
        async def fake_list_pending():
            return [{"node_id": "alice", "queued_count": 2}]
        async def fake_promote(nid):
            return {"ok": True, "drained": 3, "error": None}
        async def fake_block(nid):
            return {"ok": True, "discarded": 2, "error": None}
        daemon.list_pending_trust = fake_list_pending
        daemon.promote_pending_peer = fake_promote
        daemon.block_pending_peer = fake_block
        # IronMeshMCP just stashes the loop — it doesn't have to be running for the
        # threadsafe scheduler to enqueue, but it does need to be running for results.
        mcp = IronMeshMCP(daemon, loop)
        return mcp, loop, TOOL_SPECS

    def _spec(self, specs, name):
        for s in specs:
            if s["name"] == name:
                return s
        return None

    def test_tool_specs_include_pending_trust_trio(self):
        from ironmesh_mcp.server import TOOL_SPECS
        names = {s["name"] for s in TOOL_SPECS}
        assert "ironmesh_list_pending_trust" in names
        assert "ironmesh_trust_peer" in names
        assert "ironmesh_block_peer" in names

    def test_block_peer_requires_confirm(self):
        mcp, loop, _ = self._build_mcp()
        try:
            out = mcp.tool_block_peer({"peer": "a" * 32})
            assert "error" in out
            assert "confirm" in out["error"].lower()
        finally:
            loop.close()

    def test_trust_peer_requires_peer_arg(self):
        mcp, loop, _ = self._build_mcp()
        try:
            out = mcp.tool_trust_peer({})
            assert "error" in out
        finally:
            loop.close()

    def test_resolve_node_id_accepts_hex(self):
        mcp, loop, _ = self._build_mcp()
        try:
            nid = "f" * 32
            assert mcp._resolve_node_id(nid) == nid
        finally:
            loop.close()

    def test_resolve_node_id_resolves_agent_name(self):
        mcp, loop, _ = self._build_mcp()
        try:
            mcp.daemon.peers = {"node-xyz": SimpleNamespace(name="alice")}
            assert mcp._resolve_node_id("alice") == "node-xyz"
            assert mcp._resolve_node_id("nobody") is None
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# End-to-end gate via BridgeDaemon._gate_inbound_msg
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGateEndToEnd:
    async def _build_daemon(self, tmp_path, monkeypatch, *, gate_on: bool):
        """Construct a BridgeDaemon stub with just enough for _gate_inbound_msg.

        Avoids running the full daemon (no network sockets, no event loop
        wiring). Stubs out config, _db, _keypair, _gui_broadcast, _audit.

        The gate constructs ``TrustStore(agent_key=...)`` without an explicit
        path, picking up the DEFAULT_TRUST_PATH default which expands ``~``.
        We redirect HOME/USERPROFILE to the per-test tmp_path so both the
        test's TrustStore and the gate's internal one resolve to the same
        file, MAC'd with the same key.
        """
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        # Minimal config object the gate reads.
        cfg = SimpleNamespace(
            require_message_promotion=gate_on,
            pending_trust_queue_cap=5,
        )
        # Backing store with the v3 schema.
        store = MessageStore(str(tmp_path / "gate.db"))
        await store.open()
        # Trust store at an explicit per-test path. v0.8.5 piped trust_path
        # through BridgeDaemon so the gate's internal TrustStore reads the
        # same file we write the test's pinned peers to.
        trust_path = str(tmp_path / "known_peers.json")
        agent_key = b"\xa5" * 32
        ts = TrustStore(agent_key=agent_key, path=trust_path)
        # Stub keypair: gate code only reads .ed25519_secret[:32] for the MAC.
        keypair = SimpleNamespace(ed25519_secret=agent_key + b"\x00" * 32)

        async def _noop_broadcast(_msg):
            return None
        import threading
        daemon = SimpleNamespace(
            config=cfg,
            _db=store,
            _keypair=keypair,
            _gui_broadcast=_noop_broadcast,
            _audit=None,
            node_id="self-node-id-32-hex" + "0" * 14,
            # v0.8.5.7 B22: metrics stub now includes every counter
            # `promote_pending_peer` / `block_pending_peer` / the
            # cap-binding path touches via _reserve_counter_bump.
            metrics=SimpleNamespace(
                messages_received_blocked=0,
                peer_promoted=0,
                peer_blocked=0,
                peer_cap_set_changed=0,
                peer_cap_baseline=0,
                peer_cap_accepted=0,
                peer_cap_binding_partial=0,
                msg_replay_cross_transport=0,
                peer_revoked_local=0,
                peer_state_changed=0,
            ),
            bus=SimpleNamespace(publish=lambda *a, **k: None),
            trust_path=trust_path,
            # v0.8.5.2-R5: per-peer audit-write rate-limit dict.
            _gate_audit_last_write={},
            # v0.8.5.7 B21 / B22: reservation dict + lock for the
            # _reserve_counter_bump path; the audit-log scanner is
            # inactive in these unit tests, so reservations just
            # accumulate (harmless — we only read counter values).
            _in_proc_counter_bumps={},
            _counter_lock=threading.Lock(),
        )
        # Bind the gate methods to our stub.
        from ironmesh.bridge import BridgeDaemon
        for name in ("_gate_inbound_msg", "promote_pending_peer",
                     "block_pending_peer", "list_pending_trust",
                     "_reserve_counter_bump", "_GATED_MSG_TYPES"):
            attr = getattr(BridgeDaemon, name)
            if callable(attr):
                setattr(daemon, name, attr.__get__(daemon, daemon.__class__))
            else:
                setattr(daemon, name, attr)
        return daemon, ts, store

    def _frame(self, *, msg_type="MSG", source=None, msg_id="m1", payload=b"hi"):
        f = SimpleNamespace(
            msg_type=msg_type,
            msg_id=msg_id,
            payload=payload,
            source=source,
            destination=None,
            priority="NORMAL",
        )
        return f

    async def test_gate_off_always_delivers(self, tmp_path, monkeypatch):
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=False)
        try:
            f = self._frame(source="random-peer")
            assert await daemon._gate_inbound_msg("immediate", f) == "deliver"
        finally:
            await store.close()

    async def test_gate_on_pending_peer_queues(self, tmp_path, monkeypatch):
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            ts.pin_peer("strange", "S" * 64, trust_state="pending")
            f = self._frame(source="strange")
            action = await daemon._gate_inbound_msg("strange", f)
            assert action == "queue"
            assert await store.pending_trust_count_for("strange") == 1
        finally:
            await store.close()

    async def test_gate_on_trusted_peer_delivers(self, tmp_path, monkeypatch):
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            ts.pin_peer("friend", "F" * 64, trust_state="trusted")
            f = self._frame(source="friend")
            assert await daemon._gate_inbound_msg("friend", f) == "deliver"
        finally:
            await store.close()

    async def test_gate_on_blocked_peer_drops(self, tmp_path, monkeypatch):
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            ts.pin_peer("baddie", "B" * 64, trust_state="blocked")
            f = self._frame(source="baddie")
            assert await daemon._gate_inbound_msg("baddie", f) == "drop"
            assert await store.pending_trust_count_for("baddie") == 0
        finally:
            await store.close()

    async def test_gate_skips_control_frames(self, tmp_path, monkeypatch):
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            # Even an unknown peer's control frame should pass — the gate
            # only inspects user-payload types.
            f = self._frame(msg_type="HEARTBEAT", source="strange")
            assert await daemon._gate_inbound_msg("strange", f) == "deliver"
        finally:
            await store.close()

    async def test_gate_does_not_gate_self(self, tmp_path, monkeypatch):
        """Self-bypass keys on peer_id (wire-authenticated), NOT
        frame.source (unauthenticated envelope field)."""
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            # A frame whose immediate peer == self bypasses (defensive
            # loopback handling; in practice a daemon doesn't connect to
            # itself over the wire).
            f = self._frame(source=None)
            assert await daemon._gate_inbound_msg(daemon.node_id, f) == "deliver"
        finally:
            await store.close()

    async def test_pending_peer_cannot_bypass_via_forged_source(self, tmp_path, monkeypatch):
        """Security regression: a pending peer must not bypass the gate by
        forging frame.source to claim it's our own node_id. The frame's
        source field is not cryptographically bound to peer_id — only the
        encrypted payload is signed. Trust judgement keys on peer_id."""
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            ts.pin_peer("attacker", "X" * 64, trust_state="pending")
            # Attacker forges frame.source to look like it came from us.
            f = self._frame(source=daemon.node_id)
            action = await daemon._gate_inbound_msg("attacker", f)
            assert action == "queue", (
                f"forged-source bypass: pending peer delivered as 'self' (got {action})"
            )
            assert await store.pending_trust_count_for("attacker") == 1
        finally:
            await store.close()

    async def test_promote_drains_queue_in_order(self, tmp_path, monkeypatch):
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            ts.pin_peer("noisy", "N" * 64, trust_state="pending")
            published = []
            daemon.bus = SimpleNamespace(
                publish=lambda mt, env: published.append((mt, env["msg_id"])),
            )
            for i in range(3):
                await daemon._gate_inbound_msg("noisy", self._frame(
                    source="noisy", msg_id=f"m{i}", payload=f"body-{i}".encode(),
                ))
            assert await store.pending_trust_count_for("noisy") == 3
            result = await daemon.promote_pending_peer("noisy")
            assert result == {"ok": True, "drained": 3, "error": None}
            assert [p[1] for p in published] == ["m0", "m1", "m2"]
            # Re-read trust store from disk to bypass the test-local cache.
            tp = str(tmp_path / "known_peers.json")
            assert TrustStore(agent_key=b"\xa5" * 32, path=tp).get_trust_state("noisy") == "trusted"
            # And subsequent inbound delivers directly.
            new_action = await daemon._gate_inbound_msg("noisy", self._frame(
                source="noisy", msg_id="post"))
            assert new_action == "deliver"
        finally:
            await store.close()

    async def test_promote_unknown_peer_returns_error(self, tmp_path, monkeypatch):
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            result = await daemon.promote_pending_peer("ghost")
            assert result["ok"] is False
            assert "not in trust store" in result["error"]
        finally:
            await store.close()

    async def test_block_discards_pending_queue(self, tmp_path, monkeypatch):
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            ts.pin_peer("annoy", "A" * 64, trust_state="pending")
            for i in range(2):
                await daemon._gate_inbound_msg("annoy", self._frame(
                    source="annoy", msg_id=f"m{i}", payload=b"x"))
            assert await store.pending_trust_count_for("annoy") == 2
            result = await daemon.block_pending_peer("annoy")
            assert result == {"ok": True, "discarded": 2, "error": None}
            assert await store.pending_trust_count_for("annoy") == 0
            tp = str(tmp_path / "known_peers.json")
            assert TrustStore(agent_key=b"\xa5" * 32, path=tp).get_trust_state("annoy") == "blocked"
        finally:
            await store.close()

    async def test_list_pending_trust_includes_queued_count(self, tmp_path, monkeypatch):
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            ts.pin_peer("peerA", "1" * 64, trust_state="pending")
            ts.pin_peer("peerB", "2" * 64, trust_state="pending")
            # Only peerA has queued messages.
            await daemon._gate_inbound_msg("peerA", self._frame(source="peerA"))
            await daemon._gate_inbound_msg("peerA", self._frame(
                source="peerA", msg_id="m2"))
            listing = await daemon.list_pending_trust()
            by_id = {p["node_id"]: p for p in listing}
            assert by_id["peerA"]["queued_count"] == 2
            assert by_id["peerB"]["queued_count"] == 0
        finally:
            await store.close()

    async def test_promote_then_inbound_delivers_no_loss(self, tmp_path, monkeypatch):
        """Race window between promote() and a fresh inbound from the
        same peer: drained messages publish in arrival order and the
        new inbound delivers via the trusted fast path. No message is
        lost or double-published."""
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            ts.pin_peer("racy", "R" * 64, trust_state="pending")
            published: list[str] = []
            daemon.bus = SimpleNamespace(
                publish=lambda mt, env: published.append(env["msg_id"]),
            )
            # Queue 2 messages while pending.
            await daemon._gate_inbound_msg("racy", self._frame(
                source="racy", msg_id="q1"))
            await daemon._gate_inbound_msg("racy", self._frame(
                source="racy", msg_id="q2"))
            # Concurrently: promote drains, and a fresh inbound arrives.
            promote_task = asyncio.create_task(daemon.promote_pending_peer("racy"))
            await asyncio.sleep(0)  # let promote start
            new_action = await daemon._gate_inbound_msg("racy", self._frame(
                source="racy", msg_id="post"))
            result = await promote_task
            assert result["ok"] is True
            assert result["drained"] == 2
            # New inbound must deliver (gate flipped to trusted by promote).
            assert new_action == "deliver"
            # Drained messages must be published in arrival order.
            drained_ids = [m for m in published if m in ("q1", "q2")]
            assert drained_ids == ["q1", "q2"]
            # Pending queue empty afterwards.
            assert await store.pending_trust_count_for("racy") == 0
        finally:
            await store.close()

    async def test_concurrent_inbound_serializes_into_queue(self, tmp_path, monkeypatch):
        """Two coroutines emit MSGs from the same pending peer at the same
        time. Both should land in the queue — the SQLite table's
        UNIQUE(source, msg_id) constraint serializes them safely."""
        daemon, ts, store = await self._build_daemon(tmp_path, monkeypatch, gate_on=True)
        try:
            ts.pin_peer("concurrent", "C" * 64, trust_state="pending")
            results = await asyncio.gather(
                daemon._gate_inbound_msg("concurrent", self._frame(
                    source="concurrent", msg_id="A")),
                daemon._gate_inbound_msg("concurrent", self._frame(
                    source="concurrent", msg_id="B")),
            )
            assert results == ["queue", "queue"]
            assert await store.pending_trust_count_for("concurrent") == 2
        finally:
            await store.close()
