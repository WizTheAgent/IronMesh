"""Tests for ironmesh.mesh — RoutingTable, DedupCache, CircuitBreaker, MeshRouter."""

import asyncio
import json
import os
import time

import pytest

from ironmesh.mesh import (
    INFINITY_COST,
    CircuitBreaker,
    DedupCache,
    MeshRouter,
    RoutingTable,
)


# ---------------------------------------------------------------------------
# RoutingTable unit tests (1-8)
# ---------------------------------------------------------------------------

class TestRoutingTable:
    def test_add_route_basic(self):
        rt = RoutingTable("self")
        assert rt.add_route("dst", "next1", cost=2, learned_from="next1") is True
        assert rt.get_next_hop("dst") == "next1"
        assert rt.get_cost("dst") == 2

    def test_add_route_prefers_shorter_cost(self):
        rt = RoutingTable("self")
        rt.add_route("dst", "next1", cost=5, learned_from="learner1")
        # Lower cost from a different learner replaces the route
        rt.add_route("dst", "next2", cost=2, learned_from="learner2")
        assert rt.get_next_hop("dst") == "next2"
        assert rt.get_cost("dst") == 2

    def test_add_route_ignores_longer_cost(self):
        rt = RoutingTable("self")
        rt.add_route("dst", "next1", cost=2, learned_from="learner1")
        # Higher cost from a different learner is ignored
        rt.add_route("dst", "next2", cost=5, learned_from="learner2")
        assert rt.get_next_hop("dst") == "next1"
        assert rt.get_cost("dst") == 2

    def test_route_expires_after_ttl(self):
        rt = RoutingTable("self", ttl=10)
        t0 = time.time()
        rt.add_route("dst", "n", cost=1, learned_from="n", now=t0)
        # Pretend now is t0 + 100s
        expired = rt.expire_old(now=t0 + 100)
        assert "dst" in expired
        assert rt.get_next_hop("dst") is None

    def test_route_refreshes_on_readd(self):
        rt = RoutingTable("self", ttl=10)
        t0 = time.time()
        rt.add_route("dst", "n", cost=1, learned_from="n", now=t0)
        rt.add_route("dst", "n", cost=1, learned_from="n", now=t0 + 5)
        # Should still be present at t0 + 12 (refreshed at t0+5, ttl=10 → expires at t0+15)
        expired = rt.expire_old(now=t0 + 12)
        assert "dst" not in expired

    def test_to_announcement_split_horizon(self):
        rt = RoutingTable("self")
        rt.add_route("dst", "via_a", cost=2, learned_from="A")
        # Announcing back to A should not advertise dst at its real cost
        ann = rt.to_announcement(exclude_peer="A")
        for entry in ann:
            if entry["destination"] == "dst":
                assert entry["cost"] == INFINITY_COST  # poisoned reverse
                break

    def test_to_announcement_poisoned_reverse(self):
        rt = RoutingTable("self")
        rt.add_route("dst", "via_a", cost=2, learned_from="A")
        # Routes learned from A appear at infinity in announcements TO A
        ann = rt.to_announcement(exclude_peer="A")
        infinities = [e for e in ann if e["cost"] == INFINITY_COST]
        assert any(e["destination"] == "dst" for e in infinities)
        # But NOT in announcements to other peers
        ann_b = rt.to_announcement(exclude_peer="B")
        for e in ann_b:
            if e["destination"] == "dst":
                assert e["cost"] == 2

    def test_includes_self_with_cost_zero(self):
        rt = RoutingTable("self_node")
        rt.add_route("other", "n", cost=1, learned_from="n")
        ann = rt.to_announcement(exclude_peer=None)
        self_entries = [e for e in ann if e["destination"] == "self_node"]
        assert len(self_entries) == 1
        assert self_entries[0]["cost"] == 0


# ---------------------------------------------------------------------------
# DedupCache unit tests (9-13)
# ---------------------------------------------------------------------------

class TestDedupCache:
    def test_dedup_new_not_duplicate(self):
        cache = DedupCache()
        assert cache.is_duplicate("src", "msg1") is False

    def test_cleanup_expired_thread_safe_with_concurrent_add(self):
        """B9 regression: cleanup_expired must hold self._lock so it
        can't race with concurrent add()/check_and_add(). Pre-fix it
        iterated self._sources WITHOUT the lock, and a concurrent
        adder calling self._sources.move_to_end / self._sources.popitem
        could raise ``dict changed size during iteration`` or skip
        entries.
        """
        import threading
        cache = DedupCache(per_source_max=10000, sources_max=10000,
                           ttl=0.001)  # tiny TTL forces lots of expiry work
        stop = threading.Event()
        errors: list = []

        def adder():
            i = 0
            while not stop.is_set():
                try:
                    cache.add(f"s{i % 50}", f"m{i}")
                    i += 1
                except Exception as e:
                    errors.append(("adder", repr(e)))
                    return

        def cleaner():
            while not stop.is_set():
                try:
                    cache.cleanup_expired()
                except Exception as e:
                    errors.append(("cleaner", repr(e)))
                    return

        threads = [threading.Thread(target=adder) for _ in range(3)]
        threads.append(threading.Thread(target=cleaner))
        threads.append(threading.Thread(target=cleaner))
        for t in threads:
            t.start()
        # Burn the bug for a moment
        import time as _t; _t.sleep(0.6)
        stop.set()
        for t in threads:
            t.join(timeout=2)
        assert errors == [], f"Race detected: {errors}"

    def test_dedup_same_is_duplicate(self):
        cache = DedupCache()
        cache.add("src", "msg1")
        assert cache.is_duplicate("src", "msg1") is True
        assert cache.is_duplicate("src", "msg2") is False

    def test_dedup_per_source_quota_isolation(self):
        cache = DedupCache(per_source_max=3)
        for i in range(10):
            cache.add("flooder", f"msg{i}")
        # Flooder is bounded at per_source_max
        assert sum(1 for k in range(10) if cache.is_duplicate("flooder", f"msg{k}")) == 3
        # Other sources are unaffected
        cache.add("good", "x")
        assert cache.is_duplicate("good", "x") is True

    def test_dedup_source_lru_eviction(self):
        cache = DedupCache(sources_max=3)
        cache.add("a", "1")
        cache.add("b", "1")
        cache.add("c", "1")
        cache.add("d", "1")  # should evict "a"
        assert cache.is_duplicate("a", "1") is False
        assert cache.is_duplicate("d", "1") is True

    def test_dedup_entry_ttl_expiration(self):
        cache = DedupCache(ttl=10)
        t0 = time.time()
        cache.add("src", "msg1", now=t0)
        cache.cleanup_expired(now=t0 + 100)
        assert cache.is_duplicate("src", "msg1") is False


# ---------------------------------------------------------------------------
# CircuitBreaker unit tests
# ---------------------------------------------------------------------------

class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker()
        assert cb.is_open("peer") is False

    def test_opens_after_threshold_failures(self):
        cb = CircuitBreaker(failure_threshold=3, window=60)
        for _ in range(3):
            cb.record_failure("peer")
        assert cb.is_open("peer") is True

    def test_does_not_open_below_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, window=60)
        cb.record_failure("peer")
        cb.record_failure("peer")
        assert cb.is_open("peer") is False

    def test_success_resets_failures(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure("peer")
        cb.record_failure("peer")
        cb.record_success("peer")
        cb.record_failure("peer")
        cb.record_failure("peer")
        assert cb.is_open("peer") is False  # only 2 failures since success

    def test_cooldown_closes_breaker(self):
        cb = CircuitBreaker(failure_threshold=2, window=60, cooldown=5)
        t0 = time.time()
        cb.record_failure("peer", now=t0)
        cb.record_failure("peer", now=t0)
        assert cb.is_open("peer", now=t0) is True
        # After cooldown, breaker reopens
        assert cb.is_open("peer", now=t0 + 100) is False

    def test_trip_callback_fires_once(self):
        events = []
        cb = CircuitBreaker(failure_threshold=2)
        cb.set_trip_callback(lambda pid: events.append(pid))
        cb.record_failure("peer")
        cb.record_failure("peer")
        assert events == ["peer"]
        # Additional failures while open don't re-trip
        cb.record_failure("peer")
        assert events == ["peer"]


# ---------------------------------------------------------------------------
# RoutingTable persistence
# ---------------------------------------------------------------------------

class TestRoutingTablePersistence:
    def test_save_and_load_with_hmac(self, tmp_path):
        rt = RoutingTable("self")
        rt.add_route("dst1", "n1", cost=2, learned_from="n1")
        rt.add_route("dst2", "n2", cost=3, learned_from="n2")

        path = str(tmp_path / "routes.json")
        key = b"\x42" * 32
        rt.save(path, key)
        assert os.path.exists(path)

        rt2 = RoutingTable("self", ttl=90.0)
        ok = rt2.load(path, key, refresh_ttl=30.0)
        assert ok is True
        assert rt2.get_next_hop("dst1") == "n1"
        assert rt2.get_next_hop("dst2") == "n2"

    def test_load_rejects_tampered_file(self, tmp_path):
        rt = RoutingTable("self")
        rt.add_route("dst", "n", cost=2, learned_from="n")
        path = str(tmp_path / "routes.json")
        key = b"k" * 32
        rt.save(path, key)
        # Tamper
        with open(path) as f:
            data = json.load(f)
        data["body"] = data["body"].replace("dst", "evil")
        with open(path, "w") as f:
            json.dump(data, f)

        rt2 = RoutingTable("self")
        assert rt2.load(path, key) is False
        assert rt2.get_next_hop("dst") is None
        assert rt2.get_next_hop("evil") is None


# ---------------------------------------------------------------------------
# MeshRouter forwarding / convergence integration tests (14-22)
# Use a lightweight FakeDaemon that captures _send_frame calls.
# ---------------------------------------------------------------------------

class _FakePeerState:
    def __init__(self, supports_mesh=True, is_online=True):
        self.supports_mesh = supports_mesh
        self.is_online = is_online
        self.last_route_announce = 0
        self.is_relay_capable = False
        self.last_seen = 0
        self.identity_public = b"\x00" * 32

    def next_sequence(self):
        return 1


class _FakeKeypair:
    ed25519_secret = b"\x42" * 32
    ed25519_public = b"\x43" * 32

    def get_signing_key(self):
        from nacl.signing import SigningKey
        return SigningKey(self.ed25519_secret)


class _FakeDaemon:
    """Minimal daemon stub for MeshRouter unit-level integration tests."""

    def __init__(self, node_id="self"):
        self._node_id = node_id
        self.peers = {}
        self.ws_clients = {}
        self._keypair = _FakeKeypair()
        self._audit = None
        self._running = True
        self.metrics = type("M", (), {"messages_relayed": 0})()
        self.sent: list = []  # captured (peer_id, frame) tuples

    @property
    def node_id(self):
        return self._node_id

    def add_peer(self, pid, supports_mesh=True):
        self.peers[pid] = _FakePeerState(supports_mesh=supports_mesh)
        self.ws_clients[pid] = object()  # any truthy stand-in

    async def _send_frame(self, peer_id, frame):
        self.sent.append((peer_id, frame))


class _FakeConfig:
    mesh_routing = "relay"
    max_hops = 5
    route_announce_interval = 30.0
    route_ttl = 90.0
    routes_path = "/tmp/test_routes.json"
    dedup_sources_max = 128
    dedup_per_source_max = 1024
    dedup_cache_ttl = 300.0


def _make_frame(source="A", destination="C", msg_id="m1", ttl=5, hops=None):
    from ironmesh import protocol as ew_protocol
    f = ew_protocol.Frame(
        msg_type=ew_protocol.MessageType.MSG,
        payload=b"hello",
        msg_id=msg_id,
        source=source,
        destination=destination,
    )
    f.ttl = ttl
    f.hops = list(hops) if hops else []
    return f


class TestMeshRouterRelay:
    @pytest.mark.asyncio
    async def test_three_node_line_relay(self):
        """B with route C->C should relay A's message destined for C."""
        daemon = _FakeDaemon(node_id="B")
        daemon.add_peer("A")
        daemon.add_peer("C")
        router = MeshRouter(daemon, _FakeConfig())
        # B knows C is reachable directly
        router.table.add_route("C", "C", cost=1, learned_from="C")

        frame = _make_frame(source="A", destination="C")
        ok = await router.relay_message(frame, from_peer="A")
        assert ok is True
        assert len(daemon.sent) == 1
        next_hop, sent_frame = daemon.sent[0]
        assert next_hop == "C"
        assert "B" in sent_frame.hops  # B appended itself
        assert sent_frame.ttl == 4     # decremented from 5

    @pytest.mark.asyncio
    async def test_loop_prevention_via_hop_list(self):
        daemon = _FakeDaemon(node_id="B")
        daemon.add_peer("A")
        daemon.add_peer("C")
        router = MeshRouter(daemon, _FakeConfig())
        router.table.add_route("C", "C", cost=1, learned_from="C")

        # Frame already passed through B once — must drop
        frame = _make_frame(source="A", destination="C", hops=["A", "B"])
        ok = await router.relay_message(frame, from_peer="A")
        assert ok is False
        assert daemon.sent == []

    @pytest.mark.asyncio
    async def test_ttl_expiration_drops_at_zero(self):
        daemon = _FakeDaemon(node_id="B")
        daemon.add_peer("A")
        daemon.add_peer("C")
        router = MeshRouter(daemon, _FakeConfig())
        router.table.add_route("C", "C", cost=1, learned_from="C")

        frame = _make_frame(source="A", destination="C", ttl=0)
        ok = await router.relay_message(frame, from_peer="A")
        assert ok is False
        assert daemon.sent == []

    @pytest.mark.asyncio
    async def test_no_route_returns_unreachable(self):
        daemon = _FakeDaemon(node_id="B")
        daemon.add_peer("A")
        router = MeshRouter(daemon, _FakeConfig())
        # Provide return path to A so unreachable can be sent
        router.table.add_route("A", "A", cost=1, learned_from="A")

        frame = _make_frame(source="A", destination="UNKNOWN")
        ok = await router.relay_message(frame, from_peer="A")
        assert ok is False
        # Unreachable was attempted via the return path
        unreachables = [f for _, f in daemon.sent
                        if f.msg_type == "ROUTE_UNREACHABLE"]
        assert len(unreachables) == 1

    @pytest.mark.asyncio
    async def test_passive_mode_does_not_relay(self):
        cfg = _FakeConfig()
        cfg.mesh_routing = "passive"
        daemon = _FakeDaemon(node_id="B")
        daemon.add_peer("A")
        daemon.add_peer("C")
        router = MeshRouter(daemon, cfg)
        router.table.add_route("C", "C", cost=1, learned_from="C")

        frame = _make_frame(source="A", destination="C")
        ok = await router.relay_message(frame, from_peer="A")
        assert ok is False
        assert daemon.sent == []

    @pytest.mark.asyncio
    async def test_dedup_prevents_relayed_replay(self):
        daemon = _FakeDaemon(node_id="B")
        daemon.add_peer("A")
        daemon.add_peer("C")
        router = MeshRouter(daemon, _FakeConfig())
        router.table.add_route("C", "C", cost=1, learned_from="C")

        f1 = _make_frame(msg_id="dup-id")
        f2 = _make_frame(msg_id="dup-id")  # Same source + msg_id
        ok1 = await router.relay_message(f1, from_peer="A")
        ok2 = await router.relay_message(f2, from_peer="A")
        assert ok1 is True
        assert ok2 is False  # Second one is dedup'd
        assert len(daemon.sent) == 1

    @pytest.mark.asyncio
    async def test_cross_transport_replay_emits_audit_event(self):
        """v0.8.5.6 S4 regression: same (source, msg_id) arriving once
        on transport=ws and again on transport=rns must fire
        EVENT_MSG_REPLAY_CROSS_TRANSPORT (in addition to the normal
        EVENT_DUPLICATE_DROPPED).
        """
        from ironmesh.audit import (
            EVENT_DUPLICATE_DROPPED,
            EVENT_MSG_REPLAY_CROSS_TRANSPORT,
        )

        captured: list = []

        class _CapturingAudit:
            def log(self, event, details):
                captured.append((event, details))

        daemon = _FakeDaemon(node_id="B")
        daemon.add_peer("A")
        daemon.add_peer("C")
        daemon._audit = _CapturingAudit()
        router = MeshRouter(daemon, _FakeConfig())
        router.table.add_route("C", "C", cost=1, learned_from="C")

        f1 = _make_frame(msg_id="x-replay-1")
        f2 = _make_frame(msg_id="x-replay-1")  # same id, will be a replay
        ok1 = await router.relay_message(f1, from_peer="A", transport="ws")
        ok2 = await router.relay_message(f2, from_peer="A", transport="rns")
        assert ok1 is True
        assert ok2 is False

        events = [e for e, _ in captured]
        assert EVENT_DUPLICATE_DROPPED in events
        assert EVENT_MSG_REPLAY_CROSS_TRANSPORT in events, (
            "S4 regression: cross-transport replay must surface as a "
            "dedicated audit event, not just a generic duplicate-drop."
        )
        # Inspect the cross-transport detail payload
        cx = next(d for e, d in captured
                  if e == EVENT_MSG_REPLAY_CROSS_TRANSPORT)
        assert cx["original_transport"] == "ws"
        assert cx["replay_transport"] == "rns"
        assert cx["msg_id"] == "x-replay-1"
        assert isinstance(cx.get("time_delta_ms"), int)

    @pytest.mark.asyncio
    async def test_same_transport_replay_does_not_fire_cross_transport(self):
        """Negative control for S4: a same-transport replay must
        emit EVENT_DUPLICATE_DROPPED but NOT
        EVENT_MSG_REPLAY_CROSS_TRANSPORT.
        """
        from ironmesh.audit import (
            EVENT_DUPLICATE_DROPPED,
            EVENT_MSG_REPLAY_CROSS_TRANSPORT,
        )
        captured: list = []

        class _CapturingAudit:
            def log(self, event, details):
                captured.append((event, details))

        daemon = _FakeDaemon(node_id="B")
        daemon.add_peer("A")
        daemon.add_peer("C")
        daemon._audit = _CapturingAudit()
        router = MeshRouter(daemon, _FakeConfig())
        router.table.add_route("C", "C", cost=1, learned_from="C")

        f1 = _make_frame(msg_id="same-tx-1")
        f2 = _make_frame(msg_id="same-tx-1")
        await router.relay_message(f1, from_peer="A", transport="ws")
        await router.relay_message(f2, from_peer="A", transport="ws")
        events = [e for e, _ in captured]
        assert EVENT_DUPLICATE_DROPPED in events
        assert EVENT_MSG_REPLAY_CROSS_TRANSPORT not in events


class TestMeshRouterAnnouncements:
    @pytest.mark.asyncio
    async def test_handle_route_announce_learns_routes(self):
        daemon = _FakeDaemon(node_id="self")
        daemon.add_peer("A")
        router = MeshRouter(daemon, _FakeConfig())

        payload = json.dumps({
            "origin": "A",
            "sequence_number": 1,
            "routes": [
                {"destination": "A", "cost": 0},
                {"destination": "C", "cost": 1},
            ],
        }).encode()
        await router.handle_route_announce("A", payload)

        # We should have learned a route to A (cost 1) and to C (cost 2)
        assert router.table.get_next_hop("A") == "A"
        assert router.table.get_cost("A") == 1
        assert router.table.get_next_hop("C") == "A"
        assert router.table.get_cost("C") == 2
        # Peer was marked relay-capable
        assert daemon.peers["A"].is_relay_capable is True

    @pytest.mark.asyncio
    async def test_handle_route_announce_rejects_malicious_destination(self):
        """B16 regression: a malicious peer can send a ROUTE_ANNOUNCE
        with a non-string destination (e.g., a list). Pre-fix, the
        loop's add_route call would propagate TypeError because dict
        keys must be hashable. Handler must skip bad entries and
        continue processing the good ones.
        """
        daemon = _FakeDaemon(node_id="self")
        daemon.add_peer("A")
        router = MeshRouter(daemon, _FakeConfig())

        payload = json.dumps({
            "origin": "A",
            "sequence_number": 1,
            "routes": [
                {"destination": ["not", "a", "string"], "cost": 1},  # bad
                {"destination": {"x": 1}, "cost": 1},                 # bad
                {"destination": 42, "cost": 1},                       # bad
                {"destination": None, "cost": 1},                     # bad
                {"destination": "", "cost": 1},                       # bad (empty)
                "not a dict at all",                                  # bad
                {"destination": "GOOD", "cost": 1},                   # good
            ],
        }).encode()
        # Must NOT raise
        await router.handle_route_announce("A", payload)
        # Good route was learned
        assert router.table.get_next_hop("GOOD") == "A"
        # Bad routes did not pollute the table
        assert router.table.get_next_hop("") is None

    @pytest.mark.asyncio
    async def test_route_convergence_via_two_announces(self):
        """A->B->C convergence: B learns C from C, then announces to A."""
        daemon_b = _FakeDaemon(node_id="B")
        daemon_b.add_peer("A")
        daemon_b.add_peer("C")
        router_b = MeshRouter(daemon_b, _FakeConfig())

        # Step 1: C announces itself to B
        payload_c = json.dumps({
            "origin": "C", "sequence_number": 1,
            "routes": [{"destination": "C", "cost": 0}],
        }).encode()
        await router_b.handle_route_announce("C", payload_c)
        assert router_b.table.get_next_hop("C") == "C"

        # Step 2: B announces its routes to A — split horizon should NOT
        # poison-reverse C (since C wasn't learned via A).
        ann = router_b.table.to_announcement(exclude_peer="A")
        c_entries = [e for e in ann if e["destination"] == "C"]
        assert len(c_entries) == 1
        assert c_entries[0]["cost"] == 1
        # B's self-route is always present at cost 0
        b_self = [e for e in ann if e["destination"] == "B"]
        assert len(b_self) == 1
        assert b_self[0]["cost"] == 0


class TestMeshRouterPersistence:
    def test_route_persistence_round_trip(self, tmp_path):
        cfg = _FakeConfig()
        cfg.routes_path = str(tmp_path / "routes.json")
        daemon = _FakeDaemon(node_id="self")
        router = MeshRouter(daemon, cfg)
        router.table.add_route("C", "B", cost=2, learned_from="B")
        router.save_routes()

        # New router instance loads same routes
        daemon2 = _FakeDaemon(node_id="self")
        router2 = MeshRouter(daemon2, cfg)
        ok = router2.load_persisted_routes()
        assert ok is True
        assert router2.table.get_next_hop("C") == "B"

    def test_route_persistence_rejects_other_node(self, tmp_path):
        cfg = _FakeConfig()
        cfg.routes_path = str(tmp_path / "routes.json")
        daemon_a = _FakeDaemon(node_id="A")
        router_a = MeshRouter(daemon_a, cfg)
        router_a.table.add_route("X", "Y", cost=2, learned_from="Y")
        router_a.save_routes()

        # Different daemon should refuse to load these routes
        daemon_b = _FakeDaemon(node_id="B")
        router_b = MeshRouter(daemon_b, cfg)
        ok = router_b.load_persisted_routes()
        assert ok is False
        assert router_b.table.get_next_hop("X") is None


class TestMeshRouterCircuitBreaker:
    def test_get_route_skips_circuit_broken_peer(self):
        daemon = _FakeDaemon(node_id="self")
        daemon.add_peer("B")
        router = MeshRouter(daemon, _FakeConfig())
        router.table.add_route("C", "B", cost=2, learned_from="B")

        assert router.get_route("C") == "B"
        # Trip the breaker
        for _ in range(3):
            router.circuit_breaker.record_failure("B")
        assert router.get_route("C") is None

    def test_get_route_prefers_direct_connection(self):
        daemon = _FakeDaemon(node_id="self")
        daemon.add_peer("C")
        router = MeshRouter(daemon, _FakeConfig())
        # Even if a longer route via B exists, direct C wins
        router.table.add_route("C", "B", cost=2, learned_from="B")
        assert router.get_route("C") == "C"
