"""Tests for v0.8.5.6 trust-binding features.

Covers:
  - canonical_capability_hash stability + edge cases
  - TrustStore.observe_capabilities first-observation / match / changed paths
  - TrustStore.accept_capability_change
  - TrustStore.list_by_capability_status
  - DedupCache.check_and_add_with_transport (cross-transport detection)
  - Audit-log event emission via the bridge for cap-set changes and
    cross-transport replays
"""
from __future__ import annotations

import os

import pytest
from hypothesis import given, settings, strategies as st

from ironmesh.trust import canonical_capability_hash, TrustStore
from ironmesh.mesh import DedupCache


# ---------------------------------------------------------------------------
# canonical_capability_hash
# ---------------------------------------------------------------------------

class TestCanonicalCapabilityHash:

    def test_empty_set_has_stable_nonzero_hash(self):
        h1 = canonical_capability_hash([])
        h2 = canonical_capability_hash(None)
        h3 = canonical_capability_hash(())
        assert h1 == h2 == h3
        assert len(h1) == 64
        # Not the all-zeros sentinel
        assert h1 != "0" * 64

    def test_reorder_is_stable(self):
        h1 = canonical_capability_hash(["llm:llama3", "role:ops", "tool:fs"])
        h2 = canonical_capability_hash(["tool:fs", "role:ops", "llm:llama3"])
        h3 = canonical_capability_hash(["role:ops", "llm:llama3", "tool:fs"])
        assert h1 == h2 == h3

    def test_whitespace_normalized(self):
        h1 = canonical_capability_hash(["llm:llama3", "role:ops"])
        h2 = canonical_capability_hash(["  llm:llama3  ", " role:ops"])
        h3 = canonical_capability_hash(["llm:llama3\t", "role:ops\n"])
        assert h1 == h2 == h3

    def test_duplicates_collapsed(self):
        h1 = canonical_capability_hash(["llm:llama3", "role:ops"])
        h2 = canonical_capability_hash(
            ["llm:llama3", "role:ops", "llm:llama3", "role:ops"],
        )
        assert h1 == h2

    def test_case_sensitive(self):
        # Capability matching is case-sensitive; the hash must reflect that.
        h1 = canonical_capability_hash(["role:ops"])
        h2 = canonical_capability_hash(["role:OPS"])
        assert h1 != h2

    def test_different_sets_diverge(self):
        h1 = canonical_capability_hash(["role:ops"])
        h2 = canonical_capability_hash(["role:admin"])
        assert h1 != h2

    def test_empty_strings_ignored(self):
        h1 = canonical_capability_hash(["role:ops"])
        h2 = canonical_capability_hash(["role:ops", "", "  ", None])
        assert h1 == h2

    @given(st.lists(st.text(min_size=1, max_size=32), min_size=0, max_size=20))
    @settings(max_examples=200, deadline=None)
    def test_fuzz_reorder_invariant(self, caps):
        """Property: shuffling the input never changes the hash."""
        import random
        shuffled = list(caps)
        random.shuffle(shuffled)
        assert canonical_capability_hash(caps) == canonical_capability_hash(
            shuffled
        )

    @given(st.lists(st.text(min_size=1, max_size=32), min_size=0, max_size=20))
    @settings(max_examples=200, deadline=None)
    def test_fuzz_dup_invariant(self, caps):
        """Property: duplicating any element never changes the hash."""
        if not caps:
            return
        with_dup = caps + [caps[0]]
        assert canonical_capability_hash(caps) == canonical_capability_hash(
            with_dup
        )


# ---------------------------------------------------------------------------
# TrustStore capability-set binding
# ---------------------------------------------------------------------------

@pytest.fixture
def fresh_store(tmp_path):
    """A TrustStore with a deterministic agent key, fresh per test."""
    store = TrustStore(
        agent_key=b"\xaa" * 32,
        path=str(tmp_path / "known_peers.json"),
    )
    return store


PEER_NID = "a" * 32
PEER_PUB_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


class TestMacMismatchReadOnlyLatch:
    """B7 regression: a TrustStore that loaded a file with an
    unverifiable MAC must REFUSE to ``_save()``. Otherwise any later
    mutation (TOFU pin, capability observe) writes a near-empty file
    on top of a real one — silently wiping every pinned peer.

    Trigger scenario: two processes on the same host accidentally share
    ``~/.ironmesh/known_peers.json`` because one of them used the
    default trust path while having its own auto-generated keypair
    (typical test/quickstart pattern). The "production" daemon's next
    save would clobber the real file.
    """

    def test_save_refuses_after_mac_failure(self, tmp_path):
        """Two TrustStores with different agent keys against the same
        path. The second one's _load fails MAC verification and
        latches read-only. Any subsequent mutation must NOT write to
        disk.
        """
        path = str(tmp_path / "known_peers.json")
        # First store: production daemon's identity. Pins three peers.
        prod = TrustStore(agent_key=b"\xaa" * 32, path=path)
        prod.pin_peer("p1" * 16, PEER_PUB_B64)
        prod.pin_peer("p2" * 16, PEER_PUB_B64)
        prod.pin_peer("p3" * 16, PEER_PUB_B64)
        assert len(prod.list_peers()) == 3

        # Second store: a colliding test process with a different
        # identity, opens the same file. Loads with MAC mismatch.
        rogue = TrustStore(agent_key=b"\xbb" * 32, path=path)
        # _load detected MAC mismatch and latched read-only
        assert rogue._readonly_due_to_mac_failure is True
        assert len(rogue._peers) == 0
        # Mutate + save — should be a no-op on disk
        rogue.pin_peer("rogue" * 6 + "xx", PEER_PUB_B64)

        # Disk must STILL have the production daemon's three peers
        prod2 = TrustStore(agent_key=b"\xaa" * 32, path=path)
        names = {p["node_id"] for p in prod2.list_peers()}
        assert names == {"p1" * 16, "p2" * 16, "p3" * 16}, (
            "B7 regression: rogue TrustStore wrote over the production "
            "trust file. Disk now has " + repr(names)
        )

    def test_legitimate_save_still_works_when_mac_matches(self, tmp_path):
        """Sanity: the read-only latch must NOT trip on the happy path
        (correct MAC). Otherwise we'd brick every legitimate write."""
        path = str(tmp_path / "known_peers.json")
        store = TrustStore(agent_key=b"\xcc" * 32, path=path)
        store.pin_peer(PEER_NID, PEER_PUB_B64)
        # Re-open with same key — MAC verifies — peer present
        store2 = TrustStore(agent_key=b"\xcc" * 32, path=path)
        assert store2._readonly_due_to_mac_failure is False
        assert any(
            p["node_id"] == PEER_NID for p in store2.list_peers()
        )


class TestMetricsCounters:
    """v0.8.5.7: every new audit event type has a matching Prometheus
    counter on BridgeDaemon.metrics. This test asserts each counter
    increments exactly once per fired event, so Grafana alerts fire
    on real conditions rather than silently ignoring them.
    """

    def _make_daemon(self, tmp_path):
        from ironmesh.bridge import BridgeDaemon
        from ironmesh.keys import generate_keypair
        daemon = BridgeDaemon(
            name="metrics-test",
            port=29810,
            passphrase="test-passphrase-12-plus",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "data.db"),
            trust_path=str(tmp_path / "known_peers.json"),
        )
        daemon._keypair = generate_keypair()
        return daemon

    def test_first_observation_bumps_baseline_counter(self, tmp_path):
        daemon = self._make_daemon(tmp_path)
        before = daemon.metrics.peer_cap_baseline
        daemon._handle_cap_observation("p" * 32, {
            "status": "first-observation",
            "hash": "a" * 64,
            "set": ["llm:x"],
        })
        assert daemon.metrics.peer_cap_baseline == before + 1

    def test_changed_with_full_persist_bumps_set_changed_counter(self, tmp_path):
        daemon = self._make_daemon(tmp_path)
        peer = "q" * 32
        ts = daemon._open_trust_store()
        ts.pin_peer(peer, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    trust_state="trusted")
        ts.observe_capabilities(peer, ["role:a"])
        before_changed = daemon.metrics.peer_cap_set_changed
        before_partial = daemon.metrics.peer_cap_binding_partial
        daemon._handle_cap_observation(peer, {
            "status": "changed",
            "old_hash": "a" * 64,
            "new_hash": "b" * 64,
            "old_set": ["role:a"],
            "new_set": ["role:b"],
            "added": ["role:b"],
            "removed": ["role:a"],
        })
        assert daemon.metrics.peer_cap_set_changed == before_changed + 1
        assert daemon.metrics.peer_cap_binding_partial == before_partial

    def test_changed_with_stash_failure_bumps_partial_counter(self, tmp_path):
        # Force stash to fail by tampering the trust file so the
        # read-only latch trips. The B8 partial-failure path should
        # then emit EVENT_PEER_CAP_BINDING_PARTIAL and the partial
        # counter — NOT the set-changed one.
        import json as _json
        daemon = self._make_daemon(tmp_path)
        peer = "r" * 32
        # Seed a peer via the normal path, then corrupt the on-disk MAC.
        ts = daemon._open_trust_store()
        ts.pin_peer(peer, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    trust_state="trusted")
        ts.observe_capabilities(peer, ["role:a"])
        del ts
        bad = {"peers": {peer: {
            "pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "fingerprint": peer,
            "trust_state": "trusted",
        }}, "revoked": {}, "_mac": "0" * 64}
        with open(str(tmp_path / "known_peers.json"), "w") as f:
            _json.dump(bad, f)
        before_changed = daemon.metrics.peer_cap_set_changed
        before_partial = daemon.metrics.peer_cap_binding_partial
        daemon._handle_cap_observation(peer, {
            "status": "changed",
            "old_hash": "a" * 64,
            "new_hash": "b" * 64,
            "old_set": ["role:a"],
            "new_set": ["role:b"],
            "added": ["role:b"],
            "removed": ["role:a"],
        })
        assert daemon.metrics.peer_cap_binding_partial == before_partial + 1
        assert daemon.metrics.peer_cap_set_changed == before_changed

    def test_to_dict_exports_all_nine_new_counters(self):
        """Guard: if someone adds a counter but forgets to_dict, it
        silently won't surface through Prometheus. Assert all nine
        event-driven counters flow end-to-end through the dict.
        """
        from ironmesh.bridge import BridgeDaemon
        d = BridgeDaemon(
            name="x", port=29811, passphrase="test-passphrase-12-plus",
        )
        md = d.metrics.to_dict()
        for key in (
            "peer_cap_set_changed",
            "peer_cap_baseline",
            "peer_cap_accepted",
            "peer_cap_binding_partial",
            "msg_replay_cross_transport",
            "peer_revoked_local",
            "peer_state_changed",
            # v0.8.5.7 B22 additions
            "peer_promoted",
            "peer_blocked",
        ):
            assert key in md, f"metric {key!r} missing from to_dict()"

    def test_scanner_rescues_events_across_rotation(self, tmp_path):
        """B24 regression: when the audit log rotates BETWEEN scans,
        events that landed in the rotated `.1` file after our last
        offset must still be counted. Rotation is detected via inode
        comparison (catches the case where the post-rotation live
        file re-grows past our stored offset before the next scan).
        """
        from ironmesh.audit import AuditLog
        from ironmesh.bridge import BridgeDaemon

        audit_path = tmp_path / "audit.log"
        hmac_key = b"\xd4" * 32
        daemon = BridgeDaemon(
            name="rot-reg",
            port=29823,
            passphrase="test-passphrase-12-plus",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "data.db"),
            trust_path=str(tmp_path / "known_peers.json"),
        )
        daemon._audit = AuditLog(path=str(audit_path), hmac_key=hmac_key,
                                 max_bytes=10_000)
        # First scan adopts the current file identity (no events yet).
        daemon._audit.log("STARTUP", {})
        daemon._audit_counter_offset = 0
        daemon._scan_audit_for_counters(str(audit_path))

        # 40 events, scan → counter = 40
        for i in range(40):
            daemon._audit.log("PEER_PROMOTED", {"peer_id": f"p{i}"})
        daemon._scan_audit_for_counters(str(audit_path))
        assert daemon.metrics.peer_promoted == 40

        # 60 more events. Rotation fires at ~10 KB threshold. Live
        # file re-grows past the old offset before we next scan.
        for i in range(40, 100):
            daemon._audit.log("PEER_PROMOTED", {"peer_id": f"p{i}"})

        assert os.path.exists(str(audit_path) + ".1"), (
            "rotation didn't trigger — test setup issue"
        )

        daemon._scan_audit_for_counters(str(audit_path))
        assert daemon.metrics.peer_promoted == 100, (
            f"expected 100 after rotation rescue, got "
            f"{daemon.metrics.peer_promoted}"
        )

    def test_scanner_counts_peer_promoted_and_blocked(self, tmp_path):
        """B22 regression: PEER_PROMOTED and PEER_BLOCKED fire from
        CLI `set-state trusted` and `set-state blocked` respectively.
        Scanner must map both to their counters so dashboards can
        distinguish them from PEER_STATE_CHANGED.
        """
        from ironmesh.audit import AuditLog
        from ironmesh.bridge import BridgeDaemon

        audit_path = tmp_path / "audit.log"
        hmac_key = b"\xc1" * 32
        daemon = BridgeDaemon(
            name="scanner-test-3",
            port=29822,
            passphrase="test-passphrase-12-plus",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "data.db"),
            trust_path=str(tmp_path / "known_peers.json"),
        )
        daemon._audit = AuditLog(path=str(audit_path), hmac_key=hmac_key)
        daemon._audit_counter_offset = 0

        cli_log = AuditLog(path=str(audit_path), hmac_key=hmac_key)
        cli_log.log("PEER_PROMOTED", {"peer_id": "p1", "actor": "cli"})
        cli_log.log("PEER_PROMOTED", {"peer_id": "p2", "actor": "cli"})
        cli_log.log("PEER_BLOCKED", {"peer_id": "p3", "actor": "cli"})

        daemon._scan_audit_for_counters(str(audit_path))
        assert daemon.metrics.peer_promoted == 2
        assert daemon.metrics.peer_blocked == 1

    def test_audit_scanner_bumps_counter_for_external_event(self, tmp_path):
        """B21 regression: an audit event written by a SEPARATE process
        (CLI, MCP, anything that isn't the daemon itself) must still
        produce a counter bump. The audit-log scanner is the single
        source of truth that reconciles in-process and out-of-process
        writers.
        """
        from ironmesh.audit import AuditLog
        from ironmesh.bridge import BridgeDaemon

        audit_path = tmp_path / "audit.log"
        hmac_key = b"\xa5" * 32

        # Step 1: seed the file with one "legacy" entry so the daemon's
        # startup offset lands past it. The scanner should NOT count
        # pre-startup entries.
        seed_log = AuditLog(path=str(audit_path), hmac_key=hmac_key)
        seed_log.log("PEER_CAP_ACCEPTED", {"peer": "pre-start", "actor": "cli"})

        # Step 2: construct a daemon that would point at this log. We
        # don't call _start() (which binds sockets); instead we wire the
        # fields the scanner needs by hand and drive _scan_audit_for_counters.
        daemon = BridgeDaemon(
            name="scanner-test",
            port=29820,
            passphrase="test-passphrase-12-plus",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "data.db"),
            trust_path=str(tmp_path / "known_peers.json"),
        )
        daemon._audit = seed_log  # so _scan sees the same path
        daemon._audit_counter_offset = os.path.getsize(str(audit_path))

        # Step 3: simulate a CLI process writing an event AFTER daemon startup.
        # The CLI opens its own AuditLog on the same path — this is the
        # pattern `ironmesh trust cap-promote` uses today.
        cli_log = AuditLog(path=str(audit_path), hmac_key=hmac_key)
        cli_log.log("PEER_CAP_ACCEPTED", {
            "peer": "post-start", "actor": "cli",
            "old_hash": "a" * 64, "new_hash": "b" * 64,
        })
        cli_log.log("PEER_REVOKED_LOCAL", {"peer_id": "p", "actor": "cli"})
        cli_log.log("PEER_STATE_CHANGED", {
            "peer_id": "p", "actor": "cli",
            "old_state": "pending-cap-change", "new_state": "trusted",
        })

        # Step 4: run the scanner synchronously (the async loop is just
        # a ticker around this method).
        before_accepted = daemon.metrics.peer_cap_accepted
        before_revoked = daemon.metrics.peer_revoked_local
        before_changed = daemon.metrics.peer_state_changed
        daemon._scan_audit_for_counters(str(audit_path))

        assert daemon.metrics.peer_cap_accepted == before_accepted + 1, (
            "CLI-written PEER_CAP_ACCEPTED should bump the accepted counter"
        )
        assert daemon.metrics.peer_revoked_local == before_revoked + 1
        assert daemon.metrics.peer_state_changed == before_changed + 1

    def test_audit_scanner_does_not_double_count_in_proc_bumps(self, tmp_path):
        """Regression for the deduplication half of the scanner: events
        the daemon ORIGINATED are bumped in-process + reserved; when the
        scanner reads them back it must deduct from the reservation,
        NOT bump again.
        """
        from ironmesh.audit import AuditLog
        from ironmesh.bridge import BridgeDaemon

        audit_path = tmp_path / "audit.log"
        hmac_key = b"\xb7" * 32
        daemon = BridgeDaemon(
            name="scanner-test-2",
            port=29821,
            passphrase="test-passphrase-12-plus",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "data.db"),
            trust_path=str(tmp_path / "known_peers.json"),
        )
        daemon._audit = AuditLog(path=str(audit_path), hmac_key=hmac_key)
        daemon._audit_counter_offset = 0  # scan from the top

        # Simulate daemon emission: bump in-process + reserve.
        daemon._reserve_counter_bump("peer_cap_set_changed")
        daemon._audit.log("PEER_CAP_SET_CHANGED", {"peer": "x"})

        before = daemon.metrics.peer_cap_set_changed
        # Scanner should see the entry but NOT double-count — the
        # reservation consumes one event.
        daemon._scan_audit_for_counters(str(audit_path))
        assert daemon.metrics.peer_cap_set_changed == before, (
            "in-process reserved event should not be bumped again by scanner"
        )
        assert daemon._in_proc_counter_bumps.get(
            "peer_cap_set_changed", 0) == 0, (
            "reservation should be consumed after scanner reads the event"
        )


class TestConcurrentCapPromoteRace:
    """S7 regression: simulate 5 concurrent operator-initiated
    cap-promote calls against a peer in pending-cap-change. Mirrors
    what `ironmesh trust cap-promote` does end-to-end (load, check
    pending, accept, set_trust_state). Race outcome must be:

      - exactly ONE process succeeds (returns True from
        accept_capability_change)
      - the other processes see pending was cleared by the winner
        and return False
      - final on-disk state has the new baseline + trust_state=trusted
      - no torn writes / no MAC corruption
    """

    def test_five_concurrent_promotes_yield_exactly_one_success(self, tmp_path):
        from concurrent.futures import ThreadPoolExecutor

        path = str(tmp_path / "known_peers.json")
        agent_key = b"\xfe" * 32

        # Set up: pin a peer, observe a baseline, then observe a
        # change so it's in pending-cap-change with pending stashed.
        setup = TrustStore(agent_key=agent_key, path=path)
        setup.pin_peer(PEER_NID, PEER_PUB_B64, trust_state="trusted")
        setup.observe_capabilities(PEER_NID, ["role:ops"])
        change = setup.observe_capabilities(PEER_NID, ["role:admin"])
        assert change["status"] == "changed"
        setup.stash_pending_capability_change(PEER_NID, ["role:admin"])
        setup.set_trust_state(PEER_NID, "pending-cap-change")
        # Confirm setup
        rec = setup.get_peer(PEER_NID)
        assert rec["capability_hash_pending"] is not None
        assert setup.get_trust_state(PEER_NID) == "pending-cap-change"

        def cli_cap_promote() -> bool:
            """Replicate cli.py cap-promote handler logic verbatim."""
            store = TrustStore(agent_key=agent_key, path=path)
            r = store.get_peer(PEER_NID)
            if r is None or r.get("capability_hash_pending") is None:
                return False
            ok = store.accept_capability_change(PEER_NID)
            if ok:
                store.set_trust_state(PEER_NID, "trusted")
            return ok

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(cli_cap_promote) for _ in range(5)]
            results = [f.result(timeout=10) for f in futures]

        # Exactly one True, rest False
        successes = sum(1 for r in results if r)
        assert successes == 1, (
            f"S7 regression: expected 1 winner, got {successes}. "
            f"results={results}"
        )

        # Final state: re-open, verify clean trusted with new baseline
        verify = TrustStore(agent_key=agent_key, path=path)
        assert verify._readonly_due_to_mac_failure is False, (
            "concurrent saves corrupted the trust store MAC"
        )
        rec = verify.get_peer(PEER_NID)
        assert rec is not None
        assert verify.get_trust_state(PEER_NID) == "trusted"
        assert rec.get("capability_hash_pending") is None
        assert rec["capability_hash"] == canonical_capability_hash(
            ["role:admin"]
        )


class TestObserveCapabilities:

    def test_first_observation_records_baseline(self, fresh_store):
        fresh_store.pin_peer(PEER_NID, PEER_PUB_B64, trust_state="trusted")
        result = fresh_store.observe_capabilities(
            PEER_NID, ["role:ops", "llm:llama3"],
        )
        assert result["status"] == "first-observation"
        assert "hash" in result
        # Subsequent observation of the same set returns "match"
        result2 = fresh_store.observe_capabilities(
            PEER_NID, ["llm:llama3", "role:ops"],  # different order, same set
        )
        assert result2["status"] == "match"
        assert result2["hash"] == result["hash"]

    def test_changed_returns_diff(self, fresh_store):
        fresh_store.pin_peer(PEER_NID, PEER_PUB_B64, trust_state="trusted")
        fresh_store.observe_capabilities(PEER_NID, ["role:ops", "llm:llama3"])
        result = fresh_store.observe_capabilities(
            PEER_NID, ["role:admin", "llm:llama3"],
        )
        assert result["status"] == "changed"
        assert result["added"] == ["role:admin"]
        assert result["removed"] == ["role:ops"]
        assert result["old_hash"] != result["new_hash"]

    def test_unknown_peer(self, fresh_store):
        result = fresh_store.observe_capabilities(
            "unpinned" * 4, ["role:ops"],
        )
        assert result["status"] == "unknown-peer"

    def test_match_does_not_overwrite_baseline(self, fresh_store):
        fresh_store.pin_peer(PEER_NID, PEER_PUB_B64, trust_state="trusted")
        fresh_store.observe_capabilities(PEER_NID, ["role:ops"])
        rec_before = dict(fresh_store.get_peer(PEER_NID))
        fresh_store.observe_capabilities(PEER_NID, ["role:ops"])
        rec_after = fresh_store.get_peer(PEER_NID)
        assert rec_after["capability_hash"] == rec_before["capability_hash"]

    def test_pending_match_does_not_refire_on_reannounce(self, fresh_store):
        """Regression: a peer already in pending-cap-change that
        re-announces the same pending set must NOT return ``changed``
        (which would cause the bridge to re-emit
        ``PEER_CAP_SET_CHANGED`` every 30s). Returns ``pending-match``
        instead so the bridge can stay silent.
        """
        fresh_store.pin_peer(PEER_NID, PEER_PUB_B64, trust_state="trusted")
        fresh_store.observe_capabilities(PEER_NID, ["role:ops"])
        result1 = fresh_store.observe_capabilities(PEER_NID, ["role:admin"])
        assert result1["status"] == "changed"
        fresh_store.stash_pending_capability_change(PEER_NID, ["role:admin"])
        result2 = fresh_store.observe_capabilities(PEER_NID, ["role:admin"])
        assert result2["status"] == "pending-match"
        for _ in range(5):
            r = fresh_store.observe_capabilities(PEER_NID, ["role:admin"])
            assert r["status"] == "pending-match"

    def test_revert_clears_pending_stash(self, fresh_store):
        """Regression: a peer that changes its caps then reverts back
        to the accepted baseline must have its pending stash cleared.
        Otherwise a later ``accept_capability_change`` would promote
        stale data. Returns ``reverted`` status so the bridge can emit
        an audit event.
        """
        fresh_store.pin_peer(PEER_NID, PEER_PUB_B64, trust_state="trusted")
        fresh_store.observe_capabilities(PEER_NID, ["role:ops"])
        baseline_hash = fresh_store.get_peer(PEER_NID)["capability_hash"]
        fresh_store.observe_capabilities(PEER_NID, ["role:admin"])
        fresh_store.stash_pending_capability_change(PEER_NID, ["role:admin"])
        assert fresh_store.get_peer(PEER_NID).get(
            "capability_hash_pending") is not None
        result = fresh_store.observe_capabilities(PEER_NID, ["role:ops"])
        assert result["status"] == "reverted"
        assert result["hash"] == baseline_hash
        assert result.get("cleared_pending_hash") is not None
        rec = fresh_store.get_peer(PEER_NID)
        assert rec.get("capability_hash_pending") is None
        assert not rec.get("capability_set_pending")
        assert rec["capability_hash"] == baseline_hash


class TestAcceptCapabilityChange:

    def test_accept_promotes_pending_to_baseline(self, fresh_store):
        fresh_store.pin_peer(PEER_NID, PEER_PUB_B64, trust_state="trusted")
        fresh_store.observe_capabilities(PEER_NID, ["role:ops"])
        # Capability set changes — caller stashes the pending set
        result = fresh_store.observe_capabilities(
            PEER_NID, ["role:admin"],
        )
        assert result["status"] == "changed"
        fresh_store.stash_pending_capability_change(PEER_NID, ["role:admin"])
        # Operator accepts
        accepted = fresh_store.accept_capability_change(PEER_NID)
        assert accepted is True
        # New baseline should hash to the new set
        new_hash = canonical_capability_hash(["role:admin"])
        assert fresh_store.get_peer(PEER_NID)["capability_hash"] == new_hash
        # Pending fields are cleared
        assert fresh_store.get_peer(PEER_NID).get("capability_hash_pending") is None

    def test_accept_with_no_pending_returns_false(self, fresh_store):
        fresh_store.pin_peer(PEER_NID, PEER_PUB_B64, trust_state="trusted")
        fresh_store.observe_capabilities(PEER_NID, ["role:ops"])
        # No pending change — accept is a no-op
        accepted = fresh_store.accept_capability_change(PEER_NID)
        assert accepted is False

    def test_accept_unknown_peer_returns_false(self, fresh_store):
        accepted = fresh_store.accept_capability_change("unknown" * 4)
        assert accepted is False


class TestListByCapabilityStatus:

    def test_pending_cap_change_listing(self, fresh_store):
        fresh_store.pin_peer(PEER_NID, PEER_PUB_B64, trust_state="trusted")
        fresh_store.observe_capabilities(PEER_NID, ["role:ops"])
        fresh_store.observe_capabilities(PEER_NID, ["role:admin"])
        fresh_store.stash_pending_capability_change(PEER_NID, ["role:admin"])
        rows = fresh_store.list_by_capability_status("pending-cap-change")
        assert len(rows) == 1
        assert rows[0]["node_id"] == PEER_NID
        assert "role:admin" in rows[0]["pending_set"]
        assert "role:ops" in rows[0]["capability_set"]


# ---------------------------------------------------------------------------
# DedupCache cross-transport detection
# ---------------------------------------------------------------------------

class TestDedupCacheCrossTransport:

    def test_first_arrival_not_duplicate(self):
        cache = DedupCache()
        result = cache.check_and_add_with_transport("src1", "msg1", "ws")
        assert result["duplicate"] is False

    def test_same_transport_replay_is_not_cross_transport(self):
        cache = DedupCache()
        cache.check_and_add_with_transport("src1", "msg1", "ws")
        result = cache.check_and_add_with_transport("src1", "msg1", "ws")
        assert result["duplicate"] is True
        assert result["cross_transport"] is False
        assert result["original_transport"] == "ws"
        assert result["this_transport"] == "ws"

    def test_cross_transport_replay_flagged(self):
        cache = DedupCache()
        cache.check_and_add_with_transport("src1", "msg1", "ws")
        result = cache.check_and_add_with_transport("src1", "msg1", "rns")
        assert result["duplicate"] is True
        assert result["cross_transport"] is True
        assert result["original_transport"] == "ws"
        assert result["this_transport"] == "rns"
        assert result["time_delta_s"] >= 0

    def test_legacy_check_and_add_still_works(self):
        """The pre-v0.8.5.6 check_and_add path remains backward-compatible."""
        cache = DedupCache()
        assert cache.check_and_add("src1", "msg1") is False
        assert cache.check_and_add("src1", "msg1") is True

    def test_legacy_entry_treated_as_unknown_transport(self):
        """A bucket entry created by legacy check_and_add reports
        original_transport=None and is NOT flagged as cross-transport
        because we don't know what transport delivered it originally."""
        cache = DedupCache()
        cache.check_and_add("src1", "msg1")
        result = cache.check_and_add_with_transport("src1", "msg1", "rns")
        assert result["duplicate"] is True
        assert result["original_transport"] is None
        assert result["cross_transport"] is False

    def test_cleanup_expired_handles_both_storage_shapes(self):
        """cleanup_expired must read both bare-float and (ts, transport)
        bucket values without crashing."""
        import time
        cache = DedupCache(ttl=0.0)  # everything expires immediately
        cache.check_and_add("src1", "msg-legacy")
        cache.check_and_add_with_transport("src2", "msg-tagged", "ws")
        time.sleep(0.01)
        removed = cache.cleanup_expired()
        assert removed == 2


# ---------------------------------------------------------------------------
# Bridge-level integration: would have caught B1 (the AttributeError on
# self._trust in the CAPABILITY_ANNOUNCE handler) before live testing.
# ---------------------------------------------------------------------------

class TestBridgeCapBindingIntegration:
    """End-to-end smoke through BridgeDaemon's CAPABILITY_ANNOUNCE path.

    The unit tests in this file exercise TrustStore directly. That's
    necessary but not sufficient — the bridge wires the SDK methods
    into a class instance, and an AttributeError or call-site typo
    only surfaces when you actually invoke the wired path. v0.8.5.6
    shipped (briefly) with self._trust referenced where TrustStore was
    constructed ad-hoc, breaking cap-binding entirely on the live
    daemon while every unit test passed.

    This test instantiates a real BridgeDaemon, populates a peer in
    its trust store, then directly invokes _handle_cap_observation
    with a synthetic observation result — exercising the same code
    path the live CAPABILITY_ANNOUNCE handler takes.
    """

    def test_handle_cap_observation_first_observation(self, tmp_path):
        """First-observation path: emit PEER_CAP_BASELINE, no demote."""
        from ironmesh.bridge import BridgeDaemon

        passphrase = "test-passphrase-12-plus"
        daemon = BridgeDaemon(
            name="test-wiz",
            port=29800,  # high port, no real bind in this test
            passphrase=passphrase,
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "data.db"),
            trust_path=str(tmp_path / "known_peers.json"),
        )
        # _open_trust_store needs _keypair; construct it explicitly
        from ironmesh.keys import generate_keypair
        daemon._keypair = generate_keypair()

        # Simulate the result that observe_capabilities would return
        # for a first-observation scenario
        result = {
            "status": "first-observation",
            "hash": "a" * 64,
            "set": ["llm:llama3", "role:ops"],
        }
        # This was the bug: _handle_cap_observation referenced
        # self._trust which didn't exist. Calling it should NOT raise
        # AttributeError.
        daemon._handle_cap_observation("a" * 32, result)
        # No exception = pass. (Audit isn't initialized in this test
        # so no log entry is written.)

    def test_handle_cap_observation_changed_demotes_peer(self, tmp_path):
        """Changed path: demote the peer + stash pending set."""
        from ironmesh.bridge import BridgeDaemon
        from ironmesh.keys import generate_keypair

        daemon = BridgeDaemon(
            name="test-wiz",
            port=29801,
            passphrase="test-passphrase-12-plus",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "data.db"),
            trust_path=str(tmp_path / "known_peers.json"),
        )
        daemon._keypair = generate_keypair()

        # Pin a peer first (so observe_capabilities has a record to mutate)
        ts = daemon._open_trust_store()
        assert ts is not None, "_open_trust_store should return a TrustStore"
        peer_node_id = "b" * 32
        ts.pin_peer(peer_node_id, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    trust_state="trusted")
        # Record an initial cap baseline
        ts.observe_capabilities(peer_node_id, ["role:ops"])

        # Now simulate a changed-cap observation
        result = {
            "status": "changed",
            "old_hash": "a" * 64,
            "new_hash": "b" * 64,
            "old_set": ["role:ops"],
            "new_set": ["role:admin"],
            "added": ["role:admin"],
            "removed": ["role:ops"],
        }
        # The bug version would raise AttributeError here
        daemon._handle_cap_observation(peer_node_id, result)

        # Verify the peer was demoted
        ts2 = daemon._open_trust_store()
        assert ts2.get_trust_state(peer_node_id) == "pending-cap-change", (
            "peer should be demoted to pending-cap-change after a "
            "changed-cap observation"
        )
        # Verify the pending set was stashed
        rec = ts2.get_peer(peer_node_id)
        assert rec.get("capability_hash_pending") is not None
        assert rec.get("capability_set_pending") == ["role:admin"]

    def test_partial_binding_fires_distinct_audit_event(self, tmp_path):
        """B8 regression: when the stash / demote half of
        _handle_cap_observation fails to persist, the bridge must
        fire EVENT_PEER_CAP_BINDING_PARTIAL rather than claim
        EVENT_PEER_CAP_SET_CHANGED. Forensic review must be able to
        distinguish "change detected + applied" from "change detected
        + persistence failed".
        """
        from ironmesh.bridge import BridgeDaemon
        from ironmesh.keys import generate_keypair

        daemon = BridgeDaemon(
            name="test-wiz",
            port=29803,
            passphrase="test-passphrase-12-plus",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "data.db"),
            trust_path=str(tmp_path / "known_peers.json"),
        )
        daemon._keypair = generate_keypair()

        captured = []

        class _Audit:
            def log(self, event, details):
                captured.append((event, details))
        daemon._audit = _Audit()

        peer_node_id = "c" * 32
        # Force stash+demote to fail by corrupting the trust store
        # on disk so _load marks it read-only (B7 latch).
        import os as _os
        path = str(tmp_path / "known_peers.json")
        ts = daemon._open_trust_store()
        ts.pin_peer(peer_node_id, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    trust_state="trusted")
        ts.observe_capabilities(peer_node_id, ["role:ops"])
        del ts
        # Tamper: write a file with a MAC derived from a DIFFERENT
        # key so the daemon's fresh TrustStore latches read-only.
        import json as _json
        bad = {"peers": {peer_node_id: {
            "pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "fingerprint": peer_node_id,
            "trust_state": "trusted",
        }}, "revoked": {}, "_mac": "0" * 64}
        with open(path, "w") as f:
            _json.dump(bad, f)

        result = {
            "status": "changed",
            "old_hash": "a" * 64,
            "new_hash": "b" * 64,
            "old_set": ["role:ops"],
            "new_set": ["role:admin"],
            "added": ["role:admin"],
            "removed": ["role:ops"],
        }
        daemon._handle_cap_observation(peer_node_id, result)

        from ironmesh.audit import (
            EVENT_PEER_CAP_SET_CHANGED,
            EVENT_PEER_CAP_BINDING_PARTIAL,
        )
        events = [e for e, _ in captured]
        assert EVENT_PEER_CAP_BINDING_PARTIAL in events, (
            "B8 regression: partial-failure did not emit distinct event. "
            f"got events={events}"
        )
        assert EVENT_PEER_CAP_SET_CHANGED not in events, (
            "B8 regression: full-success event fired despite partial "
            "failure. got events={}".format(events)
        )

    def test_open_trust_store_returns_none_before_keypair_loaded(self, tmp_path):
        """_open_trust_store should be None-safe before _keypair is set."""
        from ironmesh.bridge import BridgeDaemon
        daemon = BridgeDaemon(
            name="test-wiz",
            port=29802,
            passphrase="test-passphrase-12-plus",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "data.db"),
            trust_path=str(tmp_path / "known_peers.json"),
        )
        # _keypair starts as None
        assert daemon._open_trust_store() is None
