"""Tests for ironmesh.bridge — daemon lifecycle, handshake, message routing."""

import asyncio
import base64
import json
import os
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from ironmesh.bridge import BridgeDaemon, ensure_agent_keys, rotate_keys, Metrics
from ironmesh.keys import generate_keypair, generate_ephemeral
from ironmesh.crypto import ecdh_exchange, encrypt_message
from ironmesh.protocol import MessageType, PeerState


MESH_PASSPHRASE = "bridge-test-mesh-passphrase-12"


def _keys_envelope(keys_path):
    with open(keys_path) as f:
        return json.load(f)


@pytest.mark.asyncio
class TestEnsureAgentKeys:
    async def test_generates_new_keys(self, keys_path):
        keys = await ensure_agent_keys(keys_path, allow_plaintext=True)
        assert len(keys.ed25519_secret) == 32
        assert len(keys.ed25519_public) == 32
        assert os.path.exists(keys_path)

    async def test_loads_existing_keys(self, keys_path):
        keys1 = await ensure_agent_keys(keys_path, allow_plaintext=True)
        keys2 = await ensure_agent_keys(keys_path, allow_plaintext=True)
        assert keys1.ed25519_public == keys2.ed25519_public

    async def test_rotate_keys(self, keys_path):
        keys1 = await ensure_agent_keys(keys_path, allow_plaintext=True)
        keys2 = await rotate_keys(keys_path, allow_plaintext=True)
        assert keys1.ed25519_public != keys2.ed25519_public

    # Encrypted-by-default: auto-generated key files are encrypted with
    # whatever passphrase is available; plaintext requires the explicit
    # allow_plaintext (--plaintext-keys) opt-in.

    async def test_autogen_encrypts_with_mesh_passphrase_fallback(self, keys_path):
        keys = await ensure_agent_keys(
            keys_path, None, fallback_passphrase=MESH_PASSPHRASE)
        assert _keys_envelope(keys_path)["encrypted"] is True
        # Round-trips with the mesh passphrase (what a daemon restart does).
        again = await ensure_agent_keys(
            keys_path, None, fallback_passphrase=MESH_PASSPHRASE)
        assert again.ed25519_public == keys.ed25519_public

    async def test_autogen_without_any_passphrase_refuses_plaintext(self, keys_path):
        with pytest.raises(ValueError, match="plaintext-keys"):
            await ensure_agent_keys(keys_path)
        assert not os.path.exists(keys_path)

    async def test_plaintext_opt_in_writes_unencrypted(self, keys_path):
        await ensure_agent_keys(keys_path, allow_plaintext=True)
        assert _keys_envelope(keys_path)["encrypted"] is False

    async def test_plaintext_opt_in_skips_reencrypt_migration(self, keys_path):
        """A plaintext key file stays plaintext across restarts when the
        operator explicitly opted in, even with a mesh passphrase."""
        await ensure_agent_keys(keys_path, allow_plaintext=True)
        await ensure_agent_keys(keys_path,
                                fallback_passphrase=MESH_PASSPHRASE,
                                allow_plaintext=True)
        assert _keys_envelope(keys_path)["encrypted"] is False

    async def test_plaintext_file_reencrypted_forward_with_mesh(self, keys_path):
        """Without the opt-in, a plaintext key file is migrated to
        encrypted using the mesh passphrase on next load."""
        keys1 = await ensure_agent_keys(keys_path, allow_plaintext=True)
        keys2 = await ensure_agent_keys(
            keys_path, None, fallback_passphrase=MESH_PASSPHRASE)
        assert keys1.ed25519_public == keys2.ed25519_public
        assert _keys_envelope(keys_path)["encrypted"] is True

    async def test_rotate_without_any_passphrase_refuses_plaintext(self, keys_path):
        await ensure_agent_keys(keys_path, "rotate-test-passphrase-12")
        with pytest.raises(ValueError, match="plaintext-keys"):
            await rotate_keys(keys_path)
        # Original encrypted file untouched.
        assert _keys_envelope(keys_path)["encrypted"] is True

    async def test_rotate_encrypts_with_fallback(self, keys_path):
        keys1 = await ensure_agent_keys(
            keys_path, None, fallback_passphrase=MESH_PASSPHRASE)
        keys2 = await rotate_keys(
            keys_path, None, fallback_passphrase=MESH_PASSPHRASE)
        assert keys1.ed25519_public != keys2.ed25519_public
        assert _keys_envelope(keys_path)["encrypted"] is True


class TestMetrics:
    def test_initial_values(self):
        m = Metrics()
        assert m.messages_sent == 0
        assert m.messages_received == 0

    def test_to_dict(self):
        m = Metrics()
        m.messages_sent = 10
        d = m.to_dict()
        assert d["messages_sent"] == 10
        assert "uptime_seconds" in d


class TestBridgeDaemonInit:
    def test_no_passphrase_raises(self):
        """BridgeDaemon refuses to start without an explicit passphrase."""
        import pytest
        with pytest.raises(ValueError, match="Passphrase is required"):
            BridgeDaemon(name="test")

    def test_default_config_with_passphrase(self):
        d = BridgeDaemon(name="test", passphrase="my-secret-long-12")
        assert d.name == "test"
        assert d.port == 8765
        assert d.passphrase == "my-secret-long-12"

    def test_custom_config(self, tmp_path):
        d = BridgeDaemon(
            name="custom",
            port=9999,
            passphrase="secret-pass-12",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "test.db"),
        )
        assert d.name == "custom"
        assert d.port == 9999
        assert d.passphrase == "secret-pass-12"


@pytest.mark.asyncio
class TestBridgeHandshake:
    async def test_full_handshake_flow(self, keys_path, db_path):
        """Test that the handshake establishes matching session keys on both sides."""
        # This tests the crypto flow without actual WebSocket connections

        # Generate identity keys for two agents
        keys_a = generate_keypair("alice")
        keys_b = generate_keypair("bob")

        # Generate ephemeral keys for this session
        eph_priv_a, eph_pub_a = generate_ephemeral()
        eph_priv_b, eph_pub_b = generate_ephemeral()

        # Each side derives the shared secret
        secret_a = ecdh_exchange(eph_priv_a, eph_pub_b)
        secret_b = ecdh_exchange(eph_priv_b, eph_pub_a)

        # Both sides should derive the same session key
        assert secret_a == secret_b

        # Verify messages can be encrypted/decrypted with the shared key
        plaintext = b"Hello from Alice to Bob!"
        encrypted = encrypt_message(secret_a, plaintext)
        from ironmesh.crypto import decrypt_message
        decrypted = decrypt_message(secret_b, encrypted)
        assert decrypted == plaintext

    async def test_different_sessions_different_keys(self):
        """Each session should produce different ephemeral keys."""
        eph_priv_1, eph_pub_1 = generate_ephemeral()
        eph_priv_2, eph_pub_2 = generate_ephemeral()
        assert bytes(eph_pub_1) != bytes(eph_pub_2)


class TestCounterDriftOnAuditFailure:
    """The daemon bumps Prometheus counters before the paired audit event
    reaches disk and reserves the bump against the scanner loop's dedup
    window. If the audit emit then fails, a stale reservation used to sit
    in `_in_proc_counter_bumps` forever, either leaving the counter +1
    above truth or silently absorbing the next real event of the same
    type. `_emit_audit_with_reservation` releases the reservation on
    failure so neither can happen.
    """

    def _daemon(self, tmp_path):
        return BridgeDaemon(
            name="drift-test",
            passphrase="test-passphrase-12",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "test.db"),
        )

    def test_reserve_then_unreserve_is_zero_net(self, tmp_path):
        d = self._daemon(tmp_path)
        d._reserve_counter_bump("peer_promoted")
        assert d.metrics.peer_promoted == 1
        assert d._in_proc_counter_bumps.get("peer_promoted") == 1
        d._unreserve_counter_bump("peer_promoted")
        assert d.metrics.peer_promoted == 0
        assert d._in_proc_counter_bumps.get("peer_promoted", 0) == 0

    def test_unreserve_floors_at_zero(self, tmp_path):
        d = self._daemon(tmp_path)
        # Unreserve with nothing reserved must not drive the counter
        # negative nor the pending-bumps dict.
        d._unreserve_counter_bump("peer_blocked")
        d._unreserve_counter_bump("peer_blocked")
        assert d.metrics.peer_blocked == 0
        assert d._in_proc_counter_bumps.get("peer_blocked", 0) == 0

    def test_unknown_counter_is_silently_ignored(self, tmp_path):
        d = self._daemon(tmp_path)
        # Reserve + unreserve of a non-existent counter must not raise
        # — the helpers catch AttributeError so a typo in a new event
        # wiring can't crash the daemon.
        d._reserve_counter_bump("no_such_counter")
        d._unreserve_counter_bump("no_such_counter")

    def test_emit_with_reservation_no_audit_bumps_counter_only(self, tmp_path):
        d = self._daemon(tmp_path)
        assert d._audit is None
        ok = d._emit_audit_with_reservation(
            "peer_promoted", "PEER_PROMOTED", {"peer_id": "x"},
        )
        assert ok is False
        # With no audit log attached, the scanner doesn't run either, so
        # the reservation is never consumed. The counter bump is the only
        # observable record — match the prior behavior exactly.
        assert d.metrics.peer_promoted == 1
        assert d._in_proc_counter_bumps.get("peer_promoted") == 1

    def test_emit_with_reservation_emit_success(self, tmp_path):
        d = self._daemon(tmp_path)
        d._audit = MagicMock()
        ok = d._emit_audit_with_reservation(
            "peer_blocked", "PEER_BLOCKED", {"peer_id": "x"},
        )
        assert ok is True
        d._audit.log.assert_called_once_with("PEER_BLOCKED", {"peer_id": "x"})
        assert d.metrics.peer_blocked == 1
        # Reservation sits until the scanner reads the event back; the
        # helper must NOT release it on the happy path.
        assert d._in_proc_counter_bumps.get("peer_blocked") == 1

    def test_emit_with_reservation_emit_failure_releases_reservation(
        self, tmp_path,
    ):
        d = self._daemon(tmp_path)
        d._audit = MagicMock()
        d._audit.log.side_effect = RuntimeError("disk full")
        ok = d._emit_audit_with_reservation(
            "peer_cap_baseline", "PEER_CAP_BASELINE", {"peer": "x"},
        )
        assert ok is False
        d._audit.log.assert_called_once()
        # The whole point: counter is back to zero and the reservation is
        # gone, so the next real event of this type bumps the counter
        # normally (no drift, no silent absorption).
        assert d.metrics.peer_cap_baseline == 0
        assert d._in_proc_counter_bumps.get("peer_cap_baseline", 0) == 0

    def test_no_bare_reserve_counter_bump_outside_helper(self):
        """Static guard: `_reserve_counter_bump` must not be called
        directly from new code. The drift bug this test class exercises
        was born from call sites that reserved a counter, then emitted
        an audit event with a bare `except: pass`. `_emit_audit_with_reservation`
        bundles both so the pattern is impossible. If a future change
        re-introduces a bare `self._reserve_counter_bump(...)` outside
        the helper, this test fails and asks the author to either use
        the helper or justify the new call site.
        """
        import ast
        import pathlib

        repo = pathlib.Path(__file__).resolve().parent.parent
        bridge_src = (repo / "bridge.py").read_text(encoding="utf-8")
        tree = ast.parse(bridge_src)

        allowed_enclosing_methods = {
            "_emit_audit_with_reservation",
            "_reserve_counter_bump",  # the helper may reference its own name in docstring
            "_unreserve_counter_bump",
        }

        offenders: list[tuple[str, int]] = []

        class Visitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.method_stack: list[str] = []

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self.method_stack.append(node.name)
                self.generic_visit(node)
                self.method_stack.pop()

            def visit_AsyncFunctionDef(
                self, node: ast.AsyncFunctionDef,
            ) -> None:
                self.method_stack.append(node.name)
                self.generic_visit(node)
                self.method_stack.pop()

            def visit_Call(self, node: ast.Call) -> None:
                func = node.func
                if isinstance(func, ast.Attribute) and \
                        func.attr == "_reserve_counter_bump":
                    enclosing = (self.method_stack[-1]
                                 if self.method_stack else "<module>")
                    if enclosing not in allowed_enclosing_methods:
                        offenders.append((enclosing, node.lineno))
                self.generic_visit(node)

        Visitor().visit(tree)
        assert not offenders, (
            "Bare _reserve_counter_bump calls outside "
            "_emit_audit_with_reservation re-introduce the drift bug. "
            f"Offenders (method, line): {offenders}. "
            "Use _emit_audit_with_reservation(counter, event, payload) "
            "instead."
        )

    def test_reconcile_from_audit_tail_seeds_counters(self, tmp_path):
        """Daemon restart should NOT zero mirrored counters. The
        reconcile helper reads the audit tail and bumps counters to
        match, so Grafana's rate() queries stay smooth across restart.
        """
        import json as _json
        d = self._daemon(tmp_path)
        # Fabricate an audit log next to the daemon's db path (same
        # directory the real AuditLog writes into).
        audit_path = tmp_path / "audit.log"
        entries = (
            [{"event": "PEER_PROMOTED"}] * 3
            + [{"event": "PEER_CAP_BASELINE"}] * 2
            + [{"event": "PEER_CAP_SET_CHANGED"}] * 1
            + [{"event": "STARTUP"}] * 5  # not in _AUDIT_EVENT_TO_COUNTER
        )
        audit_path.write_text(
            "\n".join(_json.dumps(e) for e in entries) + "\n",
            encoding="utf-8",
        )
        # Attach a minimal audit-log stub (just needs ._path).
        d._audit = type("Stub", (), {"_path": str(audit_path)})()
        assert d.metrics.peer_promoted == 0
        d._reconcile_counters_from_audit_tail(limit=10_000)
        assert d.metrics.peer_promoted == 3
        assert d.metrics.peer_cap_baseline == 2
        assert d.metrics.peer_cap_set_changed == 1
        # Events without a counter mapping are correctly ignored.
        assert getattr(d.metrics, "startup", None) in (None, 0)

    def test_reconcile_respects_limit(self, tmp_path):
        """When the audit log has more than `limit` entries, only the
        tail contributes. Older events beyond the bound are skipped —
        a deliberate trade-off to keep startup fast on huge logs."""
        import json as _json
        d = self._daemon(tmp_path)
        audit_path = tmp_path / "audit.log"
        # 10 PEER_PROMOTED events, but limit=3 means only the last 3
        # contribute (all still PEER_PROMOTED, so the counter is 3
        # not 10).
        entries = [{"event": "PEER_PROMOTED"}] * 10
        audit_path.write_text(
            "\n".join(_json.dumps(e) for e in entries) + "\n",
            encoding="utf-8",
        )
        d._audit = type("Stub", (), {"_path": str(audit_path)})()
        d._reconcile_counters_from_audit_tail(limit=3)
        assert d.metrics.peer_promoted == 3

    def test_reconcile_tolerates_missing_audit_log(self, tmp_path):
        """Daemon start when audit.log doesn't exist must not raise."""
        d = self._daemon(tmp_path)
        d._audit = type("Stub", (), {"_path": str(tmp_path / "nope.log")})()
        d._reconcile_counters_from_audit_tail(limit=100)
        assert d.metrics.peer_promoted == 0

    def test_reconcile_tolerates_torn_json_line(self, tmp_path):
        """A torn trailing line (SIGKILL mid-write) must not crash the
        reconcile — the malformed line is skipped, valid lines count."""
        import json as _json
        d = self._daemon(tmp_path)
        audit_path = tmp_path / "audit.log"
        good = _json.dumps({"event": "PEER_PROMOTED"})
        # Trailing line is a truncated JSON fragment.
        audit_path.write_text(good + "\n" + '{"event": "PEER_PROM',
                              encoding="utf-8")
        d._audit = type("Stub", (), {"_path": str(audit_path)})()
        d._reconcile_counters_from_audit_tail(limit=100)
        assert d.metrics.peer_promoted == 1

    def test_every_counter_name_is_driftproof_on_failure(self, tmp_path):
        # Covers every counter_name that the daemon passes to
        # _emit_audit_with_reservation today. If a new one is added,
        # this test will pass trivially until a site actually drives
        # it through the helper (by design — the helper itself is
        # the contract).
        counter_names = [
            "peer_promoted",
            "peer_blocked",
            "peer_cap_baseline",
            "peer_cap_set_changed",
            "peer_cap_binding_partial",
            "peer_cap_accepted",
            "msg_replay_cross_transport",
        ]
        d = self._daemon(tmp_path)
        d._audit = MagicMock()
        d._audit.log.side_effect = RuntimeError("simulated audit write failure")
        for name in counter_names:
            ok = d._emit_audit_with_reservation(name, "X", {})
            assert ok is False, f"{name}: emit should report failure"
            assert getattr(d.metrics, name) == 0, \
                f"{name}: counter drifted after emit failure"
            assert d._in_proc_counter_bumps.get(name, 0) == 0, \
                f"{name}: reservation leaked after emit failure"


class TestFlushPendingCounters:
    """Flush of queued offline messages used to bypass both per-peer and
    daemon-level send counters (`messages_sent_total`,
    `messages_delivered_total`, `bytes_sent_total`). Caught during the
    v0.9.0 stress run on the live mesh — the counter under-reported any
    traffic that went through the offline-queue → flush path. v0.9.0
    fix: parity with the direct + routed paths."""

    def _daemon(self, tmp_path):
        return BridgeDaemon(
            name="flush-test",
            passphrase="test-passphrase-12",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "test.db"),
        )

    @pytest.mark.asyncio
    async def test_flush_pending_increments_messages_sent_per_message(self, tmp_path):
        d = self._daemon(tmp_path)
        # Stub _send_frame so the flush path runs end-to-end without
        # needing a live WS peer.
        d._send_frame = AsyncMock(return_value=None)
        # Stub the queue so we can hand back synthetic pending entries
        # without touching SQLite. Three pending msgs of varying sizes.
        d._db = MagicMock()
        d._db.get_pending_for_peer = AsyncMock(return_value=[
            {"msg_type": "MSG", "payload": b"A" * 10,  "msg_id": "id-1",
             "source": "0" * 32, "priority": "NORMAL"},
            {"msg_type": "MSG", "payload": b"B" * 50,  "msg_id": "id-2",
             "source": "0" * 32, "priority": "NORMAL"},
            {"msg_type": "MSG", "payload": b"C" * 100, "msg_id": "id-3",
             "source": "0" * 32, "priority": "NORMAL"},
        ])
        d._db.mark_delivered = AsyncMock(return_value=None)

        peer_id = "f" * 32
        # Inject a peer state so the per-peer counters can move.
        from ironmesh.protocol import PeerState as _PS
        ps = _PS(node_id=peer_id)
        ps.session_key = b"k" * 32
        d.peers[peer_id] = ps

        sent_pre = d.metrics.messages_sent
        delivered_pre = d.metrics.messages_delivered
        peer_sent_pre = d.peers[peer_id].messages_sent
        peer_bytes_pre = d.peers[peer_id].bytes_sent_total

        await d._flush_pending(peer_id)

        # Daemon-level counters: +3 sent, +3 delivered.
        assert d.metrics.messages_sent == sent_pre + 3
        assert d.metrics.messages_delivered == delivered_pre + 3
        # Per-peer counters: +3 sent, +160 bytes (10 + 50 + 100).
        assert d.peers[peer_id].messages_sent == peer_sent_pre + 3
        assert d.peers[peer_id].bytes_sent_total == peer_bytes_pre + 160
        # All three were marked delivered in the queue.
        assert d._db.mark_delivered.await_count == 3

    @pytest.mark.asyncio
    async def test_flush_pending_with_no_peer_state_still_increments_daemon_counters(self, tmp_path):
        # When the peer state has been GC'd between queue-and-flush, the
        # daemon-level counter still reflects the send so /metrics stays
        # in sync. The per-peer increment is silently skipped.
        d = self._daemon(tmp_path)
        d._send_frame = AsyncMock(return_value=None)
        d._db = MagicMock()
        d._db.get_pending_for_peer = AsyncMock(return_value=[
            {"msg_type": "MSG", "payload": b"x", "msg_id": "id-1",
             "source": "0" * 32, "priority": "NORMAL"},
        ])
        d._db.mark_delivered = AsyncMock(return_value=None)

        unknown_peer = "9" * 32
        sent_pre = d.metrics.messages_sent
        await d._flush_pending(unknown_peer)
        assert d.metrics.messages_sent == sent_pre + 1
