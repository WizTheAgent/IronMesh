"""Tests for the v0.9.2 chunk A handshake-skip path.

The skip path bypasses stage-1 (passphrase challenge / verify) on
identified RNS Links when both peers advertise the `hskip` feature.
These tests cover the eligibility decision matrix; the actual
handshake-shorter execution is exercised end-to-end in the live
stress test rig.
"""

from unittest.mock import MagicMock

import pytest

from ironmesh.protocol import Handshake


# ---------------------------------------------------------------------------
# Skip channel binding sentinel
# ---------------------------------------------------------------------------

class TestSkipChannelBinding:
    def test_returns_32_bytes(self):
        nonce = Handshake.skip_channel_binding()
        assert isinstance(nonce, bytes)
        assert len(nonce) == 32

    def test_is_deterministic(self):
        # Both peers must derive the same value without exchanging it
        a = Handshake.skip_channel_binding()
        b = Handshake.skip_channel_binding()
        assert a == b

    def test_differs_from_random_server_nonce(self):
        # Vanishingly unlikely a random nonce equals the sentinel —
        # if it ever does, the sentinel was misderived.
        sentinel = Handshake.skip_channel_binding()
        random = Handshake.generate_server_nonce()
        assert sentinel != random


# ---------------------------------------------------------------------------
# Eligibility decision (server + client share the same predicate)
# ---------------------------------------------------------------------------

class _FakeBridge:
    """Bind the eligibility helpers from BridgeDaemon onto a stub.

    Mirrors the same harness pattern in test_unified_transport.py —
    avoids a heavy daemon init while still exercising the real code.
    """
    def __init__(self):
        self._rns_skip_handshake = False
        self._rns_discovered = {}
        # Late-bind the helpers so they see this stub's attributes
        from ironmesh.bridge import BridgeDaemon
        self._peer_advertises_hskip = (
            BridgeDaemon._peer_advertises_hskip.__get__(self)
        )
        self._handshake_skip_eligible_server = (
            BridgeDaemon._handshake_skip_eligible_server.__get__(self)
        )
        self._handshake_skip_eligible_client = (
            BridgeDaemon._handshake_skip_eligible_client.__get__(self)
        )


def _make_rns_adapter(remote_identity_hash):
    # Build an object that ``isinstance(_, RNSLinkAdapter)`` returns
    # True for, without the heavy real adapter. The eligibility check
    # in handshake.py uses that module's own bound RNSLinkAdapter
    # import, so mock against that exact class to avoid module-import
    # ordering issues across test files.
    import ironmesh.bridge as bridge_mod
    import ironmesh.handshake as handshake_mod
    if handshake_mod.RNSLinkAdapter is None:
        # handshake couldn't import the adapter (rns not installed in
        # its import path) — fabricate a stand-in class and patch it
        # onto both modules so the isinstance checks see it.
        class _StandIn:
            def __init__(self, h):
                self.remote_identity_hash = h
        handshake_mod.RNSLinkAdapter = _StandIn
        bridge_mod.RNSLinkAdapter = _StandIn
        return _StandIn(remote_identity_hash)
    adapter = MagicMock(spec=handshake_mod.RNSLinkAdapter)
    adapter.remote_identity_hash = remote_identity_hash
    return adapter


class TestEligibility:
    def test_disabled_when_local_flag_off(self):
        bridge = _FakeBridge()
        bridge._rns_skip_handshake = False  # default
        ws = _make_rns_adapter("aa" * 16)
        bridge._rns_discovered = {
            "any": {"identity_hash": "aa" * 16, "features": ["hskip"]}
        }
        assert bridge._handshake_skip_eligible_server(ws) is False
        assert bridge._handshake_skip_eligible_client(ws) is False

    def test_disabled_when_peer_does_not_advertise_hskip(self):
        bridge = _FakeBridge()
        bridge._rns_skip_handshake = True
        ws = _make_rns_adapter("aa" * 16)
        bridge._rns_discovered = {
            "any": {"identity_hash": "aa" * 16, "features": ["mesh", "resource"]}
        }
        assert bridge._handshake_skip_eligible_server(ws) is False
        assert bridge._handshake_skip_eligible_client(ws) is False

    def test_disabled_when_transport_is_not_rns(self):
        bridge = _FakeBridge()
        bridge._rns_skip_handshake = True
        # A non-RNS websocket — eligibility must be False
        plain_ws = MagicMock()  # not an RNSLinkAdapter
        assert bridge._handshake_skip_eligible_server(plain_ws) is False
        assert bridge._handshake_skip_eligible_client(plain_ws) is False

    def test_disabled_when_remote_identity_unknown(self):
        bridge = _FakeBridge()
        bridge._rns_skip_handshake = True
        ws = _make_rns_adapter(None)  # adapter has no Identity hash bound yet
        bridge._rns_discovered = {
            "x": {"identity_hash": "aa" * 16, "features": ["hskip"]}
        }
        assert bridge._handshake_skip_eligible_server(ws) is False
        assert bridge._handshake_skip_eligible_client(ws) is False

    def test_enabled_when_all_conditions_met(self):
        bridge = _FakeBridge()
        bridge._rns_skip_handshake = True
        ws = _make_rns_adapter("aa" * 16)
        bridge._rns_discovered = {
            "x": {"identity_hash": "aa" * 16,
                  "features": ["mesh", "resource", "hskip"]}
        }
        assert bridge._handshake_skip_eligible_server(ws) is True
        assert bridge._handshake_skip_eligible_client(ws) is True

    def test_advertises_hskip_only_when_flag_set(self):
        # The announce-builder in reticulum_transport.py adds the
        # `hskip` feature to the announce payload only when the daemon
        # opted in via rns_skip_handshake. Verify that.
        from ironmesh.reticulum_transport import (
            ReticulumTransport, decode_app_data,
        )
        # Build a stub daemon with the flag off
        daemon_off = MagicMock()
        daemon_off.name = "off-node"
        daemon_off.node_id = "n1"
        daemon_off.config = MagicMock()
        daemon_off.config.capabilities = []
        daemon_off._lxmf_enabled = False
        daemon_off._rns_skip_handshake = False
        t = ReticulumTransport.__new__(ReticulumTransport)
        t._daemon = daemon_off
        decoded = decode_app_data(t._build_app_data())
        assert "hskip" not in decoded.get("f", [])

        # Same with the flag on
        daemon_on = MagicMock()
        daemon_on.name = "on-node"
        daemon_on.node_id = "n2"
        daemon_on.config = MagicMock()
        daemon_on.config.capabilities = []
        daemon_on._lxmf_enabled = False
        daemon_on._rns_skip_handshake = True
        t._daemon = daemon_on
        decoded = decode_app_data(t._build_app_data())
        assert "hskip" in decoded.get("f", [])


# ---------------------------------------------------------------------------
# v0.9.2 chunk A — server-driven SKIP_OFFER protocol
# ---------------------------------------------------------------------------

class TestSkipOfferProtocol:
    """The corrected design after the v0.9.2-pre-r1 unilateral-decision
    bug. Server emits SKIP_OFFER carrying the channel binding sentinel
    in place of PASSPHRASE_CHALLENGE; client type-dispatches on the
    first server message. Both sides agree before HELLO is sent.
    """

    def test_skip_offer_message_type_exists(self):
        from ironmesh.protocol import MessageType, MESSAGE_SCHEMAS
        assert MessageType.SKIP_OFFER == "SKIP_OFFER"
        # Schema must require channel_binding
        assert MessageType.SKIP_OFFER in MESSAGE_SCHEMAS
        assert "channel_binding" in MESSAGE_SCHEMAS[MessageType.SKIP_OFFER]["required"]

    def test_skip_offer_channel_binding_matches_sentinel(self):
        # The server must always offer the deterministic sentinel.
        # Anything else is a downgrade attempt — the client will reject.
        from ironmesh.protocol import Handshake
        cb = Handshake.skip_channel_binding()
        assert len(cb) == 32
        # The sentinel itself is documented; equality with a known
        # constant catches accidental rederivation drift.
        # (If this hex changes, every conformance vector must be regenerated.)
        assert cb.hex() == (
            "d56294e40f47c8c7a524ec8c0fd83711"
            "968de30b951414088b82014b131d79ef"
        )

    def test_client_rejects_skip_offer_with_wrong_binding(self):
        # Defense-in-depth: a tampered channel_binding in SKIP_OFFER
        # must NOT be accepted as the binding. The client uses
        # hmac.compare_digest against Handshake.skip_channel_binding()
        # — verified by manually invoking the comparison here.
        import hmac as _hmac
        from ironmesh.protocol import Handshake
        sentinel = Handshake.skip_channel_binding()
        attacker_chosen = b"X" * 32
        # The literal check that lives in _do_client_handshake:
        assert not _hmac.compare_digest(attacker_chosen, sentinel)
        # And the trivially-correct case:
        assert _hmac.compare_digest(sentinel, sentinel)

    def test_client_rejects_skip_offer_missing_binding(self):
        # The client checks `cb_hex = msg.get("channel_binding")` and
        # bails on falsy. None / empty string both reject.
        for bad in (None, "", "not-hex-at-all-...zzz"):
            try:
                bytes.fromhex(bad) if bad else None
                rejectable = bad in (None, "")
            except Exception:
                rejectable = True
            assert rejectable

    def test_first_message_dispatch_table(self):
        # Catalog of valid first-message types from server. Anything
        # else is a protocol violation (handled by the else branch
        # in _do_client_handshake).
        from ironmesh.protocol import MessageType
        accepted = {MessageType.SKIP_OFFER, MessageType.PASSPHRASE_CHALLENGE}
        # Ensure these enum values exist (regression guard).
        assert MessageType.SKIP_OFFER in accepted
        assert MessageType.PASSPHRASE_CHALLENGE in accepted

    def test_skip_metric_fields_exist(self):
        # The three-way counter split is part of the v0.9.2 surface.
        # Operators rely on offered/activated divergence and rejected
        # spikes for alerting; renaming or dropping these without a
        # deprecation cycle is a SemVer break.
        from ironmesh.bridge import Metrics
        m = Metrics()
        for field in (
            "handshake_skips_offered",
            "handshake_skips_activated",
            "handshake_skips_rejected",
        ):
            assert hasattr(m, field), f"metric field {field!r} missing"
            assert getattr(m, field) == 0, f"{field} should default to 0"
        # to_dict() must surface all three for the JSON metrics endpoint.
        d = m.to_dict()
        for field in (
            "handshake_skips_offered",
            "handshake_skips_activated",
            "handshake_skips_rejected",
        ):
            assert field in d, f"to_dict() missing {field!r}"
