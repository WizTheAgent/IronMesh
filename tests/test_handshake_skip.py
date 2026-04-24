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
    # in bridge.py uses bridge's own bound RNSLinkAdapter import, so
    # mock against that exact class to avoid module-import ordering
    # issues across test files.
    import ironmesh.bridge as bridge_mod
    if bridge_mod.RNSLinkAdapter is None:
        # bridge couldn't import the adapter (rns not installed in
        # bridge's import path) — fabricate a stand-in class and
        # patch it onto bridge so the isinstance check sees it.
        class _StandIn:
            def __init__(self, h):
                self.remote_identity_hash = h
        bridge_mod.RNSLinkAdapter = _StandIn
        return _StandIn(remote_identity_hash)
    adapter = MagicMock(spec=bridge_mod.RNSLinkAdapter)
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
