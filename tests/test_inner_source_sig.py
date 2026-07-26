"""Regression tests for inner end-to-end source-signature verification.

Historically the inner ``source_signature`` was produced and carried on the
wire but NEVER verified on the production receive paths (``verify_source_key``
was passed only by tests). Any node on a multi-hop path could therefore
attribute arbitrary content to any source identity.

These tests drive the real chokepoint — ``RoutingMixin._verify_inner_source``
(mixed into ``BridgeDaemon``) — which every inbound transport (WebSocket
binary, WebSocket JSON, and RNS/Reticulum) reaches via ``_handle_message``
-> ``_dispatch_message``.

The legacy v1 (payload-only) scheme is verified under a fail-closed policy:
  * control-plane frame types are exempt;
  * a direct frame (source == immediate peer) is covered by the outer
    per-hop signature, so a missing inner sig is tolerated, but a present
    one must verify;
  * a relayed frame (source != immediate peer) MUST carry a verifiable inner
    source signature or it is dropped.

The bound v2 scheme additionally binds source/destination/msg_id — see
``TestV2BoundScheme``.
"""

import base64
import threading
from types import SimpleNamespace

import pytest

from ironmesh.keys import generate_keypair
from ironmesh.protocol import Frame, MessageType
from ironmesh.routing import RoutingMixin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Two distinct 32-hex-ish node ids (length is irrelevant to the policy logic).
SRC_ID = "aa" * 16
RELAY_ID = "bb" * 16
UNKNOWN_ID = "cc" * 16


def _build_daemon(*, known_sources, min_protocol="ironmesh/0.3",
                  store_sources=None):
    """A BridgeDaemon stub with just enough state for _verify_inner_source.

    ``known_sources`` maps node_id -> AgentKeys whose Ed25519 public is
    exposed via the live peer registry (so _lookup_source_verify_key resolves
    them). ``store_sources`` maps node_id -> AgentKeys resolvable ONLY via
    the persistent trust store (the restart / mid-chain-relay case, where
    the source never handshook this process run). Anything in neither map
    is an unknown source.
    """
    daemon = SimpleNamespace(
        peers={
            nid: SimpleNamespace(identity_public=keys.ed25519_public)
            for nid, keys in known_sources.items()
        },
        _pinned_peers={},
        _min_protocol_version=min_protocol,
        _audit=None,
        metrics=SimpleNamespace(inner_source_sig_drops=0),
        node_id="self" + "0" * 28,
        _counter_lock=threading.Lock(),
    )
    store = None
    if store_sources is not None:
        pinned = {
            nid: {"pubkey": base64.b64encode(keys.ed25519_public).decode("ascii")}
            for nid, keys in store_sources.items()
        }
        store = SimpleNamespace(get_peer=pinned.get)
    daemon._open_trust_store = lambda: store
    for name in ("_verify_inner_source", "_lookup_source_verify_key",
                 "_lookup_dest_identity", "_get_peer_identity_key",
                 "_inner_source_allow_v1",
                 "_audit_inner_source_drop", "_SOURCE_SIG_REQUIRED_TYPES"):
        attr = getattr(RoutingMixin, name)
        if callable(attr):
            setattr(daemon, name, attr.__get__(daemon, daemon.__class__))
        else:
            setattr(daemon, name, attr)
    return daemon


def _frame(*, source, payload=b"hello", msg_type=MessageType.MSG, msg_id="m1",
           destination="*"):
    f = Frame(msg_type=msg_type, payload=payload, msg_id=msg_id,
              source=source, destination=destination)
    return f


def _sign_v1(keys, payload):
    """Produce the legacy v1 (payload-only) inner signature."""
    return bytes(keys.get_signing_key().sign(payload).signature)


def _sign_v2(keys, frame):
    """Attach a bound v2 inner signature to ``frame`` (the production form)."""
    from ironmesh.crypto import (
        SIG_CTX_FRAME_INNER_SOURCE, sign_detached_with_context,
    )
    from ironmesh.protocol import canonical_inner_source_bytes
    canon = canonical_inner_source_bytes(
        frame.source, frame.destination, frame.msg_id, frame.payload,
    )
    frame.source_signature = sign_detached_with_context(
        keys.get_signing_key(), SIG_CTX_FRAME_INNER_SOURCE, canon,
    )
    frame.source_sig_scheme = Frame.SOURCE_SIG_SCHEME_V2
    return frame


# ---------------------------------------------------------------------------
# Direct frames (source == immediate peer)
# ---------------------------------------------------------------------------

class TestDirectFrames:
    def test_direct_no_signature_delivers(self):
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _frame(source=SRC_ID)
        # Direct: outer per-hop signature authenticates the sender.
        assert daemon._verify_inner_source(SRC_ID, f) is True
        assert f.source_authenticated is False

    def test_direct_valid_v1_sets_authenticated(self):
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _frame(source=SRC_ID)
        f.source_signature = _sign_v1(src, f.payload)
        assert daemon._verify_inner_source(SRC_ID, f) is True
        assert f.source_authenticated is True

    def test_direct_forged_signature_dropped(self):
        # A present-but-invalid signature is ALWAYS dropped, even direct.
        src = generate_keypair("src")
        attacker = generate_keypair("attacker")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _frame(source=SRC_ID)
        f.source_signature = _sign_v1(attacker, f.payload)  # wrong key
        assert daemon._verify_inner_source(SRC_ID, f) is False


# ---------------------------------------------------------------------------
# Relayed frames (source != immediate peer) — the core verification gap
# ---------------------------------------------------------------------------

class TestRelayedFrames:
    def test_relayed_missing_signature_dropped(self):
        # THE regression: pre-fix code delivered this (source spoofable).
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _frame(source=SRC_ID)  # no inner signature
        assert daemon._verify_inner_source(RELAY_ID, f) is False

    def test_relayed_valid_v1_authenticates(self):
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _frame(source=SRC_ID)
        f.source_signature = _sign_v1(src, f.payload)
        assert daemon._verify_inner_source(RELAY_ID, f) is True
        assert f.source_authenticated is True

    def test_relayed_unknown_source_dropped(self):
        # Signed, but we cannot resolve the claimed originator's identity.
        unknown = generate_keypair("unknown")
        daemon = _build_daemon(known_sources={})  # nobody known
        f = _frame(source=UNKNOWN_ID)
        f.source_signature = _sign_v1(unknown, f.payload)
        assert daemon._verify_inner_source(RELAY_ID, f) is False

    def test_relayed_forged_signature_dropped(self):
        src = generate_keypair("src")
        attacker = generate_keypair("attacker")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _frame(source=SRC_ID)
        f.source_signature = _sign_v1(attacker, f.payload)  # attacker forges
        assert daemon._verify_inner_source(RELAY_ID, f) is False

    def test_relayed_tampered_payload_dropped(self):
        # Valid v1 sig over the original payload; a relay mutates the payload.
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _frame(source=SRC_ID, payload=b"original")
        f.source_signature = _sign_v1(src, b"original")
        f.payload = b"tampered"  # relay alters the body
        assert daemon._verify_inner_source(RELAY_ID, f) is False

    def test_drop_increments_metric(self):
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _frame(source=SRC_ID)  # relayed + unsigned -> drop
        daemon._verify_inner_source(RELAY_ID, f)
        assert daemon.metrics.inner_source_sig_drops == 1


# ---------------------------------------------------------------------------
# Scope + protocol-floor behaviour
# ---------------------------------------------------------------------------

class TestScopeAndFloor:
    @pytest.mark.parametrize("ctrl_type", [
        MessageType.ROUTE_ANNOUNCE,
        MessageType.CAPABILITY_ANNOUNCE,
        MessageType.GROUP_BROADCAST,
        MessageType.HELLO,
    ])
    def test_control_frames_exempt(self, ctrl_type):
        # Control-plane types authenticate via their own mechanisms; a relayed
        # control frame with no frame.source_signature must NOT be dropped.
        daemon = _build_daemon(known_sources={})
        f = _frame(source=SRC_ID, msg_type=ctrl_type)
        assert daemon._verify_inner_source(RELAY_ID, f) is True

    def test_floor_below_09_accepts_v1(self):
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src},
                               min_protocol="ironmesh/0.4")
        f = _frame(source=SRC_ID)
        f.source_signature = _sign_v1(src, f.payload)
        assert daemon._verify_inner_source(RELAY_ID, f) is True

    def test_floor_09_rejects_v1(self):
        # At floor >= 0.9 the unbound legacy v1 form is refused.
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src},
                               min_protocol="ironmesh/0.9")
        f = _frame(source=SRC_ID)
        f.source_signature = _sign_v1(src, f.payload)  # v1
        assert daemon._verify_inner_source(RELAY_ID, f) is False


# ---------------------------------------------------------------------------
# Bound v2 scheme — binds source/destination/msg_id against relay tampering
# ---------------------------------------------------------------------------

class TestV2BoundScheme:
    def test_encrypt_and_serialize_produces_v2(self):
        # The production sign path emits the bound v2 scheme.
        src = generate_keypair("src")
        shared = b"\x07" * 32  # session key; ECDH details irrelevant here
        f = _frame(source=SRC_ID)
        f.encrypt_and_serialize(shared, source_signing_key=src.get_signing_key())
        assert f.source_sig_scheme == Frame.SOURCE_SIG_SCHEME_V2
        assert len(f.source_signature) == 64

    def test_relayed_valid_v2_authenticates(self):
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _sign_v2(src, _frame(source=SRC_ID, destination="dst", msg_id="m9"))
        assert daemon._verify_inner_source(RELAY_ID, f) is True
        assert f.source_authenticated is True

    def test_v2_destination_tamper_dropped(self):
        # A relay rewrites the destination after the originator signed.
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _sign_v2(src, _frame(source=SRC_ID, destination="dst-A"))
        f.destination = "dst-B"  # relay redirection attempt
        assert daemon._verify_inner_source(RELAY_ID, f) is False

    def test_v2_msgid_tamper_dropped(self):
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _sign_v2(src, _frame(source=SRC_ID, msg_id="orig"))
        f.msg_id = "replayed"  # replay-relabel attempt
        assert daemon._verify_inner_source(RELAY_ID, f) is False

    def test_v2_source_reattribution_dropped(self):
        # A relay rewrites source to another *known* peer; the v2 canonical
        # then uses the new source while the signature bound the old one.
        src = generate_keypair("src")
        other = generate_keypair("other")
        daemon = _build_daemon(known_sources={SRC_ID: src, RELAY_ID: other})
        f = _sign_v2(src, _frame(source=SRC_ID))
        f.source = RELAY_ID  # re-attribution attempt; vk resolves to `other`
        assert daemon._verify_inner_source("hop", f) is False

    def test_v2_payload_tamper_dropped(self):
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src})
        f = _sign_v2(src, _frame(source=SRC_ID, payload=b"orig"))
        f.payload = b"tampered"
        assert daemon._verify_inner_source(RELAY_ID, f) is False

    def test_floor_09_accepts_v2(self):
        # Only the legacy v1 form is refused at floor >= 0.9; v2 still verifies.
        src = generate_keypair("src")
        daemon = _build_daemon(known_sources={SRC_ID: src},
                               min_protocol="ironmesh/0.9")
        f = _sign_v2(src, _frame(source=SRC_ID))
        assert daemon._verify_inner_source(RELAY_ID, f) is True

    def test_v2_roundtrips_through_wire(self):
        # Full serialize -> deserialize with the protocol-level callback.
        src = generate_keypair("src")
        shared = b"\x07" * 32
        f = _frame(source=SRC_ID, destination="dst", msg_id="rt1")
        wire = f.encrypt_and_serialize(
            shared, source_signing_key=src.get_signing_key())

        def lookup(node_id):
            assert node_id == SRC_ID
            return src.get_verify_key()

        f2 = Frame.deserialize_and_decrypt(wire, shared, verify_source_key=lookup)
        assert f2.source_sig_scheme == Frame.SOURCE_SIG_SCHEME_V2
        assert f2.payload == f.payload


class TestStorePinnedSourceResolution:
    """The originator's key must resolve from the persistent trust store,
    not only the live peer registry — the live registry is empty for any
    source that has not handshaken THIS process run (daemon restart, or an
    intermediate relay that never met the originator). Regression tests for
    the documented "live peer or existing TOFU pin" contract."""

    def test_relayed_from_store_pinned_source_authenticates(self):
        src = generate_keypair("src")
        d = _build_daemon(known_sources={}, store_sources={SRC_ID: src})
        f = _sign_v2(src, _frame(source=SRC_ID))
        assert d._verify_inner_source(RELAY_ID, f) is True
        assert f.source_authenticated is True

    def test_live_registry_still_wins_when_present(self):
        src = generate_keypair("src")
        d = _build_daemon(known_sources={SRC_ID: src},
                          store_sources={SRC_ID: src})
        f = _sign_v2(src, _frame(source=SRC_ID))
        assert d._verify_inner_source(RELAY_ID, f) is True

    def test_store_miss_still_drops_relayed(self):
        src = generate_keypair("src")
        d = _build_daemon(known_sources={}, store_sources={})  # empty store
        f = _sign_v2(src, _frame(source=SRC_ID))
        assert d._verify_inner_source(RELAY_ID, f) is False
        assert d.metrics.inner_source_sig_drops == 1

    def test_store_open_failure_fails_closed(self):
        src = generate_keypair("src")
        d = _build_daemon(known_sources={})

        def _boom():
            raise OSError("trust store unreadable")

        d._open_trust_store = _boom
        f = _sign_v2(src, _frame(source=SRC_ID))
        assert d._verify_inner_source(RELAY_ID, f) is False
        assert d.metrics.inner_source_sig_drops == 1
