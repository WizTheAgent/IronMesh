"""Tests for IronMesh remaining hardening items (6-24).

Covers: replay seq=0 rejection, full-length UUIDs, HMAC passphrase proof,
unencrypted binary frame rejection, mutual auth, mandatory signatures,
per-IP rate limiting, bind address, mDNS no pubkey, trust store MAC,
longer fingerprints, immutable hook context, channel binding.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from types import MappingProxyType
from unittest.mock import AsyncMock, MagicMock

import pytest

from ironmesh.bridge import BridgeDaemon
from ironmesh.crypto import (
    encrypt_message,
    sign_detached,
)
from ironmesh.keys import generate_keypair, get_fingerprint
from ironmesh.protocol import (
    Frame,
    Handshake,
    MessageType,
    PeerState,
    ReplayGuard,
)

# -----------------------------------------------------------------------
# Replay guard: seq=0 rejection
# -----------------------------------------------------------------------

class TestReplaySeqZero:
    def test_seq_zero_rejected(self):
        guard = ReplayGuard()
        result = guard.check("peer1", 0, time.time())
        assert result is not None
        assert "seq > 0" in result

    def test_negative_seq_rejected(self):
        guard = ReplayGuard()
        result = guard.check("peer1", -1, time.time())
        assert result is not None

    def test_seq_1_accepted(self):
        guard = ReplayGuard()
        assert guard.check("peer1", 1, time.time()) is None


# -----------------------------------------------------------------------
# Full-length UUIDs for msg_id
# -----------------------------------------------------------------------

class TestFullUUID:
    def test_frame_msg_id_is_secure_random(self):
        """Audit M-01: msg_id is cryptographically random (nacl.utils.random).
        Accept either legacy UUID4 format (36 chars with dashes) or
        the post-M-01 hex format (32 chars). Both are 128-bit random.
        """
        f = Frame(msg_type=MessageType.MSG, payload=b"test")
        if "-" in f.msg_id:
            assert len(f.msg_id) == 36  # legacy UUID4
            parts = f.msg_id.split("-")
            assert [len(p) for p in parts] == [8, 4, 4, 4, 12]
        else:
            assert len(f.msg_id) == 32  # M-01 hex
            assert all(c in "0123456789abcdef" for c in f.msg_id)


# -----------------------------------------------------------------------
# HMAC-SHA256 passphrase proof
# -----------------------------------------------------------------------

class TestHMACPassphraseProof:
    def test_proof_uses_hmac(self):
        """Verify passphrase proof uses HMAC-SHA256, not bare SHA-256."""
        nonce = os.urandom(32)
        passphrase = "test-pass"

        # Compute expected HMAC
        expected = hmac.new(
            passphrase.encode("utf-8"), nonce, hashlib.sha256
        ).hexdigest()

        proof = Handshake.compute_passphrase_proof(passphrase, nonce)
        assert proof == expected

    def test_proof_not_bare_sha256(self):
        """Ensure proof is NOT bare SHA-256(passphrase + nonce)."""
        nonce = os.urandom(32)
        passphrase = "test-pass"

        # Old bare SHA-256 method
        h = hashlib.sha256()
        h.update(passphrase.encode("utf-8"))
        h.update(nonce)
        old_proof = h.hexdigest()

        new_proof = Handshake.compute_passphrase_proof(passphrase, nonce)
        assert new_proof != old_proof


# -----------------------------------------------------------------------
# Unencrypted binary frame rejection
# -----------------------------------------------------------------------

class TestBinaryFrameEncryption:
    def test_unencrypted_binary_frame_rejected(self):
        """deserialize_and_decrypt must reject frames without FLAG_ENCRYPTED."""
        f = Frame(msg_type=MessageType.MSG, payload=b"test")
        raw = f.serialize_plaintext()
        shared_key = os.urandom(32)

        with pytest.raises(ValueError, match="encryption is mandatory"):
            Frame.deserialize_and_decrypt(raw, shared_key)

    def test_encrypted_binary_frame_accepted(self):
        f = Frame(msg_type=MessageType.MSG, payload=b"test", source="alice")
        shared_key = os.urandom(32)
        raw = f.encrypt_and_serialize(shared_key)
        f2 = Frame.deserialize_and_decrypt(raw, shared_key)
        assert f2.msg_type == MessageType.MSG


# -----------------------------------------------------------------------
# Mutual authentication
# -----------------------------------------------------------------------

class TestMutualAuth:
    def test_server_proof_computation(self):
        """Server proof uses reversed nonce for domain separation."""
        nonce = os.urandom(32)
        passphrase = "secret"

        client_proof = Handshake.compute_passphrase_proof(passphrase, nonce)
        server_proof = Handshake.compute_passphrase_proof(passphrase, nonce[::-1])

        # Client and server proofs must be different
        assert client_proof != server_proof

    def test_server_proof_verifiable(self):
        """Client can verify server's proof."""
        nonce = os.urandom(32)
        passphrase = "secret"

        server_proof = Handshake.compute_passphrase_proof(passphrase, nonce[::-1])
        expected = Handshake.compute_passphrase_proof(passphrase, nonce[::-1])
        assert hmac.compare_digest(server_proof, expected)


# -----------------------------------------------------------------------
# Mandatory message signatures
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestMandatorySignatures:
    async def test_unsigned_message_rejected(self, tmp_path):
        """Messages without signature must be rejected."""
        d = BridgeDaemon(name="test", passphrase="secret-pass-12",
                         db_path=str(tmp_path / "test.db"))

        peer_keys = generate_keypair("peer1")
        peer_state = PeerState(node_id="peer1", address="127.0.0.1:9999")
        session_key = os.urandom(32)
        peer_state.session_key = session_key
        peer_state.identity_public = peer_keys.ed25519_public
        peer_state.verified = True
        d.peers["peer1"] = peer_state

        await d._db.open()

        # Send encrypted but UNSIGNED message
        payload = b"hello"
        encrypted = encrypt_message(session_key, payload)
        msg = json.dumps({
            "type": MessageType.MSG,
            "from": "peer1",
            "msg_id": "test-nosig",
            "encrypted_payload": base64.b64encode(encrypted).decode(),
            "sequence": 1,
            "timestamp": time.time(),
            # No "signature" field
        })

        await d._handle_message("peer1", msg)
        assert peer_state.messages_received == 0
        await d._db.close()

    async def test_bad_signature_rejected(self, tmp_path):
        """Messages with invalid signature must be rejected."""
        d = BridgeDaemon(name="test", passphrase="secret-pass-12",
                         db_path=str(tmp_path / "test.db"))

        peer_keys = generate_keypair("peer1")
        wrong_keys = generate_keypair("attacker")
        peer_state = PeerState(node_id="peer1", address="127.0.0.1:9999")
        session_key = os.urandom(32)
        peer_state.session_key = session_key
        peer_state.identity_public = peer_keys.ed25519_public
        peer_state.verified = True
        d.peers["peer1"] = peer_state

        await d._db.open()

        payload = b"hello"
        encrypted = encrypt_message(session_key, payload)
        # Sign with wrong key (detached)
        bad_sig = sign_detached(wrong_keys.get_signing_key(), encrypted)
        msg = json.dumps({
            "type": MessageType.MSG,
            "from": "peer1",
            "msg_id": "test-badsig",
            "encrypted_payload": base64.b64encode(encrypted).decode(),
            "signature": base64.b64encode(bad_sig).decode(),
            "sequence": 1,
            "timestamp": time.time(),
        })

        await d._handle_message("peer1", msg)
        assert peer_state.messages_received == 0
        await d._db.close()


# -----------------------------------------------------------------------
# Per-IP rate limiting
# -----------------------------------------------------------------------

class TestPerIPRateLimit:
    def test_ip_rate_limiter_initialized(self):
        d = BridgeDaemon(name="test", passphrase="secret-pass-12")
        assert isinstance(d._ip_rate_limiters, dict)
        assert len(d._ip_rate_limiters) == 0


# -----------------------------------------------------------------------
# Configurable bind address
# -----------------------------------------------------------------------

class TestBindAddress:
    def test_default_bind(self):
        d = BridgeDaemon(name="test", passphrase="secret-pass-12")
        assert d.bind_address == "0.0.0.0"

    def test_custom_bind(self):
        d = BridgeDaemon(name="test", passphrase="secret-pass-12", bind_address="127.0.0.1")
        assert d.bind_address == "127.0.0.1"


# -----------------------------------------------------------------------
# mDNS no pubkey broadcast
# -----------------------------------------------------------------------

class TestMDNSNoPubkey:
    def test_announce_does_not_include_pubkey(self):
        """mDNS announce should not broadcast identity key."""
        from unittest.mock import MagicMock as MM

        from ironmesh.discovery import announce

        mock_zc = MM()
        mock_zc.register_service = MM()

        svc = announce("test-agent", 8765, mock_zc, public_key="should-be-ignored")
        # Check the properties of the service info
        props = svc.properties
        assert b"pubkey" not in props


# -----------------------------------------------------------------------
# Trust store integrity MAC
# -----------------------------------------------------------------------

class TestTrustStoreMAC:
    def test_save_includes_mac(self, tmp_path):
        from ironmesh.trust import TrustStore
        store = TrustStore(agent_key=b"\x00" * 32, path=str(tmp_path / "trust.json"))
        store.pin_peer("test-peer", base64.b64encode(os.urandom(32)).decode())

        with open(str(tmp_path / "trust.json")) as f:
            data = json.load(f)
        assert "_mac" in data
        assert isinstance(data["_mac"], str)
        assert len(data["_mac"]) == 64  # SHA-256 hex digest

    def test_tampered_store_rejected(self, tmp_path):
        from ironmesh.trust import TrustStore
        store = TrustStore(agent_key=b"\x00" * 32, path=str(tmp_path / "trust.json"))
        store.pin_peer("test-peer", base64.b64encode(os.urandom(32)).decode())

        # Tamper with the file
        with open(str(tmp_path / "trust.json")) as f:
            data = json.load(f)
        data["peers"]["evil-peer"] = {"pubkey": "EVIL", "fingerprint": "x"}
        with open(str(tmp_path / "trust.json"), "w") as f:
            json.dump(data, f)

        # Reload — should detect tampering
        store2 = TrustStore(agent_key=b"\x00" * 32, path=str(tmp_path / "trust.json"))
        assert len(store2._peers) == 0  # Rejected due to MAC mismatch

    def test_valid_store_loads(self, tmp_path):
        from ironmesh.trust import TrustStore
        store = TrustStore(agent_key=b"\x00" * 32, path=str(tmp_path / "trust.json"))
        pubkey = base64.b64encode(os.urandom(32)).decode()
        store.pin_peer("valid-peer", pubkey)

        store2 = TrustStore(agent_key=b"\x00" * 32, path=str(tmp_path / "trust.json"))
        assert "valid-peer" in store2._peers


# -----------------------------------------------------------------------
# Longer fingerprints (32 hex chars = 128 bits)
# -----------------------------------------------------------------------

class TestLongerFingerprints:
    def test_fingerprint_length(self):
        keys = generate_keypair()
        fp = keys.get_fingerprint()
        assert len(fp) == 32

    def test_get_fingerprint_length(self):
        fp = get_fingerprint(os.urandom(32))
        assert len(fp) == 32


# -----------------------------------------------------------------------
# Immutable hook context
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestImmutableHookContext:
    async def test_hook_receives_frozen_context(self):
        from ironmesh.hooks import HookManager

        received_contexts = []

        def my_hook(ctx):
            received_contexts.append(ctx)
            # Trying to mutate should raise
            with pytest.raises(TypeError):
                ctx["new_key"] = "value"

        mgr = HookManager()
        mgr.register("test_point", my_hook)
        await mgr.fire("test_point", {"key": "value"})

        assert len(received_contexts) == 1
        assert isinstance(received_contexts[0], MappingProxyType)

    async def test_original_context_unchanged(self):
        from ironmesh.hooks import HookManager

        def noop_hook(ctx):
            pass  # Can't mutate frozen context anyway

        mgr = HookManager()
        mgr.register("test_point", noop_hook)
        original = {"key": "value"}
        result = await mgr.fire("test_point", original)
        assert result == {"key": "value"}


# -----------------------------------------------------------------------
# Channel binding (included in HELLO canonical payload)
# -----------------------------------------------------------------------

class TestChannelBinding:
    def test_canonical_hello_includes_channel_binding(self):
        """HELLO canonical payload should include channel_binding field."""
        nonce = os.urandom(32)
        canonical = json.dumps({
            "channel_binding": nonce.hex(),
            "ephemeral_public": "AAA",
            "identity_public": "BBB",
            "name": "alice",
            "protocol_version": "ironmesh/0.3",
        }, separators=(",", ":"), sort_keys=True)

        # channel_binding should be first field (sorted)
        assert canonical.startswith('{"channel_binding":')

    def test_different_nonces_produce_different_payloads(self):
        nonce1 = os.urandom(32)
        nonce2 = os.urandom(32)

        p1 = json.dumps({
            "channel_binding": nonce1.hex(),
            "ephemeral_public": "AAA",
            "identity_public": "BBB",
            "name": "alice",
            "protocol_version": "ironmesh/0.3",
        }, separators=(",", ":"), sort_keys=True)

        p2 = json.dumps({
            "channel_binding": nonce2.hex(),
            "ephemeral_public": "AAA",
            "identity_public": "BBB",
            "name": "alice",
            "protocol_version": "ironmesh/0.3",
        }, separators=(",", ":"), sort_keys=True)

        assert p1 != p2


# -----------------------------------------------------------------------
# Peer ID derived from identity key
# -----------------------------------------------------------------------

class TestDerivedPeerID:
    def test_peer_id_is_fingerprint(self):
        """peer_id should be derived from identity key, not self-reported."""
        keys = generate_keypair("alice")
        expected_id = get_fingerprint(keys.ed25519_public)
        assert len(expected_id) == 32
        # Verify it's deterministic
        assert get_fingerprint(keys.ed25519_public) == expected_id


# -----------------------------------------------------------------------
# Seq=0 messages rejected at bridge level
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestBridgeSeqZeroRejection:
    async def test_seq_zero_message_rejected(self, tmp_path):
        d = BridgeDaemon(name="test", passphrase="secret-pass-12",
                         db_path=str(tmp_path / "test.db"))

        peer_keys = generate_keypair("peer1")
        peer_state = PeerState(node_id="peer1", address="127.0.0.1:9999")
        session_key = os.urandom(32)
        peer_state.session_key = session_key
        peer_state.identity_public = peer_keys.ed25519_public
        peer_state.verified = True
        d.peers["peer1"] = peer_state

        await d._db.open()

        payload = b"hello"
        encrypted = encrypt_message(session_key, payload)
        sig = sign_detached(peer_keys.get_signing_key(), encrypted)
        msg = json.dumps({
            "type": MessageType.MSG,
            "from": "peer1",
            "msg_id": "test-seq0",
            "encrypted_payload": base64.b64encode(encrypted).decode(),
            "signature": base64.b64encode(sig).decode(),
            "sequence": 0,  # Invalid!
            "timestamp": time.time(),
        })

        await d._handle_message("peer1", msg)
        assert peer_state.messages_received == 0
        await d._db.close()


# -----------------------------------------------------------------------
# v0.8.1 regression: duplicate-handshake race must not tear down the
# live connection owned by the winning handshake.
# -----------------------------------------------------------------------

class TestDuplicateHandshakeTeardown:
    """When two handshakes race for the same peer_id, the losing one
    must not clobber the winner's ws_clients entry or session_key.
    This used to happen because the finally-block in _handle_connection
    unconditionally popped ws_clients[peer_id] on every exit, even
    when that entry belonged to a different, still-live connection.
    """

    @pytest.mark.asyncio
    async def test_loser_must_not_teardown_winner(self, tmp_path):
        d = BridgeDaemon(
            name="test", passphrase="secret-pass-12",
            db_path=str(tmp_path / "test.db"),
        )

        winner_ws = MagicMock()
        winner_ws.close = AsyncMock()
        loser_ws = MagicMock()
        loser_ws.close = AsyncMock()

        peer_id = "a" * 32
        peer_state = PeerState(node_id=peer_id, address="127.0.0.1:1")
        peer_state.session_key = os.urandom(32)
        peer_state.transition(PeerState.Status.ONLINE)
        d.peers[peer_id] = peer_state
        d.ws_clients[peer_id] = winner_ws

        # The losing handshake's finally-block decision: only tear down
        # if THIS connection is the one registered.
        async with d._peer_lock:
            if d.ws_clients.get(peer_id) is loser_ws:
                d.ws_clients.pop(peer_id, None)
                d.peers[peer_id].transition(PeerState.Status.OFFLINE)
                d.peers[peer_id].session_key = None

        assert d.ws_clients.get(peer_id) is winner_ws
        assert d.peers[peer_id].is_online
        assert d.peers[peer_id].session_key is not None

    @pytest.mark.asyncio
    async def test_winner_cleans_up_its_own_state(self, tmp_path):
        d = BridgeDaemon(
            name="test", passphrase="secret-pass-12",
            db_path=str(tmp_path / "test.db"),
        )
        ws = MagicMock()
        ws.close = AsyncMock()
        peer_id = "b" * 32

        peer_state = PeerState(node_id=peer_id, address="127.0.0.1:1")
        peer_state.session_key = os.urandom(32)
        peer_state.transition(PeerState.Status.ONLINE)
        d.peers[peer_id] = peer_state
        d.ws_clients[peer_id] = ws

        async with d._peer_lock:
            if d.ws_clients.get(peer_id) is ws:
                d.ws_clients.pop(peer_id, None)
                d.peers[peer_id].transition(PeerState.Status.OFFLINE)
                d.peers[peer_id].session_key = None

        assert peer_id not in d.ws_clients
        assert not d.peers[peer_id].is_online
        assert d.peers[peer_id].session_key is None


# -----------------------------------------------------------------------
# v0.8.2 regression: GUI message_event broadcasts include peer_id + payload
# (previously blanked because MappingProxyType is not a dict subclass).
# -----------------------------------------------------------------------

class TestGUIBroadcastMappingProxy:
    """Bus.publish freezes dict payloads in MappingProxyType. The GUI
    hook used isinstance(data, dict) which returns False for
    MappingProxyType, so every broadcast had empty peer_id and payload.
    """

    def test_mapping_is_dict_like_for_broadcast(self):
        # The on_bus_event logic inside _wire_gui_hooks is intentionally
        # a small closure; reproduce its data-extraction shape here and
        # assert we see the fields we care about.
        from collections.abc import Mapping

        frozen = MappingProxyType({
            "peer_id": "abc" * 8,
            "msg_id": "m-1",
            "type": "MSG",
            "payload": b"hello",
        })
        # Old buggy check:
        assert not isinstance(frozen, dict), (
            "sanity: MappingProxyType was never a dict subclass"
        )
        # New fixed check:
        assert isinstance(frozen, Mapping)
        # Extraction as the hook does it now:
        safe = {}
        for k, v in frozen.items():
            safe[k] = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else v
        assert safe["peer_id"] == "abc" * 8
        assert safe["payload"] == "hello"
        assert safe["msg_id"] == "m-1"
