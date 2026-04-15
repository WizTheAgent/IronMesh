"""Tests for IronMesh security fixes — passphrase enforcement, timing-safe
comparison, plaintext rejection, TOFU enforcement, and HELLO signing."""

import base64
import hashlib
import json
import os
import time
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from ironmesh.bridge import BridgeDaemon
from ironmesh.keys import generate_keypair, generate_ephemeral
from ironmesh.crypto import (
    ecdh_exchange, encrypt_message, decrypt_message,
    sign_message, verify_signature, sign_detached, verify_detached,
)
from ironmesh.protocol import (
    Handshake, MessageType, PeerState, ErrorCode,
)


# -----------------------------------------------------------------------
# Fix 1: Refuse to start with default passphrase
# -----------------------------------------------------------------------

class TestPassphraseEnforcement:
    def test_no_passphrase_raises_valueerror(self):
        """BridgeDaemon must refuse to start without a passphrase."""
        with pytest.raises(ValueError, match="Passphrase is required"):
            BridgeDaemon(name="test")

    def test_none_passphrase_raises(self):
        with pytest.raises(ValueError, match="Passphrase is required"):
            BridgeDaemon(name="test", passphrase=None)

    def test_empty_string_passphrase_raises(self):
        with pytest.raises(ValueError):
            BridgeDaemon(name="test", passphrase="")

    def test_valid_passphrase_accepted(self):
        d = BridgeDaemon(name="test", passphrase="hunter2-strong-pass")
        assert d.passphrase == "hunter2-strong-pass"

    def test_cli_get_passphrase_no_default(self):
        """get_passphrase() must not fall back to 'empire'."""
        from ironmesh.cli import get_passphrase
        env = os.environ.copy()
        env.pop("IRONMESH_PASSPHRASE", None)
        env.pop("IRONMESH_PASSPHRASE_FILE", None)
        with patch.dict(os.environ, env, clear=True):
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.isatty.return_value = False
                with pytest.raises(SystemExit):
                    get_passphrase()

    def test_cli_get_passphrase_from_env(self):
        from ironmesh.cli import get_passphrase
        with patch.dict(os.environ, {"IRONMESH_PASSPHRASE": "env-secret"}):
            assert get_passphrase() == "env-secret"


# -----------------------------------------------------------------------
# Fix 2: hmac.compare_digest for passphrase proof
# -----------------------------------------------------------------------

class TestTimingSafeComparison:
    def test_correct_proof_accepted(self):
        nonce = os.urandom(32)
        proof = Handshake.compute_passphrase_proof("secret", nonce)
        assert Handshake.verify_passphrase_proof(proof, "secret", nonce) is True

    def test_wrong_proof_rejected(self):
        nonce = os.urandom(32)
        assert Handshake.verify_passphrase_proof("wrong", "secret", nonce) is False

    def test_uses_hmac_compare_digest(self):
        """Verify the implementation uses hmac.compare_digest, not ==."""
        import hmac
        nonce = os.urandom(32)
        proof = Handshake.compute_passphrase_proof("secret", nonce)

        with patch("ironmesh.protocol.hmac.compare_digest", wraps=hmac.compare_digest) as mock_cmp:
            Handshake.verify_passphrase_proof(proof, "secret", nonce)
            mock_cmp.assert_called_once()

    def test_wrong_passphrase_different_nonce_rejected(self):
        nonce1 = os.urandom(32)
        nonce2 = os.urandom(32)
        proof = Handshake.compute_passphrase_proof("secret", nonce1)
        assert Handshake.verify_passphrase_proof(proof, "secret", nonce2) is False

    def test_proof_is_deterministic(self):
        nonce = os.urandom(32)
        proof1 = Handshake.compute_passphrase_proof("secret", nonce)
        proof2 = Handshake.compute_passphrase_proof("secret", nonce)
        assert proof1 == proof2


# -----------------------------------------------------------------------
# Fix 3: Reject plaintext messages after handshake
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestPlaintextRejection:
    async def test_plaintext_message_rejected(self, tmp_path):
        """Messages without encrypted_payload must be rejected after handshake."""
        d = BridgeDaemon(name="test", passphrase="secret-pass-12",
                         db_path=str(tmp_path / "test.db"))

        # Set up a fake peer with a session key
        peer_state = PeerState(node_id="peer1", address="127.0.0.1:9999")
        session_key = os.urandom(32)
        peer_state.session_key = session_key
        peer_state.verified = True
        d.peers["peer1"] = peer_state

        await d._db.open()

        # Send a plaintext message (no encrypted_payload)
        plaintext_msg = json.dumps({
            "type": MessageType.MSG,
            "from": "peer1",
            "msg_id": "test123",
            "payload": base64.b64encode(b"hello plaintext").decode(),
        })

        # Should silently reject (no crash, no storage)
        await d._handle_message("peer1", plaintext_msg)

        # Verify the message was NOT stored
        assert peer_state.messages_received == 0
        await d._db.close()

    async def test_encrypted_message_accepted(self, tmp_path):
        """Messages with encrypted_payload + signature must be accepted."""
        d = BridgeDaemon(name="test", passphrase="secret-pass-12",
                         db_path=str(tmp_path / "test.db"))

        # Create peer keys so we can sign
        peer_keys = generate_keypair("peer1")
        peer_state = PeerState(node_id="peer1", address="127.0.0.1:9999")
        session_key = os.urandom(32)
        peer_state.session_key = session_key
        peer_state.identity_public = peer_keys.ed25519_public
        peer_state.verified = True
        d.peers["peer1"] = peer_state

        await d._db.open()

        # Send an encrypted + signed message (detached signature)
        payload = b"hello encrypted"
        encrypted = encrypt_message(session_key, payload)
        sig_bytes = sign_detached(peer_keys.get_signing_key(), encrypted)
        enc_msg = json.dumps({
            "type": MessageType.MSG,
            "from": "peer1",
            "msg_id": "test456",
            "encrypted_payload": base64.b64encode(encrypted).decode(),
            "signature": base64.b64encode(sig_bytes).decode(),
            "sequence": 1,
            "timestamp": time.time(),
        })

        await d._handle_message("peer1", enc_msg)
        assert peer_state.messages_received == 1
        await d._db.close()

    async def test_bad_encrypted_payload_rejected(self, tmp_path):
        """Corrupted encrypted_payload should be rejected."""
        d = BridgeDaemon(name="test", passphrase="secret-pass-12",
                         db_path=str(tmp_path / "test.db"))

        peer_state = PeerState(node_id="peer1", address="127.0.0.1:9999")
        peer_state.session_key = os.urandom(32)
        peer_state.verified = True
        d.peers["peer1"] = peer_state

        await d._db.open()

        bad_msg = json.dumps({
            "type": MessageType.MSG,
            "from": "peer1",
            "msg_id": "test789",
            "encrypted_payload": base64.b64encode(b"not-valid-ciphertext").decode(),
        })

        await d._handle_message("peer1", bad_msg)
        assert peer_state.messages_received == 0
        await d._db.close()


# -----------------------------------------------------------------------
# Fix 4: TOFU mismatch disconnects peer
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestTOFUEnforcement:
    async def test_tofu_pins_new_peer(self, tmp_path):
        """First connection should pin the peer's key."""
        d = BridgeDaemon(name="test", passphrase="secret-pass-12")
        # _check_tofu requires a loaded keypair (audit C-03 — trust store MAC key)
        d._keypair = generate_keypair("test-node")

        keys = generate_keypair("peer1")
        identity_b64 = keys.get_public_key_base64()

        mock_trust = MagicMock()
        mock_trust.verify_peer.return_value = "new"
        mock_trust.is_revoked.return_value = False

        with patch("ironmesh.trust.TrustStore", return_value=mock_trust):
            await d._check_tofu("peer1", identity_b64)
            mock_trust.pin_peer.assert_called_once_with("peer1", identity_b64)

    async def test_tofu_trusted_peer_passes(self, tmp_path):
        """Known peer with matching key should pass."""
        d = BridgeDaemon(name="test", passphrase="secret-pass-12")
        d._keypair = generate_keypair("test-node")

        mock_trust = MagicMock()
        mock_trust.verify_peer.return_value = "trusted"
        mock_trust.is_revoked.return_value = False

        with patch("ironmesh.trust.TrustStore", return_value=mock_trust):
            # Should not raise
            await d._check_tofu("peer1", "some-key-b64")

    async def test_tofu_mismatch_raises_and_disconnects(self, tmp_path):
        """TOFU mismatch must raise ConnectionError and clean up peer."""
        d = BridgeDaemon(name="test", passphrase="secret-pass-12")
        d._keypair = generate_keypair("test-node")

        # Set up fake peer state
        mock_ws = AsyncMock()
        d.peers["peer1"] = PeerState(node_id="peer1", address="127.0.0.1:9999")
        d.ws_clients["peer1"] = mock_ws
        d._peer_rate_limiters["peer1"] = MagicMock()

        mock_trust = MagicMock()
        mock_trust.verify_peer.return_value = "mismatch"
        mock_trust.is_revoked.return_value = False

        with patch("ironmesh.trust.TrustStore", return_value=mock_trust):
            with pytest.raises(ConnectionError, match="TOFU mismatch"):
                await d._check_tofu("peer1", "changed-key-b64")

            # Verify peer was cleaned up
            assert "peer1" not in d.peers
            assert "peer1" not in d.ws_clients
            assert "peer1" not in d._peer_rate_limiters

            # Verify error was sent to peer before disconnect
            mock_ws.send.assert_called_once()
            sent = json.loads(mock_ws.send.call_args[0][0])
            assert sent["type"] == MessageType.ERROR
            assert sent["code"] == ErrorCode.AUTH_FAILED
            mock_ws.close.assert_called_once()


# -----------------------------------------------------------------------
# Fix 5: Sign HELLO messages with Ed25519
# -----------------------------------------------------------------------

class TestHelloSigning:
    def test_sign_and_verify_hello_payload(self):
        """HELLO payload signed with Ed25519 should be verifiable."""
        keys = generate_keypair("alice")
        _, eph_pub = generate_ephemeral()

        eph_b64 = base64.b64encode(bytes(eph_pub)).decode()
        identity_b64 = keys.get_public_key_base64()

        # Build canonical payload (sorted keys, compact JSON)
        canonical = json.dumps({
            "ephemeral_public": eph_b64,
            "identity_public": identity_b64,
            "name": "alice",
            "protocol_version": "ironmesh/0.3",
        }, separators=(",", ":"), sort_keys=True)

        # Sign
        signed = sign_message(keys.get_signing_key(), canonical.encode())

        # Verify
        from nacl.signing import VerifyKey
        verify_key = VerifyKey(keys.ed25519_public)
        result = verify_signature(verify_key, signed)
        assert result == canonical.encode()

    def test_wrong_key_fails_verification(self):
        """HELLO signed by Alice should fail verification with Bob's key."""
        alice = generate_keypair("alice")
        bob = generate_keypair("bob")
        _, eph_pub = generate_ephemeral()

        payload = json.dumps({
            "ephemeral_public": base64.b64encode(bytes(eph_pub)).decode(),
            "identity_public": alice.get_public_key_base64(),
            "name": "alice",
            "protocol_version": "ironmesh/0.3",
        }, separators=(",", ":"), sort_keys=True)

        signed = sign_message(alice.get_signing_key(), payload.encode())

        from nacl.signing import VerifyKey
        bob_verify = VerifyKey(bob.ed25519_public)
        with pytest.raises(Exception):  # BadSignatureError
            verify_signature(bob_verify, signed)

    def test_tampered_hello_fails(self):
        """Modifying signed HELLO payload should fail verification."""
        keys = generate_keypair("alice")
        _, eph_pub = generate_ephemeral()

        payload = json.dumps({
            "ephemeral_public": base64.b64encode(bytes(eph_pub)).decode(),
            "identity_public": keys.get_public_key_base64(),
            "name": "alice",
            "protocol_version": "ironmesh/0.3",
        }, separators=(",", ":"), sort_keys=True)

        signed = sign_message(keys.get_signing_key(), payload.encode())

        # Tamper with the signed data (flip a byte in the message part)
        tampered = bytearray(signed)
        tampered[-1] ^= 0xFF
        tampered = bytes(tampered)

        from nacl.signing import VerifyKey
        verify_key = VerifyKey(keys.ed25519_public)
        with pytest.raises(Exception):
            verify_signature(verify_key, tampered)

    def test_canonical_json_is_deterministic(self):
        """Canonical JSON must be deterministic regardless of dict insertion order."""
        payload1 = json.dumps({
            "name": "alice",
            "ephemeral_public": "AAA",
            "identity_public": "BBB",
            "protocol_version": "ironmesh/0.3",
        }, separators=(",", ":"), sort_keys=True)

        payload2 = json.dumps({
            "protocol_version": "ironmesh/0.3",
            "identity_public": "BBB",
            "name": "alice",
            "ephemeral_public": "AAA",
        }, separators=(",", ":"), sort_keys=True)

        assert payload1 == payload2
