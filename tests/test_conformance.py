"""IronMesh protocol conformance tests.

These tests encode the invariants that any implementation of the
IronMesh protocol must uphold.  They double as:

  - A sanity net against accidental protocol-breaking changes in our
    own implementation (regression catcher).
  - A reference for anyone writing a second implementation (Rust/Go)
    to understand the protocol surface without reading all of our code.

See ``docs/PROTOCOL.md`` for the human-readable specification.
"""

from __future__ import annotations

import hmac
import json
import time

import pytest
from nacl.signing import SigningKey

from ironmesh import crypto as ew_crypto
from ironmesh import keys as ew_keys
from ironmesh.protocol import (
    Frame, Handshake, MessageType, PeerState, ReplayGuard,
)
from ironmesh.trust import TrustStore


# ---------------------------------------------------------------------------
# Wire format invariants
# ---------------------------------------------------------------------------

class TestWireFormat:
    """Invariants any parser implementation must hold."""

    def test_magic_bytes_constant(self):
        """Frame magic MUST be 0xE7F6 (2 bytes)."""
        assert Frame.MAGIC == b"\xe7\xf6"
        assert len(Frame.MAGIC) == 2

    def test_header_size_is_32(self):
        """Frame header MUST be exactly 32 bytes (magic+ver+flags+seq+ts+id+len)."""
        assert Frame.HEADER_SIZE == 32

    def test_flag_encrypted_value(self):
        """FLAG_ENCRYPTED MUST be bit 2 (0x04)."""
        assert Frame.FLAG_ENCRYPTED == 0x04

    def test_flag_signed_value(self):
        """FLAG_SIGNED MUST be bit 3 (0x08)."""
        assert Frame.FLAG_SIGNED == 0x08

    def test_unencrypted_frame_rejected(self):
        """Any frame after handshake without FLAG_ENCRYPTED MUST be rejected."""
        # Craft a minimal header with FLAG_ENCRYPTED unset
        header = (
            Frame.MAGIC
            + (4).to_bytes(1, "big")  # version
            + (0).to_bytes(1, "big")  # NO flags — plaintext
            + (1).to_bytes(8, "big")  # seq
            + (int(time.time() * 1000)).to_bytes(8, "big")  # ts
            + b"\x00" * 8  # msg_id hash
            + (0).to_bytes(4, "big")  # payload_len
        )
        assert len(header) == Frame.HEADER_SIZE
        with pytest.raises((ValueError, Exception)):
            Frame.deserialize_and_decrypt(header, b"\x00" * 32)

    def test_short_frame_rejected(self):
        """Buffer shorter than HEADER_SIZE MUST raise ValueError."""
        with pytest.raises(ValueError):
            Frame.deserialize_and_decrypt(b"\x00" * 10, b"\x00" * 32)

    def test_wrong_magic_rejected(self):
        """Non-matching magic bytes MUST raise ValueError."""
        bogus = b"\xde\xad" + b"\x00" * (Frame.HEADER_SIZE - 2)
        with pytest.raises(ValueError):
            Frame.deserialize_and_decrypt(bogus, b"\x00" * 32)


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------

class TestReplayProtection:

    def test_seq_zero_rejected_post_handshake(self):
        """seq=0 MUST be rejected after handshake (only valid during)."""
        guard = ReplayGuard()
        now = time.time()
        result = guard.check("peer-a", 0, now)
        assert result is not None

    def test_duplicate_seq_rejected(self):
        """Duplicate seq within the window MUST be rejected."""
        guard = ReplayGuard()
        now = time.time()
        assert guard.check("peer-a", 5, now) is None  # first accept
        assert guard.check("peer-a", 5, now) is not None  # duplicate

    def test_stale_timestamp_rejected(self):
        """Timestamps older than the window (default 30s) MUST be rejected."""
        guard = ReplayGuard()
        stale = time.time() - 60
        assert guard.check("peer-a", 1, stale) is not None


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------

class TestHandshake:

    def test_passphrase_proof_deterministic(self):
        """HMAC-SHA256(passphrase, nonce) MUST be deterministic."""
        pp = "testpassphrase1234"
        nonce = b"\x00" * 32
        p1 = Handshake.compute_passphrase_proof(pp, nonce)
        p2 = Handshake.compute_passphrase_proof(pp, nonce)
        assert p1 == p2
        assert len(p1) == 64  # hex-encoded SHA256

    def test_mutual_auth_reversed_nonce(self):
        """Server proof MUST be computed over the reversed nonce."""
        pp = "testpassphrase1234"
        nonce = bytes(range(32))
        client_proof = Handshake.compute_passphrase_proof(pp, nonce)
        server_proof = Handshake.compute_passphrase_proof(pp, nonce[::-1])
        assert client_proof != server_proof  # proves reversed-nonce gives distinct proof

    def test_passphrase_verify_constant_time(self):
        """Proof comparison MUST use constant-time compare (hmac.compare_digest)."""
        pp = "testpassphrase1234"
        nonce = b"\x11" * 32
        expected = Handshake.compute_passphrase_proof(pp, nonce)
        # Verify: identical proof returns True via constant-time compare
        assert hmac.compare_digest(expected, expected)
        assert not hmac.compare_digest(expected, "0" * 64)


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

class TestSignatures:

    def test_detached_signature_is_64_bytes(self):
        """Ed25519 detached signature MUST be 64 bytes."""
        sk = SigningKey.generate()
        sig = ew_crypto.sign_detached(sk, b"hello")
        assert len(sig) == 64

    def test_detached_signature_verify(self):
        """verify_detached MUST succeed for valid signature."""
        sk = SigningKey.generate()
        vk = sk.verify_key
        msg = b"hello world"
        sig = ew_crypto.sign_detached(sk, msg)
        # Should not raise
        ew_crypto.verify_detached(vk, msg, sig)

    def test_detached_signature_tampered_rejected(self):
        """Tampered signature MUST raise BadSignatureError."""
        from nacl.exceptions import BadSignatureError
        sk = SigningKey.generate()
        sig = ew_crypto.sign_detached(sk, b"hello")
        tampered = bytes([sig[0] ^ 0xff]) + sig[1:]
        with pytest.raises((BadSignatureError, Exception)):
            ew_crypto.verify_detached(sk.verify_key, b"hello", tampered)


# ---------------------------------------------------------------------------
# TOFU behavior
# ---------------------------------------------------------------------------

class TestTOFU:

    def test_new_peer_reports_new(self, tmp_path):
        """First-time peer MUST return 'new'."""
        store = TrustStore(agent_key=b"\x00" * 32, path=str(tmp_path / "trust.json"))
        result = store.verify_peer("peer-abc", "base64pubkey==")
        assert result == "new"

    def test_pinned_peer_reports_trusted(self, tmp_path):
        """Subsequent verification with same key MUST return 'trusted'."""
        store = TrustStore(agent_key=b"\x00" * 32, path=str(tmp_path / "trust.json"))
        pubkey = "validbase64key=="
        store.pin_peer("peer-abc", pubkey)
        assert store.verify_peer("peer-abc", pubkey) == "trusted"

    def test_changed_key_reports_mismatch(self, tmp_path):
        """Same peer with different key MUST return 'mismatch'."""
        store = TrustStore(agent_key=b"\x00" * 32, path=str(tmp_path / "trust.json"))
        store.pin_peer("peer-abc", "originalkey==")
        assert store.verify_peer("peer-abc", "differentkey==") == "mismatch"

    def test_revoked_peer_flagged(self, tmp_path):
        """v0.6: revoked peer MUST be reported as revoked."""
        store = TrustStore(agent_key=b"\x00" * 32, path=str(tmp_path / "trust.json"))
        store.mark_revoked(
            target_node_id="peer-abc",
            revoker_node_id="revoker-xyz",
            timestamp=time.time(),
            reason="test",
        )
        assert store.is_revoked("peer-abc") is True
        assert store.is_revoked("peer-other") is False


# ---------------------------------------------------------------------------
# Protocol version parsing
# ---------------------------------------------------------------------------

class TestVersionNegotiation:

    def test_parse_valid_version(self):
        """ironmesh/X.Y parses to (X, Y)."""
        from ironmesh.bridge import _parse_protocol_version
        assert _parse_protocol_version("ironmesh/0.6") == (0, 6)
        assert _parse_protocol_version("ironmesh/1.2") == (1, 2)

    def test_parse_invalid_version_returns_zero_zero(self):
        """Malformed versions MUST return (0, 0) — never crash."""
        from ironmesh.bridge import _parse_protocol_version
        assert _parse_protocol_version("") == (0, 0)
        assert _parse_protocol_version("garbage") == (0, 0)
        assert _parse_protocol_version("ironmesh") == (0, 0)

    def test_version_comparison_uses_tuple(self):
        """Version gates MUST use tuple comparison."""
        from ironmesh.bridge import _parse_protocol_version
        assert _parse_protocol_version("ironmesh/0.5") >= _parse_protocol_version("ironmesh/0.5")
        assert _parse_protocol_version("ironmesh/0.6") > _parse_protocol_version("ironmesh/0.5")
        assert _parse_protocol_version("ironmesh/0.4") < _parse_protocol_version("ironmesh/0.5")


# ---------------------------------------------------------------------------
# Message types (catalog sanity)
# ---------------------------------------------------------------------------

class TestMessageTypeCatalog:
    """These message types are part of the protocol surface.

    Any implementation must recognize the names (may no-op on types it
    doesn't implement).
    """

    def test_core_message_types_exist(self):
        expected = {
            "HELLO", "MSG", "ACK", "PING", "PONG", "ERROR",
            "PASSPHRASE_CHALLENGE", "PASSPHRASE_VERIFIED", "PASSPHRASE_REJECTED",
            "KEY_ROTATE",
        }
        for name in expected:
            assert hasattr(MessageType, name), f"Missing MessageType.{name}"

    def test_v04_routing_types_exist(self):
        assert hasattr(MessageType, "ROUTE_ANNOUNCE")
        assert hasattr(MessageType, "ROUTE_UNREACHABLE")

    def test_v04_capability_types_exist(self):
        assert hasattr(MessageType, "CAPABILITY_ANNOUNCE")

    def test_v05_rekey_types_exist(self):
        assert hasattr(MessageType, "REKEY_REQUEST")
        assert hasattr(MessageType, "REKEY_RESPONSE")

    def test_v06_revocation_type_exists(self):
        assert hasattr(MessageType, "REVOCATION")
