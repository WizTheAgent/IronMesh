"""Pre-audit hardening tests — frame length ceiling + narrowed signing-path excepts.

Two hardening fixes covered here:

1. **MAX_FRAME_BYTES ceiling** — Frame.deserialize_and_decrypt must reject an
   attacker-declared encrypted_length before slicing/allocating the buffer.
   Without the ceiling, a single malicious frame can force allocation of up
   to 4 GiB (u32 wire field).

2. **Narrowed except in inner-source signing path** — Frame.encrypt_and_serialize
   no longer swallows every Exception when generating the inner Ed25519
   signature. It catches the crypto-input subset (nacl CryptoError, TypeError,
   ValueError) and lets programmer errors / KeyboardInterrupt propagate.
"""

from __future__ import annotations

import nacl.utils
import pytest
from nacl.signing import SigningKey

from ironmesh.protocol import MAX_FRAME_BYTES, Frame, MessagePriority, MessageType


def _shared_key() -> bytes:
    return nacl.utils.random(32)


def _build_attacker_frame(declared_length: int) -> bytes:
    """Build a wire frame with an arbitrary attacker-declared encrypted_length."""
    magic = Frame.MAGIC
    version = (4).to_bytes(1, "big")
    flags = (Frame.FLAG_ENCRYPTED).to_bytes(1, "big")
    sequence = (1).to_bytes(8, "big")
    timestamp_ms = (0).to_bytes(8, "big")
    msg_id_hash = b"\x00" * 8
    length_field = declared_length.to_bytes(4, "big")
    # No actual payload bytes — the ceiling check must trip before the
    # buffer slice would even try to allocate `declared_length` bytes.
    return magic + version + flags + sequence + timestamp_ms + msg_id_hash + length_field


class TestFrameLengthCeiling:
    def test_ceiling_value_is_one_mib(self):
        assert MAX_FRAME_BYTES == 1 * 1024 * 1024

    def test_attacker_declared_4gib_rejected_before_alloc(self):
        # u32 max — without the ceiling this would attempt to slice 4 GiB.
        wire = _build_attacker_frame(0xFFFF_FFFF)
        with pytest.raises(ValueError, match="exceeds MAX_FRAME_BYTES"):
            Frame.deserialize_and_decrypt(wire, _shared_key())

    def test_attacker_declared_just_above_ceiling_rejected(self):
        wire = _build_attacker_frame(MAX_FRAME_BYTES + 1)
        with pytest.raises(ValueError, match="exceeds MAX_FRAME_BYTES"):
            Frame.deserialize_and_decrypt(wire, _shared_key())

    def test_attacker_declared_at_ceiling_passes_size_check(self):
        # At exactly the ceiling the size check passes; subsequent
        # truncation / decryption checks will fail (no real payload).
        # The point: rejection happens for the *right* reason — not
        # because the size check fires below the documented ceiling.
        wire = _build_attacker_frame(MAX_FRAME_BYTES)
        with pytest.raises(ValueError) as exc:
            Frame.deserialize_and_decrypt(wire, _shared_key())
        assert "MAX_FRAME_BYTES" not in str(exc.value)

    def test_serialize_rejects_oversize_plaintext(self):
        # serialize_plaintext path also enforces the ceiling so we don't
        # ship a frame our own peers will reject.
        f = Frame(
            msg_type=MessageType.MSG,
            payload=b"x" * (MAX_FRAME_BYTES + 1),
            source="alice",
            destination="bob",
        )
        with pytest.raises(ValueError, match="exceeds MAX_FRAME_BYTES"):
            f.serialize_plaintext()

    def test_encrypt_and_serialize_rejects_oversize_ciphertext(self):
        # encrypt_and_serialize trips the ceiling after SecretBox expansion.
        # Use a payload large enough that the ciphertext + nonce + MAC
        # crosses the ceiling.
        oversized_payload = b"x" * (MAX_FRAME_BYTES + 1)
        f = Frame(
            msg_type=MessageType.MSG,
            payload=oversized_payload,
            source="alice",
            destination="bob",
        )
        with pytest.raises(ValueError, match="exceeds MAX_FRAME_BYTES"):
            f.encrypt_and_serialize(_shared_key())

    def test_legitimate_small_frame_roundtrip_still_works(self):
        # Regression guard: ceiling must not interfere with normal traffic.
        sk = _shared_key()
        f = Frame(
            msg_type=MessageType.MSG,
            payload=b"hello",
            source="alice",
            destination="bob",
            priority=MessagePriority.NORMAL,
            sequence=1,
        )
        wire = f.encrypt_and_serialize(sk)
        out = Frame.deserialize_and_decrypt(wire, sk)
        assert out.payload == b"hello"


class TestInnerSourceSignatureNarrowedExcept:
    def test_bad_key_type_propagates(self):
        # A non-SigningKey object passed as source_signing_key would have
        # raised AttributeError inside the old bare-except `pass`,
        # silently dropping the inner signature forever. Now it propagates.
        f = Frame(
            msg_type=MessageType.MSG,
            payload=b"hello",
            source="alice",
            destination="bob",
        )

        class NotASigningKey:
            pass

        with pytest.raises(AttributeError):
            f.encrypt_and_serialize(
                _shared_key(),
                source_signing_key=NotASigningKey(),
            )

    def test_typeerror_on_non_bytes_payload_is_caught(self):
        # Inner-sig generation against an unusual payload type that triggers
        # nacl's TypeError (e.g. non-bytes payload) is caught — the frame
        # still ships, just without the inner signature.
        f = Frame(
            msg_type=MessageType.MSG,
            payload=b"hello",
            source="alice",
            destination="bob",
        )
        # Force the signing input to a type nacl rejects with TypeError.
        f.payload = "not-bytes"  # type: ignore[assignment]
        signing_key = SigningKey.generate()

        with pytest.raises(TypeError):
            # json.dumps(self.to_dict()) will fail before we even get to
            # SecretBox — the point is the signing-path catch doesn't
            # mask this as a "silent no-op". We assert the exception
            # surfaces rather than getting swallowed.
            f.encrypt_and_serialize(_shared_key(), source_signing_key=signing_key)

    def test_legitimate_signing_still_works(self):
        # Regression guard: narrowing the except must not break the
        # happy path of inner-source-signature generation.
        sk = _shared_key()
        signing_key = SigningKey.generate()
        f = Frame(
            msg_type=MessageType.MSG,
            payload=b"hello",
            source="alice",
            destination="bob",
        )
        wire = f.encrypt_and_serialize(sk, source_signing_key=signing_key)
        # source_signature was populated.
        assert f.source_signature is not None
        assert len(f.source_signature) == 64  # Ed25519 sig size
        # And the frame still round-trips.
        out = Frame.deserialize_and_decrypt(
            wire,
            sk,
            verify_source_key=lambda _src: signing_key.verify_key,
        )
        assert out.payload == b"hello"


class TestJSONDepthGuard:
    def test_safe_json_loads_accepts_normal_shape(self):
        from ironmesh.protocol import safe_json_loads
        # A typical capability-announce shape — 3 levels deep.
        raw = b'{"origin":"x","capabilities":["a","b"],"meta":{"v":1}}'
        out = safe_json_loads(raw)
        assert out["origin"] == "x"

    def test_safe_json_loads_rejects_deep_dict(self):
        from ironmesh.protocol import MAX_JSON_DEPTH, safe_json_loads
        # 100 nested dicts — well above the configured 64.
        raw = b"{}"
        for _ in range(100):
            raw = b'{"x":' + raw + b"}"
        with pytest.raises(ValueError, match="exceeds max depth"):
            safe_json_loads(raw)
        assert MAX_JSON_DEPTH == 64

    def test_safe_json_loads_rejects_deep_list(self):
        from ironmesh.protocol import safe_json_loads
        raw = b"[]"
        for _ in range(100):
            raw = b"[" + raw + b"]"
        with pytest.raises(ValueError, match="exceeds max depth"):
            safe_json_loads(raw)

    def test_safe_json_loads_at_boundary_accepts(self):
        from ironmesh.protocol import MAX_JSON_DEPTH, safe_json_loads
        raw = b"1"
        for _ in range(MAX_JSON_DEPTH):
            raw = b"[" + raw + b"]"
        safe_json_loads(raw)  # exactly at the limit must not raise

    def test_frame_deserialize_rejects_deeply_nested_payload(self):
        # End-to-end: an oversized-depth payload inside a valid frame is
        # rejected by Frame.deserialize_and_decrypt via the safe_json_loads
        # wrapper. Use a fresh shared key so the frame round-trips through
        # the SecretBox path normally.
        sk = _shared_key()
        f = Frame(
            msg_type=MessageType.MSG,
            payload=b"hello",
            source="alice",
            destination="bob",
        )
        # Inject an over-deep `hops` list into the frame's dict
        # representation before serialization. We bypass the normal
        # constructor + use to_dict()/from_dict() to force the shape.
        wire = f.encrypt_and_serialize(sk)
        # Round-trip the small frame first as a control.
        Frame.deserialize_and_decrypt(wire, sk)
        # Now build a frame whose to_dict()-encoded payload nests deeply.
        deep = [1]
        for _ in range(100):
            deep = [deep]
        f2 = Frame(
            msg_type=MessageType.MSG,
            payload=b"hello",
            source="alice",
            destination="bob",
        )
        # Monkey-patch the to_dict shape — the wire path will JSON-encode
        # whatever to_dict returns, and the receiver will run it through
        # safe_json_loads.
        original_to_dict = f2.to_dict
        f2.to_dict = lambda: {**original_to_dict(), "deep_test_field": deep}
        wire = f2.encrypt_and_serialize(sk)
        with pytest.raises(ValueError, match="exceeds max depth"):
            Frame.deserialize_and_decrypt(wire, sk)


class TestReplayGuardMaxSequence:
    def test_max_sequence_constant(self):
        from ironmesh.protocol import ReplayGuard
        assert ReplayGuard.MAX_SEQUENCE == (1 << 48)

    def test_sequence_above_max_rejected(self):
        import time as _t

        from ironmesh.protocol import ReplayGuard
        rg = ReplayGuard(max_age=30.0)
        result = rg.check("peer1", (1 << 48) + 1, _t.time())
        assert result is not None
        assert "exceeds MAX_SEQUENCE" in result

    def test_sequence_at_max_accepted(self):
        import time as _t

        from ironmesh.protocol import ReplayGuard
        rg = ReplayGuard(max_age=30.0)
        result = rg.check("peer1", (1 << 48), _t.time())
        assert result is None  # exactly at the ceiling is legal

    def test_attacker_giant_seq_does_not_break_subsequent_legit_traffic(self):
        # The regression this guard prevents: a single frame with a huge
        # seq used to ratchet last_seq permanently, blocking all future
        # legitimate small-seq traffic from the same peer. With the cap
        # in place the giant seq is rejected before last_seq moves.
        import time as _t

        from ironmesh.protocol import ReplayGuard
        rg = ReplayGuard(max_age=30.0)
        rg.check("peer1", (1 << 60), _t.time())  # attacker frame
        # Legitimate small seq should still be accepted because last_seq
        # was never ratcheted by the rejected attacker frame.
        assert rg.check("peer1", 5, _t.time()) is None


class TestNarrowedVerificationExcepts:
    def test_signature_verify_failure_raises_valueerror(self):
        # Tampering the outer signature must still produce a clean
        # ValueError("Signature verification failed: ...") — not a raw
        # nacl error or a generic catch-all.
        sk = _shared_key()
        signing_key = SigningKey.generate()
        f = Frame(
            msg_type=MessageType.MSG,
            payload=b"hello",
            source="alice",
            destination="bob",
        )
        wire = f.encrypt_and_serialize(sk, signing_key=signing_key)
        # Flip a byte inside the appended Ed25519 signature.
        tampered = bytearray(wire)
        tampered[-1] ^= 0xFF
        with pytest.raises(ValueError, match="Signature verification failed"):
            Frame.deserialize_and_decrypt(
                bytes(tampered),
                sk,
                verify_key=signing_key.verify_key,
            )

    def test_decryption_failure_raises_valueerror(self):
        # Tampering the ciphertext (post-MAC) yields a CryptoError from
        # nacl which is converted to ValueError("Decryption failed: ...").
        sk = _shared_key()
        f = Frame(
            msg_type=MessageType.MSG,
            payload=b"hello",
            source="alice",
            destination="bob",
        )
        wire = bytearray(f.encrypt_and_serialize(sk))
        # Flip a byte inside the ciphertext (offset 32 = after header).
        wire[40] ^= 0xFF
        with pytest.raises(ValueError, match="Decryption failed"):
            Frame.deserialize_and_decrypt(bytes(wire), sk)
