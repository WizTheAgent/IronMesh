"""Tests for domain-separated Ed25519 signing (Option C dual-use mitigation).

These tests guard the ``sign_detached_with_context`` /
``verify_detached_with_context`` surface in ``ironmesh.crypto``. The signing
contexts are the wire-stable labels that all NEW Ed25519 signing surfaces
(signed capability announce, future trust-pin export, etc.) MUST use.
"""

from __future__ import annotations

import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from ironmesh.crypto import (
    SIG_CTX_CAPABILITY_ANNOUNCE,
    SIG_CTX_FUTURE_FRAME_INNER_SOURCE,
    SIG_CTX_FUTURE_FRAME_OUTER,
    SIG_CTX_FUTURE_HELLO,
    SIG_CTX_FUTURE_REVOCATION,
    SIG_CTX_TRUST_PIN_EXPORT,
    sign_detached_with_context,
    verify_detached_with_context,
)


class TestSigningContextRoundtrip:
    def test_sign_verify_roundtrip(self):
        sk = SigningKey.generate()
        msg = b"hello"
        sig = sign_detached_with_context(sk, SIG_CTX_CAPABILITY_ANNOUNCE, msg)
        assert len(sig) == 64
        assert verify_detached_with_context(
            sk.verify_key, SIG_CTX_CAPABILITY_ANNOUNCE, msg, sig
        )

    def test_signature_is_deterministic(self):
        # Ed25519 is deterministic — sign(k, ctx, m) is the same every call.
        # Guards against an accidental future swap to a randomized scheme
        # that would break replay-detection schemes built on the signature
        # bytes (e.g. announce-replay dedup LRU).
        sk = SigningKey.generate()
        msg = b"hello"
        a = sign_detached_with_context(sk, SIG_CTX_CAPABILITY_ANNOUNCE, msg)
        b = sign_detached_with_context(sk, SIG_CTX_CAPABILITY_ANNOUNCE, msg)
        assert a == b


class TestDomainSeparation:
    def test_signature_for_context_A_does_not_verify_under_context_B(self):
        # The core mitigation. Signing the SAME message under context A
        # must produce a signature that is rejected when verified under
        # context B — this is what prevents an attacker who coerces a
        # signature in one role from replaying it as a different role.
        sk = SigningKey.generate()
        msg = b"trojan payload"
        sig_a = sign_detached_with_context(sk, SIG_CTX_CAPABILITY_ANNOUNCE, msg)
        with pytest.raises(BadSignatureError):
            verify_detached_with_context(
                sk.verify_key, SIG_CTX_TRUST_PIN_EXPORT, msg, sig_a
            )

    @pytest.mark.parametrize("other_ctx", [
        SIG_CTX_TRUST_PIN_EXPORT,
        SIG_CTX_FUTURE_FRAME_OUTER,
        SIG_CTX_FUTURE_FRAME_INNER_SOURCE,
        SIG_CTX_FUTURE_HELLO,
        SIG_CTX_FUTURE_REVOCATION,
    ])
    def test_cross_context_rejection_full_matrix(self, other_ctx):
        # Every other defined context must reject a capability-announce
        # signature. Guards against a future label edit that accidentally
        # collides with another label byte sequence.
        sk = SigningKey.generate()
        msg = b"hello"
        sig = sign_detached_with_context(sk, SIG_CTX_CAPABILITY_ANNOUNCE, msg)
        with pytest.raises(BadSignatureError):
            verify_detached_with_context(sk.verify_key, other_ctx, msg, sig)

    def test_all_defined_contexts_unique(self):
        labels = {
            SIG_CTX_CAPABILITY_ANNOUNCE,
            SIG_CTX_TRUST_PIN_EXPORT,
            SIG_CTX_FUTURE_FRAME_OUTER,
            SIG_CTX_FUTURE_FRAME_INNER_SOURCE,
            SIG_CTX_FUTURE_HELLO,
            SIG_CTX_FUTURE_REVOCATION,
        }
        assert len(labels) == 6  # no duplicates

    def test_labels_are_nul_terminated(self):
        # NUL terminator prevents one label from being a prefix of another
        # (e.g. "frame" vs "frame-outer"). Encoded once here, asserted on
        # the parametrized full set.
        for label in (
            SIG_CTX_CAPABILITY_ANNOUNCE,
            SIG_CTX_TRUST_PIN_EXPORT,
            SIG_CTX_FUTURE_FRAME_OUTER,
            SIG_CTX_FUTURE_FRAME_INNER_SOURCE,
            SIG_CTX_FUTURE_HELLO,
            SIG_CTX_FUTURE_REVOCATION,
        ):
            assert label.endswith(b"\x00"), label


class TestArgValidation:
    def test_empty_context_rejected_on_sign(self):
        sk = SigningKey.generate()
        with pytest.raises(ValueError, match="non-empty bytes"):
            sign_detached_with_context(sk, b"", b"hello")

    def test_empty_context_rejected_on_verify(self):
        sk = SigningKey.generate()
        sig = sign_detached_with_context(sk, SIG_CTX_CAPABILITY_ANNOUNCE, b"hello")
        with pytest.raises(ValueError, match="non-empty bytes"):
            verify_detached_with_context(sk.verify_key, b"", b"hello", sig)

    def test_non_bytes_context_rejected(self):
        sk = SigningKey.generate()
        with pytest.raises(ValueError, match="non-empty bytes"):
            sign_detached_with_context(sk, "not-bytes", b"hello")  # type: ignore[arg-type]


class TestTamperDetection:
    def test_flipped_signature_byte_rejected(self):
        sk = SigningKey.generate()
        msg = b"hello"
        sig = bytearray(sign_detached_with_context(sk, SIG_CTX_CAPABILITY_ANNOUNCE, msg))
        sig[0] ^= 0xFF
        with pytest.raises(BadSignatureError):
            verify_detached_with_context(
                sk.verify_key, SIG_CTX_CAPABILITY_ANNOUNCE, msg, bytes(sig)
            )

    def test_flipped_message_byte_rejected(self):
        sk = SigningKey.generate()
        msg = b"hello"
        sig = sign_detached_with_context(sk, SIG_CTX_CAPABILITY_ANNOUNCE, msg)
        with pytest.raises(BadSignatureError):
            verify_detached_with_context(
                sk.verify_key, SIG_CTX_CAPABILITY_ANNOUNCE, b"hellp", sig
            )

    def test_wrong_verify_key_rejected(self):
        sk_signer = SigningKey.generate()
        sk_other = SigningKey.generate()
        msg = b"hello"
        sig = sign_detached_with_context(sk_signer, SIG_CTX_CAPABILITY_ANNOUNCE, msg)
        with pytest.raises(BadSignatureError):
            verify_detached_with_context(
                sk_other.verify_key, SIG_CTX_CAPABILITY_ANNOUNCE, msg, sig
            )
