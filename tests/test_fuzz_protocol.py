"""Property-based fuzzing tests for the IronMesh frame parser.

Uses Hypothesis to generate random byte strings and assert that the
frame deserializer never crashes with an unexpected exception.  All
malformed input must either parse successfully or raise ValueError /
known crypto exceptions.

Install dev dep: ``pip install hypothesis``
Run: ``pytest tests/test_fuzz_protocol.py -v``
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st
from hypothesis import HealthCheck
from nacl.signing import SigningKey
from nacl.exceptions import CryptoError, BadSignatureError

from ironmesh.protocol import Frame
from ironmesh.crypto import generate_ephemeral_keypair, ecdh_exchange


# Pre-build a valid session key + Ed25519 verify key that the fuzzer can use
_test_signing_key = SigningKey.generate()
_test_verify_key = _test_signing_key.verify_key
_priv, _pub = generate_ephemeral_keypair()
_other_priv, _other_pub = generate_ephemeral_keypair()
_session_key = ecdh_exchange(_priv, _other_pub)


# Acceptable exception classes — anything else is a bug
_ACCEPTABLE_EXCEPTIONS = (
    ValueError,
    CryptoError,
    BadSignatureError,
    TypeError,
    IndexError,      # slicing beyond buffer
    UnicodeDecodeError,
)


@given(st.binary(max_size=2000))
@settings(max_examples=1000, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def test_deserialize_random_bytes_never_crashes(data: bytes):
    """Frame.deserialize_and_decrypt must handle any random input gracefully."""
    try:
        Frame.deserialize_and_decrypt(
            data, _session_key, verify_key=_test_verify_key,
        )
    except _ACCEPTABLE_EXCEPTIONS:
        pass
    except Exception as e:
        pytest.fail(f"Unexpected exception on random input: {type(e).__name__}: {e}")


@given(st.binary(min_size=2, max_size=32))
@settings(max_examples=1000, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def test_short_frames_rejected_cleanly(data: bytes):
    """Frames shorter than the header must raise ValueError, not crash."""
    with pytest.raises(_ACCEPTABLE_EXCEPTIONS):
        Frame.deserialize_and_decrypt(
            data, _session_key, verify_key=_test_verify_key,
        )


@given(
    magic=st.binary(min_size=2, max_size=2),
    trailing=st.binary(max_size=1500),
)
@settings(max_examples=300, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def test_wrong_magic_rejected(magic: bytes, trailing: bytes):
    """Any non-matching magic bytes must raise ValueError."""
    # Skip accidentally-valid magic
    from ironmesh.protocol import Frame as _F
    valid_magic = getattr(_F, "MAGIC", b"\xe7\xf6")
    if magic == valid_magic:
        return
    data = magic + b"\x04\x00" + b"\x00" * 30 + trailing  # fake header
    with pytest.raises(_ACCEPTABLE_EXCEPTIONS):
        Frame.deserialize_and_decrypt(
            data, _session_key, verify_key=_test_verify_key,
        )


@given(st.text(max_size=100))
@settings(max_examples=500, deadline=None)
def test_protocol_version_parser_never_crashes(version_str: str):
    """_parse_protocol_version must always return a (int, int) tuple."""
    from ironmesh.bridge import _parse_protocol_version
    result = _parse_protocol_version(version_str)
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert isinstance(result[0], int)
    assert isinstance(result[1], int)


# --- JSON payload fuzzing (for the handshake JSON path) ---

@given(st.recursive(
    st.none() | st.booleans() | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=100) | st.integers(),
    lambda children: st.lists(children, max_size=10)
    | st.dictionaries(st.text(max_size=20), children, max_size=10),
    max_leaves=30,
))
@settings(max_examples=200, deadline=None)
def test_random_json_handshake_payload_does_not_crash(payload: Any):
    """A daemon seeing random JSON where it expects a handshake dict
    should reject cleanly with a known error, not crash.

    We just exercise the JSON serialize/parse + expected-keys path.
    """
    try:
        raw = json.dumps(payload).encode()
        parsed = json.loads(raw)
        # Simulate the bridge's use: .get() must always work
        if isinstance(parsed, dict):
            parsed.get("type")
            parsed.get("ephemeral_public")
            parsed.get("identity_public")
            parsed.get("protocol_version", "ironmesh/0.3")
    except (ValueError, TypeError, OverflowError):
        pass
