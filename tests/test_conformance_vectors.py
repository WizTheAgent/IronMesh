"""Reference-implementation conformance test runner.

Loads every JSON vector from `tests/conformance/vectors/` and exercises
the reference implementation (this Python codebase) against it. Other
implementations (Go, Rust, Swift) are expected to load the same JSON
files and run an equivalent runner in their own language.

A vector is **directional**:

* If `expected_bytes_hex` is present: the implementation must produce
  these bytes when given `input`.
* If `expected_decoded` is present: the implementation must produce
  this dict when given `expected_bytes_hex` (or `input_bytes_hex`).

Round-trip-only vectors (those marked with `"round_trip_only": true`)
skip the byte-equality check — useful when JSON key ordering varies
between implementations but the decoded form is canonical.
"""

import hashlib
import json
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).parent / "conformance" / "vectors"


def _load_vectors():
    if not VECTORS_DIR.is_dir():
        return []
    return sorted(VECTORS_DIR.glob("*.json"))


@pytest.mark.parametrize("vector_path", _load_vectors(),
                          ids=lambda p: p.stem)
def test_vector(vector_path):
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    name = vector["name"]
    category = name.split(".")[0]

    if category == "announce":
        _exercise_announce_vector(vector)
    elif category == "handshake":
        _exercise_handshake_vector(vector)
    else:
        pytest.skip(f"category {category!r} not yet covered by reference runner")


def _exercise_announce_vector(vector):
    from ironmesh.reticulum_transport import encode_app_data, decode_app_data

    if "input_bytes_hex" in vector:
        raw = bytes.fromhex(vector["input_bytes_hex"])
        decoded = decode_app_data(raw)
        assert decoded == vector["expected_decoded"], (
            f"vector {vector['name']!r} decode mismatch: "
            f"got {decoded!r}, expected {vector['expected_decoded']!r}"
        )
        return

    inp = vector["input"]
    encoded = encode_app_data(
        name=inp["name"],
        version=inp["version"],
        node_id=inp["node_id"],
        capabilities=inp.get("capabilities"),
        features=inp.get("features"),
    )

    if vector.get("round_trip_only"):
        decoded = decode_app_data(encoded)
        assert decoded == vector["expected_decoded"], (
            f"vector {vector['name']!r} round-trip mismatch: "
            f"got {decoded!r}, expected {vector['expected_decoded']!r}"
        )
        return

    expected_hex = vector["expected_bytes_hex"]
    actual_hex = encoded.hex()
    assert actual_hex == expected_hex, (
        f"vector {vector['name']!r} bytes mismatch:\n"
        f"  expected: {expected_hex}\n"
        f"  actual:   {actual_hex}"
    )
    decoded = decode_app_data(encoded)
    assert decoded == vector["expected_decoded"]


def _exercise_handshake_vector(vector):
    from ironmesh.protocol import Handshake

    if vector["name"] == "handshake.skip_channel_binding":
        sentinel = Handshake.skip_channel_binding()
        documented = hashlib.sha256(
            b"ironmesh-handshake-skip-channel-binding-v1"
        ).digest()
        assert sentinel == documented, (
            "skip_channel_binding() does not match documented derivation"
        )
        assert sentinel.hex() == vector["expected_bytes_hex"], (
            f"skip sentinel hex mismatch: got {sentinel.hex()!r}, "
            f"expected {vector['expected_bytes_hex']!r}"
        )
    else:
        pytest.skip(f"handshake vector {vector['name']!r} runner not implemented")
