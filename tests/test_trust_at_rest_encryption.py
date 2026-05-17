"""Tests for trust-store at-rest encryption (v0.9.3 v2 envelope).

Covers:
- new stores write the v2 (encrypted) envelope shape
- v2 round-trip preserves peer state
- legacy v1 plaintext envelopes still load and migrate forward
- a wrong agent_key cannot decrypt a v2 envelope and the store goes
  read-only instead of overwriting
- ciphertext does not contain known plaintext (the peer's pubkey)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trust import _TRUST_ENVELOPE_VERSION, TrustStore

_AGENT_A = b"a" * 32
_AGENT_B = b"b" * 32
_PEER_NODE_ID = "peer-001"
_PEER_PUBKEY_B64 = "kVtPQ4UkBNzqAdyZk7y2vNEN7zVDxGbA6kyjLwmYZAA="


def _make_store(tmp_path: Path, *, agent_key: bytes = _AGENT_A) -> TrustStore:
    return TrustStore(agent_key=agent_key, path=str(tmp_path / "trust.json"))


def test_new_store_writes_v2_envelope(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    store.pin_peer(_PEER_NODE_ID, _PEER_PUBKEY_B64)

    raw = json.loads((tmp_path / "trust.json").read_text())
    assert raw["version"] == _TRUST_ENVELOPE_VERSION
    assert "ciphertext" in raw
    assert "_mac" in raw
    # No plaintext peers field at the top level — that's the whole point.
    assert "peers" not in raw


def test_v2_round_trip_preserves_peer(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    store.pin_peer(_PEER_NODE_ID, _PEER_PUBKEY_B64)

    reopened = _make_store(tmp_path)
    pinned = reopened.get_peer(_PEER_NODE_ID)
    assert pinned is not None
    assert pinned["pubkey"] == _PEER_PUBKEY_B64


def test_legacy_v1_plaintext_loads_and_migrates(tmp_path: Path) -> None:
    # Hand-craft a v1 envelope with the agent-key MAC so it loads cleanly.
    store_for_mac = _make_store(tmp_path)  # only used to compute the MAC
    inner = {
        "peers": {
            _PEER_NODE_ID: {
                "pubkey": _PEER_PUBKEY_B64,
                "fingerprint": "abc",
                "first_seen": 1.0,
                "last_seen": 1.0,
                "trust_state": "trusted",
            }
        },
        "revoked": {},
    }
    inner_str = json.dumps(inner, sort_keys=True, separators=(",", ":"))
    legacy = dict(inner)
    legacy["_mac"] = store_for_mac._compute_mac(inner_str)

    # Overwrite the file with the legacy envelope (the store_for_mac wrote
    # an empty v2 envelope; replace it).
    (tmp_path / "trust.json").write_text(json.dumps(legacy))

    # Reopen — should load via the v1 path and migrate forward on next save.
    migrated = _make_store(tmp_path)
    assert migrated.get_peer(_PEER_NODE_ID) is not None

    # Trigger a save.
    migrated.pin_peer("peer-002", _PEER_PUBKEY_B64)

    raw = json.loads((tmp_path / "trust.json").read_text())
    assert raw["version"] == _TRUST_ENVELOPE_VERSION
    assert "peers" not in raw  # encrypted now


def test_wrong_agent_key_locks_read_only(tmp_path: Path) -> None:
    # Write a v2 envelope keyed to AGENT_A.
    store_a = _make_store(tmp_path, agent_key=_AGENT_A)
    store_a.pin_peer(_PEER_NODE_ID, _PEER_PUBKEY_B64)

    # Open with AGENT_B — MAC fails, store goes read-only.
    store_b = _make_store(tmp_path, agent_key=_AGENT_B)
    assert store_b._readonly_due_to_mac_failure is True
    assert store_b.get_peer(_PEER_NODE_ID) is None  # in-memory is empty
    # _save() must refuse, preserving the on-disk file.
    assert store_b._save() is False

    # The original file is intact — AGENT_A can still read it.
    store_a_reopen = _make_store(tmp_path, agent_key=_AGENT_A)
    assert store_a_reopen.get_peer(_PEER_NODE_ID) is not None


def test_ciphertext_does_not_leak_plaintext_pubkey(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    store.pin_peer(_PEER_NODE_ID, _PEER_PUBKEY_B64)

    raw_bytes = (tmp_path / "trust.json").read_bytes()
    # The pubkey base64 string must not appear in the on-disk envelope.
    assert _PEER_PUBKEY_B64.encode("ascii") not in raw_bytes
    # And neither must the node_id (which the v1 plaintext envelope did expose).
    assert _PEER_NODE_ID.encode("ascii") not in raw_bytes


def test_tamper_with_ciphertext_locks_read_only(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    store.pin_peer(_PEER_NODE_ID, _PEER_PUBKEY_B64)

    raw = json.loads((tmp_path / "trust.json").read_text())
    # Flip a single base64 character in the ciphertext.
    ct = raw["ciphertext"]
    flipped = ("A" if ct[10] != "A" else "B") + ct[11:]
    raw["ciphertext"] = ct[:10] + flipped
    (tmp_path / "trust.json").write_text(json.dumps(raw))

    tampered = _make_store(tmp_path)
    assert tampered._readonly_due_to_mac_failure is True
    assert tampered.get_peer(_PEER_NODE_ID) is None


@pytest.mark.parametrize("revoked", [
    {},
    {"baddie": {"revoker": "good", "timestamp": 1.0, "reason": "test"}},
])
def test_revoked_state_round_trips_through_envelope(
    tmp_path: Path, revoked: dict
) -> None:
    store = _make_store(tmp_path)
    store.pin_peer(_PEER_NODE_ID, _PEER_PUBKEY_B64)
    for nid, data in revoked.items():
        store.mark_revoked(nid, data["revoker"], data["timestamp"], data["reason"])

    reopened = _make_store(tmp_path)
    for nid in revoked:
        assert reopened.is_revoked(nid)
