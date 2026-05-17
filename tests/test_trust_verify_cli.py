"""Tests for the v0.9.3 ``ironmesh trust verify`` and ``trust migrate``
CLI subcommands.

The fingerprint-matching helper is exercised directly so we can cover
every edge case without standing up a full daemon. Migration behavior
is tested at the TrustStore + ``_save()`` level — the CLI handler is
just a wrapper that reports.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cli import _normalize_fingerprint, fingerprint_matches
from trust import TrustStore


_PUBKEY = "kVtPQ4UkBNzqAdyZk7y2vNEN7zVDxGbA6kyjLwmYZAA="


@pytest.mark.parametrize("raw,expected", [
    ("aBcDeF1234567890", "abcdef1234567890"),
    ("ab:cd:ef:12:34:56:78:90", "abcdef1234567890"),
    ("  ab cd ef 12 34 56 78 90  ", "abcdef1234567890"),
    ("", ""),
    (None, ""),
])
def test_normalize_fingerprint_strips_separators(raw, expected) -> None:
    assert _normalize_fingerprint(raw) == expected


def test_full_fingerprint_match_is_match() -> None:
    actual = "abcdef1234567890" * 2  # 32-hex
    assert fingerprint_matches(actual, actual) is True


def test_uppercase_match_normalizes() -> None:
    actual = "abcdef1234567890" * 2
    assert fingerprint_matches(actual.upper(), actual) is True


def test_colon_separated_match() -> None:
    actual = "abcdef1234567890" * 2
    expected = ":".join(actual[i:i + 2] for i in range(0, len(actual), 2))
    assert fingerprint_matches(actual, expected) is True


def test_8_char_prefix_is_minimum() -> None:
    actual = "abcdef1234567890" * 2
    # 8 chars: prefix match accepted.
    assert fingerprint_matches(actual, "abcdef12") is True
    # 7 chars: rejected as too short.
    assert fingerprint_matches(actual, "abcdef1") is False


def test_empty_expected_is_mismatch() -> None:
    actual = "abcdef1234567890" * 2
    assert fingerprint_matches(actual, "") is False


def test_wrong_prefix_is_mismatch() -> None:
    actual = "abcdef1234567890" * 2
    assert fingerprint_matches(actual, "deadbeef") is False


def test_migrate_already_v2_is_idempotent(tmp_path: Path) -> None:
    """Calling _save() on a v2-on-disk store rewrites it without harm."""
    path = tmp_path / "trust.json"
    store = TrustStore(agent_key=b"a" * 32, path=str(path))
    store.pin_peer("peer-1", _PUBKEY)
    raw_before = json.loads(path.read_text())
    assert raw_before["version"] == 2

    # Re-save (the migrate CLI's underlying call). State should be
    # preserved and the file should still be v2.
    assert store._save() is True
    raw_after = json.loads(path.read_text())
    assert raw_after["version"] == 2

    reopened = TrustStore(agent_key=b"a" * 32, path=str(path))
    assert reopened.get_peer("peer-1") is not None


def test_migrate_from_v1_rewrites_as_v2(tmp_path: Path) -> None:
    """A v1 plaintext envelope rewritten via _save() becomes v2 encrypted."""
    path = tmp_path / "trust.json"
    seed = TrustStore(agent_key=b"a" * 32, path=str(path))
    inner = {
        "peers": {
            "peer-1": {
                "pubkey": _PUBKEY,
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
    legacy["_mac"] = seed._compute_mac(inner_str)
    path.write_text(json.dumps(legacy))

    # Reopen: load via the v1 path, then trigger the migration save.
    migrated = TrustStore(agent_key=b"a" * 32, path=str(path))
    assert migrated.get_peer("peer-1") is not None
    assert migrated._save() is True

    raw_after = json.loads(path.read_text())
    assert raw_after["version"] == 2
    assert "ciphertext" in raw_after
    assert "peers" not in raw_after
