"""Tests for ironmesh.backup — create/restore encrypted archives."""

from __future__ import annotations

import json
import os

import pytest

from ironmesh import backup


STRONG_PP = "backup-passphrase-minimum-length"


# ---------------------------------------------------------------------------
# Passphrase enforcement
# ---------------------------------------------------------------------------

class TestPassphraseValidation:

    def test_short_passphrase_rejected(self, tmp_path):
        out = tmp_path / "backup.imb"
        keys = tmp_path / "keys.json"
        keys.write_text("{}")
        with pytest.raises(ValueError):
            backup.create_backup(
                out_path=str(out), passphrase="short",
                keys_path=str(keys),
                trust_path=str(tmp_path / "trust.json"),
                audit_path=str(tmp_path / "audit.log"),
            )


# ---------------------------------------------------------------------------
# Roundtrip: create + restore
# ---------------------------------------------------------------------------

class TestRoundtrip:

    def test_create_and_restore(self, tmp_path):
        # Create sources
        keys_src = tmp_path / "src_keys.json"
        keys_src.write_text(json.dumps({"ed25519_public": "xxx"}))
        trust_src = tmp_path / "src_trust.json"
        trust_src.write_text(json.dumps({"peers": {}, "_mac": "mac"}))
        audit_src = tmp_path / "src_audit.log"
        audit_src.write_text('{"event":"startup"}\n')

        # Back up
        out = tmp_path / "bundle.imb"
        backup.create_backup(
            out_path=str(out), passphrase=STRONG_PP,
            keys_path=str(keys_src),
            trust_path=str(trust_src),
            audit_path=str(audit_src),
            node_id="node-xyz",
        )
        assert out.exists()
        assert out.stat().st_size > 100  # encrypted payload + headers

        # Restore into different paths
        kd = tmp_path / "restored_keys.json"
        td = tmp_path / "restored_trust.json"
        ad = tmp_path / "restored_audit.log"
        manifest = backup.restore_backup(
            in_path=str(out), passphrase=STRONG_PP,
            keys_path=str(kd), trust_path=str(td), audit_path=str(ad),
        )
        assert manifest["node_id"] == "node-xyz"
        assert kd.exists() and td.exists() and ad.exists()
        assert kd.read_text() == keys_src.read_text()
        assert td.read_text() == trust_src.read_text()
        assert ad.read_text() == audit_src.read_text()

    def test_restore_wrong_passphrase_fails(self, tmp_path):
        keys_src = tmp_path / "k.json"
        keys_src.write_text("{}")
        out = tmp_path / "bundle.imb"
        backup.create_backup(
            out_path=str(out), passphrase=STRONG_PP,
            keys_path=str(keys_src),
            trust_path=str(tmp_path / "no_trust.json"),
            audit_path=str(tmp_path / "no_audit.log"),
        )
        with pytest.raises(ValueError, match="(Decryption|passphrase)"):
            backup.restore_backup(
                in_path=str(out), passphrase="wrong-passphrase-1234",
                keys_path=str(tmp_path / "out.json"),
                trust_path=str(tmp_path / "t.json"),
                audit_path=str(tmp_path / "a.log"),
            )


# ---------------------------------------------------------------------------
# File conflicts
# ---------------------------------------------------------------------------

class TestOverwriteProtection:

    def test_restore_refuses_to_overwrite(self, tmp_path):
        keys_src = tmp_path / "k.json"
        keys_src.write_text("{}")
        out = tmp_path / "bundle.imb"
        backup.create_backup(
            out_path=str(out), passphrase=STRONG_PP,
            keys_path=str(keys_src),
            trust_path=str(tmp_path / "no_trust.json"),
            audit_path=str(tmp_path / "no_audit.log"),
        )
        # Destination already exists
        dest = tmp_path / "exists.json"
        dest.write_text("pre-existing content")
        with pytest.raises(ValueError, match="exist"):
            backup.restore_backup(
                in_path=str(out), passphrase=STRONG_PP,
                keys_path=str(dest),
                trust_path=str(tmp_path / "no_t.json"),
                audit_path=str(tmp_path / "no_a.log"),
            )
        # --force overrides
        backup.restore_backup(
            in_path=str(out), passphrase=STRONG_PP,
            keys_path=str(dest),
            trust_path=str(tmp_path / "t2.json"),
            audit_path=str(tmp_path / "a2.log"),
            force=True,
        )
        assert dest.read_text() == "{}"


# ---------------------------------------------------------------------------
# Corrupted archive
# ---------------------------------------------------------------------------

class TestCorruption:

    def test_bad_magic_rejected(self, tmp_path):
        bogus = tmp_path / "bogus.imb"
        bogus.write_bytes(b"NOPE" + b"\x00" * 64)
        with pytest.raises(ValueError, match="Not an IronMesh"):
            backup.restore_backup(
                in_path=str(bogus), passphrase=STRONG_PP,
                keys_path=str(tmp_path / "k.json"),
                trust_path=str(tmp_path / "t.json"),
                audit_path=str(tmp_path / "a.log"),
            )

    def test_no_sources_raises(self, tmp_path):
        """If none of the source files exist, create_backup raises."""
        out = tmp_path / "empty.imb"
        with pytest.raises(ValueError, match="No source files"):
            backup.create_backup(
                out_path=str(out), passphrase=STRONG_PP,
                keys_path=str(tmp_path / "none_k.json"),
                trust_path=str(tmp_path / "none_t.json"),
                audit_path=str(tmp_path / "none_a.log"),
            )
