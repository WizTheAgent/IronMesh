"""Tests for ironmesh.cli — argument parsing and passphrase sourcing."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

import pytest

from ironmesh import cli


def _parse(argv):
    """Run cli.parse_args with a specific argv list."""
    with patch.object(sys, "argv", ["ironmesh"] + argv):
        return cli.parse_args()


# ---------------------------------------------------------------------------
# Subcommand parsing
# ---------------------------------------------------------------------------

class TestSubcommandParsing:

    def test_run_subcommand(self):
        args = _parse(["run", "--name", "wiz", "--port", "8765"])
        assert args.command == "run"
        assert args.name == "wiz"
        assert args.port == 8765

    def test_trust_list(self):
        args = _parse(["trust", "list"])
        assert args.command == "trust"
        assert args.trust_command == "list"

    def test_trust_revoke(self):
        args = _parse(["trust", "revoke", "abc123"])
        assert args.command == "trust"
        assert args.trust_command == "revoke"
        assert args.node_id == "abc123"

    def test_keys_generate(self):
        args = _parse(["keys", "generate"])
        assert args.command == "keys"
        assert args.keys_command == "generate"

    def test_backup_requires_out(self):
        with pytest.raises(SystemExit):
            _parse(["backup"])

    def test_audit_verify(self):
        args = _parse(["audit", "verify"])
        assert args.command == "audit"
        assert args.audit_command == "verify"


# ---------------------------------------------------------------------------
# Passphrase sourcing
# ---------------------------------------------------------------------------

class TestPassphraseSources:

    def test_passphrase_file_read(self, tmp_path, monkeypatch):
        """IRONMESH_PASSPHRASE_FILE is read and stripped."""
        pp = tmp_path / "pp"
        pp.write_text("file-phrase-1234567890\n")
        monkeypatch.setenv("IRONMESH_PASSPHRASE_FILE", str(pp))
        monkeypatch.delenv("IRONMESH_PASSPHRASE", raising=False)
        assert cli.get_passphrase() == "file-phrase-1234567890"

    def test_env_fallback(self, monkeypatch):
        """IRONMESH_PASSPHRASE used when no file set."""
        monkeypatch.delenv("IRONMESH_PASSPHRASE_FILE", raising=False)
        monkeypatch.setenv("IRONMESH_PASSPHRASE", "env-phrase-1234567890")
        assert cli.get_passphrase() == "env-phrase-1234567890"

    def test_short_passphrase_rejected_by_bridge(self):
        from ironmesh.bridge import BridgeDaemon
        with pytest.raises(ValueError, match="too short"):
            BridgeDaemon(name="x", passphrase="short")

    def test_empty_passphrase_rejected_by_bridge(self):
        from ironmesh.bridge import BridgeDaemon
        with pytest.raises(ValueError):
            BridgeDaemon(name="x", passphrase="")


# ---------------------------------------------------------------------------
# No --passphrase positional on subcommand help (audit #14)
# ---------------------------------------------------------------------------

class TestPassphraseNotInProcList:

    def test_run_help_does_not_document_passphrase(self, capsys):
        """The `run` help text must not advertise --passphrase (it's
        hidden for security — users must use --passphrase-file or env).
        """
        with pytest.raises(SystemExit):
            _parse(["run", "--help"])
        out = capsys.readouterr().out
        # --passphrase-file should appear; bare --passphrase should not
        assert "--passphrase-file" in out
        # The flag may exist with argparse.SUPPRESS but must not be documented
        # in the visible help text.
        visible_lines = [l for l in out.splitlines() if "--passphrase" in l
                         and "--passphrase-file" not in l
                         and "--passphrase-env" not in l
                         and "--keys-passphrase" not in l
                         and "--rns-" not in l]
        assert not visible_lines, f"Unexpected --passphrase documentation: {visible_lines}"
