"""Tests for ironmesh.cli — argument parsing and passphrase sourcing."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
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
        args = _parse(["run", "--name", "alice", "--port", "8765"])
        assert args.command == "run"
        assert args.name == "alice"
        assert args.port == 8765

    def test_demo_subcommand_defaults(self):
        args = _parse(["demo"])
        assert args.command == "demo"
        assert args.port == 18765
        assert args.timeout == 30.0

    def test_demo_subcommand_custom_port_and_timeout(self):
        args = _parse(["demo", "--port", "40000", "--timeout", "5"])
        assert args.command == "demo"
        assert args.port == 40000
        assert args.timeout == 5.0

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


# ---------------------------------------------------------------------------
# Setup wizard (cmd_setup) — non-interactive path used by automation / CI.
# ---------------------------------------------------------------------------

class TestSetupWizard:
    """Non-interactive `ironmesh setup` walkthrough.

    Interactive prompts are exercised by manual smoke testing only;
    these tests cover the scriptable path that automation depends on.
    """

    def _run_setup(self, tmpdir, **flags):
        """Invoke cmd_setup with the given flag overrides; return exit code."""
        keys_path = tmpdir / "keys.json"
        pass_path = tmpdir / "passphrase"
        argv = [
            "ironmesh", "setup",
            "--non-interactive",
            "--passphrase-from-env",
            "--keys-path", str(keys_path),
            "--passphrase-file", str(pass_path),
        ]
        for key, value in flags.items():
            cli_flag = "--" + key.replace("_", "-")
            if value is True:
                argv.append(cli_flag)
            elif value is False:
                continue
            else:
                argv.extend([cli_flag, str(value)])
        with patch.object(sys, "argv", argv):
            return cli.main()

    def test_non_interactive_creates_passphrase_and_keys(self, tmp_path):
        env = {"IRONMESH_SETUP_PASSPHRASE": "wizard-test-passphrase-12-plus"}
        with patch.dict(os.environ, env, clear=False):
            rc = self._run_setup(
                tmp_path,
                name="testnode",
                port=18999,
                allowed_peers="alice,bob",
                enable_trust_gate=True,
            )
        assert rc == 0
        assert (tmp_path / "passphrase").is_file()
        assert (tmp_path / "keys.json").is_file()
        assert (tmp_path / "passphrase").read_text(
            encoding="utf-8"
        ) == "wizard-test-passphrase-12-plus"

    def test_non_interactive_requires_passphrase_source(self, tmp_path, capsys):
        # Neither an existing file nor IRONMESH_SETUP_PASSPHRASE -> hard fail
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IRONMESH_SETUP_PASSPHRASE", None)
            rc = self._run_setup(tmp_path, name="testnode", port=18999)
        assert rc == 1
        out = capsys.readouterr().out
        assert "passphrase" in out.lower()

    def test_non_interactive_rejects_short_env_passphrase(self, tmp_path, capsys):
        # Empty env value should fail clearly, not silently use ""
        env = {"IRONMESH_SETUP_PASSPHRASE": ""}
        with patch.dict(os.environ, env, clear=False):
            rc = self._run_setup(tmp_path, name="testnode", port=18999)
        assert rc == 1

    def test_non_interactive_keeps_existing_passphrase_file(self, tmp_path):
        # Pre-create a passphrase file; wizard should reuse it without
        # needing the env var
        existing = "preexisting-passphrase-12-plus"
        pass_path = tmp_path / "passphrase"
        pass_path.write_text(existing, encoding="utf-8")
        # No IRONMESH_SETUP_PASSPHRASE set; should still succeed because
        # the file already exists
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IRONMESH_SETUP_PASSPHRASE", None)
            rc = self._run_setup(
                tmp_path,
                name="testnode",
                port=18999,
                no_trust_gate=True,
            )
        assert rc == 0
        # Existing passphrase preserved
        assert pass_path.read_text(encoding="utf-8") == existing
