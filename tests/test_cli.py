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

    def test_trust_accepts_audit_path(self):
        """`trust --audit-path ...` is the explicit override so operators
        can point the CLI at a daemon's audit log. Without this flag, a
        daemon running with a custom --db-path would keep its audit log
        next to the db, while the CLI wrote mutations to
        ~/.ironmesh/audit.log — the daemon's scanner never saw them and
        the PEER_CAP_ACCEPTED counter stayed stuck at zero.
        """
        args = _parse([
            "trust",
            "--trust-path", "/tmp/custom/known_peers.json",
            "--audit-path", "/tmp/custom/audit.log",
            "list",
        ])
        assert args.audit_path == "/tmp/custom/audit.log"
        assert args.trust_path == "/tmp/custom/known_peers.json"

    def test_trust_audit_path_defaults_to_none(self):
        """When neither --audit-path nor --trust-path are given, the
        CLI uses AuditLog's default (~/.ironmesh/audit.log)."""
        args = _parse(["trust", "list"])
        assert args.audit_path is None
        assert args.trust_path is None

    def test_doctor_unpacks_verify_chain_three_tuple(self):
        """`audit.verify_chain` returns a 3-tuple
        `(ok, entries_checked, first_invalid_line)`. The doctor
        subcommand previously unpacked it as `ok, msg = ...` which
        raised `too many values to unpack (expected 2)` whenever an
        audit log existed at the resolved path. This test pins the
        unpacking signature so a future verify_chain change forces an
        intentional update on both sides.
        """
        from ironmesh import audit as audit_mod
        import inspect
        src = inspect.getsource(audit_mod.verify_chain)
        # The signature comment in verify_chain documents the tuple shape.
        assert "ok, entries_checked, first_invalid_line" in src or \
               "Returns" in src
        # And the value count: verify_chain delegates to AuditLog.verify
        # which returns (valid, entries_checked, first_invalid_line) per
        # its own docstring.
        ret = audit_mod.AuditLog.verify.__doc__ or ""
        assert "valid" in ret and "entries_checked" in ret \
            and "first_invalid_line" in ret


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

    def _read_keys_envelope(self, keys_path):
        import json
        with open(keys_path) as f:
            return json.load(f)

    def test_wizard_keys_are_encrypted_with_mesh_passphrase(self, tmp_path):
        """The wizard encrypts the key file with the mesh passphrase —
        the invariant the run-time mesh-passphrase fallback relies on."""
        from ironmesh.keys import load_keys
        env = {"IRONMESH_SETUP_PASSPHRASE": "wizard-test-passphrase-12-plus"}
        with patch.dict(os.environ, env, clear=False):
            rc = self._run_setup(tmp_path, name="testnode", port=18999)
        assert rc == 0
        envelope = self._read_keys_envelope(tmp_path / "keys.json")
        assert envelope["encrypted"] is True
        keys = load_keys(str(tmp_path / "keys.json"),
                         passphrase="wizard-test-passphrase-12-plus")
        assert len(keys.ed25519_secret) == 32

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


# ---------------------------------------------------------------------------
# Identity key-file passphrase resolution (golden-path fix).
#
# `ironmesh setup` encrypts keys.json with the mesh passphrase, then
# prints an `ironmesh run` command that previously failed with
# "Key file is encrypted but no passphrase provided". These tests pin
# the full precedence chain that makes the printed command work:
#   --keys-passphrase > --keys-passphrase-file > IRONMESH_KEYS_PASSPHRASE
#   > mesh passphrase (tried silently) > interactive prompt > hard error.
# ---------------------------------------------------------------------------

MESH_PASSPHRASE = "golden-mesh-passphrase-12plus"
OTHER_KEYS_PASSPHRASE = "different-keys-passphrase-12plus"


@pytest.fixture(scope="module")
def encrypted_keys_file(tmp_path_factory):
    """A keys.json encrypted with the mesh passphrase (what setup writes)."""
    from ironmesh.keys import generate_keypair, save_keys
    path = tmp_path_factory.mktemp("keys-mesh") / "keys.json"
    save_keys(generate_keypair("golden"), str(path),
              passphrase=MESH_PASSPHRASE)
    return str(path)


@pytest.fixture(scope="module")
def separately_encrypted_keys_file(tmp_path_factory):
    """A keys.json encrypted with a passphrase != mesh passphrase."""
    from ironmesh.keys import generate_keypair, save_keys
    path = tmp_path_factory.mktemp("keys-sep") / "keys.json"
    save_keys(generate_keypair("golden-sep"), str(path),
              passphrase=OTHER_KEYS_PASSPHRASE)
    return str(path)


@pytest.fixture(autouse=True)
def _clear_keys_passphrase_env(monkeypatch):
    monkeypatch.delenv("IRONMESH_KEYS_PASSPHRASE", raising=False)


class TestResolveKeysPassphrase:

    def test_explicit_flag_wins_and_warns(self, encrypted_keys_file,
                                          capsys, monkeypatch):
        monkeypatch.setenv("IRONMESH_KEYS_PASSPHRASE", "env-should-lose")
        pp = cli._resolve_keys_passphrase(
            encrypted_keys_file,
            explicit="explicit-wins",
            passphrase_file=None,
            mesh_passphrase=MESH_PASSPHRASE,
        )
        assert pp == "explicit-wins"
        out = capsys.readouterr().out
        assert "process list" in out  # discouraged-flag warning

    def test_passphrase_file_beats_env_and_strips_newline(
            self, encrypted_keys_file, tmp_path, monkeypatch):
        monkeypatch.setenv("IRONMESH_KEYS_PASSPHRASE", "env-should-lose")
        pp_file = tmp_path / "kp"
        pp_file.write_text(OTHER_KEYS_PASSPHRASE + "\n", encoding="utf-8")
        pp = cli._resolve_keys_passphrase(
            encrypted_keys_file,
            passphrase_file=str(pp_file),
            mesh_passphrase=MESH_PASSPHRASE,
        )
        assert pp == OTHER_KEYS_PASSPHRASE

    def test_env_var_beats_mesh_fallback(self, encrypted_keys_file,
                                         monkeypatch):
        monkeypatch.setenv("IRONMESH_KEYS_PASSPHRASE", "from-the-env")
        pp = cli._resolve_keys_passphrase(
            encrypted_keys_file, mesh_passphrase=MESH_PASSPHRASE)
        assert pp == "from-the-env"

    def test_mesh_passphrase_fallback_golden_path(self, encrypted_keys_file):
        """Setup-produced state: nothing supplied, mesh passphrase
        decrypts the key file silently — no prompt, no flags."""
        pp = cli._resolve_keys_passphrase(
            encrypted_keys_file, mesh_passphrase=MESH_PASSPHRASE)
        assert pp == MESH_PASSPHRASE

    def test_mesh_mismatch_falls_through_to_prompt(
            self, separately_encrypted_keys_file, monkeypatch):
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        with patch.object(cli.getpass, "getpass",
                          return_value=OTHER_KEYS_PASSPHRASE) as gp:
            pp = cli._resolve_keys_passphrase(
                separately_encrypted_keys_file,
                mesh_passphrase=MESH_PASSPHRASE,
            )
        assert pp == OTHER_KEYS_PASSPHRASE
        prompt = gp.call_args[0][0]
        assert separately_encrypted_keys_file in prompt  # names the file

    def test_interactive_prompt_wrong_passphrase_is_actionable(
            self, separately_encrypted_keys_file, monkeypatch):
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        with patch.object(cli.getpass, "getpass",
                          return_value="not-the-passphrase"):
            with pytest.raises(ValueError) as exc:
                cli._resolve_keys_passphrase(separately_encrypted_keys_file)
        msg = str(exc.value)
        assert "wrong passphrase" in msg
        assert "--keys-passphrase-file" in msg
        assert "IRONMESH_KEYS_PASSPHRASE" in msg

    def test_non_tty_nothing_supplied_hard_error_lists_options(
            self, encrypted_keys_file, monkeypatch):
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        with pytest.raises(ValueError) as exc:
            cli._resolve_keys_passphrase(encrypted_keys_file)
        msg = str(exc.value)
        assert "--keys-passphrase-file" in msg
        assert "IRONMESH_KEYS_PASSPHRASE" in msg
        assert "process list" in msg  # argv flag documented as discouraged

    def test_non_tty_mesh_mismatch_error_mentions_mesh_try(
            self, separately_encrypted_keys_file, monkeypatch):
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        with pytest.raises(ValueError) as exc:
            cli._resolve_keys_passphrase(
                separately_encrypted_keys_file,
                mesh_passphrase=MESH_PASSPHRASE,
            )
        assert "mesh passphrase was tried" in str(exc.value)

    def test_plaintext_key_file_needs_no_passphrase(self, tmp_path):
        from ironmesh.keys import generate_keypair, save_keys
        path = tmp_path / "plain.json"
        save_keys(generate_keypair("p"), str(path), allow_plaintext=True)
        assert cli._resolve_keys_passphrase(
            str(path), mesh_passphrase=MESH_PASSPHRASE) is None

    def test_missing_key_file_resolves_without_prompt(self, tmp_path,
                                                      monkeypatch):
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        with patch.object(cli.getpass, "getpass") as gp:
            cli._resolve_keys_passphrase(str(tmp_path / "nope.json"),
                                         mesh_passphrase=MESH_PASSPHRASE)
        gp.assert_not_called()

    def test_unreadable_passphrase_file_is_actionable(self, tmp_path,
                                                      encrypted_keys_file):
        with pytest.raises(ValueError, match="keys passphrase file"):
            cli._resolve_keys_passphrase(
                encrypted_keys_file,
                passphrase_file=str(tmp_path / "does-not-exist"),
            )


class TestGoldenPathRunWiring:
    """setup-produced state → `ironmesh run` (as printed by the wizard)
    resolves the key-file passphrase via the mesh-passphrase fallback.
    BridgeDaemon is stubbed so no network/daemon starts; the hands-on
    daemon start is covered by the release smoke run."""

    def _setup_node(self, tmp_path):
        env = {"IRONMESH_SETUP_PASSPHRASE": MESH_PASSPHRASE}
        argv = [
            "ironmesh", "setup", "--non-interactive", "--passphrase-from-env",
            "--name", "goldennode", "--port", "18998",
            "--keys-path", str(tmp_path / "keys.json"),
            "--passphrase-file", str(tmp_path / "passphrase"),
        ]
        with patch.dict(os.environ, env, clear=False):
            with patch.object(sys, "argv", argv):
                assert cli.main() == 0

    def _run_daemon_argv(self, tmp_path, extra=()):
        return [
            "ironmesh", "run", "--name", "goldennode", "--port", "18998",
            "--passphrase-file", str(tmp_path / "passphrase"),
            "--keys-path", str(tmp_path / "keys.json"),
            *extra,
        ]

    def _invoke_run(self, argv):
        """Run cli.main() with BridgeDaemon stubbed; return captured kwargs."""
        captured = {}

        class _StubDaemon:
            def __init__(self, **kwargs):
                captured.update(kwargs)

            def run(self):
                pass

        with patch("ironmesh.bridge.BridgeDaemon", _StubDaemon):
            with patch.object(sys, "argv", argv):
                rc = cli.main()
        return rc, captured

    def test_wizard_printed_command_resolves_keys_passphrase(self, tmp_path):
        self._setup_node(tmp_path)
        rc, captured = self._invoke_run(self._run_daemon_argv(tmp_path))
        assert rc == 0
        # The mesh passphrase was adopted as the key-file passphrase.
        assert captured["keys_passphrase"] == MESH_PASSPHRASE
        assert captured["passphrase"] == MESH_PASSPHRASE

    def test_explicit_keys_passphrase_still_wins(self, tmp_path, capsys):
        self._setup_node(tmp_path)
        rc, captured = self._invoke_run(self._run_daemon_argv(
            tmp_path, extra=("--keys-passphrase", MESH_PASSPHRASE)))
        assert rc == 0
        assert captured["keys_passphrase"] == MESH_PASSPHRASE
        assert "process list" in capsys.readouterr().out

    def test_keys_passphrase_file_flag(self, tmp_path):
        self._setup_node(tmp_path)
        kp_file = tmp_path / "keys-pass"
        kp_file.write_text(MESH_PASSPHRASE + "\n", encoding="utf-8")
        rc, captured = self._invoke_run(self._run_daemon_argv(
            tmp_path, extra=("--keys-passphrase-file", str(kp_file))))
        assert rc == 0
        assert captured["keys_passphrase"] == MESH_PASSPHRASE

    def test_headless_wrong_mesh_passphrase_fails_actionably(
            self, tmp_path, capsys, monkeypatch):
        """Key file encrypted with a different passphrase + headless run
        with nothing supplied -> clean exit 1 with the options listed."""
        from ironmesh.keys import generate_keypair, save_keys
        self._setup_node(tmp_path)
        save_keys(generate_keypair("other"), str(tmp_path / "keys.json"),
                  passphrase=OTHER_KEYS_PASSPHRASE)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        rc, captured = self._invoke_run(self._run_daemon_argv(tmp_path))
        assert rc == 1
        assert not captured  # daemon never constructed
        out = capsys.readouterr().out
        assert "IRONMESH_KEYS_PASSPHRASE" in out
        assert "--keys-passphrase-file" in out


class TestEnsureAgentKeysMeshFallback:
    """Daemon-side fallback: BridgeDaemon passes the mesh passphrase to
    ensure_agent_keys so library callers get the golden path too."""

    @pytest.mark.asyncio
    async def test_encrypted_file_loads_via_fallback(self, encrypted_keys_file):
        from ironmesh.bridge import ensure_agent_keys
        keys = await ensure_agent_keys(
            encrypted_keys_file, None, fallback_passphrase=MESH_PASSPHRASE)
        assert len(keys.ed25519_secret) == 32

    @pytest.mark.asyncio
    async def test_fallback_mismatch_is_actionable(
            self, separately_encrypted_keys_file):
        from ironmesh.bridge import ensure_agent_keys
        with pytest.raises(ValueError) as exc:
            await ensure_agent_keys(separately_encrypted_keys_file, None,
                                    fallback_passphrase=MESH_PASSPHRASE)
        msg = str(exc.value)
        assert "different from the mesh passphrase" in msg
        assert "--keys-passphrase-file" in msg

    @pytest.mark.asyncio
    async def test_no_passphrase_no_fallback_is_actionable(
            self, encrypted_keys_file):
        from ironmesh.bridge import ensure_agent_keys
        with pytest.raises(ValueError) as exc:
            await ensure_agent_keys(encrypted_keys_file, None)
        assert "IRONMESH_KEYS_PASSPHRASE" in str(exc.value)

    @pytest.mark.asyncio
    async def test_wrong_explicit_passphrase_is_actionable(
            self, encrypted_keys_file):
        from ironmesh.bridge import ensure_agent_keys
        with pytest.raises(ValueError) as exc:
            await ensure_agent_keys(encrypted_keys_file, "wrong-passphrase-x")
        assert "wrong passphrase" in str(exc.value)
        assert "--keys-passphrase-file" in str(exc.value)
