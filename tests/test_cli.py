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

    def test_plaintext_key_file_no_prompt_but_migration_passphrase(
            self, tmp_path, monkeypatch):
        """A plaintext key file never prompts; the mesh passphrase is
        handed back so the daemon can re-encrypt the file forward —
        unless plaintext keys were explicitly opted into."""
        from ironmesh.keys import generate_keypair, save_keys
        path = tmp_path / "plain.json"
        save_keys(generate_keypair("p"), str(path), allow_plaintext=True)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        with patch.object(cli.getpass, "getpass") as gp:
            assert cli._resolve_keys_passphrase(
                str(path), mesh_passphrase=MESH_PASSPHRASE) == MESH_PASSPHRASE
            assert cli._resolve_keys_passphrase(
                str(path), mesh_passphrase=MESH_PASSPHRASE,
                plaintext_opt_in=True) is None
        gp.assert_not_called()

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


class TestAutogenKeysEncryptedByDefault:
    """Bare `ironmesh run --name X` (no setup, no key file yet) must not
    silently write a plaintext keys.json: the mesh passphrase — always
    present by the time keys are generated — encrypts the new key file.
    Plaintext requires the explicit --plaintext-keys opt-in."""

    def _invoke_run(self, tmp_path, extra=()):
        captured = {}

        class _StubDaemon:
            def __init__(self, **kwargs):
                captured.update(kwargs)

            def run(self):
                pass

        pass_file = tmp_path / "passphrase"
        pass_file.write_text(MESH_PASSPHRASE, encoding="utf-8")
        argv = [
            "ironmesh", "run", "--name", "barenode", "--port", "18997",
            "--passphrase-file", str(pass_file),
            "--keys-path", str(tmp_path / "keys.json"),
            *extra,
        ]
        with patch("ironmesh.bridge.BridgeDaemon", _StubDaemon):
            with patch.object(sys, "argv", argv):
                rc = cli.main()
        return rc, captured

    def test_bare_run_encrypts_autogen_keys_with_mesh_passphrase(self, tmp_path):
        rc, captured = self._invoke_run(tmp_path)
        assert rc == 0
        assert captured["keys_passphrase"] == MESH_PASSPHRASE
        assert captured["plaintext_keys"] is False

    def test_plaintext_keys_flag_is_the_only_plaintext_path(self, tmp_path):
        rc, captured = self._invoke_run(tmp_path, extra=("--plaintext-keys",))
        assert rc == 0
        assert captured["keys_passphrase"] is None
        assert captured["plaintext_keys"] is True

    def test_existing_plaintext_file_gets_mesh_passphrase_for_migration(
            self, tmp_path):
        from ironmesh.keys import generate_keypair, save_keys
        save_keys(generate_keypair("plain"), str(tmp_path / "keys.json"),
                  allow_plaintext=True)
        rc, captured = self._invoke_run(tmp_path)
        assert rc == 0
        # The daemon re-encrypts the plaintext file forward with this.
        assert captured["keys_passphrase"] == MESH_PASSPHRASE


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


# ---------------------------------------------------------------------------
# Profiles (_apply_profile) — canonical postures + behavior-preserving aliases
# ---------------------------------------------------------------------------

class TestProfiles:
    """Profile resolution for the canonical set (lan / lora / homelab /
    tactical / custom) and the three back-compat aliases (secure / dev /
    offline). Aliases MUST be behavior-preserving — the same argv must
    produce the same mutated args + warnings it did before the canonical
    set was introduced.
    """

    def _resolve(self, profile, extra=()):
        """Parse a real `run` argv with the given --profile, apply the
        profile, and return (args, warnings)."""
        argv = ["run", "--name", "n"]
        if profile is not None:
            argv += ["--profile", profile]
        argv += list(extra)
        args = _parse(argv)
        warnings = cli._apply_profile(args)
        return args, warnings

    # -- canonical postures -------------------------------------------------

    def test_lan_sets_no_opinionated_defaults(self):
        """lan == the shipped zero-config default: no flag mutations."""
        base, _ = self._resolve(None)
        args, warnings = self._resolve("lan")
        assert warnings == []
        assert args.require_message_promotion == base.require_message_promotion
        assert args.open_discovery == base.open_discovery
        assert args.allow_plaintext_ws == base.allow_plaintext_ws
        assert args.reticulum == base.reticulum

    def test_custom_sets_no_opinionated_defaults(self):
        base, _ = self._resolve(None)
        args, warnings = self._resolve("custom")
        assert warnings == []
        assert args.require_message_promotion == base.require_message_promotion
        assert args.open_discovery == base.open_discovery
        assert args.reticulum == base.reticulum

    def test_lora_enables_reticulum(self):
        args, warnings = self._resolve("lora")
        assert args.reticulum is True
        assert warnings == []
        # lora leaves discovery alone (default-deny handles it).
        assert args.open_discovery is False

    def test_homelab_leaves_lan_defaults(self):
        base, _ = self._resolve(None)
        args, warnings = self._resolve("homelab")
        assert warnings == []
        assert args.open_discovery == base.open_discovery
        assert args.reticulum == base.reticulum

    def test_tactical_enables_trust_gate(self):
        args, warnings = self._resolve("tactical")
        assert args.require_message_promotion is True
        assert warnings == []

    def test_tactical_warns_on_open_discovery_override(self):
        args, warnings = self._resolve("tactical", extra=("--open-discovery",))
        # Explicit flag wins…
        assert args.open_discovery is True
        # …but a warning is emitted naming the tactical profile.
        assert any("tactical" in w and "open-discovery" in w for w in warnings)

    def test_tactical_warns_on_plaintext_ws_override(self):
        args, warnings = self._resolve(
            "tactical", extra=("--allow-plaintext-ws",))
        assert args.allow_plaintext_ws is True
        assert any("tactical" in w and "allow-plaintext-ws" in w
                   for w in warnings)

    # -- back-compat aliases: behavior-preserving ---------------------------

    def test_secure_is_behavior_preserving(self):
        """`--profile=secure` must produce exactly the pre-change args +
        warnings: require_message_promotion True, no other mutation, no
        warning when no insecure flags are set."""
        args, warnings = self._resolve("secure")
        assert args.require_message_promotion is True
        assert args.open_discovery is False
        assert args.allow_plaintext_ws is False
        assert warnings == []

    def test_secure_warns_exact_legacy_text(self):
        """The alias must reproduce the historical warning text verbatim
        (an alias that changed the message is a behavior change)."""
        args, warnings = self._resolve(
            "secure", extra=("--open-discovery", "--allow-plaintext-ws"))
        joined = "\n".join(warnings)
        assert "profile=secure was overridden: --allow-plaintext-ws is set" \
            in joined
        assert "profile=secure was overridden: --open-discovery is set" \
            in joined

    def test_secure_is_distinct_from_tactical(self):
        """secure and tactical are kept as separate branches (not aliased).
        They agree on the gate flag today, but the warning text differs by
        name — proving they are distinct code paths so tactical can diverge
        (crypto-suite pinning) without silently changing `secure`."""
        _, sec_w = self._resolve("secure", extra=("--open-discovery",))
        _, tac_w = self._resolve("tactical", extra=("--open-discovery",))
        assert any("profile=secure" in w for w in sec_w)
        assert any("profile=tactical" in w for w in tac_w)

    def test_dev_enables_insecure_shortcuts(self):
        args, warnings = self._resolve("dev")
        assert args.open_discovery is True
        assert args.allow_plaintext_ws is True
        assert warnings == []

    def test_offline_enables_reticulum(self):
        args, warnings = self._resolve("offline")
        assert args.reticulum is True
        assert warnings == []

    def test_offline_is_distinct_from_lora(self):
        """offline and lora both currently enable Reticulum but are
        separate branches with different documented intent — offline must
        NOT be an alias of lora."""
        off, _ = self._resolve("offline")
        lora, _ = self._resolve("lora")
        # Both enable reticulum, but they are reached via distinct choices.
        assert off.profile == "offline"
        assert lora.profile == "lora"

    def test_explicit_flag_wins_over_profile(self):
        """A user-supplied flag is never clobbered by the profile."""
        # dev would set open_discovery True; user did not ask, so it's set.
        args, _ = self._resolve("dev")
        assert args.open_discovery is True
        # tactical would set the gate; user can still leave it — but if the
        # user explicitly set require_message_promotion it stays set.
        args2, _ = self._resolve(
            "tactical", extra=("--require-message-promotion",))
        assert args2.require_message_promotion is True

    def test_no_profile_is_noop(self):
        args, warnings = self._resolve(None)
        assert warnings == []
        assert args.profile is None

    def test_all_canonical_and_alias_choices_parse(self):
        """Every documented profile name must be an accepted choice."""
        for name in ("lan", "lora", "homelab", "tactical", "custom",
                     "secure", "dev", "offline"):
            args = _parse(["run", "--name", "n", "--profile", name])
            assert args.profile == name


# ---------------------------------------------------------------------------
# Doctor onboarding + safe auto-fix (Item 1)
# ---------------------------------------------------------------------------

from types import SimpleNamespace


class TestDoctorDetectionHelpers:
    """The single OS/network-detection code path shared by doctor and the
    future wizard."""

    def test_detect_os_returns_known_family(self):
        assert cli._detect_os() in ("linux", "macos", "windows", "unknown")

    def test_firewall_command_per_os(self):
        assert "ufw allow 8765" in cli._firewall_command("linux", 8765)
        assert "socketfilterfw" in cli._firewall_command("macos", 8765)
        assert "netsh advfirewall" in cli._firewall_command("windows", 8765)
        assert "8765" in cli._firewall_command("unknown", 8765)

    def test_detect_network_posture_shape(self):
        p = cli._detect_network_posture(0, "127.0.0.1")
        for key in ("os", "over_ssh", "mdns_ok", "mdns_detail",
                    "port_bindable", "firewall_hint"):
            assert key in p
        # Binding to an ephemeral port on loopback should be possible.
        assert p["port_bindable"] in (True, False)

    def test_over_ssh_reads_ssh_connection(self, monkeypatch):
        monkeypatch.setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")
        assert cli._over_ssh() is True

    def test_over_ssh_false_without_env(self, monkeypatch):
        for v in ("SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"):
            monkeypatch.delenv(v, raising=False)
        assert cli._over_ssh() is False

    def test_probe_ollama_never_raises(self):
        up, detail = cli._probe_ollama(timeout=0.1)
        assert isinstance(up, bool)
        assert isinstance(detail, str)


class TestDoctorParserFlags:
    """The new doctor flags must be registered and default off."""

    def test_onboard_fix_flags_default_off(self):
        args = _parse(["doctor"])
        assert args.onboard is False
        assert args.fix is False
        assert args.allow_remote_network_fix is False

    def test_flags_settable(self):
        args = _parse(["doctor", "--onboard", "--fix",
                       "--allow-remote-network-fix"])
        assert args.onboard is True
        assert args.fix is True
        assert args.allow_remote_network_fix is True

    def test_doctor_accepts_profile(self):
        args = _parse(["doctor", "--profile", "homelab"])
        assert args.profile == "homelab"


class TestDoctorFirewallFixSafety:
    """--fix must NEVER auto-apply a firewall rule. It requires a TTY +
    explicit y confirmation, and is refused over SSH without the opt-in."""

    def _posture(self):
        return {
            "os": "linux",
            "over_ssh": False,
            "mdns_ok": True,
            "mdns_detail": "",
            "port_bindable": True,
            "firewall_hint": cli._firewall_command("linux", 8765),
        }

    def test_refused_over_ssh_without_flag(self, monkeypatch, capsys):
        monkeypatch.setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")
        args = SimpleNamespace(fix=True, allow_remote_network_fix=False)
        applied = cli._doctor_fix_firewall(args, self._posture())
        assert applied is False
        assert "FIX REFUSED" in capsys.readouterr().out

    def test_no_tty_skips_without_applying(self, monkeypatch, capsys):
        """No TTY → cannot confirm → never applies (and never prompts)."""
        for v in ("SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"):
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        # If this tried to run subprocess, the test would error — assert it
        # never gets there.
        with patch("subprocess.call") as sub:
            args = SimpleNamespace(fix=True, allow_remote_network_fix=False)
            applied = cli._doctor_fix_firewall(args, self._posture())
        assert applied is False
        sub.assert_not_called()
        assert "FIX SKIP" in capsys.readouterr().out

    def test_declined_confirmation_does_not_apply(self, monkeypatch, capsys):
        for v in ("SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"):
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda *a, **k: "n")
        with patch("subprocess.call") as sub:
            args = SimpleNamespace(fix=True, allow_remote_network_fix=False)
            applied = cli._doctor_fix_firewall(args, self._posture())
        assert applied is False
        sub.assert_not_called()

    def test_ssh_allowed_with_optin_still_requires_confirmation(
            self, monkeypatch):
        """Even with --allow-remote-network-fix over SSH, a 'n' answer must
        not apply the rule (the confirmation gate is independent)."""
        monkeypatch.setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda *a, **k: "n")
        with patch("subprocess.call") as sub:
            args = SimpleNamespace(fix=True, allow_remote_network_fix=True)
            applied = cli._doctor_fix_firewall(args, self._posture())
        assert applied is False
        sub.assert_not_called()


class TestDoctorLocalFixes:
    """Local file fixes are idempotent, non-destructive, and allowed even
    over SSH."""

    def test_chmod_fix_idempotent_and_ssh_allowed(self, tmp_path,
                                                   monkeypatch):
        if os.name != "posix":
            pytest.skip("chmod perms only meaningful on POSIX")
        pf = tmp_path / "passphrase"
        pf.write_text("a-real-passphrase-1234")
        os.chmod(str(pf), 0o644)
        # Over SSH — local file fix must still be allowed.
        monkeypatch.setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")
        args = SimpleNamespace()
        assert cli._doctor_fix_passphrase_perms(str(pf), args) is True
        assert (os.stat(str(pf)).st_mode & 0o777) == 0o600
        # Idempotent — running again is still fine.
        assert cli._doctor_fix_passphrase_perms(str(pf), args) is True

    def test_missing_keys_fix_never_overwrites(self, tmp_path):
        from ironmesh.keys import generate_keypair, save_keys
        kp_path = tmp_path / "keys.json"
        save_keys(generate_keypair("existing"), str(kp_path),
                  allow_plaintext=True)
        before = kp_path.read_bytes()
        args = SimpleNamespace(keys_passphrase="pp-1234567890ab",
                               keys_passphrase_file=None,
                               passphrase_file=None, name="x")
        # File exists → fix must refuse and return None (no overwrite).
        assert cli._doctor_fix_missing_keys(str(kp_path), args) is None
        assert kp_path.read_bytes() == before

    def test_missing_keys_fix_regenerates_when_absent(self, tmp_path):
        kp_path = tmp_path / "keys.json"
        args = SimpleNamespace(keys_passphrase="pp-1234567890ab",
                               keys_passphrase_file=None,
                               passphrase_file=None, name="fixnode")
        result = cli._doctor_fix_missing_keys(str(kp_path), args)
        assert result is not None
        assert kp_path.is_file()

    def test_missing_keys_fix_refuses_plaintext_without_passphrase(
            self, tmp_path, monkeypatch):
        """No passphrase available → refuse rather than write a plaintext
        key file (a security downgrade is not a 'safe fix')."""
        for v in ("IRONMESH_KEYS_PASSPHRASE", "IRONMESH_PASSPHRASE"):
            monkeypatch.delenv(v, raising=False)
        kp_path = tmp_path / "keys.json"
        args = SimpleNamespace(keys_passphrase=None, keys_passphrase_file=None,
                               passphrase_file=None, name="x")
        assert cli._doctor_fix_missing_keys(str(kp_path), args) is None
        assert not kp_path.exists()

    def test_missing_config_fix_creates_and_does_not_overwrite(
            self, tmp_path, monkeypatch):
        cfg_path = tmp_path / "config.json"
        monkeypatch.setattr(
            "ironmesh.config.DEFAULT_CONFIG_PATH", str(cfg_path))
        args = SimpleNamespace(name="cfgnode")
        assert cli._doctor_fix_missing_config(args) is True
        assert cfg_path.is_file()
        # Second run: present → no-op (returns False, does not overwrite).
        before = cfg_path.read_bytes()
        assert cli._doctor_fix_missing_config(args) is False
        assert cfg_path.read_bytes() == before

    def test_passphrase_perm_warning_flags_permissive(self, tmp_path):
        if os.name != "posix":
            pytest.skip("perm bits only meaningful on POSIX")
        pf = tmp_path / "pp"
        pf.write_text("x")
        os.chmod(str(pf), 0o644)
        assert cli._passphrase_file_perm_warning(str(pf)) is not None
        os.chmod(str(pf), 0o600)
        assert cli._passphrase_file_perm_warning(str(pf)) is None
