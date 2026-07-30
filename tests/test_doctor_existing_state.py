"""Doctor + audit-verify behavior against EXISTING on-disk state.

Two bugs in one release cycle (the TOFU-store source-resolution gap and
the doctor check-7 headless hang) shared a single test blind spot: every
test ran against a pristine HOME, so nothing exercised a node with real
accumulated state on disk. These tests run against a populated
``~/.ironmesh`` — prefer the ``populated_home`` fixture over a pristine
HOME whenever the behavior under test touches files a long-running node
accumulates (keys, audit chain, trust store, queue db).

The check-7 regression class: ``audit.verify_chain()`` reached an
unconditional ``getpass()`` when no passphrase was supplied. On Windows
that prompt reads the console device — not stdin — so a headless
``ironmesh doctor`` froze forever whenever an audit log existed.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import ironmesh
from ironmesh.audit import AuditLog, _derive_audit_key, verify_chain
from ironmesh.keys import generate_keypair, save_keys

TEST_PP = "existing-state-pp-123456"


@pytest.fixture
def populated_home(tmp_path, monkeypatch):
    """A HOME whose ~/.ironmesh holds encrypted keys + a real audit chain."""
    home = tmp_path / "home"
    cfg = home / ".ironmesh"
    cfg.mkdir(parents=True)
    kp = generate_keypair("existing-node")
    save_keys(kp, str(cfg / "keys.json"), passphrase=TEST_PP)
    log = AuditLog(path=str(cfg / "audit.log"),
                   hmac_key=_derive_audit_key(kp.ed25519_secret))
    for i in range(5):
        log.log("TEST_EVENT", {"seq": i})
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for var in ("IRONMESH_PASSPHRASE", "IRONMESH_KEYS_PASSPHRASE"):
        monkeypatch.delenv(var, raising=False)
    return home, cfg, kp


def _no_tty(monkeypatch):
    # The strict guard (GetConsoleMode-backed on Windows) is the single
    # gate for interactive prompts — patch it rather than sys.stdin.
    monkeypatch.setattr("ironmesh.cli_output.stdin_is_interactive",
                        lambda: False)


# ---------------------------------------------------------------------------
# Library level — audit.verify_chain resolution policy
# ---------------------------------------------------------------------------

class TestVerifyChainHeadless:
    def test_encrypted_keys_headless_raises_actionably(self, populated_home,
                                                       monkeypatch):
        _home, cfg, _kp = populated_home
        _no_tty(monkeypatch)
        with pytest.raises(ValueError, match="headless"):
            verify_chain(str(cfg / "audit.log"),
                         keys_path=str(cfg / "keys.json"))

    def test_never_prompts_when_headless(self, populated_home, monkeypatch):
        import getpass as getpass_mod
        _home, cfg, _kp = populated_home
        _no_tty(monkeypatch)

        def _boom(prompt=""):
            raise AssertionError("getpass called in a headless run")

        monkeypatch.setattr(getpass_mod, "getpass", _boom)
        with pytest.raises(ValueError):
            verify_chain(str(cfg / "audit.log"),
                         keys_path=str(cfg / "keys.json"))

    def test_explicit_passphrase_verifies(self, populated_home, monkeypatch):
        _home, cfg, _kp = populated_home
        _no_tty(monkeypatch)
        ok, entries, _ = verify_chain(str(cfg / "audit.log"),
                                      keys_path=str(cfg / "keys.json"),
                                      keys_passphrase=TEST_PP)
        assert ok is True
        assert entries == 5

    def test_legacy_env_var_still_honored(self, populated_home, monkeypatch):
        _home, cfg, _kp = populated_home
        _no_tty(monkeypatch)
        monkeypatch.setenv("IRONMESH_PASSPHRASE", TEST_PP)
        ok, entries, _ = verify_chain(str(cfg / "audit.log"),
                                      keys_path=str(cfg / "keys.json"))
        assert ok is True
        assert entries == 5

    def test_plaintext_keys_verify_headless_with_no_config(self, tmp_path,
                                                           monkeypatch):
        cfg = tmp_path / ".ironmesh"
        cfg.mkdir()
        kp = generate_keypair("plain-node")
        save_keys(kp, str(cfg / "keys.json"), passphrase=None,
                  allow_plaintext=True)
        log = AuditLog(path=str(cfg / "audit.log"),
                       hmac_key=_derive_audit_key(kp.ed25519_secret))
        log.log("TEST_EVENT", {})
        _no_tty(monkeypatch)
        for var in ("IRONMESH_PASSPHRASE", "IRONMESH_KEYS_PASSPHRASE"):
            monkeypatch.delenv(var, raising=False)
        ok, entries, _ = verify_chain(str(cfg / "audit.log"),
                                      keys_path=str(cfg / "keys.json"))
        assert ok is True
        assert entries == 1

    def test_interactive_tty_may_prompt(self, populated_home, monkeypatch):
        import getpass as getpass_mod
        _home, cfg, _kp = populated_home
        monkeypatch.setattr("ironmesh.cli_output.stdin_is_interactive",
                            lambda: True)
        monkeypatch.setattr(getpass_mod, "getpass", lambda prompt="": TEST_PP)
        ok, entries, _ = verify_chain(str(cfg / "audit.log"),
                                      keys_path=str(cfg / "keys.json"))
        assert ok is True
        assert entries == 5


# ---------------------------------------------------------------------------
# CLI level — a real headless `ironmesh doctor` against existing state
# ---------------------------------------------------------------------------

_DOCTOR_CMD = ("import sys; sys.argv = ['ironmesh', 'doctor']; "
               "from ironmesh.cli import main; raise SystemExit(main())")


def _run_doctor(home, extra_env=None, timeout=120):
    """Run doctor in a genuinely headless subprocess (stdin is not a tty).

    The timeout IS the regression assertion: the pre-fix code froze here
    forever with an existing audit log present.
    """
    env = {k: v for k, v in os.environ.items()
           if k not in ("IRONMESH_PASSPHRASE", "IRONMESH_KEYS_PASSPHRASE")}
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env["PYTHONPATH"] = str(Path(ironmesh.__file__).resolve().parent.parent)
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-c", _DOCTOR_CMD],
        stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8",
        env=env, timeout=timeout,
    )


class TestDoctorExistingState:
    def test_headless_unresolvable_errors_out_not_hangs(self, populated_home):
        home, _cfg, _kp = populated_home
        res = _run_doctor(home)
        combined = res.stdout + res.stderr
        assert res.returncode != 0
        assert "Identity key passphrase" not in combined  # never prompted
        assert "could not decrypt key file" in combined   # check 1 actionable
        assert "cannot verify the chain" in combined      # check 7 SKIP, not hang

    def test_headless_resolvable_verifies_chain_without_prompt(
            self, populated_home):
        home, _cfg, _kp = populated_home
        res = _run_doctor(home,
                          extra_env={"IRONMESH_KEYS_PASSPHRASE": TEST_PP})
        combined = res.stdout + res.stderr
        assert "chain verifies clean (5 entries)" in combined
        assert "Identity key passphrase" not in combined
