"""A mistyped security setting must refuse to start, never silently mean "off".

Covers the runtime entry points that read these settings from the environment
directly (``ironmesh run``, ``ironmesh-mcp``, the daemon's key-rotation
trigger) plus the CLI flag for the pending-trust queue cap, whose zero or
negative values would otherwise disable the cap entirely.
"""

import argparse
import asyncio
import sys

import pytest

import ironmesh.bridge as bridge_mod
import ironmesh.cli as cli
import ironmesh_mcp.server as mcp_srv
from ironmesh.config import ConfigError, parse_env_flag, parse_env_limit


class _Reached(Exception):
    """Raised if a startup step runs that a config error should have blocked."""


def _forbid(*_args, **_kwargs):
    raise _Reached("startup continued past an invalid setting")


class TestIronmeshRun:
    @pytest.fixture(autouse=True)
    def _guard(self, monkeypatch):
        monkeypatch.setattr(bridge_mod, "BridgeDaemon", _forbid)
        monkeypatch.setattr(bridge_mod, "rotate_keys", _forbid)
        for var in ("IRONMESH_REQUIRE_MSG_PROMOTION", "IRONMESH_ROTATE_KEYS"):
            monkeypatch.delenv(var, raising=False)

    def _args(self, **extra):
        return argparse.Namespace(name="strict-node", rotate_keys=True, **extra)

    @pytest.mark.parametrize("var,typo", [
        ("IRONMESH_REQUIRE_MSG_PROMOTION", "ture"),
        ("IRONMESH_ROTATE_KEYS", "yse"),
    ])
    def test_typo_refuses_before_any_startup_step(self, monkeypatch, capsys,
                                                 var, typo):
        monkeypatch.setenv(var, typo)
        assert cli.cmd_run(self._args()) == 1
        out = capsys.readouterr().out
        assert "ERROR:" in out and var in out and typo in out


class TestMcpEntrypoint:
    @pytest.fixture(autouse=True)
    def _guard(self, monkeypatch):
        monkeypatch.setattr(mcp_srv, "BridgeDaemon", _forbid)
        monkeypatch.setenv("IRONMESH_PASSPHRASE", "strict-env-test-passphrase")
        monkeypatch.setattr(sys, "argv", ["ironmesh-mcp"])
        for var in ("IRONMESH_REQUIRE_MSG_PROMOTION", "IRONMESH_ROTATE_KEYS",
                    "IRONMESH_PENDING_QUEUE_CAP"):
            monkeypatch.delenv(var, raising=False)

    @pytest.mark.parametrize("var,bad", [
        ("IRONMESH_REQUIRE_MSG_PROMOTION", "ture"),
        ("IRONMESH_ROTATE_KEYS", "maybe"),
        ("IRONMESH_PENDING_QUEUE_CAP", "-1"),
        ("IRONMESH_PENDING_QUEUE_CAP", "0"),
        ("IRONMESH_PENDING_QUEUE_CAP", "1O"),
    ])
    def test_invalid_value_refuses_before_daemon(self, monkeypatch, capsys,
                                                 var, bad):
        monkeypatch.setenv(var, bad)
        assert mcp_srv.main() == 2
        err = capsys.readouterr().err
        assert "ERROR:" in err and var in err

    def test_recognised_values_reach_the_daemon(self, monkeypatch):
        seen = {}

        def _capture(**kwargs):
            seen.update(kwargs)
            raise _Reached()

        monkeypatch.setattr(mcp_srv, "BridgeDaemon", _capture)
        monkeypatch.setenv("IRONMESH_REQUIRE_MSG_PROMOTION", "on")
        monkeypatch.setenv("IRONMESH_PENDING_QUEUE_CAP", "25")
        with pytest.raises(_Reached):
            mcp_srv.main()
        assert seen["require_message_promotion"] is True
        assert seen["pending_trust_queue_cap"] == 25


class TestQueueCapFlag:
    @pytest.mark.parametrize("value", ["0", "-1", "ten"])
    def test_rejects_values_that_disable_the_cap(self, monkeypatch, value):
        monkeypatch.setattr(sys, "argv", [
            "ironmesh", "run", "--name", "a",
            "--pending-trust-queue-cap", value])
        with pytest.raises(SystemExit) as exc:
            cli.parse_args()
        assert exc.value.code == 2

    def test_accepts_positive_cap(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", [
            "ironmesh", "run", "--name", "a", "--pending-trust-queue-cap", "5"])
        assert cli.parse_args().pending_trust_queue_cap == 5


class TestRotateKeysTrigger:
    def test_daemon_start_rejects_a_typo(self, monkeypatch, tmp_path):
        # Library users who start BridgeDaemon directly get the same rule.
        monkeypatch.setenv("IRONMESH_ROTATE_KEYS", "ture")
        daemon = bridge_mod.BridgeDaemon(
            name="rotate-strict", passphrase="rotate-strict-passphrase",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "data.db"), port=0, bind_address="127.0.0.1")
        with pytest.raises(ConfigError, match="IRONMESH_ROTATE_KEYS"):
            asyncio.run(daemon._start())


class TestParsers:
    def test_flag_unset_and_empty_use_default(self, monkeypatch):
        monkeypatch.delenv("X_FLAG", raising=False)
        assert parse_env_flag("X_FLAG", default=True) is True
        monkeypatch.setenv("X_FLAG", "")
        assert parse_env_flag("X_FLAG", default=False) is False

    def test_limit_rejects_non_finite_and_low(self, monkeypatch):
        for bad in ("nan", "inf", "-inf", "0.5"):
            monkeypatch.setenv("X_LIMIT", bad)
            with pytest.raises(ConfigError):
                parse_env_limit("X_LIMIT", 10.0, float, 1.0)
        monkeypatch.setenv("X_LIMIT", "2.5")
        assert parse_env_limit("X_LIMIT", 10.0, float, 1.0) == 2.5
