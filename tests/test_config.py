"""Tests for ironmesh.config — defaults, file loading, env overrides."""

from __future__ import annotations

import json
import os
from dataclasses import fields

import pytest

from ironmesh.config import IronMeshConfig


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

class TestDefaults:

    def test_defaults_reasonable(self):
        cfg = IronMeshConfig()
        assert cfg.agent_name == "agent"
        assert cfg.port == 8765
        assert cfg.max_message_size == 1_048_576
        assert cfg.log_level == "INFO"
        assert cfg.replay_max_age == 30.0
        assert cfg.replay_window_size == 1024

    def test_all_fields_have_defaults(self):
        """Every dataclass field must have a default or default_factory."""
        for f in fields(IronMeshConfig):
            assert f.default is not f.default_factory or f.default is not None or f.default_factory is not None


# ---------------------------------------------------------------------------
# from_file
# ---------------------------------------------------------------------------

class TestFromFile:

    def test_valid_json_overrides_defaults(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({"agent_name": "mybridge", "port": 9999}))
        cfg = IronMeshConfig.from_file(str(p))
        assert cfg.agent_name == "mybridge"
        assert cfg.port == 9999
        # Defaults for unspecified fields preserved
        assert cfg.max_message_size == 1_048_576

    def test_missing_file_returns_defaults(self, tmp_path):
        cfg = IronMeshConfig.from_file(str(tmp_path / "does-not-exist.json"))
        assert cfg.agent_name == "agent"

    @pytest.mark.xfail(reason="Audit L-07 fix pending (Phase 4): malformed JSON currently raises")
    def test_invalid_json_falls_back_to_defaults(self, tmp_path):
        """Audit L-07: malformed JSON must not crash — fall back."""
        p = tmp_path / "cfg.json"
        p.write_text("{ this is not valid JSON ][ :")
        cfg = IronMeshConfig.from_file(str(p))
        assert cfg.agent_name == "agent"

    def test_unknown_keys_ignored(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({"agent_name": "ok", "unknown_key": "ignored"}))
        cfg = IronMeshConfig.from_file(str(p))
        assert cfg.agent_name == "ok"
        assert not hasattr(cfg, "unknown_key")


# ---------------------------------------------------------------------------
# from_env
# ---------------------------------------------------------------------------

class TestFromEnv:

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("IRONMESH_NAME", "from-env")
        monkeypatch.setenv("IRONMESH_PORT", "7777")
        cfg = IronMeshConfig.from_env()
        assert cfg.agent_name == "from-env"
        assert cfg.port == 7777

    def test_env_partial_override(self, monkeypatch):
        """Only IRONMESH_NAME set — other fields keep defaults."""
        monkeypatch.setenv("IRONMESH_NAME", "only-name")
        monkeypatch.delenv("IRONMESH_PORT", raising=False)
        cfg = IronMeshConfig.from_env()
        assert cfg.agent_name == "only-name"
        assert cfg.port == 8765


# ---------------------------------------------------------------------------
# save
# ---------------------------------------------------------------------------

class TestSave:

    def test_roundtrip(self, tmp_path):
        cfg = IronMeshConfig(agent_name="roundtrip", port=5555)
        path = str(tmp_path / "out.json")
        cfg.save(path)
        reloaded = IronMeshConfig.from_file(path)
        assert reloaded.agent_name == "roundtrip"
        assert reloaded.port == 5555

    def test_save_excludes_secrets(self, tmp_path):
        """Audit: passphrase fields must not be persisted."""
        cfg = IronMeshConfig(agent_name="x", passphrase="secret123secret",
                             keys_passphrase="kpsecret123")
        path = str(tmp_path / "out.json")
        cfg.save(path)
        with open(path) as f:
            data = json.load(f)
        assert "passphrase" not in data
        assert "keys_passphrase" not in data


# ---------------------------------------------------------------------------
# Reserved group_crypto_suite stub (keyed to the pending keying RFC)
# ---------------------------------------------------------------------------

class TestReservedCryptoSuiteStub:
    """The group_crypto_suite field is an INERT reservation: unset by
    default, never rejected by a validator, and invisible on disk until
    the keying RFC selects a suite."""

    def test_defaults_to_none(self):
        cfg = IronMeshConfig()
        assert cfg.group_crypto_suite is None

    def test_none_does_not_break_post_init(self):
        """__post_init__ must not reject the unset stub."""
        cfg = IronMeshConfig(group_crypto_suite=None)
        assert cfg.group_crypto_suite is None

    def test_excluded_from_save(self, tmp_path):
        """Stays invisible on disk until the RFC lands — even if a value
        was somehow set in memory, save() omits it."""
        cfg = IronMeshConfig(agent_name="x")
        cfg.group_crypto_suite = "some-future-suite"
        path = str(tmp_path / "out.json")
        cfg.save(path)
        with open(path) as f:
            data = json.load(f)
        assert "group_crypto_suite" not in data

    def test_config_load_save_roundtrip_unaffected(self, tmp_path):
        """Adding the stub must not break normal load/save."""
        cfg = IronMeshConfig(agent_name="rt", port=6001)
        path = str(tmp_path / "cfg.json")
        cfg.save(path)
        reloaded = IronMeshConfig.from_file(path)
        assert reloaded.agent_name == "rt"
        assert reloaded.port == 6001
        # The stub stays at its default after a roundtrip (never persisted).
        assert reloaded.group_crypto_suite is None
