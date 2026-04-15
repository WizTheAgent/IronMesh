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
