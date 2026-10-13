"""Tests for ironmesh.config — defaults, file loading, env overrides."""

from __future__ import annotations

import json
import os
from dataclasses import fields

import pytest

from ironmesh.config import ConfigError, IronMeshConfig


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

    def test_invalid_json_falls_back_to_defaults(self, tmp_path, caplog):
        """Malformed JSON must not crash — warn and fall back to defaults."""
        import logging
        p = tmp_path / "cfg.json"
        p.write_text("{ this is not valid JSON ][ :")
        with caplog.at_level(logging.WARNING, logger="ironmesh.config"):
            cfg = IronMeshConfig.from_file(str(p))
        assert cfg.agent_name == "agent"
        assert any("malformed or unreadable" in r.getMessage()
                   for r in caplog.records)

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

    def test_malformed_numeric_env_does_not_crash(self, monkeypatch, caplog):
        """A numeric env override that cannot be converted must not crash
        from_env() — log a warning, keep the default for that field, and
        still apply every other env var."""
        import logging
        monkeypatch.setenv("IRONMESH_NAME", "survivor")
        monkeypatch.setenv("IRONMESH_PORT", "abc")
        monkeypatch.setenv("IRONMESH_LOG_LEVEL", "WARN")
        cfg = IronMeshConfig.from_env()
        assert cfg.agent_name == "survivor"
        assert cfg.port == 8765
        assert cfg.log_level == "WARN"
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING
                    and "IRONMESH_PORT" in r.getMessage()]
        assert len(warnings) == 1

    def test_malformed_numeric_env_other_vars_still_applied(self, monkeypatch):
        """When one numeric env var is bad, other env vars in the same call
        are still applied."""
        monkeypatch.setenv("IRONMESH_NAME", "still-applied")
        monkeypatch.setenv("IRONMESH_PORT", "abc")
        monkeypatch.setenv("IRONMESH_LOG_LEVEL", "ERROR")
        cfg = IronMeshConfig.from_env()
        assert cfg.agent_name == "still-applied"
        assert cfg.log_level == "ERROR"
        assert cfg.port == 8765

    # Policy for from_env():
    # - IRONMESH_PORT is lenient: an unparseable value warns, keeps the default
    #   and the other overrides still apply (a bad port cannot weaken a
    #   control; an unusable one fails at bind).
    # - Booleans and security-relevant limits are strict: an unrecognised,
    #   non-finite or below-minimum value raises ConfigError, because any
    #   fallback could be weaker than what the operator meant.
    def test_port_override_parses_or_falls_back(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("IRONMESH_PORT", "9001")
        assert IronMeshConfig.from_env().port == 9001

        monkeypatch.setenv("IRONMESH_PORT", "abc")
        monkeypatch.setenv("IRONMESH_NAME", "kept")
        with caplog.at_level(logging.WARNING, logger="ironmesh.config"):
            cfg = IronMeshConfig.from_env()
        assert cfg.port == IronMeshConfig().port
        assert cfg.agent_name == "kept"
        assert any("IRONMESH_PORT" in r.getMessage() for r in caplog.records)

    @pytest.mark.parametrize("env_var,attr,good,expected,bad_values", [
        ("IRONMESH_RNS_RATCHET_INTERVAL", "rns_ratchet_interval", "900.5",
         900.5, ["half-hour", "nan", "inf", "0", "-60"]),
        ("IRONMESH_RNS_RETAINED_RATCHETS", "rns_retained_ratchets", "7", 7,
         ["4.5", "seven", "0", "-1"]),
        ("IRONMESH_PENDING_QUEUE_CAP", "pending_trust_queue_cap", "250", 250,
         ["1O", "100k", "0", "-1"]),
    ])
    def test_security_limits_reject_instead_of_falling_back(
            self, monkeypatch, env_var, attr, good, expected, bad_values):
        monkeypatch.setenv(env_var, good)
        assert getattr(IronMeshConfig.from_env(), attr) == expected
        for bad in bad_values:
            monkeypatch.setenv(env_var, bad)
            with pytest.raises(ConfigError, match=env_var):
                IronMeshConfig.from_env()

    def test_unset_or_empty_limits_keep_defaults(self, monkeypatch):
        defaults = IronMeshConfig()
        for var in ("IRONMESH_RNS_RATCHET_INTERVAL",
                    "IRONMESH_RNS_RETAINED_RATCHETS",
                    "IRONMESH_PENDING_QUEUE_CAP"):
            monkeypatch.setenv(var, "  ")
        cfg = IronMeshConfig.from_env()
        assert cfg.rns_ratchet_interval == defaults.rns_ratchet_interval
        assert cfg.rns_retained_ratchets == defaults.rns_retained_ratchets
        assert cfg.pending_trust_queue_cap == defaults.pending_trust_queue_cap


_BOOL_SETTINGS = [
    ("IRONMESH_REQUIRE_MSG_PROMOTION", "require_message_promotion"),
    ("IRONMESH_RNS_RATCHETS", "rns_ratchets_enabled"),
    ("IRONMESH_RNS_ENABLED", "rns_enabled"),
]


class TestStrictBooleans:
    @pytest.mark.parametrize("env_var,attr", _BOOL_SETTINGS)
    @pytest.mark.parametrize("raw,expected", [
        ("1", True), ("true", True), ("YES", True), (" On ", True),
        ("0", False), ("false", False), ("No", False), ("off", False),
    ])
    def test_recognised_values(self, monkeypatch, env_var, attr, raw, expected):
        monkeypatch.setenv(env_var, raw)
        assert getattr(IronMeshConfig.from_env(), attr) is expected

    @pytest.mark.parametrize("env_var,attr", _BOOL_SETTINGS)
    @pytest.mark.parametrize("typo", ["ture", "flase", "yes please", "2", "enable"])
    def test_typo_is_a_configuration_error(self, monkeypatch, env_var, attr, typo):
        monkeypatch.setenv(env_var, typo)
        with pytest.raises(ConfigError, match=env_var):
            IronMeshConfig.from_env()

    @pytest.mark.parametrize("env_var,attr", _BOOL_SETTINGS)
    def test_unset_or_empty_keeps_default(self, monkeypatch, env_var, attr):
        monkeypatch.setenv(env_var, "")
        assert getattr(IronMeshConfig.from_env(), attr) == getattr(IronMeshConfig(), attr)

    def test_typo_cannot_disable_ratchets(self, monkeypatch):
        # Ratchets default ON; under the old parser any unrecognised value
        # (e.g. a misspelt "true") silently turned them off.
        assert IronMeshConfig().rns_ratchets_enabled is True
        monkeypatch.setenv("IRONMESH_RNS_RATCHETS", "treu")
        with pytest.raises(ConfigError):
            IronMeshConfig.from_env()


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
