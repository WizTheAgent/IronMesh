"""Tests for the IronMesh Federation Gateway."""

import json
import pytest

from ironmesh.federation import FederationGateway, FederationPolicy, FORWARD_PREFIX


class TestFederationPolicy:
    def test_default_allows_everything(self):
        p = FederationPolicy()
        assert p.should_forward("llm:llama3") is True
        assert p.should_forward("tool:filesystem") is True

    def test_deny_overrides_allow(self):
        p = FederationPolicy(allow=["*"], deny=["tool:filesystem"])
        assert p.should_forward("llm:llama3") is True
        assert p.should_forward("tool:filesystem") is False
        assert p.should_forward("tool:search") is True

    def test_allow_restricts_to_pattern(self):
        p = FederationPolicy(allow=["llm:*"], deny=[])
        assert p.should_forward("llm:llama3") is True
        assert p.should_forward("llm:gpt4") is True
        assert p.should_forward("tool:filesystem") is False

    def test_deny_glob(self):
        p = FederationPolicy(allow=["*"], deny=["tool:*"])
        assert p.should_forward("llm:llama3") is True
        assert p.should_forward("tool:anything") is False

    def test_to_dict(self):
        p = FederationPolicy(allow=["llm:*"], deny=["tool:fs"])
        d = p.to_dict()
        assert d["allow"] == ["llm:*"]
        assert d["deny"] == ["tool:fs"]

    # v0.9.2: per-source rules
    def test_per_source_match_overrides_global(self):
        p = FederationPolicy(
            allow=["llm:*"],
            deny=["tool:filesystem"],
            per_source=[
                {"source": "ops-*", "allow": ["*"]},
                {"source": "guest-*", "deny": ["*"]},
            ],
        )
        # Global rule for unmatched source
        assert p.should_forward("llm:any", source="other-1") is True
        assert p.should_forward("tool:filesystem", source="other-1") is False
        # ops-* override: everything allowed
        assert p.should_forward("tool:filesystem", source="ops-blue") is True
        assert p.should_forward("llm:any", source="ops-blue") is True
        # guest-* override: everything denied
        assert p.should_forward("llm:any", source="guest-1") is False
        assert p.should_forward("tool:search", source="guest-1") is False

    def test_per_source_first_match_wins(self):
        p = FederationPolicy(
            per_source=[
                {"source": "trader-*", "allow": ["tool:trade:read"],
                 "deny": ["tool:trade:write"]},
                {"source": "*", "allow": ["*"]},
            ],
        )
        assert p.should_forward("tool:trade:read", source="trader-1") is True
        assert p.should_forward("tool:trade:write", source="trader-1") is False
        # Falls to global catch-all
        assert p.should_forward("anything", source="other") is True

    def test_per_source_absent_source_uses_global(self):
        p = FederationPolicy(allow=["llm:*"], per_source=[
            {"source": "ops-*", "allow": ["*"]},
        ])
        assert p.should_forward("tool:x", source=None) is False  # global says no
        assert p.should_forward("llm:x", source=None) is True

    def test_to_dict_includes_per_source_when_present(self):
        p = FederationPolicy(allow=["*"], per_source=[
            {"source": "s-*", "allow": ["llm:*"]},
        ])
        d = p.to_dict()
        assert "per_source" in d
        assert d["per_source"][0]["source"] == "s-*"


class TestFederationGateway:
    def test_init(self):
        gw = FederationGateway(
            mesh_a={"name": "gw-a", "port": 19200, "passphrase": "pass-a-test-12345"},
            mesh_b={"name": "gw-b", "port": 19201, "passphrase": "pass-b-test-12345"},
            policy={"allow": ["llm:*"], "deny": ["tool:*"]},
        )
        assert gw.agent_a.name == "gw-a"
        assert gw.agent_b.name == "gw-b"
        assert gw.policy.should_forward("llm:test") is True
        assert gw.policy.should_forward("tool:test") is False

    def test_stats_initialized(self):
        gw = FederationGateway(
            mesh_a={"name": "gw-a", "port": 19202, "passphrase": "pass-a-test-12345"},
            mesh_b={"name": "gw-b", "port": 19203, "passphrase": "pass-b-test-12345"},
        )
        assert gw.stats["forwarded_a_to_b"] == 0
        assert gw.stats["forwarded_b_to_a"] == 0
        assert gw.stats["denied"] == 0
        assert gw.stats["errors"] == 0

    def test_forward_prefix_prevents_loop(self):
        gw = FederationGateway(
            mesh_a={"name": "gw-a", "port": 19204, "passphrase": "pass-a-test-12345"},
            mesh_b={"name": "gw-b", "port": 19205, "passphrase": "pass-b-test-12345"},
        )
        handler = gw._forward_handler(gw.agent_a, gw.agent_b, "a_to_b")
        handler("peer1", FORWARD_PREFIX + b"already forwarded")
        assert gw.stats["forwarded_a_to_b"] == 0

    def test_stop_is_safe(self):
        gw = FederationGateway(
            mesh_a={"name": "gw-a", "port": 19206, "passphrase": "pass-a-test-12345"},
            mesh_b={"name": "gw-b", "port": 19207, "passphrase": "pass-b-test-12345"},
        )
        gw.stop()
