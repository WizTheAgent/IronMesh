"""Tests for ironmesh.capabilities — local advertise, remote learn, glob find."""

import json
import os

import pytest

from ironmesh.capabilities import CapabilityRegistry


class TestCapabilityRegistryLocal:
    def test_advertise_local_capability(self):
        reg = CapabilityRegistry("self")
        reg.advertise_local("llm:llama3")
        assert "llm:llama3" in reg.local_capabilities()

    def test_advertise_dedup(self):
        reg = CapabilityRegistry("self")
        reg.advertise_local("llm:llama3")
        reg.advertise_local("llm:llama3")
        assert reg.local_capabilities() == ["llm:llama3"]

    def test_remove_local_capability(self):
        reg = CapabilityRegistry("self")
        reg.advertise_local("llm:llama3")
        reg.remove_local("llm:llama3")
        assert reg.local_capabilities() == []

    def test_advertise_ignores_empty(self):
        reg = CapabilityRegistry("self")
        reg.advertise_local("")
        reg.advertise_local(None)  # type: ignore[arg-type]
        assert reg.local_capabilities() == []

    def test_set_local_replaces_not_merges(self, tmp_path):
        """Regression — ghost capabilities: a daemon that loads a
        persisted capability set and then sets its new config-provided
        caps must NOT announce the union of old + new. Before the fix,
        the load+advertise_local pattern produced ghost caps that
        outlived their original --role config. set_local must produce
        exactly the caller-supplied set, not union it with anything.
        """
        import hashlib
        # Persist an "old" local set (simulating a prior daemon run
        # with --role assistant)
        path = str(tmp_path / "capabilities.json")
        key = hashlib.sha256(b"test-key").digest()
        reg_old = CapabilityRegistry(
            "self", persist_path=path, hmac_key=key,
        )
        reg_old.advertise_local("role:assistant")
        reg_old.advertise_local("llm:llama3")
        reg_old.save()

        # New daemon run with a different --role. Load the prior
        # state (old behavior), then apply authoritative new config.
        reg_new = CapabilityRegistry(
            "self", persist_path=path, hmac_key=key,
        )
        reg_new.load()
        # Pre-fix behavior with advertise_local would produce a
        # union {role:assistant, role:coder, llm:llama3}.
        # set_local REPLACES:
        reg_new.set_local(["role:coder", "llm:llama3"])
        got = set(reg_new.local_capabilities())
        assert got == {"role:coder", "llm:llama3"}, (
            "Regression: set_local leaked ghost caps. got=" + repr(got)
        )
        assert "role:assistant" not in got


class TestCapabilityRegistryRemote:
    def test_learn_remote_capability(self):
        reg = CapabilityRegistry("self")
        reg.learn_remote("nodeA", ["llm:llama3", "tool:filesystem"])
        all_caps = reg.all()
        assert sorted(all_caps["nodeA"]) == ["llm:llama3", "tool:filesystem"]

    def test_learn_remote_replaces(self):
        reg = CapabilityRegistry("self")
        reg.learn_remote("nodeA", ["a"])
        reg.learn_remote("nodeA", ["b", "c"])
        assert reg.all()["nodeA"] == ["b", "c"]

    def test_self_node_id_ignored_in_remote(self):
        reg = CapabilityRegistry("self")
        delta = reg.learn_remote("self", ["spoof"])
        assert delta == 0
        assert "spoof" not in reg.all().get("self", [])

    def test_forget_remote(self):
        reg = CapabilityRegistry("self")
        reg.learn_remote("nodeA", ["a"])
        reg.forget_remote("nodeA")
        assert "nodeA" not in reg.all()


class TestCapabilityFind:
    def test_glob_matching_basic(self):
        reg = CapabilityRegistry("self")
        reg.advertise_local("llm:llama3")
        reg.learn_remote("nodeA", ["llm:gpt4", "tool:filesystem"])
        results = reg.find("llm:*")
        nodes = sorted({r[0] for r in results})
        caps = sorted({r[1] for r in results})
        assert nodes == ["nodeA", "self"]
        assert caps == ["llm:gpt4", "llm:llama3"]

    def test_glob_matching_exact(self):
        reg = CapabilityRegistry("self")
        reg.advertise_local("llm:llama3")
        reg.learn_remote("nodeA", ["llm:llama3"])
        results = reg.find("llm:llama3")
        nodes = sorted({r[0] for r in results})
        assert nodes == ["nodeA", "self"]

    def test_glob_no_match(self):
        reg = CapabilityRegistry("self")
        reg.advertise_local("tool:fs")
        assert reg.find("llm:*") == []


class TestCapabilityPersistence:
    def test_save_load_roundtrip(self, tmp_path):
        path = str(tmp_path / "caps.json")
        key = b"\x42" * 32
        reg = CapabilityRegistry("self", persist_path=path, hmac_key=key)
        reg.advertise_local("llm:llama3")
        reg.learn_remote("nodeA", ["tool:filesystem"])
        assert reg.save() is True
        assert os.path.exists(path)

        reg2 = CapabilityRegistry("self", persist_path=path, hmac_key=key)
        assert reg2.load() is True
        assert reg2.local_capabilities() == ["llm:llama3"]
        assert reg2.all()["nodeA"] == ["tool:filesystem"]

    def test_load_rejects_tampered(self, tmp_path):
        path = str(tmp_path / "caps.json")
        key = b"k" * 32
        reg = CapabilityRegistry("self", persist_path=path, hmac_key=key)
        reg.advertise_local("real")
        reg.save()
        with open(path) as f:
            data = json.load(f)
        data["body"] = data["body"].replace("real", "fake")
        with open(path, "w") as f:
            json.dump(data, f)

        reg2 = CapabilityRegistry("self", persist_path=path, hmac_key=key)
        assert reg2.load() is False
        assert reg2.local_capabilities() == []

    def test_load_rejects_wrong_node(self, tmp_path):
        path = str(tmp_path / "caps.json")
        key = b"k" * 32
        reg_a = CapabilityRegistry("nodeA", persist_path=path, hmac_key=key)
        reg_a.advertise_local("a")
        reg_a.save()

        reg_b = CapabilityRegistry("nodeB", persist_path=path, hmac_key=key)
        assert reg_b.load() is False


class TestCapabilityAnnouncementPayload:
    def test_announcement_payload_shape(self):
        reg = CapabilityRegistry("self")
        reg.advertise_local("llm:llama3")
        reg.advertise_local("tool:filesystem")
        payload = reg.announcement_payload()
        assert payload["origin"] == "self"
        assert sorted(payload["capabilities"]) == ["llm:llama3", "tool:filesystem"]
