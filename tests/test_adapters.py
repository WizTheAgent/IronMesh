"""Tests for IronMesh framework adapters.

Tests the adapter logic without requiring LangChain/CrewAI/AutoGen installed.
We mock the framework classes to verify our wrappers dispatch correctly.
"""

import json
import threading
import time
from collections import deque
from unittest.mock import MagicMock, patch

import pytest

from ironmesh.agent import Agent
from ironmesh.protocol import PeerState


STRONG_PASS = "adapter-test-passphrase-ok"


# -----------------------------------------------------------------------
# Shared test fixtures
# -----------------------------------------------------------------------

@pytest.fixture
def mock_agent():
    """An Agent with mock peers and no real networking."""
    a = Agent("adapter-test", port=19100, passphrase=STRONG_PASS)
    ps = PeerState(node_id="aaaa1111bbbb2222cccc3333dddd4444", address="10.0.0.1:8765")
    ps.transition(PeerState.Status.ONLINE)
    ps.agent_name = "peer-one"
    ps.latency_ms = 12.0
    a.daemon.peers["aaaa1111bbbb2222cccc3333dddd4444"] = ps
    return a


# -----------------------------------------------------------------------
# LangChain adapter tests
# -----------------------------------------------------------------------

class TestLangChainAdapter:
    """Test the LangChain tool wrappers without LangChain installed.
    We mock the imports since CI might not have langchain-core."""

    def test_mesh_context_collects_messages(self, mock_agent):
        """_MeshContext's bus subscriber collects incoming messages."""
        # Import inline with mocked langchain if needed
        try:
            from ironmesh.adapters.langchain_adapter import _MeshContext
        except ImportError:
            pytest.skip("langchain-core not installed")

        ctx = _MeshContext(mock_agent)
        # Simulate bus publish (normally done by daemon)
        mock_agent.daemon.bus.publish("MSG", {
            "peer_id": "sender1", "payload": b"hello from langchain test"
        })
        msgs = ctx.drain(10)
        assert len(msgs) == 1
        assert msgs[0]["peer_id"] == "sender1"
        assert "hello" in msgs[0]["payload"]

    def test_peers_tool_returns_json(self, mock_agent):
        try:
            from ironmesh.adapters.langchain_adapter import IronMeshPeersTool, _MeshContext
        except ImportError:
            pytest.skip("langchain-core not installed")

        ctx = _MeshContext(mock_agent)
        tool = IronMeshPeersTool(ctx=ctx)
        result = tool._run()
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["node_id"] == "aaaa1111bbbb2222cccc3333dddd4444"
        assert data[0]["rtt_ms"] == 12.0

    def test_discover_tool(self, mock_agent):
        try:
            from ironmesh.adapters.langchain_adapter import IronMeshDiscoverTool, _MeshContext
        except ImportError:
            pytest.skip("langchain-core not installed")

        ctx = _MeshContext(mock_agent)
        tool = IronMeshDiscoverTool(ctx=ctx)
        result = tool._run(pattern="llm:*")
        data = json.loads(result)
        assert isinstance(data, list)

    def test_send_tool_without_running_agent(self, mock_agent):
        try:
            from ironmesh.adapters.langchain_adapter import IronMeshSendTool, _MeshContext
        except ImportError:
            pytest.skip("langchain-core not installed")

        ctx = _MeshContext(mock_agent)
        tool = IronMeshSendTool(ctx=ctx)
        result = tool._run(target="peer-one", message="hi")
        data = json.loads(result)
        assert "error" in data


# -----------------------------------------------------------------------
# AutoGen adapter tests (no autogen dependency needed)
# -----------------------------------------------------------------------

class TestAutoGenAdapter:
    def test_register_adds_functions(self, mock_agent):
        from ironmesh.adapters.autogen_adapter import register_ironmesh

        mock_autogen_agent = MagicMock(spec=[])  # spec=[] prevents auto-attrs
        mock_autogen_agent.function_map = {}

        register_ironmesh(mock_agent, mock_autogen_agent)

        assert "ironmesh_send" in mock_autogen_agent.function_map
        assert "ironmesh_peers" in mock_autogen_agent.function_map
        assert "ironmesh_receive" in mock_autogen_agent.function_map
        assert "ironmesh_discover" in mock_autogen_agent.function_map

    def test_peers_function_returns_json(self, mock_agent):
        from ironmesh.adapters.autogen_adapter import register_ironmesh

        mock_autogen_agent = MagicMock(spec=[])
        mock_autogen_agent.function_map = {}

        register_ironmesh(mock_agent, mock_autogen_agent)

        result = mock_autogen_agent.function_map["ironmesh_peers"]()
        data = json.loads(result)
        assert len(data) == 1
        assert data[0]["name"] == "peer-one"

    def test_receive_drains_inbox(self, mock_agent):
        from ironmesh.adapters.autogen_adapter import register_ironmesh

        mock_autogen_agent = MagicMock(spec=[])
        mock_autogen_agent.function_map = {}

        inbox = register_ironmesh(mock_agent, mock_autogen_agent)

        # Simulate incoming message
        mock_agent.daemon.bus.publish("MSG", {
            "peer_id": "xyz", "payload": b"autogen test msg"
        })

        result = mock_autogen_agent.function_map["ironmesh_receive"](limit=5)
        data = json.loads(result)
        assert len(data) == 1
        assert "autogen test" in data[0]["text"]

    def test_custom_prefix(self, mock_agent):
        from ironmesh.adapters.autogen_adapter import register_ironmesh

        mock_autogen_agent = MagicMock(spec=[])
        mock_autogen_agent.function_map = {}

        register_ironmesh(mock_agent, mock_autogen_agent, prefix="mesh_")

        assert "mesh_send" in mock_autogen_agent.function_map
        assert "mesh_peers" in mock_autogen_agent.function_map

    def test_function_descriptions_schema(self):
        from ironmesh.adapters.autogen_adapter import create_mesh_function_descriptions

        descs = create_mesh_function_descriptions()
        assert len(descs) == 4
        names = {d["name"] for d in descs}
        assert names == {"ironmesh_send", "ironmesh_peers", "ironmesh_receive", "ironmesh_discover"}
        for d in descs:
            assert "description" in d
            assert "parameters" in d
            assert d["parameters"]["type"] == "object"

    def test_raises_on_incompatible_agent(self, mock_agent):
        from ironmesh.adapters.autogen_adapter import register_ironmesh

        bad_agent = object()
        with pytest.raises(TypeError, match="Cannot register"):
            register_ironmesh(mock_agent, bad_agent)
