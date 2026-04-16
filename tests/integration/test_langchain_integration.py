"""End-to-end integration test for the LangChain adapter.

Imports the **real** ``langchain_core`` package (not a mock) and proves
the toolkit actually sends a message across a live 2-node IronMesh and
that the other side receives it. Skips cleanly if the host doesn't have
``langchain-core`` installed, so developers running the fast unit suite
aren't forced to install the framework.
"""
from __future__ import annotations

import time

import pytest

from .conftest import INTEGRATION_PASSPHRASE, wait_for

pytest.importorskip("langchain_core", reason="langchain-core not installed")


def test_toolkit_loads_real_langchain():
    """The factory returns 4 real BaseTool instances."""
    from langchain_core.tools import BaseTool

    from ironmesh.adapters.langchain_adapter import create_ironmesh_toolkit

    tools = create_ironmesh_toolkit(
        name="lc-toolkit-smoke",
        port=31700,
        passphrase=INTEGRATION_PASSPHRASE,
        open_discovery=False,
        allow_plaintext=True,
        allowed_peers=["never-connects"],
    )
    try:
        assert len(tools) == 4
        names = {t.name for t in tools}
        assert names == {
            "ironmesh_send",
            "ironmesh_peers",
            "ironmesh_receive",
            "ironmesh_discover",
        }
        for t in tools:
            assert isinstance(t, BaseTool)
            assert t.description  # non-empty
            # Args-schema check: the send tool requires a target + message.
            if t.name == "ironmesh_send":
                schema = t.args_schema.model_json_schema()
                props = schema.get("properties", {})
                assert "target" in props
                assert "message" in props
    finally:
        # Tear down the factory-created agent.
        # The factory stashes the agent on the first tool's context.
        first = tools[0]
        ctx = getattr(first, "ctx", None) or first.__dict__.get("ctx")
        if ctx is not None and hasattr(ctx, "agent"):
            ctx.agent.stop()


def test_send_tool_delivers_message_across_mesh(two_node_mesh):
    """Using the langchain send tool on alice actually delivers a MSG to bob."""
    from ironmesh.adapters.langchain_adapter import (
        IronMeshSendTool,
        _MeshContext,
    )

    alice, bob = two_node_mesh

    # Use the existing alice Agent rather than spinning a third.
    ctx = _MeshContext(alice)
    send_tool = IronMeshSendTool(ctx=ctx)

    received: list[bytes] = []

    @bob.on_message()
    def _on_msg(peer_id: str, payload: bytes) -> None:  # noqa: ARG001
        received.append(payload)
    bob._wire_handlers()

    # LangChain calls the tool through `invoke`; we match that path so
    # we're exercising the same entry point a real agent would.
    result = send_tool.invoke({"target": "itest-bob", "message": "hello-langchain"})

    assert isinstance(result, str)
    assert "ok" in result.lower() or "sent" in result.lower() or result.startswith("{")

    assert wait_for(lambda: len(received) >= 1, timeout=5.0), (
        "bob never received the LangChain-originated message"
    )
    assert any(b"hello-langchain" in r for r in received)


def test_peers_tool_reports_live_peer(two_node_mesh):
    """The peers tool returns the live peer table in a schema LangChain can consume."""
    from ironmesh.adapters.langchain_adapter import (
        IronMeshPeersTool,
        _MeshContext,
    )

    alice, _bob = two_node_mesh
    peers_tool = IronMeshPeersTool(ctx=_MeshContext(alice))
    result = peers_tool.invoke({})
    # Tool returns JSON text; parse back and verify bob is listed online.
    import json
    data = json.loads(result)
    assert any(p.get("name") == "itest-bob" for p in data), (
        f"bob not found in peers tool output: {data!r}"
    )


def test_receive_tool_drains_inbound_queue(two_node_mesh):
    """The receive tool pulls messages that arrived since last drain."""
    from ironmesh.adapters.langchain_adapter import (
        IronMeshReceiveTool,
        _MeshContext,
    )

    alice, bob = two_node_mesh

    # Attach a context to alice (subscribes to the bus before any MSG).
    ctx = _MeshContext(alice)
    recv_tool = IronMeshReceiveTool(ctx=ctx)

    bob.send_sync("itest-alice", "lc-inbound-probe")
    assert wait_for(lambda: len(ctx.drain(50)) >= 1, timeout=5.0)

    result = recv_tool.invoke({"limit": 50})
    # Tool returns JSON text.
    import json
    msgs = json.loads(result)
    assert any("lc-inbound-probe" in str(m.get("payload", "")) for m in msgs), (
        f"receive tool did not return probe message: {msgs!r}"
    )
