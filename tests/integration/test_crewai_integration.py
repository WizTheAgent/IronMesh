"""End-to-end integration test for the CrewAI adapter.

Exercises the factory against the real ``crewai`` package. Skips
cleanly if CrewAI (or its ``langchain-core`` dependency) isn't
installed. The tool set is the LangChain toolkit wrapped for CrewAI,
so we mostly prove the factory doesn't explode and the agent holds
the mesh tools.
"""
from __future__ import annotations

import pytest

from .conftest import INTEGRATION_PASSPHRASE

pytest.importorskip("langchain_core", reason="langchain-core not installed")
pytest.importorskip("crewai", reason="crewai not installed")


def test_factory_returns_crewai_agent_with_mesh_tools():
    """create_mesh_crew_agent returns a CrewAI Agent holding IronMesh tools."""
    from crewai import Agent as CrewAgent

    from ironmesh.adapters.crewai_adapter import create_mesh_crew_agent

    # CrewAI insists on an llm object. Pass a stand-in that satisfies its
    # duck-typed expectations for this test -- we don't actually invoke it.
    class _FakeLLM:
        stop = []
        max_tokens = 256
        temperature = 0.0

        def __init__(self) -> None:
            self.model = "fake-model"

        def call(self, *args, **kwargs):  # noqa: D401, ARG002
            return "ok"

        def bind(self, *args, **kwargs):  # noqa: D401, ARG002
            return self

    # The factory creates its own Agent; give it a throwaway port +
    # allowlist that no one matches so it stays isolated.
    agent = create_mesh_crew_agent(
        role="Mesh Coordinator",
        goal="Route tasks to the best available LLM peer",
        backstory="You coordinate a team of agents over an encrypted mesh.",
        llm=_FakeLLM(),
        mesh_name="crew-itest",
        mesh_port=31740,
        mesh_passphrase=INTEGRATION_PASSPHRASE,
        mesh_capabilities=["role:tester"],
        verbose=False,
    )
    assert isinstance(agent, CrewAgent)

    # CrewAI 0.x holds tools on the `.tools` attribute; later versions
    # may rename it. Accept either.
    tools = getattr(agent, "tools", None) or getattr(agent, "_tools", None)
    assert tools, "CrewAI agent has no tools attached"
    tool_names = [getattr(t, "name", str(t)) for t in tools]
    assert "ironmesh_send" in tool_names
    assert "ironmesh_peers" in tool_names

    # Shut down the factory-spawned daemon.
    send_tool = next(t for t in tools if getattr(t, "name", None) == "ironmesh_send")
    ctx = getattr(send_tool, "ctx", None) or send_tool.__dict__.get("ctx")
    if ctx is not None and hasattr(ctx, "agent"):
        ctx.agent.stop()
