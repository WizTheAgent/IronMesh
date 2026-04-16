"""IronMesh CrewAI adapter — mesh-connected agent factory.

CrewAI accepts LangChain BaseTool objects, so this adapter reuses the
LangChain toolkit and wraps it in a CrewAI agent factory.

Usage::

    from ironmesh.adapters.crewai_adapter import create_mesh_crew_agent

    agent = create_mesh_crew_agent(
        role="Mesh Coordinator",
        goal="Route tasks to the best available LLM peer",
        backstory="You coordinate a team of agents over an encrypted mesh.",
        llm=my_llm,
        mesh_name="coordinator",
        mesh_passphrase="secret",
    )

Requires: ``pip install crewai langchain-core``
"""
from __future__ import annotations

from typing import Any, List, Optional

from ironmesh.adapters.langchain_adapter import create_ironmesh_toolkit

try:
    from crewai import Agent as CrewAgent
except ImportError:
    raise ImportError(
        "CrewAI adapter requires crewai: pip install crewai"
    )


def create_mesh_crew_agent(
    role: str,
    goal: str,
    backstory: str,
    llm: Any,
    *,
    mesh_name: str = "crewai-agent",
    mesh_port: int = 8765,
    mesh_passphrase: Optional[str] = None,
    mesh_capabilities: Optional[List[str]] = None,
    extra_tools: Optional[List] = None,
    verbose: bool = True,
    **crew_kwargs,
) -> CrewAgent:
    """Create a CrewAI agent with IronMesh mesh tools.

    The agent can send messages, list peers, receive replies, and
    discover capabilities — all encrypted, all local-first.

    Args:
        role: CrewAI role string.
        goal: What the agent is trying to achieve.
        backstory: Agent's backstory for the LLM persona.
        llm: LLM model (ChatOpenAI, Ollama, etc.).
        mesh_name: Agent's name on the IronMesh mesh.
        mesh_port: WebSocket port.
        mesh_passphrase: Mesh passphrase.
        mesh_capabilities: Capabilities to advertise.
        extra_tools: Additional tools beyond the mesh toolkit.
        verbose: CrewAI verbosity flag.
        **crew_kwargs: Extra kwargs passed to ``crewai.Agent()``.

    Returns:
        A CrewAI Agent with IronMesh tools wired in.
    """
    mesh_tools = create_ironmesh_toolkit(
        name=mesh_name,
        port=mesh_port,
        passphrase=mesh_passphrase,
        capabilities=mesh_capabilities,
    )
    all_tools = mesh_tools + (extra_tools or [])

    return CrewAgent(
        role=role,
        goal=goal,
        backstory=backstory,
        llm=llm,
        tools=all_tools,
        verbose=verbose,
        **crew_kwargs,
    )
