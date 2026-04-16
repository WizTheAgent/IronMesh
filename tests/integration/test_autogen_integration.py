"""End-to-end integration test for the AutoGen adapter.

Covers:
- ``register_ironmesh`` on a real AutoGen agent (or a close duck-typed
  stand-in if only the adapter path is present).
- The ``ironmesh_send`` function actually delivers a MSG across a live
  2-node mesh.
- The ``ironmesh_peers`` function returns JSON the LLM can consume.

Skips cleanly if AutoGen is not installed.
"""
from __future__ import annotations

import json

import pytest

from .conftest import wait_for

pytest.importorskip("ironmesh.adapters.autogen_adapter",
                    reason="autogen adapter not importable")


class _DuckTypedAutoGen:
    """Stands in for an AutoGen AssistantAgent.

    The adapter accepts anything with ``register_function`` or a
    ``function_map`` attribute, so we emulate the latter (simpler path,
    same registration contract).
    """

    def __init__(self) -> None:
        self.function_map: dict = {}


def test_register_ironmesh_populates_function_map(two_node_mesh):
    """register_ironmesh wires the four mesh functions onto the target."""
    from ironmesh.adapters.autogen_adapter import register_ironmesh

    alice, _bob = two_node_mesh
    target = _DuckTypedAutoGen()
    inbox = register_ironmesh(alice, target)

    expected = {"ironmesh_send", "ironmesh_peers",
                "ironmesh_receive", "ironmesh_discover"}
    assert expected.issubset(target.function_map.keys())
    # The inbox collector is exposed so the caller can introspect.
    assert inbox is not None


def test_ironmesh_send_delivers_across_mesh(two_node_mesh):
    """Calling the registered send function actually reaches bob."""
    from ironmesh.adapters.autogen_adapter import register_ironmesh

    alice, bob = two_node_mesh
    target = _DuckTypedAutoGen()
    register_ironmesh(alice, target)

    received: list[bytes] = []

    @bob.on_message()
    def _on_msg(peer_id: str, payload: bytes) -> None:  # noqa: ARG001
        received.append(payload)
    bob._wire_handlers()

    send_fn = target.function_map["ironmesh_send"]
    result = send_fn("itest-bob", "autogen-probe-message")
    parsed = json.loads(result)
    assert parsed.get("ok") is True, f"send returned error: {parsed!r}"

    assert wait_for(lambda: any(b"autogen-probe-message" in r for r in received),
                    timeout=5.0), (
        "bob did not receive the AutoGen-originated message"
    )


def test_ironmesh_peers_returns_live_peer(two_node_mesh):
    from ironmesh.adapters.autogen_adapter import register_ironmesh

    alice, _bob = two_node_mesh
    target = _DuckTypedAutoGen()
    register_ironmesh(alice, target)

    peers_fn = target.function_map["ironmesh_peers"]
    data = json.loads(peers_fn())
    assert any(p.get("name") == "itest-bob" for p in data)


def test_function_descriptions_schema_is_openai_shaped():
    """create_mesh_function_descriptions returns the shape OpenAI tools use."""
    from ironmesh.adapters.autogen_adapter import (
        create_mesh_function_descriptions,
    )

    descs = create_mesh_function_descriptions()
    assert len(descs) == 4
    for d in descs:
        assert "name" in d
        assert d["name"].startswith("ironmesh_")
        assert "description" in d
        assert "parameters" in d
        assert d["parameters"]["type"] == "object"


def test_real_autogen_agent_if_installed():
    """If pyautogen is installed, register on a real AssistantAgent too."""
    autogen = pytest.importorskip("autogen",
                                   reason="pyautogen not installed")
    # pyautogen's AssistantAgent insists on a llm_config. Skip the real
    # smoke if we can't satisfy that cheaply; the register path is
    # already covered by the duck-typed case.
    try:
        agent_cls = autogen.AssistantAgent  # type: ignore[attr-defined]
    except AttributeError:
        pytest.skip("autogen.AssistantAgent not present in this install")

    from ironmesh import Agent as IronMeshAgent
    from ironmesh.adapters.autogen_adapter import register_ironmesh

    mesh_agent = IronMeshAgent(
        "autogen-itest", port=31780,
        passphrase="integration-test-passphrase-12",
        open_discovery=False, allow_plaintext=True,
        allowed_peers=["never-connects"],
    )
    mesh_agent.run(foreground=False)
    try:
        assistant = agent_cls(
            "assistant",
            llm_config=False,  # disabled is valid; we're not calling the LLM
        )
        register_ironmesh(mesh_agent, assistant)
        assert any(k.startswith("ironmesh_")
                   for k in getattr(assistant, "function_map", {}))
    finally:
        mesh_agent.stop()
