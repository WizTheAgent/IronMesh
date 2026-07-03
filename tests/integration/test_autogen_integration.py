"""End-to-end integration test for the AutoGen adapter.

Covers:
- ``register_ironmesh`` on a duck-typed legacy-style AutoGen agent
  (the post-construction ``function_map`` registration contract).
- The ``ironmesh_send`` function actually delivers a MSG across a live
  2-node mesh.
- The ``ironmesh_peers`` function returns JSON the LLM can consume.
- A real ``autogen_agentchat.agents.AssistantAgent`` driving a mesh
  tool call end to end (scripted model client, no real LLM).

The real-agent test skips cleanly if ``autogen-agentchat`` is not
installed; everything else runs against the adapter alone.
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


async def test_real_autogen_agent_if_installed(two_node_mesh):
    """If autogen-agentchat is installed, drive a real AssistantAgent.

    A scripted model client makes the assistant issue one
    ``ironmesh_peers`` tool call, so this exercises the whole modern
    integration path — AssistantAgent -> FunctionTool wrapping of the
    adapter callables -> live mesh state — without a real LLM.
    """
    pytest.importorskip("autogen_agentchat",
                        reason="autogen-agentchat not installed")

    from autogen_agentchat.agents import AssistantAgent
    from autogen_core import FunctionCall
    from autogen_core.models import (
        ChatCompletionClient,
        CreateResult,
        ModelInfo,
        RequestUsage,
    )

    model_info = ModelInfo(
        vision=False, function_calling=True, json_output=False,
        family="unknown", structured_output=False,
    )

    class _ScriptedModelClient(ChatCompletionClient):
        """Replays canned CreateResults; never contacts a real model."""

        def __init__(self, script: list) -> None:
            self._script = list(script)
            self._usage = RequestUsage(prompt_tokens=0, completion_tokens=0)

        async def create(self, messages, *, tools=(), tool_choice="auto",
                         json_output=None, extra_create_args=None,
                         cancellation_token=None):
            return self._script.pop(0)

        async def create_stream(self, messages, *, tools=(),
                                tool_choice="auto", json_output=None,
                                extra_create_args=None,
                                cancellation_token=None):
            raise NotImplementedError("streaming is not scripted")
            yield  # unreachable; makes this an async generator

        async def close(self) -> None:
            return None

        def actual_usage(self):
            return self._usage

        def total_usage(self):
            return self._usage

        def count_tokens(self, messages, *, tools=()) -> int:
            return 0

        def remaining_tokens(self, messages, *, tools=()) -> int:
            return 1_000_000

        @property
        def model_info(self):
            return model_info

        @property
        def capabilities(self):
            return model_info

    from ironmesh.adapters.autogen_adapter import create_mesh_tools

    alice, _bob = two_node_mesh
    tools, _inbox = create_mesh_tools(alice)
    assert [t.__name__ for t in tools] == [
        "ironmesh_send", "ironmesh_peers",
        "ironmesh_receive", "ironmesh_discover",
    ]

    model_client = _ScriptedModelClient([
        CreateResult(
            finish_reason="function_calls",
            content=[FunctionCall(id="call-1", name="ironmesh_peers",
                                  arguments="{}")],
            usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
            cached=False,
        ),
    ])
    assistant = AssistantAgent(
        "assistant",
        model_client=model_client,
        tools=tools,
        reflect_on_tool_use=False,
    )

    result = await assistant.run(task="Which mesh peers are online?")

    # With reflect_on_tool_use=False the final message is the tool-call
    # summary, i.e. the raw JSON the ironmesh_peers adapter fn returned.
    text = result.messages[-1].to_text()
    assert "itest-bob" in text, (
        "the assistant's tool call should surface alice's live peer "
        f"list; got: {text!r}"
    )
