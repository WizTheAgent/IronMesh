"""IronMesh AutoGen adapter — mesh functions for AutoGen agents.

Exposes IronMesh operations as AutoGen-compatible functions that
agents can call during conversations. Two registration styles are
supported, matching the two generations of the AutoGen API:

Modern (``autogen-agentchat``) — tools are passed at construction::

    from ironmesh.adapters.autogen_adapter import create_mesh_tools
    from ironmesh.agent import Agent
    from autogen_agentchat.agents import AssistantAgent

    agent = Agent("autogen-node", passphrase="secret")
    agent.run(foreground=False)

    tools, inbox = create_mesh_tools(agent)
    assistant = AssistantAgent("assistant", model_client=..., tools=tools)

Legacy (``pyautogen`` < 0.10) — functions are registered after
construction on any agent exposing ``register_function`` or a
``function_map``::

    from ironmesh.adapters.autogen_adapter import register_ironmesh

    assistant = AssistantAgent("assistant", llm_config=...)
    register_ironmesh(agent, assistant)

    # Now the assistant can call ironmesh_send(), ironmesh_peers(), etc.

Requires: ``pip install autogen-agentchat`` (modern) or a legacy
``pyautogen`` (< 0.10). The adapter itself imports neither; it only
produces plain callables.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from typing import Any, Callable, Dict, List, Tuple

from ironmesh.agent import Agent

logger = logging.getLogger(__name__)


class _InboxCollector:
    """Thread-safe message collector for the AutoGen receive function."""

    def __init__(self, agent: Agent):
        self.agent = agent
        self._msgs: deque = deque(maxlen=200)
        self._lock = threading.Lock()

        # Subscribe directly to the daemon bus (works even if agent.run()
        # hasn't been called yet — the bus is available at construction).
        def _collect(data):
            peer_id = data.get("peer_id", "")
            payload = data.get("payload", b"")
            with self._lock:
                self._msgs.append({
                    "from": peer_id,
                    "text": payload.decode("utf-8", errors="replace")
                          if isinstance(payload, bytes) else str(payload),
                    "ts": time.time(),
                })
        agent.daemon.bus.subscribe("MSG", _collect)

    def recent(self, n: int = 10) -> List[Dict]:
        with self._lock:
            return list(self._msgs)[-n:]


def _build_mesh_functions(
    agent: Agent,
    inbox: _InboxCollector,
    prefix: str = "ironmesh_",
) -> Dict[str, Callable[..., str]]:
    """Build the four mesh functions as standalone callables.

    Each callable carries a prefixed ``__name__`` and a docstring so it
    can be handed directly to tool wrappers (e.g. autogen-agentchat's
    ``FunctionTool``) that derive the tool name and description from the
    function object itself.
    """

    def send(target: str, message: str, priority: str = "NORMAL") -> str:
        """Send an encrypted message to a peer on the IronMesh mesh."""
        try:
            msg_id = agent.send_sync(target, message, priority=priority)
            return json.dumps({"ok": True, "msg_id": msg_id})
        except Exception as e:
            # v0.8.5.2: don't leak internal details into LLM tool-result context.
            logger.exception("autogen ironmesh_send failed for target=%s", target)
            return json.dumps({"error": f"{type(e).__name__}: send failed"})

    def peers() -> str:
        """List online peers on the mesh with RTT and message counts."""
        return json.dumps(agent.peers, indent=2, default=str)

    def receive(limit: int = 10) -> str:
        """Read recent messages received from other mesh peers."""
        return json.dumps(inbox.recent(limit), indent=2, default=str)

    def discover(pattern: str) -> str:
        """Find peers by capability pattern (glob). E.g. 'llm:*'."""
        results = agent.discover(pattern)
        return json.dumps(
            [{"node_id": nid, "capability": cap} for nid, cap in results],
            indent=2,
        )

    fn_map: Dict[str, Callable[..., str]] = {
        f"{prefix}send": send,
        f"{prefix}peers": peers,
        f"{prefix}receive": receive,
        f"{prefix}discover": discover,
    }
    for name, fn in fn_map.items():
        fn.__name__ = name
        fn.__qualname__ = name
    return fn_map


def create_mesh_tools(
    agent: Agent,
    *,
    prefix: str = "ironmesh_",
) -> Tuple[List[Callable[..., str]], _InboxCollector]:
    """Return the mesh functions as a tool list for autogen-agentchat.

    The modern AutoGen API (``autogen_agentchat``) takes tools at agent
    construction time instead of a post-construction ``function_map``::

        tools, inbox = create_mesh_tools(agent)
        assistant = AssistantAgent("assistant", model_client=..., tools=tools)

    Each returned callable is named (``ironmesh_send`` etc.), documented,
    and type-annotated, so ``AssistantAgent`` can wrap it into a
    ``FunctionTool`` with a correct schema automatically.

    Args:
        agent: A running ``ironmesh.agent.Agent`` instance.
        prefix: Function name prefix (default ``ironmesh_``).

    Returns:
        ``(tools, inbox)`` — the tool callables in a stable order
        (send, peers, receive, discover) and the ``_InboxCollector``
        backing ``ironmesh_receive``.
    """
    inbox = _InboxCollector(agent)
    fn_map = _build_mesh_functions(agent, inbox, prefix)
    return list(fn_map.values()), inbox


def register_ironmesh(
    agent: Agent,
    autogen_agent: Any,
    *,
    prefix: str = "ironmesh_",
) -> _InboxCollector:
    """Register IronMesh functions on a legacy AutoGen agent's function_map.

    After calling this, the AutoGen agent can invoke:
    - ``ironmesh_send(target, message, priority?)`` — send encrypted MSG
    - ``ironmesh_peers()`` — list online peers
    - ``ironmesh_receive(limit?)`` — read recent inbound messages
    - ``ironmesh_discover(pattern)`` — find peers by capability

    For the modern ``autogen_agentchat`` API (construction-time tools),
    use :func:`create_mesh_tools` instead.

    Args:
        agent: A running ``ironmesh.agent.Agent`` instance.
        autogen_agent: An AutoGen ``AssistantAgent`` or ``UserProxyAgent``.
        prefix: Function name prefix (default ``ironmesh_``).

    Returns:
        The ``_InboxCollector`` in case caller wants direct access.
    """
    inbox = _InboxCollector(agent)

    # Register on the autogen agent. Legacy AutoGen expects function_map
    # or register_function depending on the version.
    fn_map = _build_mesh_functions(agent, inbox, prefix)

    if hasattr(autogen_agent, "register_function"):
        for name, fn in fn_map.items():
            autogen_agent.register_function({name: fn})
    elif hasattr(autogen_agent, "function_map"):
        autogen_agent.function_map.update(fn_map)
    else:
        raise TypeError(
            f"Cannot register functions on {type(autogen_agent).__name__}. "
            "Expected an AutoGen agent with register_function() or function_map."
        )

    return inbox


def create_mesh_function_descriptions(prefix: str = "ironmesh_") -> List[Dict]:
    """Return OpenAI-style function descriptions for AutoGen tool use.

    Pass these to the ``functions`` parameter in the LLM config so the
    model knows what mesh operations are available.
    """
    return [
        {
            "name": f"{prefix}send",
            "description": "Send an encrypted message to a peer on the IronMesh mesh.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Peer name or node_id"},
                    "message": {"type": "string", "description": "Message text"},
                    "priority": {"type": "string", "enum": ["CRITICAL", "HIGH", "NORMAL", "LOW"], "default": "NORMAL"},
                },
                "required": ["target", "message"],
            },
        },
        {
            "name": f"{prefix}peers",
            "description": "List online peers on the mesh with RTT and message counts.",
            "parameters": {"type": "object", "properties": {}},
        },
        {
            "name": f"{prefix}receive",
            "description": "Read recent messages received from other mesh peers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 10, "description": "Max messages"},
                },
            },
        },
        {
            "name": f"{prefix}discover",
            "description": "Find peers by capability pattern (glob). E.g. 'llm:*'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Capability glob pattern"},
                },
                "required": ["pattern"],
            },
        },
    ]
