"""IronMesh LangChain adapter — BaseTool wrappers for agent mesh operations.

Lets any LangChain agent send encrypted messages, discover peers, and
receive replies over IronMesh without touching WebSocket code.

Usage::

    from ironmesh.adapters.langchain_adapter import create_ironmesh_toolkit

    tools = create_ironmesh_toolkit(
        name="my-agent", port=8765, passphrase="secret",
    )
    # tools is a list of BaseTool instances ready for an agent or chain.

Requires: ``pip install langchain-core`` (or ``langchain``).
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional, Type

from ironmesh.agent import Agent

try:
    from langchain_core.tools import BaseTool
    from pydantic import BaseModel, Field
except ImportError:
    raise ImportError(
        "LangChain adapter requires langchain-core: pip install langchain-core"
    )


class _MeshContext:
    """Shared runtime: Agent instance + inbound message queue."""

    def __init__(self, agent: Agent):
        self.agent = agent
        self._inbox: deque = deque(maxlen=200)
        self._lock = threading.Lock()

        # Subscribe directly to daemon bus (works without agent.run()).
        def _collect(data):
            peer_id = data.get("peer_id", "")
            payload = data.get("payload", b"")
            with self._lock:
                self._inbox.append({
                    "peer_id": peer_id,
                    "payload": payload.decode("utf-8", errors="replace")
                            if isinstance(payload, bytes) else str(payload),
                    "timestamp": time.time(),
                })
        agent.daemon.bus.subscribe("MSG", _collect)

    def drain(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            msgs = list(self._inbox)[-limit:]
        return msgs


# ---- Tool input schemas ----

class SendInput(BaseModel):
    target: str = Field(description="Peer agent name or 32-hex node_id")
    message: str = Field(description="Text message to send")
    priority: str = Field(
        default="NORMAL",
        description="Message priority: CRITICAL, HIGH, NORMAL, LOW",
    )


class DiscoverInput(BaseModel):
    pattern: str = Field(description="Capability glob pattern, e.g. 'llm:*' or 'tool:filesystem'")


class ReceiveInput(BaseModel):
    limit: int = Field(default=10, description="Max messages to return")


# ---- Tool implementations ----

class IronMeshSendTool(BaseTool):
    """Send an encrypted message to a peer on the IronMesh mesh."""
    name: str = "ironmesh_send"
    description: str = (
        "Send an encrypted message to another agent on the mesh. "
        "Specify the target agent by name or node_id."
    )
    args_schema: Type[BaseModel] = SendInput
    ctx: Any = None

    def _run(self, target: str, message: str, priority: str = "NORMAL") -> str:
        try:
            msg_id = self.ctx.agent.send_sync(
                target, message, priority=priority, timeout=10.0,
            )
            return json.dumps({"ok": True, "msg_id": msg_id, "target": target})
        except Exception as e:
            return json.dumps({"error": str(e)})

    async def _arun(self, target: str, message: str, priority: str = "NORMAL") -> str:
        try:
            msg_id = await self.ctx.agent.send(target, message, priority=priority)
            return json.dumps({"ok": True, "msg_id": msg_id, "target": target})
        except Exception as e:
            return json.dumps({"error": str(e)})


class IronMeshPeersTool(BaseTool):
    """List online peers on the IronMesh mesh with live metrics."""
    name: str = "ironmesh_peers"
    description: str = (
        "List all currently online peers with their name, RTT, "
        "message counts, and transport type."
    )
    ctx: Any = None

    def _run(self) -> str:
        return json.dumps(self.ctx.agent.peers, indent=2, default=str)

    async def _arun(self) -> str:
        return self._run()


class IronMeshReceiveTool(BaseTool):
    """Read recent messages received from other agents on the mesh."""
    name: str = "ironmesh_receive"
    description: str = (
        "Return recent messages received from mesh peers. "
        "Each message has peer_id, payload text, and timestamp."
    )
    args_schema: Type[BaseModel] = ReceiveInput
    ctx: Any = None

    def _run(self, limit: int = 10) -> str:
        return json.dumps(self.ctx.drain(limit), indent=2, default=str)

    async def _arun(self, limit: int = 10) -> str:
        return self._run(limit)


class IronMeshDiscoverTool(BaseTool):
    """Discover peers by capability pattern on the IronMesh mesh."""
    name: str = "ironmesh_discover"
    description: str = (
        "Search for peers that advertise a specific capability. "
        "Use glob patterns like 'llm:*' or 'tool:filesystem'."
    )
    args_schema: Type[BaseModel] = DiscoverInput
    ctx: Any = None

    def _run(self, pattern: str) -> str:
        results = self.ctx.agent.discover(pattern)
        return json.dumps(
            [{"node_id": nid, "capability": cap} for nid, cap in results],
            indent=2,
        )

    async def _arun(self, pattern: str) -> str:
        return self._run(pattern)


# ---- Factory ----

def create_ironmesh_toolkit(
    name: str = "langchain-agent",
    port: int = 8765,
    passphrase: Optional[str] = None,
    capabilities: Optional[List[str]] = None,
    **agent_kwargs,
) -> List[BaseTool]:
    """Create an IronMesh toolkit (list of LangChain tools).

    Starts an IronMesh agent in the background and returns tools that
    operate on it. The agent auto-discovers peers via mDNS.

    Args:
        name: Agent name on the mesh.
        port: WebSocket port.
        passphrase: Mesh passphrase (or set IRONMESH_PASSPHRASE env var).
        capabilities: Capabilities to advertise (e.g. ['llm:gpt-4']).
        **agent_kwargs: Extra args passed to ``Agent()``.

    Returns:
        List of 4 BaseTool instances: send, peers, receive, discover.
    """
    agent = Agent(
        name, port=port, passphrase=passphrase,
        capabilities=capabilities, **agent_kwargs,
    )
    agent.run(foreground=False)
    ctx = _MeshContext(agent)

    return [
        IronMeshSendTool(ctx=ctx),
        IronMeshPeersTool(ctx=ctx),
        IronMeshReceiveTool(ctx=ctx),
        IronMeshDiscoverTool(ctx=ctx),
    ]
