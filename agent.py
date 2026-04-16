"""IronMesh Agent SDK — join the mesh in 3 lines.

High-level wrapper over ``BridgeDaemon`` that hides asyncio event-loop
threading, bus subscription plumbing, and shutdown sequencing.  Designed
for agent developers who want to send and receive encrypted messages
without becoming WebSocket/asyncio experts.

Quick start::

    from ironmesh.agent import Agent

    agent = Agent("my-bot", passphrase="secret-passphrase-12")

    @agent.on_message()
    def handle(peer_id: str, payload: bytes):
        print(f"From {peer_id}: {payload.decode()}")
        agent.reply(peer_id, b"ack")

    agent.run()

The SDK manages daemon lifecycle, loop threading, handler wiring, and
graceful shutdown internally.  For advanced use cases that need direct
access to the ``BridgeDaemon``, use ``agent.daemon``.
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ironmesh.bridge import BridgeDaemon

logger = logging.getLogger("ironmesh.agent")


class Agent:
    """High-level IronMesh agent — the public SDK entry point."""

    def __init__(
        self,
        name: str,
        port: int = 8765,
        passphrase: Optional[str] = None,
        *,
        bind: str = "0.0.0.0",
        capabilities: Optional[List[str]] = None,
        open_discovery: bool = True,
        allow_plaintext: bool = True,
        gui: bool = False,
        mesh_routing: str = "relay",
        reticulum: bool = False,
        passphrase_env: str = "IRONMESH_PASSPHRASE",
        **daemon_kwargs,
    ):
        if passphrase is None:
            passphrase = os.environ.get(passphrase_env)
        if not passphrase:
            raise ValueError(
                f"Passphrase required. Pass directly or set {passphrase_env} env var."
            )

        self.daemon = BridgeDaemon(
            name=name,
            port=port,
            passphrase=passphrase,
            bind_address=bind,
            open_discovery=open_discovery,
            allow_plaintext_ws=allow_plaintext,
            gui=gui,
            mesh_routing=mesh_routing,
            capabilities=capabilities,
            rns_enabled=reticulum,
            **daemon_kwargs,
        )
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None
        self._handlers: Dict[str, List[Callable]] = {}
        self._running = False
        self.name = name

    # ------------------------------------------------------------------
    # Decorator API
    # ------------------------------------------------------------------

    def on_message(self, msg_type: str = "MSG"):
        """Decorator: register a handler for incoming messages.

        The handler receives ``(peer_id: str, payload: bytes)``.
        Multiple handlers for the same ``msg_type`` are called in order.

        Example::

            @agent.on_message()
            def handle(peer_id, payload):
                print(peer_id, payload.decode())
        """
        def decorator(fn: Callable) -> Callable:
            self._handlers.setdefault(msg_type, []).append(fn)
            return fn
        return decorator

    def on(self, event_type: str):
        """Decorator: register a handler for any bus event type.

        The handler receives the raw event ``data`` dict.
        """
        def decorator(fn: Callable) -> Callable:
            self._handlers.setdefault(event_type, []).append(fn)
            return fn
        return decorator

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    async def send(
        self,
        target: str,
        message: Union[str, bytes],
        *,
        msg_type: str = "MSG",
        priority: str = "NORMAL",
    ) -> str:
        """Send a message (async). Returns the msg_id.

        ``target`` can be an agent name or a 32-hex node_id.
        """
        target_node = self._resolve_peer(target)
        payload = message.encode("utf-8") if isinstance(message, str) else message
        return await self.daemon.send_message(target_node, msg_type, payload, priority)

    def send_sync(
        self,
        target: str,
        message: Union[str, bytes],
        *,
        msg_type: str = "MSG",
        priority: str = "NORMAL",
        timeout: float = 10.0,
    ) -> str:
        """Send a message (blocking). Requires ``run()`` to have been called."""
        if self._loop is None:
            raise RuntimeError("Agent not running. Call run() first.")
        target_node = self._resolve_peer(target)
        payload = message.encode("utf-8") if isinstance(message, str) else message
        fut = asyncio.run_coroutine_threadsafe(
            self.daemon.send_message(target_node, msg_type, payload, priority),
            self._loop,
        )
        return fut.result(timeout=timeout)

    def reply(
        self,
        peer_id: str,
        message: Union[str, bytes],
        *,
        msg_type: str = "MSG",
        priority: str = "NORMAL",
    ) -> None:
        """Convenience: reply to a peer from inside a handler (non-blocking fire-and-forget)."""
        if self._loop is None:
            return
        payload = message.encode("utf-8") if isinstance(message, str) else message
        asyncio.run_coroutine_threadsafe(
            self.daemon.send_message(peer_id, msg_type, payload, priority),
            self._loop,
        )

    # ------------------------------------------------------------------
    # Peer discovery
    # ------------------------------------------------------------------

    @property
    def peers(self) -> List[Dict[str, Any]]:
        """Online peers with live metrics."""
        out = []
        for pid, p in self.daemon.peers.items():
            if not p.is_online:
                continue
            out.append({
                "node_id": pid,
                "name": getattr(p, "agent_name", None),
                "rtt_ms": p.latency_ms,
                "messages_sent": p.messages_sent,
                "messages_received": p.messages_received,
                "transport": getattr(p, "transport_type", "websocket"),
            })
        return out

    @property
    def node_id(self) -> Optional[str]:
        """This agent's node_id (available after ``run()``)."""
        return getattr(self.daemon, "node_id", None)

    def peer_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Find an online peer by agent name."""
        for p in self.peers:
            if p.get("name") == name:
                return p
        return None

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    def advertise(self, *capabilities: str) -> None:
        """Advertise capabilities (e.g. ``'llm:llama3'``, ``'tool:filesystem'``)."""
        if self.daemon._capabilities is None:
            logger.warning("Capabilities not available until run() is called")
            return
        for cap in capabilities:
            self.daemon._capabilities.advertise_local(cap)

    def discover(self, pattern: str) -> List[Tuple[str, str]]:
        """Find peers by capability glob pattern. Returns ``[(node_id, capability)]``."""
        if self.daemon._capabilities is None:
            return []
        return self.daemon._capabilities.find(pattern)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run(self, foreground: bool = True) -> Optional[asyncio.AbstractEventLoop]:
        """Start the agent.

        Args:
            foreground: If True (default), blocks until Ctrl-C. If False,
                returns the event loop for caller-managed lifetime.

        Returns:
            The asyncio event loop when ``foreground=False``, else None.
        """
        self._loop = self.daemon.run(background=True)
        self._running = True

        # Drive the event loop in a daemon thread
        self._loop_thread = threading.Thread(
            target=self._loop.run_forever,
            name=f"ironmesh-{self.name}",
            daemon=True,
        )
        self._loop_thread.start()

        # Wire decorator-registered handlers into the daemon's bus
        self._wire_handlers()

        logger.info("Agent '%s' running (node_id=%s, port=%d)",
                     self.name, self.daemon.node_id, self.daemon.port)

        if not foreground:
            return self._loop

        try:
            while self._running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
        return None

    def stop(self) -> None:
        """Graceful shutdown."""
        if not self._running:
            return
        self._running = False
        if self._loop is not None:
            try:
                asyncio.run_coroutine_threadsafe(
                    self.daemon.shutdown(), self._loop,
                ).result(timeout=5)
            except (TimeoutError, RuntimeError) as e:
                logger.debug("Shutdown wait: %s", e)
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._loop_thread is not None:
            self._loop_thread.join(timeout=3)
        logger.info("Agent '%s' stopped", self.name)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _resolve_peer(self, target: str) -> str:
        """Resolve agent name → node_id. Pass-through if already a node_id."""
        if len(target) == 32 and all(c in "0123456789abcdef" for c in target):
            return target
        for pid, p in self.daemon.peers.items():
            if getattr(p, "agent_name", None) == target:
                return pid
        raise ValueError(
            f"Peer '{target}' not found. Online peers: "
            f"{[getattr(p, 'agent_name', pid[:12]) for pid, p in self.daemon.peers.items() if p.is_online]}"
        )

    def _wire_handlers(self) -> None:
        """Subscribe decorator-registered handlers to the daemon bus."""
        for event_type, handlers in self._handlers.items():
            for handler in handlers:
                if event_type in ("MSG", "REQ", "RESP"):
                    def make_wrapper(fn):
                        def wrapped(data):
                            peer_id = data.get("peer_id", "")
                            payload = data.get("payload", b"")
                            try:
                                fn(peer_id, payload)
                            except Exception:
                                logger.exception("Handler error in %s", fn.__name__)
                        return wrapped
                    self.daemon.bus.subscribe(event_type, make_wrapper(handler))
                else:
                    def make_raw_wrapper(fn):
                        def wrapped(data):
                            try:
                                fn(data)
                            except Exception:
                                logger.exception("Handler error in %s", fn.__name__)
                        return wrapped
                    self.daemon.bus.subscribe(event_type, make_raw_wrapper(handler))
