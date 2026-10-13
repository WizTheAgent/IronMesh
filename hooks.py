"""IronMesh hook/plugin system for message processing.

Enables logging, metrics, message transformation, access control,
and other extensions without modifying core protocol.
Hook callbacks receive a frozen (immutable) copy of the context to prevent
accidental or malicious mutation of internal state.
"""

import asyncio
import logging
from enum import Enum
from types import MappingProxyType
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("ironmesh.hooks")


class HookPoint(str, Enum):
    PRE_SEND = "pre_send"
    POST_RECEIVE = "post_receive"
    ON_PEER_CONNECT = "on_peer_connect"
    ON_PEER_DISCONNECT = "on_peer_disconnect"
    ON_HANDSHAKE_COMPLETE = "on_handshake_complete"
    ON_ERROR = "on_error"


class HookManager:
    """Manages hook registration and execution.

    #17: Circuit breaker — after 3 consecutive failures, a callback is
    auto-unregistered and a warning is logged. Success resets the counter.
    """

    CIRCUIT_BREAKER_THRESHOLD = 3

    def __init__(self):
        self._hooks: Dict[str, List[Callable]] = {}
        # Keyed by (hook_point, callback_id) so the same callback on different
        # hook points gets independent failure counts.
        self._failure_counts: Dict[tuple, int] = {}

    def register(self, hook_point: str, callback: Callable) -> Callable:
        """Register a callback for a hook point.

        Args:
            hook_point: One of HookPoint values (or any string for custom hooks).
            callback: Async or sync callable. Receives a context dict.

        Returns:
            Unregister function.
        """
        if hook_point not in self._hooks:
            self._hooks[hook_point] = []
        self._hooks[hook_point].append(callback)
        self._failure_counts[(hook_point, id(callback))] = 0
        logger.debug("Hook registered: %s -> %s", hook_point, callback.__name__)

        def unregister():
            try:
                self._hooks[hook_point].remove(callback)
            except ValueError:
                pass  # Already removed by circuit breaker
            self._failure_counts.pop((hook_point, id(callback)), None)

        return unregister

    async def fire(self, hook_point: str, context: dict) -> dict:
        """Fire all callbacks for a hook point.

        Args:
            hook_point: The hook point to fire.
            context: Context dict. Callbacks receive an immutable (frozen) copy
                     to prevent accidental mutation of internal state.

        Returns:
            The original context dict (unmodified by callbacks).
        """
        callbacks = list(self._hooks.get(hook_point, []))
        # Freeze context so callbacks can't mutate internal state
        frozen = MappingProxyType(context)
        for cb in callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(frozen)
                else:
                    cb(frozen)
                # Success — reset failure counter for this hook point
                self._failure_counts[(hook_point, id(cb))] = 0
            except Exception as e:
                cb_id = id(cb)
                key = (hook_point, cb_id)
                self._failure_counts[key] = self._failure_counts.get(key, 0) + 1
                count = self._failure_counts[key]
                logger.error("Hook %s error in %s: %s (failure %d/%d)",
                           hook_point, cb.__name__, e, count, self.CIRCUIT_BREAKER_THRESHOLD)
                # Circuit breaker — auto-unregister after threshold.
                if count >= self.CIRCUIT_BREAKER_THRESHOLD:
                    logger.warning(
                        "Circuit breaker: auto-unregistering hook %s from %s after %d consecutive failures",
                        cb.__name__, hook_point, count,
                    )
                    try:
                        self._hooks[hook_point].remove(cb)
                    except ValueError:
                        pass
                    self._failure_counts.pop(key, None)
        return context

    def clear(self, hook_point: Optional[str] = None):
        """Clear hooks for a specific point, or all hooks."""
        if hook_point:
            self._hooks.pop(hook_point, None)
        else:
            self._hooks.clear()

    def list_hooks(self) -> Dict[str, int]:
        """List registered hook points and their callback counts."""
        return {k: len(v) for k, v in self._hooks.items()}
