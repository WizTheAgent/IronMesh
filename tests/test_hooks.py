"""Tests for ironmesh.hooks — HookManager, circuit breaker, immutability."""

from __future__ import annotations

import asyncio
from types import MappingProxyType

import pytest

from ironmesh.hooks import HookManager, HookPoint


# ---------------------------------------------------------------------------
# Registration + basic firing
# ---------------------------------------------------------------------------

class TestRegistration:

    def test_register_returns_unregister(self):
        m = HookManager()
        unregister = m.register(HookPoint.PRE_SEND, lambda ctx: None)
        assert callable(unregister)

    def test_unregister_removes_callback(self):
        m = HookManager()
        called = []
        unregister = m.register(HookPoint.PRE_SEND, lambda ctx: called.append(1))
        unregister()
        asyncio.run(m.fire(HookPoint.PRE_SEND, {"x": 1}))
        assert called == []

    def test_multiple_callbacks_all_fire(self):
        m = HookManager()
        calls = []
        m.register(HookPoint.PRE_SEND, lambda ctx: calls.append("a"))
        m.register(HookPoint.PRE_SEND, lambda ctx: calls.append("b"))
        asyncio.run(m.fire(HookPoint.PRE_SEND, {}))
        assert sorted(calls) == ["a", "b"]


# ---------------------------------------------------------------------------
# Circuit breaker (audit #17)
# ---------------------------------------------------------------------------

class TestCircuitBreaker:

    def test_threshold_unregisters_after_3_failures(self):
        m = HookManager()

        def bad(ctx):
            raise RuntimeError("boom")

        m.register(HookPoint.PRE_SEND, bad)
        for _ in range(3):
            asyncio.run(m.fire(HookPoint.PRE_SEND, {}))
        # After 3 failures, the callback should be auto-removed
        assert bad not in m._hooks.get(HookPoint.PRE_SEND, [])

    def test_success_resets_failure_count(self):
        m = HookManager()
        state = {"fail": True}

        def flaky(ctx):
            if state["fail"]:
                raise RuntimeError("boom")

        m.register(HookPoint.PRE_SEND, flaky)
        # Two failures
        for _ in range(2):
            asyncio.run(m.fire(HookPoint.PRE_SEND, {}))
        # One success
        state["fail"] = False
        asyncio.run(m.fire(HookPoint.PRE_SEND, {}))
        # Two more failures — should NOT trip since success reset count
        state["fail"] = True
        for _ in range(2):
            asyncio.run(m.fire(HookPoint.PRE_SEND, {}))
        assert flaky in m._hooks.get(HookPoint.PRE_SEND, [])


# ---------------------------------------------------------------------------
# Async callbacks
# ---------------------------------------------------------------------------

class TestAsyncCallbacks:

    def test_async_callback_fires(self):
        m = HookManager()
        called = []

        async def my_async(ctx):
            called.append(ctx.get("x"))

        m.register(HookPoint.PRE_SEND, my_async)
        asyncio.run(m.fire(HookPoint.PRE_SEND, {"x": 42}))
        assert called == [42]

    def test_async_callback_exception_caught(self):
        m = HookManager()

        async def explodes(ctx):
            raise ValueError("nope")

        m.register(HookPoint.PRE_SEND, explodes)
        # Must not propagate
        asyncio.run(m.fire(HookPoint.PRE_SEND, {}))


# ---------------------------------------------------------------------------
# Immutable context (MappingProxyType)
# ---------------------------------------------------------------------------

class TestImmutability:

    def test_context_is_frozen(self):
        m = HookManager()
        captured = []

        def capture(ctx):
            captured.append(ctx)

        m.register(HookPoint.PRE_SEND, capture)
        asyncio.run(m.fire(HookPoint.PRE_SEND, {"a": 1}))
        assert isinstance(captured[0], MappingProxyType)
        with pytest.raises(TypeError):
            captured[0]["b"] = 2  # type: ignore[index]
