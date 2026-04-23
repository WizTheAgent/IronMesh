"""Tests for the optional LXMF listener module.

All RNS / LXMF interactions are mocked. The listener's job is to:
  1. Bridge the lxmf delivery callback (RNS thread) to the asyncio loop
  2. Route inbound LXMF to a configured IronMesh peer
  3. Reverse-route IronMesh MSG events to LXMF when a mapping exists
  4. Provide an outbound API for daemon code to send LXMF directly

These tests verify the routing decisions and loop-prevention prefixes;
the actual RNS / LXMF wire calls are stubbed.
"""

from __future__ import annotations

import asyncio
import sys
import types
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Mock RNS + LXMF before importing the listener
# ---------------------------------------------------------------------------

def _make_mocks():
    rns = types.ModuleType("RNS")
    rns.Reticulum = MagicMock()
    rns.Reticulum._Reticulum__instance = None
    rns.Identity = MagicMock()
    rns.Identity.from_file = MagicMock(return_value=None)
    rns.Identity.recall = MagicMock(return_value=MagicMock())
    rns.Destination = MagicMock()
    rns.Destination.OUT = "out"
    rns.Destination.SINGLE = "single"
    rns.Transport = MagicMock()
    rns.Transport.has_path = MagicMock(return_value=True)
    rns.Transport.request_path = MagicMock()
    rns.Transport.await_path = MagicMock(return_value=True)
    rns.hexrep = lambda h, delimit=True: h.hex() if isinstance(h, bytes) else str(h)

    lxmf = types.ModuleType("LXMF")
    lxmf.LXMRouter = MagicMock()
    lxmf.LXMessage = MagicMock()
    lxmf.LXMessage.DIRECT = "direct"

    return rns, lxmf


_rns, _lxmf = _make_mocks()
sys.modules["RNS"] = _rns
sys.modules["LXMF"] = _lxmf

# Force reimport of the listener with our mocks in place
if "ironmesh.lxmf_listener" in sys.modules:
    del sys.modules["ironmesh.lxmf_listener"]

import ironmesh.lxmf_listener as lxl_mod  # noqa: E402

# Override the module's import-time guards
lxl_mod.RNS = _rns
lxl_mod.LXMF = _lxmf
lxl_mod._HAS_LXMF = True


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_daemon():
    daemon = MagicMock()
    daemon.bus = MagicMock()
    daemon.bus.subscribe = MagicMock()
    daemon.send_message = AsyncMock()
    return daemon


def _make_listener(daemon=None, **overrides):
    daemon = daemon or _make_daemon()
    defaults = dict(
        storage_path="/tmp/lxmf-test",
        display_name="test-node",
    )
    defaults.update(overrides)
    return lxl_mod.LXMFListener(daemon, **defaults)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestLXMFListener:
    def test_init_requires_lxmf(self, monkeypatch):
        monkeypatch.setattr(lxl_mod, "_HAS_LXMF", False)
        with pytest.raises(RuntimeError, match="lxmf package"):
            lxl_mod.LXMFListener(_make_daemon())

    @pytest.mark.asyncio
    async def test_start_subscribes_to_msg_bus(self, tmp_path):
        loop = asyncio.get_running_loop()
        daemon = _make_daemon()
        listener = _make_listener(daemon=daemon, storage_path=str(tmp_path))
        listener.start(loop)
        try:
            daemon.bus.subscribe.assert_called_once_with("MSG", listener._on_ironmesh_message)
            assert listener._delivery_destination is not None
            assert listener._router is not None
        finally:
            listener.shutdown()

    @pytest.mark.asyncio
    async def test_inbound_routed_to_default_peer(self, tmp_path):
        loop = asyncio.get_running_loop()
        daemon = _make_daemon()
        listener = _make_listener(
            daemon=daemon, storage_path=str(tmp_path),
            default_inbound_peer="peer-default",
        )
        listener.start(loop)
        try:
            # Simulate an LXMessage arriving
            msg = MagicMock()
            msg.source_hash = b"\xaa" * 16
            msg.content = b"hello from sideband"
            listener._on_lxmf_message(msg)
            await asyncio.sleep(0.05)
            daemon.send_message.assert_called_once()
            args = daemon.send_message.call_args.args
            assert args[0] == "peer-default"
            assert args[1] == "MSG"
            # Payload prefixed for loop-prevention on the way back
            assert args[2].startswith(lxl_mod.PREFIX_LXMF_TO_IM)
            assert listener.stats["lxmf_in"] == 1
            assert listener.stats["im_out"] == 1
        finally:
            listener.shutdown()

    @pytest.mark.asyncio
    async def test_inbound_uses_route_map_over_default(self, tmp_path):
        loop = asyncio.get_running_loop()
        daemon = _make_daemon()
        listener = _make_listener(
            daemon=daemon, storage_path=str(tmp_path),
            default_inbound_peer="peer-default",
        )
        listener.start(loop)
        try:
            src_hex = ("aa" * 16)
            listener.inbound_route[src_hex] = "peer-specific"
            msg = MagicMock()
            msg.source_hash = b"\xaa" * 16
            msg.content = b"targeted"
            listener._on_lxmf_message(msg)
            await asyncio.sleep(0.05)
            args = daemon.send_message.call_args.args
            assert args[0] == "peer-specific"
        finally:
            listener.shutdown()

    @pytest.mark.asyncio
    async def test_inbound_unmapped_with_no_default_dropped(self, tmp_path):
        loop = asyncio.get_running_loop()
        daemon = _make_daemon()
        listener = _make_listener(daemon=daemon, storage_path=str(tmp_path))
        listener.start(loop)
        try:
            msg = MagicMock()
            msg.source_hash = b"\xbb" * 16
            msg.content = b"orphan"
            listener._on_lxmf_message(msg)
            await asyncio.sleep(0.05)
            daemon.send_message.assert_not_called()
            assert listener.stats["drops_unmapped"] == 1
        finally:
            listener.shutdown()

    @pytest.mark.asyncio
    async def test_loop_prevention_drops_im_to_lxmf_prefix(self, tmp_path):
        # An inbound message that already carries the IM_TO_LXMF prefix
        # is one we ourselves sent — the LXMF network is echoing it back.
        # Drop it rather than re-injecting a loop into IronMesh.
        loop = asyncio.get_running_loop()
        daemon = _make_daemon()
        listener = _make_listener(
            daemon=daemon, storage_path=str(tmp_path),
            default_inbound_peer="peer-default",
        )
        listener.start(loop)
        try:
            msg = MagicMock()
            msg.source_hash = b"\xcc" * 16
            msg.content = lxl_mod.PREFIX_IM_TO_LXMF.encode("utf-8") + b"echoed"
            listener._on_lxmf_message(msg)
            await asyncio.sleep(0.05)
            daemon.send_message.assert_not_called()
            assert listener.stats["drops_loop"] == 1
        finally:
            listener.shutdown()

    @pytest.mark.asyncio
    async def test_outbound_im_to_lxmf_uses_reverse_map(self, tmp_path):
        loop = asyncio.get_running_loop()
        daemon = _make_daemon()
        listener = _make_listener(daemon=daemon, storage_path=str(tmp_path))
        listener.start(loop)
        try:
            # Map an LXMF dest to an IronMesh peer; an IM MSG from that
            # peer should round-trip out as an LXMessage.
            lxmf_dest_hex = "11" * 16
            listener.inbound_route[lxmf_dest_hex] = "peer-mapped"
            # Patch send_lxmf_to to capture the call without hitting RNS
            listener.send_lxmf_to = AsyncMock(return_value=True)
            listener._on_ironmesh_message({
                "peer_id": "peer-mapped",
                "payload": b"reply text",
            })
            await asyncio.sleep(0.05)
            listener.send_lxmf_to.assert_called_once_with(lxmf_dest_hex, "reply text")
        finally:
            listener.shutdown()

    @pytest.mark.asyncio
    async def test_outbound_no_mapping_silently_skipped(self, tmp_path):
        loop = asyncio.get_running_loop()
        daemon = _make_daemon()
        listener = _make_listener(daemon=daemon, storage_path=str(tmp_path))
        listener.start(loop)
        try:
            listener.send_lxmf_to = AsyncMock(return_value=True)
            listener._on_ironmesh_message({
                "peer_id": "unmapped-peer",
                "payload": b"goes nowhere",
            })
            await asyncio.sleep(0.05)
            listener.send_lxmf_to.assert_not_called()
        finally:
            listener.shutdown()

    @pytest.mark.asyncio
    async def test_send_lxmf_to_invalid_hash_returns_false(self, tmp_path):
        loop = asyncio.get_running_loop()
        listener = _make_listener(storage_path=str(tmp_path))
        listener.start(loop)
        try:
            ok = await listener.send_lxmf_to("not-hex-at-all", "x")
            assert ok is False
        finally:
            listener.shutdown()

    @pytest.mark.asyncio
    async def test_propagation_node_calls_enable_when_supported(self, tmp_path):
        loop = asyncio.get_running_loop()
        daemon = _make_daemon()
        listener = _make_listener(
            daemon=daemon, storage_path=str(tmp_path),
            propagation_node=True,
            propagation_storage_path=str(tmp_path / "propagation"),
        )
        # Inject enable_propagation onto the router mock
        router_instance = MagicMock()
        router_instance.enable_propagation = MagicMock()
        router_instance.register_delivery_identity = MagicMock(return_value=MagicMock())
        router_instance.register_delivery_callback = MagicMock()
        _lxmf.LXMRouter = MagicMock(return_value=router_instance)
        listener.start(loop)
        try:
            router_instance.enable_propagation.assert_called_once()
        finally:
            listener.shutdown()

    @pytest.mark.asyncio
    async def test_delivery_destination_hash_property(self, tmp_path):
        loop = asyncio.get_running_loop()
        listener = _make_listener(storage_path=str(tmp_path))
        # Before start: None
        assert listener.delivery_destination_hash is None
        listener.start(loop)
        try:
            # After start: returns hex string from RNS.hexrep mock
            listener._delivery_destination.hash = b"\xde\xad" * 8
            assert listener.delivery_destination_hash is not None
        finally:
            listener.shutdown()
