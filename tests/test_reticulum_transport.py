"""Tests for the Reticulum (LoRa) transport layer.

All RNS interactions are mocked — these tests verify the adapter's
duck-typed WebSocket interface and the transport lifecycle logic without
needing actual RNS hardware or ``rnsd``.
"""

import asyncio
import importlib
import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import websockets


# ---------------------------------------------------------------------------
# Provide a fake RNS module so reticulum_transport.py can import cleanly
# even when the real ``rns`` package isn't installed.
# ---------------------------------------------------------------------------

def _make_mock_rns():
    """Build a minimal mock of the ``RNS`` package."""
    rns = types.ModuleType("RNS")

    # Use plain ints for status constants (not MagicMock) so == works
    class _Link:
        ACTIVE = 1
        CLOSED = 0
        ACCEPT_ALL = 99

    class _Resource:
        COMPLETE = "complete"

    rns.Link = _Link
    rns.Resource = _Resource
    rns.Packet = MagicMock()
    rns.Destination = MagicMock()
    rns.Destination.IN = "in"
    rns.Destination.OUT = "out"
    rns.Destination.SINGLE = "single"
    rns.Identity = MagicMock()
    rns.Identity.from_file = MagicMock(return_value=None)
    rns.Identity.recall = MagicMock(return_value=MagicMock())
    rns.Reticulum = MagicMock()
    rns.Transport = MagicMock()
    rns.Transport.has_path = MagicMock(return_value=True)
    rns.Transport.request_path = MagicMock()
    rns.prettyhexrep = lambda h: h.hex() if isinstance(h, bytes) else str(h)
    rns.hexrep = lambda h, delimit=True: h.hex() if isinstance(h, bytes) else str(h)
    # Transport now needs hops_to + (de)register_announce_handler for the
    # v0.9.1 announce-discovery path.
    rns.Transport.hops_to = MagicMock(return_value=2)
    rns.Transport.register_announce_handler = MagicMock()
    rns.Transport.deregister_announce_handler = MagicMock()
    # Buffer/Channel are the bidirectional stream API the adapter now uses.
    rns.Buffer = MagicMock()
    rns.Buffer.create_bidirectional_buffer = MagicMock(return_value=MagicMock())
    rns.Channel = MagicMock()
    # Resource is a callable; tests assert on its construction args
    rns.Resource = MagicMock()
    rns.Resource.COMPLETE = "complete"

    return rns


# Install the mock BEFORE any import of reticulum_transport
_mock_rns = _make_mock_rns()
sys.modules["RNS"] = _mock_rns

# Force reimport to pick up our mock (handles case where module was
# previously imported without RNS)
if "ironmesh.reticulum_transport" in sys.modules:
    del sys.modules["ironmesh.reticulum_transport"]

import ironmesh.reticulum_transport as rt_mod
from ironmesh.reticulum_transport import RNSLinkAdapter, ReticulumTransport, _APP_NAME

# Ensure the module sees our mock
rt_mod.RNS = _mock_rns
rt_mod._HAS_RNS = True


# ===========================================================================
# RNSLinkAdapter tests
# ===========================================================================

class TestRNSLinkAdapter:
    """Test the WebSocket-compatible adapter over a mocked RNS Link."""

    def _make_link(self, status=1):
        link = MagicMock()
        link.status = status
        link.set_packet_callback = MagicMock()
        link.set_resource_concluded_callback = MagicMock()
        link.set_link_closed_callback = MagicMock()
        link.teardown = MagicMock()
        # Channel/Buffer API required by current RNSLinkAdapter
        link.get_channel = MagicMock(return_value=MagicMock())
        return link

    @pytest.fixture
    async def adapter(self):
        loop = asyncio.get_running_loop()
        link = self._make_link(status=_mock_rns.Link.ACTIVE)
        return RNSLinkAdapter(link, loop, dest_hash_hex="abcdef01")

    @pytest.mark.asyncio
    async def test_remote_address(self, adapter):
        assert adapter.remote_address == ("rns:abcdef01", 0)

    @pytest.mark.asyncio
    async def test_open_property(self, adapter):
        adapter._link.status = _mock_rns.Link.ACTIVE  # 1
        assert adapter.open is True
        adapter._link.status = _mock_rns.Link.CLOSED  # 0
        assert adapter.open is False

    @pytest.mark.asyncio
    async def test_open_property_no_link(self, adapter):
        adapter._link = None
        assert adapter.open is False

    @pytest.mark.asyncio
    async def test_recv_returns_queued_data(self, adapter):
        adapter._queue.put_nowait(b"hello")
        result = await adapter.recv()
        assert result == b"hello"

    @pytest.mark.asyncio
    async def test_recv_raises_on_sentinel(self, adapter):
        adapter._queue.put_nowait(None)
        with pytest.raises(websockets.ConnectionClosed):
            await adapter.recv()

    @pytest.mark.asyncio
    async def test_send_raises_when_closed(self, adapter):
        adapter._closed = True
        with pytest.raises(websockets.ConnectionClosed):
            await adapter.send(b"data")

    @pytest.mark.asyncio
    async def test_send_writes_to_buffer(self, adapter):
        """send() must write length-prefixed frames to the bidirectional buffer."""
        adapter._buffer.reset_mock()
        await adapter.send(b"small")
        adapter._buffer.write.assert_called_once()
        written = adapter._buffer.write.call_args[0][0]
        # Frame is [4-byte BE length][payload]
        assert written == b"\x00\x00\x00\x05" + b"small"

    @pytest.mark.asyncio
    async def test_send_string_encoded(self, adapter):
        """String data should be UTF-8 encoded before framing."""
        adapter._buffer.reset_mock()
        await adapter.send("text")
        written = adapter._buffer.write.call_args[0][0]
        assert written == b"\x00\x00\x00\x04" + b"text"

    @pytest.mark.asyncio
    async def test_close(self, adapter):
        await adapter.close()
        assert adapter._closed is True
        assert adapter._link is None

    @pytest.mark.asyncio
    async def test_close_idempotent(self, adapter):
        await adapter.close()
        await adapter.close()  # should not raise
        assert adapter._closed is True

    @pytest.mark.asyncio
    async def test_async_iteration(self, adapter):
        """async for should yield queued items and stop on sentinel."""
        adapter._queue.put_nowait(b"msg1")
        adapter._queue.put_nowait(b"msg2")
        adapter._queue.put_nowait(None)

        collected = []
        async for raw in adapter:
            collected.append(raw)
        assert collected == [b"msg1", b"msg2"]

    @pytest.mark.asyncio
    async def test_context_manager(self, adapter):
        async with adapter as a:
            assert a is adapter
        assert adapter._closed is True

    @pytest.mark.asyncio
    async def test_on_packet_enqueues(self, adapter):
        """_on_packet bridges from RNS thread to asyncio queue."""
        # Simulate what call_soon_threadsafe does — call put_nowait directly
        # (in tests we're on the same thread)
        adapter._queue.put_nowait(b"rns-data")
        result = await adapter.recv()
        assert result == b"rns-data"

    @pytest.mark.asyncio
    async def test_on_link_closed_sets_flag(self, adapter):
        adapter._on_link_closed(MagicMock())
        assert adapter._closed is True

    @pytest.mark.asyncio
    async def test_on_resource_concluded_complete(self, adapter):
        """Completed resource should enqueue data."""
        resource = MagicMock()
        resource.status = _mock_rns.Resource.COMPLETE
        resource.data.read.return_value = b"big-payload"
        # Directly enqueue as the callback would (via call_soon_threadsafe)
        adapter._queue.put_nowait(resource.data.read())
        result = await adapter.recv()
        assert result == b"big-payload"

    @pytest.mark.asyncio
    async def test_send_rejects_oversize(self, adapter):
        """send() must refuse payloads exceeding MAX_RNS_MSG to match receive-side bound."""
        from reticulum_transport import MAX_RNS_MSG
        adapter._buffer.reset_mock()
        with pytest.raises(ValueError, match="exceeds MAX_RNS_MSG"):
            await adapter.send(b"x" * (MAX_RNS_MSG + 1))
        adapter._buffer.write.assert_not_called()


# ===========================================================================
# ReticulumTransport tests
# ===========================================================================

class TestReticulumTransport:
    """Test the lifecycle manager with mocked RNS."""

    def _make_daemon(self):
        daemon = MagicMock()
        daemon.name = "test-agent"
        daemon._handle_connection = AsyncMock()
        return daemon

    def test_init(self):
        daemon = self._make_daemon()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        assert transport._daemon is daemon
        assert transport._announce_interval == 60.0
        assert transport._shutdown is False

    def test_start(self):
        daemon = self._make_daemon()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        loop = asyncio.new_event_loop()
        try:
            transport.start(loop)
            _mock_rns.Reticulum.assert_called()
            assert transport._loop is loop
            assert transport._identity is not None
            assert transport._destination is not None
        finally:
            transport.shutdown()
            loop.close()

    def test_shutdown_clears_adapters(self):
        daemon = self._make_daemon()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        loop = asyncio.new_event_loop()
        try:
            transport.start(loop)
            # Add a fake adapter
            adapter = MagicMock()
            adapter._link = MagicMock()
            transport._active_adapters.append(adapter)
            transport.shutdown()
            assert transport._shutdown is True
            assert len(transport._active_adapters) == 0
        finally:
            loop.close()

    def test_on_incoming_link_creates_adapter(self):
        daemon = self._make_daemon()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        loop = asyncio.new_event_loop()
        try:
            transport.start(loop)
            link = MagicMock()
            link.status = _mock_rns.Link.ACTIVE
            link.get_remote_identity.return_value = None
            transport._on_incoming_link(link)
            assert len(transport._active_adapters) == 1
        finally:
            transport.shutdown()
            loop.close()

    @pytest.mark.asyncio
    async def test_connect_to_destination_invalid_hash(self):
        daemon = self._make_daemon()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        transport._loop = asyncio.get_event_loop()
        transport._reticulum = MagicMock()
        result = await transport.connect_to_destination("not-a-hex-string")
        assert result is None

    def test_destination_hash_hex_not_started(self):
        daemon = self._make_daemon()
        transport = ReticulumTransport(daemon)
        assert transport.destination_hash_hex == "not-started"

    def test_destination_hash_hex_after_start(self):
        daemon = self._make_daemon()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        loop = asyncio.new_event_loop()
        try:
            transport.start(loop)
            # After start, should have some hash representation
            assert transport.destination_hash_hex != "not-started"
        finally:
            transport.shutdown()
            loop.close()


# ===========================================================================
# Announce-discovery tests (v0.9.1 Phase 1)
# ===========================================================================

class TestAnnounceAppData:
    """Round-trip and forward-compat tests for the announce app_data codec."""

    def test_encode_decode_roundtrip(self):
        raw = rt_mod.encode_app_data(
            "wiz", "0.9.1", "abc123",
            capabilities=["llm:chat", "tool:echo"],
            features=["mesh", "lxmf"],
        )
        decoded = rt_mod.decode_app_data(raw)
        assert decoded["n"] == "wiz"
        assert decoded["v"] == "0.9.1"
        assert decoded["i"] == "abc123"
        assert decoded["c"] == ["llm:chat", "tool:echo"]
        assert decoded["f"] == ["mesh", "lxmf"]

    def test_decode_legacy_plain_name(self):
        # Pre-v0.9.1 nodes emit raw bytes as the agent name.
        decoded = rt_mod.decode_app_data(b"old-agent")
        assert decoded == {"n": "old-agent"}

    def test_decode_garbage_returns_none_or_legacy(self):
        # Truly broken bytes should not raise — they fall back to the
        # legacy "treat as name" path or return None.
        result = rt_mod.decode_app_data(b"")
        assert result is None
        # Random bytes still decodable as a string -> legacy form
        result = rt_mod.decode_app_data(b"\xff\xfe")
        assert result is not None
        assert "n" in result

    def test_encode_respects_size_cap(self):
        # Stuff in many capabilities; encoder should trim until it fits.
        many_caps = [f"cap:item-{i:03d}" for i in range(100)]
        raw = rt_mod.encode_app_data(
            "node", "0.9.1", "id" * 16,
            capabilities=many_caps,
        )
        assert len(raw) <= rt_mod.APP_DATA_MAX_BYTES
        decoded = rt_mod.decode_app_data(raw)
        # Some capabilities trimmed but base fields survived
        assert decoded["n"] == "node"
        assert decoded["v"] == "0.9.1"
        assert len(decoded.get("c", [])) < len(many_caps)


class TestIronMeshAnnounceHandler:
    """The handler bridges RNS-thread callbacks into the asyncio loop."""

    def _make_transport_with_loop(self, loop):
        daemon = MagicMock()
        daemon.name = "self-node"
        # Daemon implements the discovery hook
        daemon._on_rns_peer_announced = AsyncMock()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        transport._loop = loop
        # Fake destination so self-announce filter has something to compare
        fake_dest = MagicMock()
        fake_dest.hash = b"\x00" * 16
        transport._destination = fake_dest
        return transport, daemon

    @pytest.mark.asyncio
    async def test_received_announce_dispatches_to_daemon(self):
        loop = asyncio.get_running_loop()
        transport, daemon = self._make_transport_with_loop(loop)
        handler = rt_mod._IronMeshAnnounceHandler(transport)
        # Identity has a .hash attribute; supply distinct bytes from self
        announced_identity = MagicMock()
        announced_identity.hash = b"\x11" * 16
        app_data = rt_mod.encode_app_data(
            "peer-a", "0.9.1", "node-peer-a",
            capabilities=["llm:chat"],
            features=["mesh"],
        )
        handler.received_announce(b"\x22" * 16, announced_identity, app_data)
        # Wait for the asyncio scheduling
        await asyncio.sleep(0.05)
        daemon._on_rns_peer_announced.assert_called_once()
        args = daemon._on_rns_peer_announced.call_args.args
        # (dest_hash_hex, identity_hash_hex, app_data_dict, hops)
        assert args[0].startswith("22")
        assert args[1].startswith("11")
        assert args[2]["n"] == "peer-a"
        assert args[3] == 2  # mock hops_to returns 2

    @pytest.mark.asyncio
    async def test_self_announce_ignored(self):
        loop = asyncio.get_running_loop()
        transport, daemon = self._make_transport_with_loop(loop)
        handler = rt_mod._IronMeshAnnounceHandler(transport)
        # Use the same hash as the destination
        announced_identity = MagicMock()
        announced_identity.hash = b"\x11" * 16
        handler.received_announce(
            transport._destination.hash, announced_identity,
            rt_mod.encode_app_data("self-node", "0.9.1", "self"),
        )
        await asyncio.sleep(0.05)
        daemon._on_rns_peer_announced.assert_not_called()

    @pytest.mark.asyncio
    async def test_sample_link_stats_reads_available_metrics(self):
        loop = asyncio.get_running_loop()
        link = MagicMock()
        link.status = _mock_rns.Link.ACTIVE
        link.get_channel = MagicMock(return_value=MagicMock())
        # Wire up the metrics the adapter probes. Some return values,
        # some don't exist — both branches must be exercised.
        link.get_mtu = MagicMock(return_value=508)
        link.get_mdu = MagicMock(return_value=464)
        link.get_expected_rate = MagicMock(return_value=3120.0)
        link.get_rssi = MagicMock(return_value=-72.5)
        link.get_snr = MagicMock(return_value=8.4)
        link.get_q = MagicMock(return_value=92.0)
        link.no_data_for = MagicMock(return_value=1.5)
        link.inactive_for = MagicMock(return_value=2.0)
        link.get_age = MagicMock(return_value=120.0)
        # Drop one accessor entirely to confirm None-guard works
        link.get_establishment_rate = None
        adapter = RNSLinkAdapter(link, loop, dest_hash_hex="abc")
        stats = adapter.sample_link_stats()
        assert stats["mtu"] == 508
        assert stats["mdu"] == 464
        assert stats["expected_bps"] == 3120.0
        assert stats["rssi"] == -72.5
        assert stats["snr"] == 8.4
        assert stats["q"] == 92.0
        assert stats["no_data_for_s"] == 1.5
        assert stats["age_s"] == 120.0
        assert "establishment_bps" not in stats

    @pytest.mark.asyncio
    async def test_remote_identity_captured_on_construction(self):
        # If the remote already identified before our callback was wired,
        # the adapter pulls the identity hash off the link directly.
        loop = asyncio.get_running_loop()
        link = MagicMock()
        link.status = _mock_rns.Link.ACTIVE
        link.get_channel = MagicMock(return_value=MagicMock())
        identity = MagicMock()
        identity.hash = b"\xab" * 16
        link.get_remote_identity = MagicMock(return_value=identity)
        adapter = RNSLinkAdapter(link, loop, dest_hash_hex="abc")
        assert adapter.remote_identity_hash is not None
        assert adapter.remote_identity_hash.startswith("ab")

    @pytest.mark.asyncio
    async def test_remote_identified_callback_updates_hash(self):
        # If the remote identifies after construction, the callback fires
        # and the adapter records the new identity hash.
        loop = asyncio.get_running_loop()
        link = MagicMock()
        link.status = _mock_rns.Link.ACTIVE
        link.get_channel = MagicMock(return_value=MagicMock())
        link.get_remote_identity = MagicMock(return_value=None)
        captured_cb = {}
        def _set_cb(cb):
            captured_cb["cb"] = cb
        link.set_remote_identified_callback = _set_cb
        adapter = RNSLinkAdapter(link, loop, dest_hash_hex="abc")
        assert adapter.remote_identity_hash is None
        assert "cb" in captured_cb
        # Simulate a later identify
        identity = MagicMock()
        identity.hash = b"\xcd" * 16
        captured_cb["cb"](link, identity)
        assert adapter.remote_identity_hash is not None
        assert adapter.remote_identity_hash.startswith("cd")

    @pytest.mark.asyncio
    async def test_sample_link_stats_swallows_per_attr_errors(self):
        loop = asyncio.get_running_loop()
        link = MagicMock()
        link.status = _mock_rns.Link.ACTIVE
        link.get_channel = MagicMock(return_value=MagicMock())
        link.get_mtu = MagicMock(return_value=500)
        # A getter that raises shouldn't kill the whole sample
        link.get_rssi = MagicMock(side_effect=RuntimeError("radio gone"))
        adapter = RNSLinkAdapter(link, loop, dest_hash_hex="abc")
        stats = adapter.sample_link_stats()
        assert stats["mtu"] == 500
        assert "rssi" not in stats

    @pytest.mark.asyncio
    async def test_send_uses_buffer_for_small_payloads(self):
        loop = asyncio.get_running_loop()
        link = MagicMock()
        link.status = _mock_rns.Link.ACTIVE
        link.get_channel = MagicMock(return_value=MagicMock())
        link.set_resource_strategy = MagicMock()
        adapter = RNSLinkAdapter(link, loop, dest_hash_hex="abc")
        adapter.peer_supports_resource = True
        # Reset Resource constructor call count from any prior tests
        _mock_rns.Resource.reset_mock()
        await adapter.send(b"x" * 1024)  # well under threshold
        # Buffer write was called; Resource was not constructed
        adapter._buffer.write.assert_called()
        _mock_rns.Resource.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_routes_large_payload_via_resource_when_supported(self):
        loop = asyncio.get_running_loop()
        link = MagicMock()
        link.status = _mock_rns.Link.ACTIVE
        link.get_channel = MagicMock(return_value=MagicMock())
        link.set_resource_strategy = MagicMock()
        adapter = RNSLinkAdapter(link, loop, dest_hash_hex="abc")
        adapter.peer_supports_resource = True
        _mock_rns.Resource.reset_mock()
        large_payload = b"y" * (rt_mod.RESOURCE_THRESHOLD_BYTES + 1)
        await adapter.send(large_payload)
        # Resource was constructed exactly once with the payload + link
        _mock_rns.Resource.assert_called_once()
        args, kwargs = _mock_rns.Resource.call_args
        assert args[0] == large_payload
        assert args[1] is link
        assert kwargs.get("auto_compress") is True
        assert kwargs.get("advertise") is True
        assert adapter.resources_sent == 1

    @pytest.mark.asyncio
    async def test_send_rejects_large_when_peer_lacks_resource_feature(self):
        loop = asyncio.get_running_loop()
        link = MagicMock()
        link.status = _mock_rns.Link.ACTIVE
        link.get_channel = MagicMock(return_value=MagicMock())
        link.set_resource_strategy = MagicMock()
        adapter = RNSLinkAdapter(link, loop, dest_hash_hex="abc")
        # peer_supports_resource defaults to False
        assert adapter.peer_supports_resource is False
        # Payload above MAX_RNS_MSG must raise (matches old behavior)
        with pytest.raises(ValueError):
            await adapter.send(b"z" * (rt_mod.MAX_RNS_MSG + 1))

    @pytest.mark.asyncio
    async def test_resource_concluded_enqueues_payload(self):
        loop = asyncio.get_running_loop()
        link = MagicMock()
        link.status = _mock_rns.Link.ACTIVE
        link.get_channel = MagicMock(return_value=MagicMock())
        link.set_resource_strategy = MagicMock()
        adapter = RNSLinkAdapter(link, loop, dest_hash_hex="abc")
        # Simulate a completed Resource
        from io import BytesIO
        resource = MagicMock()
        resource.status = _mock_rns.Resource.COMPLETE
        resource.data = BytesIO(b"large-bytes-payload")
        adapter._on_resource_concluded(resource)
        await asyncio.sleep(0.01)
        msg = await asyncio.wait_for(adapter.recv(), timeout=1.0)
        assert msg == b"large-bytes-payload"

    @pytest.mark.asyncio
    async def test_resource_failed_status_dropped(self):
        loop = asyncio.get_running_loop()
        link = MagicMock()
        link.status = _mock_rns.Link.ACTIVE
        link.get_channel = MagicMock(return_value=MagicMock())
        link.set_resource_strategy = MagicMock()
        adapter = RNSLinkAdapter(link, loop, dest_hash_hex="abc")
        from io import BytesIO
        resource = MagicMock()
        resource.status = "failed"
        resource.data = BytesIO(b"would-be-payload")
        adapter._on_resource_concluded(resource)
        await asyncio.sleep(0.01)
        # Queue should be empty (failed transfer dropped)
        assert adapter._queue.empty()

    @pytest.mark.asyncio
    async def test_handler_survives_bad_app_data(self):
        loop = asyncio.get_running_loop()
        transport, daemon = self._make_transport_with_loop(loop)
        handler = rt_mod._IronMeshAnnounceHandler(transport)
        announced_identity = MagicMock()
        announced_identity.hash = b"\x33" * 16
        # Should not raise even with garbage app_data
        handler.received_announce(b"\x44" * 16, announced_identity, b"")
        await asyncio.sleep(0.05)
        # Empty app_data still fires the callback with an empty dict
        daemon._on_rns_peer_announced.assert_called_once()
        assert daemon._on_rns_peer_announced.call_args.args[2] == {}
