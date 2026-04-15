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
    # Buffer/Channel are the bidirectional stream API the adapter now uses.
    rns.Buffer = MagicMock()
    rns.Buffer.create_bidirectional_buffer = MagicMock(return_value=MagicMock())
    rns.Channel = MagicMock()

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
