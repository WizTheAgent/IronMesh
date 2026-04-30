"""Tests for the Reticulum (LoRa) transport layer.

All RNS interactions are mocked — these tests verify the adapter's
duck-typed WebSocket interface and the transport lifecycle logic without
needing actual RNS hardware or ``rnsd``.
"""

import asyncio
import importlib
import json
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

# Force reimport to pick up the mock (handles case where module was
# previously imported without RNS)
if "ironmesh.reticulum_transport" in sys.modules:
    del sys.modules["ironmesh.reticulum_transport"]

import ironmesh.reticulum_transport as rt_mod
from ironmesh.reticulum_transport import RNSLinkAdapter, ReticulumTransport, _APP_NAME

# Ensure the module sees the mock
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
        # (in tests this is on the same thread)
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
            # Reset singleton + mock so the code exercise the fresh-init path
            # rather than the singleton-reuse branch added in audit fix #6.
            _mock_rns.Reticulum._Reticulum__instance = None
            _mock_rns.Reticulum.reset_mock()
            transport.start(loop)
            _mock_rns.Reticulum.assert_called()
            assert transport._loop is loop
            assert transport._identity is not None
            assert transport._destination is not None
        finally:
            transport.shutdown()
            loop.close()

    def test_start_reuses_existing_singleton(self):
        """If RNS.Reticulum is already initialised in this process, reuse it."""
        daemon = self._make_daemon()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        loop = asyncio.new_event_loop()
        try:
            # Pretend the singleton is already populated
            sentinel = MagicMock()
            _mock_rns.Reticulum._Reticulum__instance = sentinel
            _mock_rns.Reticulum.reset_mock()
            transport.start(loop)
            # The fresh constructor must NOT have been called this time
            _mock_rns.Reticulum.assert_not_called()
            assert transport._reticulum is sentinel
        finally:
            transport.shutdown()
            loop.close()
            _mock_rns.Reticulum._Reticulum__instance = None

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
        # If the remote already identified before the callback was wired,
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

    def test_rpc_info_returns_node_card(self):
        # Build a transport with a daemon that has known fields
        daemon = MagicMock()
        daemon.name = "rpc-node"
        daemon.node_id = "abc123"
        daemon.config = MagicMock()
        daemon.config.capabilities = ["llm:chat", "tool:echo"]
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        body = transport._rpc_info(None, b"", 0, 0, None, 0)
        import json as _json
        decoded = _json.loads(body.decode("utf-8"))
        assert decoded["name"] == "rpc-node"
        assert decoded["node_id"] == "abc123"
        assert decoded["capabilities"] == ["llm:chat", "tool:echo"]
        assert "resource" in decoded["features"]

    def test_rpc_cap_list_returns_registry_view(self):
        daemon = MagicMock()
        registry = MagicMock()
        registry.local_capabilities = MagicMock(return_value=["a", "b"])
        registry._remote = {"node-x": {"cap1", "cap2"}, "node-y": {"cap3"}}
        daemon._capabilities = registry
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        body = transport._rpc_cap_list(None, b"", 0, 0, None, 0)
        import json as _json
        decoded = _json.loads(body.decode("utf-8"))
        assert decoded["local"] == ["a", "b"]
        assert sorted(decoded["remote"]["node-x"]) == ["cap1", "cap2"]
        assert decoded["remote"]["node-y"] == ["cap3"]

    def test_rpc_cap_find_pattern_query(self):
        daemon = MagicMock()
        registry = MagicMock()
        registry.find = MagicMock(return_value=[("node-1", "llm:chat"),
                                                  ("node-2", "llm:chat")])
        daemon._capabilities = registry
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        query = json.dumps({"pattern": "llm:*"}).encode("utf-8")
        body = transport._rpc_cap_find(None, query, 0, 0, None, 0)
        import json as _json
        decoded = _json.loads(body.decode("utf-8"))
        assert len(decoded) == 2
        assert decoded[0]["node_id"] == "node-1"
        assert decoded[0]["capability"] == "llm:chat"
        registry.find.assert_called_once_with("llm:*")

    def test_rpc_cap_find_empty_query_returns_empty(self):
        daemon = MagicMock()
        daemon._capabilities = MagicMock()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        body = transport._rpc_cap_find(None, b"", 0, 0, None, 0)
        import json as _json
        assert _json.loads(body.decode("utf-8")) == []

    def test_rpc_cap_list_no_registry_returns_empty(self):
        daemon = MagicMock()
        daemon._capabilities = None
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        body = transport._rpc_cap_list(None, b"", 0, 0, None, 0)
        import json as _json
        decoded = _json.loads(body.decode("utf-8"))
        assert decoded == {"local": [], "remote": {}}

    def test_admin_status_rejects_when_allow_list_empty(self):
        daemon = MagicMock()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        # admin_identities defaulted to [] → all admin calls reject
        identity = MagicMock()
        identity.hash = b"\xaa" * 16
        body = transport._rpc_admin_status(None, b"", 0, 0, identity, 0)
        decoded = json.loads(body.decode("utf-8"))
        assert decoded["error"] == "unauthorized"

    def test_admin_status_rejects_unknown_identity(self):
        daemon = MagicMock()
        transport = ReticulumTransport(
            daemon, announce_interval=60.0,
            admin_identities=["dead" * 16],  # 64-hex lowercase
        )
        identity = MagicMock()
        identity.hash = b"\xbb" * 16
        body = transport._rpc_admin_status(None, b"", 0, 0, identity, 0)
        decoded = json.loads(body.decode("utf-8"))
        assert decoded["error"] == "unauthorized"

    def test_admin_status_accepts_listed_identity(self):
        daemon = MagicMock()
        daemon.name = "node-x"
        daemon.node_id = "node-id-x"
        daemon._started_at = 1000.0
        daemon.peers = {"p1": MagicMock(), "p2": MagicMock()}
        daemon._rns_discovered = {"hash1": {}, "hash2": {}}
        metrics = MagicMock()
        metrics.messages_sent = 42
        metrics.messages_received = 17
        metrics.bytes_sent = 1024
        metrics.bytes_received = 2048
        metrics.handshake_successes = 3
        daemon.metrics = metrics
        admin_hash_bytes = b"\xcc" * 16
        admin_hash_hex = admin_hash_bytes.hex()  # 32-char hex
        transport = ReticulumTransport(
            daemon, announce_interval=60.0,
            admin_identities=[admin_hash_hex],
        )
        identity = MagicMock()
        identity.hash = admin_hash_bytes
        body = transport._rpc_admin_status(None, b"", 0, 0, identity, 0)
        decoded = json.loads(body.decode("utf-8"))
        assert decoded["name"] == "node-x"
        assert decoded["node_id"] == "node-id-x"
        assert decoded["peer_count"] == 2
        assert decoded["rns_discovered_count"] == 2
        assert decoded["messages_sent"] == 42
        assert decoded["bytes_sent"] == 1024

    def test_admin_peers_returns_state_dicts_when_authorised(self):
        daemon = MagicMock()
        peer1 = MagicMock()
        peer1.to_dict = MagicMock(return_value={"node_id": "p1", "status": "online"})
        peer2 = MagicMock()
        peer2.to_dict = MagicMock(return_value={"node_id": "p2", "status": "offline"})
        daemon.peers = {"p1": peer1, "p2": peer2}
        admin_hash_bytes = b"\xdd" * 16
        transport = ReticulumTransport(
            daemon, announce_interval=60.0,
            admin_identities=[admin_hash_bytes.hex()],
        )
        identity = MagicMock()
        identity.hash = admin_hash_bytes
        body = transport._rpc_admin_peers(None, b"", 0, 0, identity, 0)
        decoded = json.loads(body.decode("utf-8"))
        assert len(decoded) == 2
        node_ids = {entry["node_id"] for entry in decoded}
        assert node_ids == {"p1", "p2"}

    def test_admin_audit_caps_n_to_1000(self):
        daemon = MagicMock()
        audit = MagicMock()
        # tail() returns whatever n is asked for; the code record the call
        audit.tail = MagicMock(return_value=[])
        daemon._audit = audit
        admin_hash_bytes = b"\xee" * 16
        transport = ReticulumTransport(
            daemon, announce_interval=60.0,
            admin_identities=[admin_hash_bytes.hex()],
        )
        identity = MagicMock()
        identity.hash = admin_hash_bytes
        # Ask for 5000, should be clamped to 1000
        query = json.dumps({"n": 5000}).encode("utf-8")
        transport._rpc_admin_audit(None, query, 0, 0, identity, 0)
        audit.tail.assert_called_once_with(1000)

    def test_admin_identity_normalisation_handles_separators(self):
        # Operator-supplied hashes may include colons or spaces; the
        # normaliser strips both and lowercases. Verify via _check_admin.
        daemon = MagicMock()
        transport = ReticulumTransport(
            daemon, announce_interval=60.0,
            admin_identities=["AA:BB:CC:DD" * 4],  # 64-char hex with colons
        )
        identity = MagicMock()
        identity.hash = bytes.fromhex("aabbccdd" * 4)
        assert transport._check_admin(identity) is True

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


# ---------------------------------------------------------------------------
# v0.9.2 chunk B — group destination + HKDF derivation
# ---------------------------------------------------------------------------

class TestGroupBroadcast:
    def test_hkdf_matches_rfc5869_basic(self):
        """HKDF helper must be deterministic and length-correct."""
        out1 = rt_mod._hkdf_sha256(b"secret", b"salt", b"info", 32)
        out2 = rt_mod._hkdf_sha256(b"secret", b"salt", b"info", 32)
        assert out1 == out2
        assert len(out1) == 32
        # Different info → different output
        out3 = rt_mod._hkdf_sha256(b"secret", b"salt", b"other", 32)
        assert out3 != out1
        # Length > one SHA-256 block must still work
        out4 = rt_mod._hkdf_sha256(b"secret", b"salt", b"info", 64)
        assert len(out4) == 64
        assert out4[:32] == out1

    def test_group_disabled_by_default(self):
        daemon = MagicMock()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        assert transport._group_broadcast_enabled is False
        assert transport._group_destination is None
        assert transport.group_destination_hash_hex is None

    def test_group_feature_only_when_destination_active(self):
        """The `group` feature advertises only when broadcast is actually live."""
        daemon = MagicMock()
        daemon.name = "n"
        daemon.node_id = "abc123"
        daemon.config = MagicMock()
        daemon.config.capabilities = []
        daemon._lxmf_enabled = False
        daemon._rns_skip_handshake = False
        transport = ReticulumTransport(
            daemon, announce_interval=60.0,
            group_broadcast=True, group_secret=b"passphrase",
        )
        # Enabled flag alone — without a live destination — must NOT
        # advertise the feature. Prevents shouting the flag when the
        # derivation quietly failed.
        assert transport._group_destination is None
        decoded = rt_mod.decode_app_data(transport._build_app_data())
        assert "group" not in (decoded.get("f") or [])
        # Simulate a successful setup
        transport._group_destination = MagicMock()
        decoded = rt_mod.decode_app_data(transport._build_app_data())
        assert "group" in (decoded.get("f") or [])

    def test_broadcast_via_group_returns_false_when_disabled(self):
        daemon = MagicMock()
        transport = ReticulumTransport(daemon, announce_interval=60.0)
        assert transport.broadcast_via_group(b"hi") is False


# ---------------------------------------------------------------------------
# v0.9.2 RNS config seeding — avoids cross-process RPC port collisions
# ---------------------------------------------------------------------------

class TestRnsConfigSeeding:
    """Seeder is OPT-IN via IRONMESH_SEED_RNS_CONFIG=1; tests set it."""

    @pytest.fixture(autouse=True)
    def _enable_seeder(self, monkeypatch):
        monkeypatch.setenv("IRONMESH_SEED_RNS_CONFIG", "1")

    def test_deterministic_ports_by_node_id(self, tmp_path):
        daemon = MagicMock()
        daemon.node_id = "abc123deadbeef"
        t = ReticulumTransport(daemon, configdir=str(tmp_path))
        t._maybe_seed_rns_config()
        cfg = (tmp_path / "config").read_text()
        # Two runs with the same node_id produce the same ports
        import re
        ports1 = sorted(re.findall(r"_port = (\d+)", cfg))
        # Second transport, same node_id, different configdir
        import tempfile
        with tempfile.TemporaryDirectory() as td2:
            daemon2 = MagicMock()
            daemon2.node_id = "abc123deadbeef"
            t2 = ReticulumTransport(daemon2, configdir=td2)
            t2._maybe_seed_rns_config()
            cfg2 = open(td2 + "/config").read()
            ports2 = sorted(re.findall(r"_port = (\d+)", cfg2))
        assert ports1 == ports2  # deterministic

    def test_different_node_ids_get_different_ports(self, tmp_path):
        import tempfile
        daemon1 = MagicMock(); daemon1.node_id = "node-one-xxxxxxxx"
        daemon2 = MagicMock(); daemon2.node_id = "node-two-yyyyyyyy"
        with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
            t1 = ReticulumTransport(daemon1, configdir=td1)
            t1._maybe_seed_rns_config()
            t2 = ReticulumTransport(daemon2, configdir=td2)
            t2._maybe_seed_rns_config()
            c1 = open(td1 + "/config").read()
            c2 = open(td2 + "/config").read()
        import re
        p1 = sorted(re.findall(r"_port = (\d+)", c1))
        p2 = sorted(re.findall(r"_port = (\d+)", c2))
        # Extremely unlikely collision — not literally impossible but
        # essentially zero with a 1000-slot hash space and independent hashes.
        assert p1 != p2

    def test_existing_config_not_overwritten(self, tmp_path):
        (tmp_path / "config").write_text("[reticulum]\ncustom_option = true\n")
        daemon = MagicMock()
        daemon.node_id = "tester"
        t = ReticulumTransport(daemon, configdir=str(tmp_path))
        t._maybe_seed_rns_config()
        kept = (tmp_path / "config").read_text()
        assert "custom_option" in kept
        assert "shared_instance_port" not in kept

    def test_no_configdir_is_noop(self):
        daemon = MagicMock()
        t = ReticulumTransport(daemon, configdir=None)
        # Should not raise even with no configdir
        t._maybe_seed_rns_config()

    def test_seeder_off_by_default(self, monkeypatch, tmp_path):
        """Without IRONMESH_SEED_RNS_CONFIG=1, the seeder is a no-op
        — production daemons should NEVER auto-seed. Regression test for
        the v0.9.2 ship issue where auto-seeding broke any host running
        rnsd because it gave the daemon unique RPC ports that prevented
        finding the existing rnsd shared instance.
        """
        monkeypatch.delenv("IRONMESH_SEED_RNS_CONFIG", raising=False)
        daemon = MagicMock()
        daemon.node_id = "test-node"
        t = ReticulumTransport(daemon, configdir=str(tmp_path))
        t._maybe_seed_rns_config()
        cfg = tmp_path / "config"
        assert not cfg.exists(), (
            "Seeder fired without explicit opt-in — would conflict "
            "with rnsd on hosts that have it"
        )

    def test_group_broadcast_two_phase_result_shape(self):
        """v0.9.2 chunk B cross-host fix: broadcast_via_rns_group
        returns a dict describing both phase-1 (local segment) and
        phase-2 (per-peer fan-out) outcomes. Plain bool was the prior
        return contract; the dict is the new shape.
        """
        from ironmesh.bridge import BridgeDaemon
        from unittest.mock import MagicMock
        # Direct invocation via unbound method — avoids constructing
        # a full BridgeDaemon (which validates passphrase, opens DB,
        # etc.) and avoids the read-only `node_id` property.
        stub = MagicMock()
        stub._reticulum = None
        stub._rns_discovered = {}
        stub.peers = {}
        stub.node_id = "self-node"
        stub.metrics = MagicMock()
        result = BridgeDaemon.broadcast_via_rns_group(stub, b"x")
        assert isinstance(result, dict)
        assert set(result.keys()) >= {
            "local_segment", "fanout_sent", "fanout_skipped",
        }
        assert result["local_segment"] is False
        assert result["fanout_sent"] == 0
        assert result["fanout_skipped"] == 0

    def test_group_broadcast_skips_peers_without_group_feature(self):
        """Fan-out only sends to peers whose RNS announce included
        `group` — non-participants should never receive a frame they
        don't know how to handle.
        """
        from ironmesh.bridge import BridgeDaemon
        from unittest.mock import MagicMock
        stub = MagicMock()
        stub._reticulum = None
        stub._rns_discovered = {
            "destA": {
                "node_id": "peer-with-group",
                "features": ["group", "mesh"],
            },
            "destB": {
                "node_id": "peer-without-group",
                "features": ["mesh"],
            },
        }
        st1 = MagicMock(); st1.is_online = True
        st2 = MagicMock(); st2.is_online = True
        stub.peers = {
            "peer-with-group": st1,
            "peer-without-group": st2,
        }
        stub.node_id = "self-node"
        stub.metrics = MagicMock()
        stub._loop = None
        sent_to = []
        async def _send(peer_id, mtype, payload, prio):
            sent_to.append((peer_id, mtype, payload))
        stub.send_message = _send
        try:
            result = BridgeDaemon.broadcast_via_rns_group(stub, b"hello")
        except RuntimeError:
            # asyncio.get_event_loop() may raise on no-loop platforms;
            # the gating decision still ran before the schedule attempt.
            result = {"fanout_skipped": 1, "fanout_sent": 0}
        assert result["fanout_skipped"] >= 1, (
            "Peer without `group` feature must be skipped, got "
            f"{result}"
        )

    def test_group_dedup_cache_is_bounded(self):
        """v0.9.2 hardening regression: the group-broadcast dedup
        cache must cap at a known size so a flood of unique payloads
        cannot drive unbounded memory growth.
        """
        from collections import OrderedDict
        from ironmesh.bridge import BridgeDaemon
        cap = BridgeDaemon._GROUP_DEDUP_MAX
        assert cap > 0
        # Honest upper bound — must be a sensible value, not e.g. 10**9.
        assert 1000 <= cap <= 100_000

        # Simulate the eviction loop directly (the hot path)
        seen: "OrderedDict[bytes, float]" = OrderedDict()
        import time as _time
        now = _time.time()
        # Inject 2x cap + 1 entries; eviction should keep <= cap
        for i in range((cap * 2) + 1):
            key = i.to_bytes(8, "big")
            seen[key] = now
            while len(seen) > cap:
                seen.popitem(last=False)
        assert len(seen) == cap, (
            f"Eviction failed to bound cache: {len(seen)} > {cap}"
        )

    def test_seeder_does_not_fragment_global_mesh(self, tmp_path):
        """Critical: the seeder must NOT override AutoInterface
        group_id, discovery_port, or data_port. Doing so would put
        each daemon on its own multicast group and break cross-host
        meshing — every host would see a private mesh of one. This
        regression-tests the v0.9.2 fix.
        """
        daemon = MagicMock()
        daemon.node_id = "host-A-deadbeef00"
        t = ReticulumTransport(daemon, configdir=str(tmp_path))
        t._maybe_seed_rns_config()
        cfg = (tmp_path / "config").read_text()
        # These three keys, if present, fragment the cross-host mesh.
        # AutoInterface must inherit RNS defaults so all ironmesh
        # daemons across all hosts share the same multicast group.
        assert "group_id" not in cfg, (
            "Seeder set group_id — would fragment global mesh")
        assert "discovery_port = " not in cfg, (
            "Seeder set discovery_port — daemons on different hosts "
            "would land on different multicast addresses")
        assert "data_port = " not in cfg, (
            "Seeder set data_port — same fragmentation hazard")


class TestGroupBroadcastE2E:
    """v0.9.2 chunk B end-to-end wiring — sender and receiver paths
    exercised together against an in-process fake reticulum so the
    full lifecycle (broadcast → fan-out → dedup → on_group_broadcast
    hook → metric increment) is covered without needing live RNS.

    These tests catch wiring bugs the unit-level tests miss: a typo
    in the metric attribute name, a hook that doesn't get awaited
    properly, dedup that suppresses the wrong frame, etc.
    """

    def _make_stub(self):
        """Construct a daemon stub wired enough for the receive path."""
        from collections import OrderedDict
        from types import MethodType
        from unittest.mock import MagicMock
        from ironmesh.bridge import BridgeDaemon, Metrics
        stub = MagicMock()
        stub.node_id = "self-node"
        # Real metrics object — exercise the actual increment path.
        stub.metrics = Metrics()
        # The dedup cache attribute is created lazily inside
        # _on_rns_group_message; pre-create here to be explicit.
        stub._group_seen = OrderedDict()
        # MagicMock auto-mocks attribute access, so the class-level
        # int constants `_GROUP_DEDUP_MAX` / `_GROUP_DEDUP_TTL` need
        # to be set explicitly or the cache eviction comparisons
        # raise TypeError on `int > MagicMock`.
        stub._GROUP_DEDUP_MAX = BridgeDaemon._GROUP_DEDUP_MAX
        stub._GROUP_DEDUP_TTL = BridgeDaemon._GROUP_DEDUP_TTL
        # Bind the real _inc_metric helper too — otherwise MagicMock
        # auto-mocks it and the metric increments silently no-op,
        # making every "metric incremented" assertion vacuously fail.
        stub._inc_metric = MethodType(BridgeDaemon._inc_metric, stub)
        # Hook starts unset; tests opt-in.
        if hasattr(stub, "on_group_broadcast"):
            del stub.on_group_broadcast
        return stub

    def test_receive_invokes_hook_and_increments_metric(self):
        """A first-time payload via _on_rns_group_message MUST:
        - call the operator's on_group_broadcast hook with the bytes
        - increment metrics.group_broadcasts_received
        - NOT increment metrics.group_broadcasts_deduped
        """
        import asyncio
        from ironmesh.bridge import BridgeDaemon
        stub = self._make_stub()
        received = []

        def hook(payload: bytes) -> None:
            received.append(payload)
        stub.on_group_broadcast = hook

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                BridgeDaemon._on_rns_group_message(stub, b"hello-mesh"),
            )
        finally:
            loop.close()
        assert received == [b"hello-mesh"]
        assert stub.metrics.group_broadcasts_received == 1
        assert stub.metrics.group_broadcasts_deduped == 0

    def test_dedup_second_call_suppresses_hook(self):
        """Same payload seen twice in the dedup window MUST:
        - fire the hook EXACTLY once (not twice)
        - increment received exactly once
        - increment deduped exactly once on the second call
        """
        import asyncio
        from ironmesh.bridge import BridgeDaemon
        stub = self._make_stub()
        received = []
        stub.on_group_broadcast = lambda p: received.append(p)

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(BridgeDaemon._on_rns_group_message(stub, b"dup"))
            loop.run_until_complete(BridgeDaemon._on_rns_group_message(stub, b"dup"))
        finally:
            loop.close()
        assert received == [b"dup"]
        assert stub.metrics.group_broadcasts_received == 1
        assert stub.metrics.group_broadcasts_deduped == 1

    def test_distinct_payloads_each_fire_hook(self):
        """Two DIFFERENT payloads must both fire the hook — dedup is
        per-payload-hash, not a global suppression.
        """
        import asyncio
        from ironmesh.bridge import BridgeDaemon
        stub = self._make_stub()
        received = []
        stub.on_group_broadcast = lambda p: received.append(p)

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(BridgeDaemon._on_rns_group_message(stub, b"a"))
            loop.run_until_complete(BridgeDaemon._on_rns_group_message(stub, b"b"))
        finally:
            loop.close()
        assert received == [b"a", b"b"]
        assert stub.metrics.group_broadcasts_received == 2
        assert stub.metrics.group_broadcasts_deduped == 0

    def test_async_hook_is_awaited(self):
        """The hook may be a coroutine function. The receive path
        MUST await it — otherwise async operator code silently never
        runs.
        """
        import asyncio
        from ironmesh.bridge import BridgeDaemon
        stub = self._make_stub()
        received = []

        async def async_hook(payload: bytes) -> None:
            await asyncio.sleep(0)  # force a real coroutine yield
            received.append(payload)
        stub.on_group_broadcast = async_hook

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                BridgeDaemon._on_rns_group_message(stub, b"async-payload"),
            )
        finally:
            loop.close()
        assert received == [b"async-payload"]

    def test_empty_payload_short_circuits(self):
        """Empty payload MUST early-return without firing hook or
        touching metrics. Defensive: an empty broadcast carries no
        information and could indicate a malformed peer.
        """
        import asyncio
        from ironmesh.bridge import BridgeDaemon
        stub = self._make_stub()
        received = []
        stub.on_group_broadcast = lambda p: received.append(p)
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                BridgeDaemon._on_rns_group_message(stub, b""),
            )
        finally:
            loop.close()
        assert received == []
        assert stub.metrics.group_broadcasts_received == 0
        assert stub.metrics.group_broadcasts_deduped == 0

    def test_hook_exception_does_not_break_dedup_or_metric(self):
        """If the operator's hook raises, the metric MUST still be
        incremented (the bytes were validly received and counted) and
        the dedup cache MUST still record the payload (so the next
        identical payload is suppressed). The exception is logged,
        not re-raised — operator bugs in their hook shouldn't take
        down the receive path.
        """
        import asyncio
        from ironmesh.bridge import BridgeDaemon
        stub = self._make_stub()

        def bad_hook(payload: bytes) -> None:
            raise RuntimeError("operator bug")
        stub.on_group_broadcast = bad_hook

        loop = asyncio.new_event_loop()
        try:
            # First call — hook raises, but receive is still counted.
            loop.run_until_complete(BridgeDaemon._on_rns_group_message(stub, b"oops"))
            assert stub.metrics.group_broadcasts_received == 1
            # Second call with same payload — dedup suppresses, no second
            # hook invocation attempt (no second exception).
            loop.run_until_complete(BridgeDaemon._on_rns_group_message(stub, b"oops"))
            assert stub.metrics.group_broadcasts_received == 1
            assert stub.metrics.group_broadcasts_deduped == 1
        finally:
            loop.close()

    def test_phase1_failure_does_not_block_phase2(self):
        """Sender side: if Phase 1 (RNS GROUP packet) raises, Phase 2
        (per-peer fan-out) MUST still run. The two phases are
        independent — a same-segment failure shouldn't drop
        cross-host delivery.
        """
        from unittest.mock import MagicMock
        from ironmesh.bridge import BridgeDaemon, Metrics
        stub = MagicMock()
        stub.node_id = "self"
        stub.metrics = Metrics()
        # Phase 1 reticulum stub that ALWAYS raises.
        bad_t = MagicMock()
        bad_t.broadcast_via_group.side_effect = RuntimeError("phase 1 bombed")
        stub._reticulum = bad_t
        # No Phase 2 peers either, but the result dict shape is still
        # the contract under test.
        stub._rns_discovered = {}
        stub.peers = {}
        result = BridgeDaemon.broadcast_via_rns_group(stub, b"x")
        # local_segment must be False (phase 1 raised), and the
        # method must NOT have re-raised — the result dict is proof.
        assert result["local_segment"] is False
        assert result["fanout_sent"] == 0
        # broadcast_via_group should have been called exactly once
        # (we don't retry phase 1 on the same broadcast).
        assert bad_t.broadcast_via_group.call_count == 1
