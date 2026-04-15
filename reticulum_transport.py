"""IronMesh Reticulum transport — LoRa/RNS link adapter and lifecycle manager.

Wraps an RNS Link to duck-type a WebSocket, so it slots into
``BridgeDaemon.ws_clients`` alongside real WebSocket connections.
The handshake and message loop code work unchanged.

This module is only imported when ``--reticulum`` is passed; ``rns`` is an
optional dependency.
"""

import asyncio
import logging
import struct
import threading
import time
from typing import Optional, Tuple

import websockets  # only for ConnectionClosed exception

logger = logging.getLogger("ironmesh.reticulum")

# Lazy-import RNS at module level so the file can be imported for tests
# even when the rns package isn't installed.  The actual classes guard
# usage with runtime checks.
try:
    import RNS
    _HAS_RNS = True
except ImportError:
    RNS = None  # type: ignore[assignment]
    _HAS_RNS = False


# Maximum accepted message length in the RNS deframing loop (audit C-05).
# Matches bridge.py's MAX_MESSAGE_SIZE to prevent memory exhaustion from
# a malformed or malicious 4-byte length prefix.
MAX_RNS_MSG = 1_048_576  # 1 MB


# ---------------------------------------------------------------------------
# RNSLinkAdapter — duck-types ``websockets.WebSocketServerProtocol``
# ---------------------------------------------------------------------------

class RNSLinkAdapter:
    """Wraps an RNS Link so it quacks like a WebSocket.

    Uses ``RNS.Buffer.create_bidirectional_buffer`` over the link's
    Channel for reliable, automatically-fragmented, bidirectional
    data transfer.  Individual IronMesh messages are length-prefixed
    (4-byte big-endian) within the stream.

    Implements the subset of the WebSocket interface used by
    ``BridgeDaemon._handle_connection`` and ``connect_to_peer``:

    * ``await adapter.send(data)``
    * ``await adapter.recv()``
    * ``async for raw in adapter:``
    * ``async with adapter:``
    * ``adapter.remote_address``  (tuple)
    * ``await adapter.close()``
    """

    # Stream IDs for the bidirectional buffer.
    # Server (incoming link) uses STREAM_A_RECV / STREAM_A_SEND.
    # Client (outgoing link) uses the swapped pair.
    _STREAM_ID_A = 0
    _STREAM_ID_B = 1

    def __init__(self, link, loop: asyncio.AbstractEventLoop,
                 dest_hash_hex: str = "unknown", *, is_server: bool = False):
        if not _HAS_RNS:
            raise RuntimeError("rns package is not installed")
        self._link = link
        self._loop = loop
        self._dest_hash_hex = dest_hash_hex
        self._queue: asyncio.Queue = asyncio.Queue()
        self._closed = False
        self._recv_buf = b""
        self._buf_lock = threading.Lock()

        # Set up Channel + bidirectional Buffer.
        channel = link.get_channel()
        if is_server:
            recv_id, send_id = self._STREAM_ID_A, self._STREAM_ID_B
        else:
            recv_id, send_id = self._STREAM_ID_B, self._STREAM_ID_A

        self._buffer = RNS.Buffer.create_bidirectional_buffer(
            recv_id, send_id, channel,
            ready_callback=self._on_data_ready,
        )

        link.set_link_closed_callback(self._on_link_closed)

    # -- RNS callbacks (called from RNS thread) ----------------------------

    def _on_data_ready(self, ready_bytes: int) -> None:
        """Called by RNS when new data arrives on the buffer stream.

        Reads complete length-prefixed messages and enqueues them for
        the asyncio consumer.  Runs on the RNS thread.
        """
        try:
            with self._buf_lock:
                chunk = self._buffer.read(ready_bytes)
                if not chunk:
                    return
                self._recv_buf += chunk

                # Deframe: [4-byte big-endian length][payload]
                while len(self._recv_buf) >= 4:
                    msg_len = struct.unpack(">I", self._recv_buf[:4])[0]
                    # Audit C-05: bound the length field to prevent
                    # memory exhaustion from a malformed prefix.
                    if msg_len == 0 or msg_len > MAX_RNS_MSG:
                        logger.warning(
                            "RNS: rejecting invalid message length %d; clearing buffer",
                            msg_len,
                        )
                        self._recv_buf = b""
                        break
                    if len(self._recv_buf) < 4 + msg_len:
                        break  # incomplete message, wait for more data
                    message = self._recv_buf[4:4 + msg_len]
                    self._recv_buf = self._recv_buf[4 + msg_len:]
                    self._loop.call_soon_threadsafe(
                        self._queue.put_nowait, message)
        except Exception:
            logger.exception("RNS _on_data_ready error")

    def _on_link_closed(self, link) -> None:
        """Enqueue sentinel so ``recv()`` raises ConnectionClosed."""
        self._closed = True
        self._loop.call_soon_threadsafe(self._queue.put_nowait, None)

    # -- WebSocket-compatible interface ------------------------------------

    @property
    def remote_address(self) -> Tuple[str, int]:
        """Return (address_string, port) tuple."""
        return (f"rns:{self._dest_hash_hex}", 0)

    @property
    def open(self) -> bool:
        if self._link is None:
            return False
        return self._link.status == RNS.Link.ACTIVE

    async def send(self, data) -> None:
        """Send a message over the RNS link (length-prefixed)."""
        if self._closed or self._link is None:
            raise websockets.ConnectionClosed(None, None)
        if isinstance(data, str):
            data = data.encode("utf-8")
        if len(data) > MAX_RNS_MSG:
            raise ValueError(
                f"payload size {len(data)} exceeds MAX_RNS_MSG ({MAX_RNS_MSG})"
            )
        frame = struct.pack(">I", len(data)) + data
        # Buffer.write() is synchronous; run in executor to avoid
        # blocking the asyncio loop.
        await self._loop.run_in_executor(
            None, self._buffer.write, frame)
        await self._loop.run_in_executor(None, self._buffer.flush)

    async def recv(self) -> bytes:
        """Await next message from the RNS link."""
        msg = await self._queue.get()
        if msg is None:
            raise websockets.ConnectionClosed(None, None)
        return msg

    async def close(self) -> None:
        """Tear down the RNS link."""
        self._closed = True
        try:
            self._buffer.close()
        except Exception:
            pass
        if self._link:
            try:
                self._link.teardown()
            except Exception:
                pass
            self._link = None

    # -- Async iteration (``async for raw in adapter:``) -------------------

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        try:
            return await self.recv()
        except websockets.ConnectionClosed:
            raise StopAsyncIteration

    # -- Async context manager (``async with adapter:``) -------------------

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        return False


# ---------------------------------------------------------------------------
# ReticulumTransport — lifecycle manager
# ---------------------------------------------------------------------------

_APP_NAME = "ironmesh"
_ASPECT_BRIDGE = "bridge"


class ReticulumTransport:
    """Manages the Reticulum side of IronMesh.

    * Initialises RNS (connects to a running ``rnsd`` or starts a
      standalone transport).
    * Creates an Identity and Destination for this IronMesh node.
    * Accepts incoming RNS links and wraps them as ``RNSLinkAdapter``,
      then schedules the daemon's ``_handle_connection`` on the asyncio loop.
    * Provides ``connect_to_destination`` for outbound RNS links.
    * Runs a periodic announce loop.
    """

    def __init__(self, daemon, announce_interval: float = 300.0,
                 configdir: Optional[str] = None):
        if not _HAS_RNS:
            raise RuntimeError("rns package is not installed — install with: pip install rns")
        self._daemon = daemon
        self._announce_interval = announce_interval
        self._configdir = configdir
        self._reticulum = None
        self._identity = None
        self._destination = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._active_adapters: list = []
        # Audit H-07: protect _active_adapters — mutated from both the
        # RNS thread (link callbacks) and asyncio (connect/shutdown).
        self._adapters_lock = threading.Lock()
        self._announce_task: Optional[asyncio.Task] = None
        self._shutdown = False

    @property
    def destination_hash_hex(self) -> str:
        if self._destination:
            return RNS.prettyhexrep(self._destination.hash)
        return "not-started"

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Initialise RNS, create Identity + Destination, start announcing.

        Must be called from the asyncio thread (inside ``_start``).

        Note: ``RNS.Reticulum()`` is a blocking constructor (connects to
        rnsd or starts a shared instance).  Ideally it would run in an
        executor, but RNS sets up threads internally that expect to exist
        before Destinations are created, so we tolerate the brief block.
        """
        self._loop = loop
        self._reticulum = RNS.Reticulum(configdir=self._configdir)

        # Use a persistent identity so the destination hash is stable
        identity_path = None
        if self._configdir:
            import os
            identity_path = os.path.join(self._configdir, "ironmesh_identity")
        if identity_path and RNS.Identity.from_file(identity_path):
            self._identity = RNS.Identity.from_file(identity_path)
        else:
            self._identity = RNS.Identity()
            if identity_path:
                self._identity.to_file(identity_path)

        self._destination = RNS.Destination(
            self._identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            _APP_NAME,
            _ASPECT_BRIDGE,
        )
        self._destination.set_link_established_callback(self._on_incoming_link)

        # Keep a strong reference so the destination is not garbage-collected.
        # Without this, Python may GC the Destination and RNS will never
        # dispatch incoming links to the callback.
        self._destination_ref = self._destination

        # Initial announce
        agent_name = self._daemon.name if self._daemon else "ironmesh"
        self._destination.announce(app_data=agent_name.encode("utf-8"))

        logger.info(
            "Reticulum transport active — destination %s",
            self.destination_hash_hex,
        )

        # Start periodic announce loop on asyncio
        self._announce_task = loop.create_task(self._announce_loop())

    # -- Incoming links ----------------------------------------------------

    def _on_incoming_link(self, link) -> None:
        """Called by RNS (on the RNS thread) when a peer establishes a link.

        This callback fires from the RNS transport thread, so all asyncio
        work must be bridged via ``call_soon_threadsafe``.  Any unhandled
        exception here would be silently swallowed by RNS, so we wrap the
        entire body in try/except.
        """
        try:
            logger.info("Incoming RNS link from %s",
                        RNS.prettyhexrep(link.get_remote_identity().hash)
                        if link.get_remote_identity() else "unknown")
            link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
            remote = "unknown"
            try:
                ri = link.get_remote_identity()
                if ri:
                    remote = RNS.prettyhexrep(ri.hash)
            except Exception:
                pass
            adapter = RNSLinkAdapter(link, self._loop, dest_hash_hex=remote,
                                     is_server=True)
            with self._adapters_lock:
                self._active_adapters.append(adapter)
            # Brief pause to let the remote side set up its Buffer.
            # The Channel/Buffer API is more resilient than raw Packets,
            # but a small window helps with LoRa's high latency.
            time.sleep(0.5)
            # Schedule the daemon's connection handler on the asyncio loop.
            # Capture adapter in default-arg to avoid late-binding issues.
            self._loop.call_soon_threadsafe(
                lambda a=adapter: asyncio.ensure_future(
                    self._daemon._handle_connection(a)
                ),
            )
        except Exception:
            logger.exception("_on_incoming_link crashed")

    # -- Outbound connections ----------------------------------------------

    async def connect_to_destination(self, dest_hash_hex: str,
                                     timeout: float = 30.0) -> Optional[RNSLinkAdapter]:
        """Resolve path and create an outbound RNS Link to a destination.

        Returns an ``RNSLinkAdapter`` ready for handshake, or ``None`` on
        failure.
        """
        try:
            dest_hash = bytes.fromhex(dest_hash_hex.replace(":", "").replace(" ", ""))
        except ValueError:
            logger.error("Invalid destination hash: %s", dest_hash_hex)
            return None

        # Request path (may take a while on LoRa)
        if not RNS.Transport.has_path(dest_hash):
            RNS.Transport.request_path(dest_hash)
            # Wait for path. Audit L-12: exponential backoff keeps us
            # from busy-polling on long LoRa path resolutions.
            start = time.monotonic()
            attempt = 0
            while not RNS.Transport.has_path(dest_hash):
                if time.monotonic() - start > timeout:
                    logger.warning("Path resolution timed out for %s", dest_hash_hex)
                    return None
                delay = min(0.5 * (2 ** attempt), 10.0)
                await asyncio.sleep(delay)
                attempt += 1

        dest_identity = RNS.Identity.recall(dest_hash)
        if not dest_identity:
            logger.warning("Cannot recall identity for %s", dest_hash_hex)
            return None

        destination = RNS.Destination(
            dest_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            _APP_NAME,
            _ASPECT_BRIDGE,
        )

        link = RNS.Link(destination)

        # Wait for link establishment first — setting packet callbacks
        # before ACTIVE interferes with RNS's internal link handshake.
        start = time.monotonic()
        while link.status != RNS.Link.ACTIVE:
            if link.status == RNS.Link.CLOSED:
                logger.warning("RNS link to %s failed to establish", dest_hash_hex)
                return None
            if time.monotonic() - start > timeout:
                logger.warning("RNS link establishment timed out for %s", dest_hash_hex)
                link.teardown()
                return None
            await asyncio.sleep(0.25)

        # Create the client-side adapter (is_server=False swaps stream IDs).
        adapter = RNSLinkAdapter(link, self._loop, dest_hash_hex=dest_hash_hex,
                                 is_server=False)
        with self._adapters_lock:
            self._active_adapters.append(adapter)
        logger.info("RNS link established to %s", dest_hash_hex)
        return adapter

    # -- Announce loop -----------------------------------------------------

    async def _announce_loop(self) -> None:
        """Periodically announce this destination on the Reticulum network."""
        while not self._shutdown:
            await asyncio.sleep(self._announce_interval)
            if self._shutdown:
                break
            try:
                agent_name = self._daemon.name if self._daemon else "ironmesh"
                self._destination.announce(app_data=agent_name.encode("utf-8"))
                logger.debug("RNS announce sent (agent=%s)", agent_name)
            except Exception as e:
                logger.warning("RNS announce failed: %s", e)

    # -- Shutdown ----------------------------------------------------------

    def shutdown(self) -> None:
        """Tear down all active RNS links and stop announcing."""
        self._shutdown = True
        if self._announce_task:
            self._announce_task.cancel()
        # Snapshot under the lock, then iterate outside to avoid
        # holding the lock while calling teardown (which may take time).
        with self._adapters_lock:
            adapters = list(self._active_adapters)
            self._active_adapters.clear()
        for adapter in adapters:
            try:
                if adapter._link:
                    adapter._link.teardown()
            except Exception:
                pass
        logger.info("Reticulum transport shut down")
