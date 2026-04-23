"""IronMesh Reticulum transport — LoRa/RNS link adapter and lifecycle manager.

Wraps an RNS Link to duck-type a WebSocket, so it slots into
``BridgeDaemon.ws_clients`` alongside real WebSocket connections.
The handshake and message loop code work unchanged.

This module is only imported when ``--reticulum`` is passed; ``rns`` is an
optional dependency.
"""

import asyncio
import json
import logging
import struct
import threading
import time
from typing import Any, Dict, Optional, Tuple

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

# Announces are bandwidth-sensitive on LoRa (3.12 kbps at SF8/BW125),
# so the announce app_data uses single-character keys to keep the
# encoded payload small. The schema is forward-compatible: peers
# ignore unknown keys and tolerate missing ones.
#
#   n: agent name (str)
#   v: ironmesh version (str)
#   i: ironmesh node_id (str — already a short id)
#   c: capability list (list[str])
#   f: feature flags (list[str]; e.g. ["mesh","lxmf","resource"])
#
# Hard cap on the encoded size so a runaway capability list can't
# exceed RNS's announce app_data limit.
APP_DATA_MAX_BYTES = 256


def encode_app_data(name: str, version: str, node_id: str,
                    capabilities: Optional[list] = None,
                    features: Optional[list] = None) -> bytes:
    """Encode IronMesh announce app_data as compact JSON.

    Truncates capabilities and features as needed to fit within
    APP_DATA_MAX_BYTES. Name and version are never truncated; if even
    the bare minimum exceeds the cap, the caller will hit the hard
    error from RNS itself, which is the right outcome — that means
    a misconfigured node, not a runtime corner case to mask.
    """
    payload: Dict[str, Any] = {"n": name, "v": version, "i": node_id}
    caps = list(capabilities) if capabilities else []
    feats = list(features) if features else []
    while True:
        if caps:
            payload["c"] = caps
        if feats:
            payload["f"] = feats
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(encoded) <= APP_DATA_MAX_BYTES:
            return encoded
        # Trim oldest capability/feature first
        if caps:
            caps.pop()
            continue
        if feats:
            feats.pop()
            continue
        # Nothing left to trim — return what we have and let RNS reject
        return encoded


def decode_app_data(raw: bytes) -> Optional[Dict[str, Any]]:
    """Decode IronMesh announce app_data. Returns None on garbage.

    Old IronMesh nodes (pre-v0.9.1) emit raw agent name bytes — not JSON.
    We treat any non-JSON payload as the legacy {n: <bytes>} form so
    discovery still works during the version-skew window.
    """
    if not raw:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        # Legacy plain-name announce
        try:
            return {"n": raw.decode("utf-8", errors="replace")}
        except Exception:
            return None
    if not isinstance(data, dict):
        return None
    return data


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
        # v0.9.1: peer node_id once the IronMesh handshake binds it,
        # so the stats poller knows which PeerState to update.
        self.peer_id: Optional[str] = None

        # Enable physical-layer stats tracking on this link so the
        # periodic poller can read RSSI/SNR/Q from radio interfaces.
        # No-op on non-radio links; safe to always call.
        if hasattr(link, "track_phy_stats"):
            try:
                link.track_phy_stats(True)
            except Exception:
                pass

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

    def sample_link_stats(self) -> Dict[str, Any]:
        """Snapshot of the underlying RNS Link's live stats.

        Called by ``ReticulumTransport``'s stats poller. All fields are
        ``None`` if RNS doesn't expose them (older versions, mocks, or
        non-radio interfaces). Never raises.
        """
        link = self._link
        if link is None:
            return {}
        stats: Dict[str, Any] = {}
        for attr, key in (
            ("get_mtu", "mtu"),
            ("get_mdu", "mdu"),
            ("get_expected_rate", "expected_bps"),
            ("get_rssi", "rssi"),
            ("get_snr", "snr"),
            ("get_q", "q"),
            ("get_establishment_rate", "establishment_bps"),
            ("get_age", "age_s"),
            ("no_data_for", "no_data_for_s"),
            ("inactive_for", "inactive_for_s"),
        ):
            getter = getattr(link, attr, None)
            if getter is None:
                continue
            try:
                value = getter()
            except Exception:
                continue
            if value is not None:
                stats[key] = value
        return stats

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


# ---------------------------------------------------------------------------
# AnnounceHandler — auto-discovery of other IronMesh nodes on the RNS mesh
# ---------------------------------------------------------------------------

class _IronMeshAnnounceHandler:
    """RNS announce handler for the ironmesh/bridge aspect.

    RNS calls ``received_announce`` on its transport thread whenever an
    announce matching ``aspect_filter`` is heard. We decode the IronMesh
    app_data and forward it to the daemon on the asyncio loop.
    """

    # RNS reads this attribute to decide whether to dispatch.
    aspect_filter = f"{_APP_NAME}.{_ASPECT_BRIDGE}"

    def __init__(self, transport: "ReticulumTransport"):
        self._transport = transport

    def received_announce(self, destination_hash, announced_identity, app_data,
                          *args, **kwargs) -> None:
        """Called by RNS when an ironmesh/bridge announce arrives.

        Signature accepts *args/**kwargs because newer RNS versions added
        positional path-response arguments and we want to stay forward-
        compatible without pinning to a single RNS minor version.
        """
        try:
            decoded = decode_app_data(app_data) if app_data else None
            dest_hash_hex = RNS.hexrep(destination_hash, delimit=False)
            identity_hash_hex = (
                RNS.hexrep(announced_identity.hash, delimit=False)
                if announced_identity is not None else None
            )
            # Self-announces: skip
            if (self._transport._destination is not None
                    and destination_hash == self._transport._destination.hash):
                return
            hops = None
            try:
                hops = RNS.Transport.hops_to(destination_hash)
            except Exception:
                pass
            self._transport._on_announce_received(
                dest_hash_hex, identity_hash_hex, decoded or {}, hops,
            )
        except Exception:
            logger.exception("RNS announce handler crashed")


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
                 configdir: Optional[str] = None, *,
                 ratchets_enabled: bool = True,
                 ratchet_interval: float = 1800.0,
                 retained_ratchets: int = 8,
                 stats_poll_interval: float = 5.0):
        if not _HAS_RNS:
            raise RuntimeError("rns package is not installed — install with: pip install rns")
        self._daemon = daemon
        self._announce_interval = announce_interval
        self._configdir = configdir
        self._ratchets_enabled = ratchets_enabled
        self._ratchet_interval = ratchet_interval
        self._retained_ratchets = retained_ratchets
        self._stats_poll_interval = stats_poll_interval
        self._reticulum = None
        self._identity = None
        self._destination = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._active_adapters: list = []
        # Protect _active_adapters — mutated from both the
        # RNS thread (link callbacks) and asyncio (connect/shutdown).
        self._adapters_lock = threading.Lock()
        self._announce_task: Optional[asyncio.Task] = None
        self._stats_task: Optional[asyncio.Task] = None
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

        # Per-packet forward secrecy for Packets sent outside an established
        # Link. Ratchet keys rotate on a timer and are advertised in the next
        # announce; peers pick them up automatically. Older retained ratchets
        # are kept so in-flight Packets encrypted under the prior key still
        # decrypt cleanly after rotation.
        if self._ratchets_enabled:
            try:
                self._destination.enable_ratchets(True)
                if hasattr(self._destination, "set_ratchet_interval"):
                    self._destination.set_ratchet_interval(self._ratchet_interval)
                if hasattr(self._destination, "set_retained_ratchets"):
                    self._destination.set_retained_ratchets(self._retained_ratchets)
                logger.info(
                    "Ratchets enabled on destination (interval=%.0fs, retained=%d)",
                    self._ratchet_interval, self._retained_ratchets,
                )
            except Exception as e:
                logger.warning("Failed to enable ratchets: %s", e)

        # Keep a strong reference so the destination is not garbage-collected.
        # Without this, Python may GC the Destination and RNS will never
        # dispatch incoming links to the callback.
        self._destination_ref = self._destination

        # Register the announce handler so we auto-discover other IronMesh
        # nodes on the RNS mesh — including ones we have no LAN connectivity
        # to. Without this, IronMesh-over-RNS only finds peers the operator
        # types in by hex hash, which defeats the point of being on a mesh.
        try:
            self._announce_handler = _IronMeshAnnounceHandler(self)
            RNS.Transport.register_announce_handler(self._announce_handler)
            logger.info("Registered RNS announce handler for aspect %s",
                        self._announce_handler.aspect_filter)
        except Exception as e:
            logger.warning("Failed to register announce handler: %s", e)
            self._announce_handler = None

        # Initial announce
        self._destination.announce(app_data=self._build_app_data())

        logger.info(
            "Reticulum transport active — destination %s",
            self.destination_hash_hex,
        )

        # Start periodic announce loop on asyncio
        self._announce_task = loop.create_task(self._announce_loop())
        # Start periodic link-stats poller. Pushes per-Link metrics
        # (MTU, expected rate, RSSI/SNR/Q) onto each peer's PeerState
        # so the dashboard and any agent making routing decisions see
        # live signal quality, not just hop count.
        self._stats_task = loop.create_task(self._stats_loop())

    # -- App data construction ---------------------------------------------

    def _build_app_data(self) -> bytes:
        """Build the announce app_data payload from current daemon state.

        Defensive against partially-initialised or mock daemons: any
        non-string field falls back to a sane default so we never feed
        json.dumps an unserialisable object during startup.
        """
        daemon = self._daemon
        def _str(value, default: str) -> str:
            return value if isinstance(value, str) and value else default
        name = _str(getattr(daemon, "name", None), "ironmesh")
        node_id = _str(getattr(daemon, "node_id", None), "")
        try:
            from . import __version__ as ironmesh_version
        except ImportError:
            ironmesh_version = "unknown"
        if not isinstance(ironmesh_version, str):
            ironmesh_version = "unknown"
        capabilities: list = []
        if daemon is not None:
            try:
                cfg_caps = getattr(getattr(daemon, "config", None),
                                   "capabilities", None)
                if cfg_caps and isinstance(cfg_caps, (list, tuple)):
                    capabilities = [c for c in cfg_caps if isinstance(c, str)]
            except Exception:
                pass
        # Static feature set for v0.9.1; later phases extend this list.
        features = ["mesh"]
        if getattr(daemon, "_lxmf_enabled", False):
            features.append("lxmf")
        return encode_app_data(name, ironmesh_version, node_id,
                                capabilities, features)

    # -- Announce-handler bridge to asyncio --------------------------------

    def _on_announce_received(self, dest_hash_hex: str,
                              identity_hash_hex: Optional[str],
                              app_data: Dict[str, Any],
                              hops: Optional[int]) -> None:
        """Schedule daemon notification on the asyncio loop.

        Runs on the RNS transport thread.
        """
        if self._loop is None or self._daemon is None:
            return
        daemon = self._daemon
        cb = getattr(daemon, "_on_rns_peer_announced", None)
        if cb is None:
            return  # daemon doesn't implement the hook yet
        try:
            self._loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(
                    cb(dest_hash_hex, identity_hash_hex, app_data, hops)
                ),
            )
        except RuntimeError:
            # Loop closed during shutdown — drop silently
            pass

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
                app_data = self._build_app_data()
                self._destination.announce(app_data=app_data)
                logger.debug("RNS announce sent (%d bytes app_data)", len(app_data))
            except Exception as e:
                logger.warning("RNS announce failed: %s", e)

    async def _stats_loop(self) -> None:
        """Sample live RNS Link stats for every active adapter, push to daemon.

        Stats are best-effort — if the daemon hasn't bound a peer_id to
        the adapter yet (handshake not complete), the sample is just
        skipped. Fully tolerant of partial RNS API surfaces.
        """
        if self._stats_poll_interval <= 0:
            return
        push = getattr(self._daemon, "_on_rns_link_stats", None)
        if push is None:
            return
        while not self._shutdown:
            await asyncio.sleep(self._stats_poll_interval)
            if self._shutdown:
                break
            with self._adapters_lock:
                snapshot = list(self._active_adapters)
            for adapter in snapshot:
                peer_id = getattr(adapter, "peer_id", None)
                if not peer_id:
                    continue
                try:
                    stats = adapter.sample_link_stats()
                except Exception:
                    continue
                if not stats:
                    continue
                try:
                    push(peer_id, stats)
                except Exception:
                    logger.exception("daemon._on_rns_link_stats raised")

    # -- Shutdown ----------------------------------------------------------

    def shutdown(self) -> None:
        """Tear down all active RNS links and stop announcing."""
        self._shutdown = True
        if self._announce_task:
            self._announce_task.cancel()
        if self._stats_task:
            self._stats_task.cancel()
        if getattr(self, "_announce_handler", None) is not None:
            try:
                RNS.Transport.deregister_announce_handler(self._announce_handler)
            except Exception:
                pass
            self._announce_handler = None
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
