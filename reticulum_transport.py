"""IronMesh Reticulum transport — LoRa/RNS link adapter and lifecycle manager.

Wraps an RNS Link to duck-type a WebSocket, so it slots into
``BridgeDaemon.ws_clients`` alongside real WebSocket connections.
The handshake and message loop code work unchanged.

This module is only imported when ``--reticulum`` is passed; ``rns`` is an
optional dependency.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import struct
import threading
import time
from typing import Any, Dict, Optional, Tuple


def _hkdf_sha256(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 per RFC 5869.

    Minimal implementation (extract + expand) so the group-destination
    derivation doesn't pull in `cryptography` just for one KDF call.
    """
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]

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


# Maximum accepted message length in the RNS deframing loop.
# Matches bridge.py's MAX_MESSAGE_SIZE to prevent memory exhaustion from
# a malformed or malicious 4-byte length prefix.
MAX_RNS_MSG = 1_048_576  # 1 MB

# Frames larger than this are sent via RNS Resource (chunked, compressed,
# resumable) instead of being inlined in the Buffer stream. The Buffer
# path is fine for short MSG/PING/ACK frames but degenerates badly on
# multi-MB payloads — Resource is the right tool for those.
RESOURCE_THRESHOLD_BYTES = 32_768

# Hard cap on a single Resource transfer. Resources are reliable but
# they consume a Link for the duration of the transfer; an attacker
# advertising a 4 GB Resource shouldn't be able to lock out other
# traffic. Operators can raise this for trusted-network deployments.
MAX_RESOURCE_BYTES = 64 * 1024 * 1024  # 64 MB

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
        # Only include the key when the list is non-empty — avoids
        # `"c":[]` overhead on LoRa after trimming (L1 audit fix).
        if caps:
            payload["c"] = caps
        else:
            payload.pop("c", None)
        if feats:
            payload["f"] = feats
        else:
            payload.pop("f", None)
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
        # Nothing left to trim — warn and let RNS reject on the wire (L4 fix)
        logger.warning(
            "announce app_data exceeds %d bytes with base fields only "
            "(name=%r version=%r node_id=%r, encoded=%d bytes); "
            "announce will likely be rejected — shorten node_id or name",
            APP_DATA_MAX_BYTES, name, version, node_id, len(encoded),
        )
        return encoded


def decode_app_data(raw: bytes) -> Optional[Dict[str, Any]]:
    """Decode IronMesh announce app_data. Returns None on garbage.

    Old IronMesh nodes (pre-v0.9.1) emit raw agent name bytes — not JSON.
    The code treat any non-JSON payload as the legacy {n: <bytes>} form so
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
        # v0.9.1: per-peer feature awareness for transport selection.
        # Set by the daemon when it learns the peer's announce feature
        # set (`resource`, `lxmf`, etc.). Defaults to False so the code never
        # surprise an unknown peer with a Resource it can't accept.
        self.peer_supports_resource: bool = False
        self.resources_sent: int = 0

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

        # Accept incoming RNS Resources for large-payload transfer.
        # ACCEPT_ALL is set in ReticulumTransport._on_incoming_link for
        # server-side links; for client-side links the code sets it here too,
        # paired with a callback that pushes the completed Resource's
        # bytes onto the same _queue the Buffer path feeds. Receivers
        # pre-Phase-3 just won't have this callback installed and will
        # silently drop incoming Resources — which is fine, the sender
        # will only route via Resource for peers that advertised the
        # `resource` feature in their announce.
        try:
            link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        except Exception:
            pass
        if hasattr(link, "set_resource_concluded_callback"):
            try:
                link.set_resource_concluded_callback(self._on_resource_concluded)
            except Exception:
                pass

        # Capture the remote's RNS Identity hash as soon as RNS confirms
        # it. Stored separately from any IronMesh-layer identity so
        # consumers can decide their own trust policy. The callback fires
        # on the RNS thread so the callback just stashes the hash — no async work.
        self.remote_identity_hash: Optional[str] = None
        if hasattr(link, "set_remote_identified_callback"):
            try:
                link.set_remote_identified_callback(self._on_remote_identified)
            except Exception:
                pass
        # If the remote already identified before the callback was attached the callback
        # (possible on a fast LAN handshake), populate from the link state.
        try:
            ri = link.get_remote_identity() if hasattr(link, "get_remote_identity") else None
            if ri is not None and getattr(ri, "hash", None):
                self.remote_identity_hash = (
                    RNS.hexrep(ri.hash, delimit=False)
                    if hasattr(RNS, "hexrep") else ri.hash.hex()
                )
        except Exception:
            pass

    def _on_remote_identified(self, link, identity) -> None:
        """RNS callback when the remote side calls ``link.identify()``.

        Runs on the RNS transport thread. The callback just stashes the identity
        hash — any IronMesh-side trust decisions happen later, on the
        asyncio loop, when the daemon's handshake code reads it.
        """
        try:
            if identity is None:
                return
            self.remote_identity_hash = (
                RNS.hexrep(identity.hash, delimit=False)
                if hasattr(RNS, "hexrep") else identity.hash.hex()
            )
        except Exception:
            logger.exception("_on_remote_identified failed")

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
                    # Bound the length field to prevent
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

    def _on_resource_concluded(self, resource) -> None:
        """Called by RNS when an incoming Resource transfer completes.

        Pushes the assembled Resource bytes onto the same async queue
        the Buffer path uses, so the daemon's existing per-message loop
        consumes large-payload frames identically to small ones.

        ResourceStatus is checked because RNS calls this on both
        completion and failure; failures are logged but don't disturb
        the queue (the sender's retry policy handles it).
        """
        try:
            status = getattr(resource, "status", None)
            done = getattr(RNS.Resource, "COMPLETE", "complete")
            if status != done:
                logger.warning(
                    "RNS Resource transfer ended with status=%r (not COMPLETE) — dropped",
                    status,
                )
                return
            data = getattr(resource, "data", None)
            if data is None:
                return
            # Resource.data is a BytesIO-like; read it out
            if hasattr(data, "read"):
                payload = data.read()
            else:
                payload = bytes(data)
            if not payload:
                return
            if len(payload) > MAX_RESOURCE_BYTES:
                logger.warning(
                    "RNS Resource exceeds MAX_RESOURCE_BYTES (%d > %d) — dropped",
                    len(payload), MAX_RESOURCE_BYTES,
                )
                return
            self._loop.call_soon_threadsafe(self._queue.put_nowait, payload)
        except Exception:
            logger.exception("_on_resource_concluded failed")

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
        """Send a message over the RNS link.

        Frames at or below RESOURCE_THRESHOLD_BYTES travel as
        length-prefixed bytes on the established Buffer stream — fast,
        cheap, no per-message setup.

        Frames above the threshold are sent via RNS Resource, which
        handles chunking, sequencing, integrity, optional bz2
        compression, and resume on its own. Resource is the right
        primitive for multi-MB payloads (file outputs, screenshots,
        large LLM responses) — it doesn't lock up the Buffer stream
        and the receiver gets a single completion callback rather
        than reassembling chunks itself.

        Resource is only used when the peer advertised the `resource`
        feature in its announce. Without that signal the code fall back to
        the Buffer path, which will reject anything over MAX_RNS_MSG.
        """
        if self._closed or self._link is None:
            raise websockets.ConnectionClosed(None, None)
        if isinstance(data, str):
            data = data.encode("utf-8")

        if len(data) > RESOURCE_THRESHOLD_BYTES and self.peer_supports_resource:
            await self._send_via_resource(data)
            return

        if len(data) > MAX_RNS_MSG:
            raise ValueError(
                f"payload size {len(data)} exceeds MAX_RNS_MSG ({MAX_RNS_MSG}) "
                f"and peer did not advertise the `resource` feature"
            )
        frame = struct.pack(">I", len(data)) + data
        # Buffer.write() is synchronous; run in executor to avoid
        # blocking the asyncio loop.
        await self._loop.run_in_executor(
            None, self._buffer.write, frame)
        await self._loop.run_in_executor(None, self._buffer.flush)

    async def _send_via_resource(self, data: bytes) -> None:
        """Hand off a large payload to RNS Resource for transfer.

        RNS handles chunking/compression/integrity; the code just await the
        advertise call (synchronous in RNS) on the executor so the
        asyncio loop stays responsive. The receiver picks up the
        completed bytes via ``_on_resource_concluded``.
        """
        if len(data) > MAX_RESOURCE_BYTES:
            raise ValueError(
                f"payload size {len(data)} exceeds MAX_RESOURCE_BYTES ({MAX_RESOURCE_BYTES})"
            )
        try:
            await self._loop.run_in_executor(
                None,
                lambda: RNS.Resource(data, self._link,
                                      auto_compress=True,
                                      advertise=True),
            )
            self.resources_sent += 1
        except Exception as e:
            logger.warning("RNS Resource send failed: %s", e)
            raise

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

# Public RNS request paths exposed by IronMesh nodes. These are
# documented as a stable interop surface — third-party RNS clients
# (Sideband, Nomadnet, custom Python scripts using only the rns
# package) can query them without any IronMesh dependency.
#
#   /im/info     → JSON: {name, version, node_id, capabilities, features}
#                  ALLOW_ALL — public node identity card.
#   /im/cap/list → JSON: {local: [...], remote: {node_id: [...]}}
#                  ALLOW_ALL — full capability registry.
#   /im/cap/find → JSON: [{node_id, capability}, ...]  query: {pattern: str}
#                  ALLOW_ALL — pattern-matched capability lookup.
#
# Operator-gated request paths use ALLOW_LIST so only Identity hashes
# in the trust store can call them. These are added in later phases
# (Phase 8 admin RPC) to expose write/control operations.
RPC_PATH_INFO = "/im/info"
RPC_PATH_CAP_LIST = "/im/cap/list"
RPC_PATH_CAP_FIND = "/im/cap/find"

# Admin RPC paths — gated by an explicit identity-hash allow-list
# managed by the operator (--rns-admin-identities CLI arg or
# IRONMESH_RNS_ADMIN_IDENTITIES env var). Each handler checks the
# caller's RNS identity hash against the allow-list and rejects
# unauthorised requests with a structured error.
#
#   /im/admin/status — daemon health snapshot (uptime, peer counts,
#                      message rates, audit chain head)
#   /im/admin/peers  — full peer table with admin detail
#   /im/admin/audit  — last N audit log entries (?n=100 default)
#
# A future release will cross-reference the IronMesh trust store so
# admin access can be granted by promoting a peer rather than editing
# a separate allow-list. Until then, the explicit list is the contract.
RPC_PATH_ADMIN_STATUS = "/im/admin/status"
RPC_PATH_ADMIN_PEERS = "/im/admin/peers"
RPC_PATH_ADMIN_AUDIT = "/im/admin/audit"


# ---------------------------------------------------------------------------
# AnnounceHandler — auto-discovery of other IronMesh nodes on the RNS mesh
# ---------------------------------------------------------------------------

class _IronMeshAnnounceHandler:
    """RNS announce handler for the ironmesh/bridge aspect.

    RNS calls ``received_announce`` on its transport thread whenever an
    announce matching ``aspect_filter`` is heard. The code decode the IronMesh
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
        positional path-response arguments and the code want to stay forward-
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
                 stats_poll_interval: float = 5.0,
                 admin_identities: Optional[list] = None,
                 group_broadcast: bool = False,
                 group_secret: Optional[bytes] = None):
        if not _HAS_RNS:
            raise RuntimeError("rns package is not installed — install with: pip install rns")
        self._daemon = daemon
        self._announce_interval = announce_interval
        self._configdir = configdir
        self._ratchets_enabled = ratchets_enabled
        self._ratchet_interval = ratchet_interval
        self._retained_ratchets = retained_ratchets
        self._stats_poll_interval = stats_poll_interval
        # Normalise admin identities to lowercase hex with no separators.
        # Empty list means admin RPC is disabled — paths still register
        # but every call returns "unauthorized".
        self._admin_identities: set = set()
        for h in (admin_identities or []):
            if isinstance(h, str) and h.strip():
                norm = h.strip().lower().replace(":", "").replace(" ", "")
                self._admin_identities.add(norm)
        # v0.9.2 chunk B: group broadcast destination. When enabled, the
        # transport creates a second Destination of type GROUP keyed off
        # a shared secret (typically the daemon passphrase) so every peer
        # in the mesh derives the exact same destination hash + symmetric
        # key. A single packet sent to this destination fans out to every
        # listener — O(1) instead of O(N) for mesh-wide notifications.
        self._group_broadcast_enabled = bool(group_broadcast)
        self._group_secret = group_secret
        self._group_identity = None
        self._group_destination = None
        self._group_dest_hash_hex: Optional[str] = None
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

    def _maybe_seed_rns_config(self) -> None:
        """Write a per-daemon RNS config with unique RPC ports.

        OPT-IN via the ``IRONMESH_SEED_RNS_CONFIG`` env var. The seeder
        addresses a niche scenario: two ironmesh daemons coexisting on
        one host WITHOUT rnsd, where each tries to be its own RNS
        shared-instance server and they collide on the default RPC port
        with different authkeys.

        It is OFF by default because turning it on prevents the daemon
        from joining an existing rnsd shared-instance — the seeded
        unique RPC ports stop the daemon from finding rnsd's RPC
        socket, so the daemon starts its own RNS instance and conflicts
        with rnsd's already-bound AutoInterface multicast.

        Only enable when:
          1. You're running multiple ironmesh daemons on one host, AND
          2. There's no rnsd on that host, AND
          3. You want each daemon's RNS to be isolated.

        For the standard single-daemon-per-host or
        multiple-daemons-via-rnsd cases, leave this off.

        If the configdir already has a config file, never overwrite —
        operator-tuned configs always win.
        """
        if not self._configdir:
            return
        # Opt-in gate. Anything truthy enables; default is off.
        flag = os.environ.get("IRONMESH_SEED_RNS_CONFIG", "").lower()
        if flag not in ("1", "true", "yes", "on"):
            return
        configdir = os.path.expanduser(self._configdir)
        cfg_path = os.path.join(configdir, "config")
        try:
            if os.path.exists(cfg_path):
                return  # respect existing operator config
            os.makedirs(configdir, exist_ok=True)
        except Exception as e:
            logger.debug("Could not ensure RNS configdir %s: %s", configdir, e)
            return

        # Derive per-daemon unique RPC ports from node_id hash. These
        # are LOCAL-ONLY (bound to 127.0.0.1) so different RPC ports
        # per daemon eliminate the same-host authkey collision without
        # touching cross-host mesh behavior.
        #
        #   [0:2]  shared_instance_port  (16000-16999)
        #   [2:4]  instance_control_port (17000-17999)
        #
        # CRITICAL: do NOT override AutoInterface group_id, discovery_port,
        # or data_port. Those govern the LAN multicast that lets ironmesh
        # daemons across different hosts find each other. Setting them
        # per-daemon FRAGMENTS the global mesh — two hosts with
        # different group_ids cannot see each other's announces. Leaving
        # AutoInterface to its defaults (group_id="reticulum",
        # discovery_port=29716) preserves cross-host mesh; same-host
        # multi-daemon AutoInterface conflict is a separate problem
        # operators should solve with rnsd (the standard pattern).
        tag = None
        if self._daemon is not None:
            tag = getattr(self._daemon, "node_id", None)
        if not tag:
            tag = f"pid{os.getpid()}"
        import hashlib as _hashlib
        h = _hashlib.sha256(str(tag).encode("utf-8")).digest()
        shared_port  = 16000 + (int.from_bytes(h[:2],  "big") % 1000)
        control_port = 17000 + (int.from_bytes(h[2:4], "big") % 1000)

        cfg_contents = (
            "# Auto-generated by IronMesh ReticulumTransport to avoid\n"
            "# cross-process RPC port collisions on the same host. Only\n"
            "# the local-only RPC ports are overridden; AutoInterface\n"
            "# settings are inherited from RNS defaults so the global\n"
            "# cross-host mesh keeps working. Delete this file to use\n"
            "# RNS's defaults entirely.\n"
            "[reticulum]\n"
            "enable_transport = Yes\n"
            "share_instance = Yes\n"
            f"shared_instance_port = {shared_port}\n"
            f"instance_control_port = {control_port}\n\n"
            "[logging]\n"
            "loglevel = 4\n\n"
            "[interfaces]\n\n"
            "  [[Default Interface]]\n"
            "    type = AutoInterface\n"
            "    enabled = yes\n"
        )
        try:
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(cfg_contents)
            logger.info(
                "Seeded RNS config %s (shared_port=%d control_port=%d) "
                "to avoid cross-process RPC collisions",
                cfg_path, shared_port, control_port,
            )
        except Exception as e:
            logger.debug("Could not seed RNS config %s: %s", cfg_path, e)

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Initialise RNS, create Identity + Destination, start announcing.

        Must be called from the asyncio thread (inside ``_start``).

        Note: ``RNS.Reticulum()`` is a blocking constructor (connects to
        rnsd or starts a shared instance).  Ideally it would run in an
        executor, but RNS sets up threads internally that expect to exist
        before Destinations are created, so the code tolerate the brief block.
        """
        self._loop = loop
        # RNS enforces a one-Reticulum-per-process singleton. If another
        # IronMesh daemon (or anything else) in this process already
        # initialised it, reuse the existing instance instead of trying
        # to start a second one (which raises). Discovered during testing — when
        # multiple Agent SDK instances ran in the same Python process.
        # v0.9.2 bug fix: ALWAYS ensure the configdir exists before
        # RNS init, even on the singleton-reuse path. RNS's per-
        # destination ratchet writer expects the parent directory of the
        # ratchet file (which lives inside configdir) to be present —
        # and on the singleton-reuse path the first daemon may have
        # used a different configdir. Live-test discovered when the
        # second in-process daemon's destination tried to persist
        # ratchets and crashed with FileNotFoundError.
        if self._configdir:
            try:
                os.makedirs(os.path.expanduser(self._configdir), exist_ok=True)
            except Exception as e:
                logger.debug("Could not pre-create configdir %s: %s",
                             self._configdir, e)

        existing = getattr(RNS.Reticulum, "_Reticulum__instance", None)
        if existing is not None:
            logger.info("Reusing existing RNS.Reticulum singleton in this process")
            self._reticulum = existing
        else:
            # v0.9.2: when two ironmesh daemons run in separate processes
            # on the same host, RNS's shared-instance RPC collides on
            # default port 37428 (Windows/AF_INET) or the default AF_UNIX
            # socket path. Each RNS process derives an rpc_key from its
            # OWN Transport identity, so the second one's client gets
            # "AuthenticationError: digest sent was rejected" when the
            # first is already the server under a different authkey.
            #
            # Fix: if the configdir is provided AND doesn't already
            # contain a config file, seed it with per-daemon unique
            # shared_instance_port + instance_control_port derived from
            # the daemon node_id hash. This guarantees each daemon gets
            # its own isolated RPC endpoint and never collides. Daemons
            # that point at the SAME configdir still share (rnsd-style).
            self._maybe_seed_rns_config()
            self._reticulum = RNS.Reticulum(configdir=self._configdir)

        # Per-daemon persistent RNS identity. The previous single-file
        # location at <configdir>/ironmesh_identity collided when two
        # IronMesh daemons shared a Reticulum configdir on the same host
        # (parallel-deploy test scenario, multi-tenant hosts) — both
        # would load the same identity and ratchet store, producing
        # indistinguishable destinations and a write-race on the ratchet
        # file. Live-test-discovered bug.
        #
        # Fix: derive the identity filename from the IronMesh daemon's
        # node_id when available, so two daemons get two distinct files.
        # Falls back to the legacy filename only when no daemon node_id
        # is reachable (defensive — shouldn't happen in practice).
        identity_path = None
        ratchets_path = None
        if self._configdir:
            tag = None
            if self._daemon is not None:
                tag = getattr(self._daemon, "node_id", None)
            if tag:
                # First 16 hex chars are plenty unique for a filename
                short = str(tag)[:16]
                identity_path = os.path.join(
                    self._configdir, f"ironmesh_{short}_identity",
                )
                ratchets_path = os.path.join(
                    self._configdir, f"ironmesh_{short}_ratchets",
                )
            else:
                identity_path = os.path.join(self._configdir, "ironmesh_identity")
                ratchets_path = os.path.join(self._configdir, "ironmesh_ratchets")
        if identity_path and RNS.Identity.from_file(identity_path):
            self._identity = RNS.Identity.from_file(identity_path)
        else:
            self._identity = RNS.Identity()
            if identity_path:
                self._identity.to_file(identity_path)
        # Stash the resolved ratchets path so the enable_ratchets call
        # below uses the per-daemon location too.
        self._ratchets_path_resolved = ratchets_path

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
        #
        # RNS's enable_ratchets() takes a *path* to a file where rotating
        # keys are persisted, NOT a boolean. Passing True silently fails
        # (open(True, "rb") opens fd 1 / stdout) and the destination ends
        # up unprotected. Live-test-discovered bug — was wrong since the
        # initial Phase 0 commit.
        if self._ratchets_enabled:
            # Use the per-daemon ratchets path resolved during identity
            # setup so two daemons sharing a configdir don't race on
            # the same ratchet file. If the code somehow reached here without
            # a resolved path (no configdir AND identity-setup failed
            # to derive a tag), fall back to a temp path that still
            # includes the daemon node_id — sharing a single
            # `<tmp>/ironmesh_ratchets` between multiple daemons in the
            # same process produces "Invalid ratchet file signature"
            # corruption on every cycle (live-test discovered).
            ratchets_path = getattr(self, "_ratchets_path_resolved", None)
            if not ratchets_path:
                import tempfile
                tag = None
                if self._daemon is not None:
                    tag = getattr(self._daemon, "node_id", None)
                short = str(tag)[:16] if tag else f"pid{os.getpid()}"
                ratchets_path = os.path.join(
                    tempfile.gettempdir(), f"ironmesh_{short}_ratchets",
                )
            try:
                ok = self._destination.enable_ratchets(ratchets_path)
                if ok is False:
                    logger.warning(
                        "Ratchets enable returned False (path=%s) — "
                        "destination running without per-packet forward secrecy",
                        ratchets_path,
                    )
                else:
                    if hasattr(self._destination, "set_ratchet_interval"):
                        self._destination.set_ratchet_interval(self._ratchet_interval)
                    if hasattr(self._destination, "set_retained_ratchets"):
                        self._destination.set_retained_ratchets(self._retained_ratchets)
                    logger.info(
                        "Ratchets enabled on destination "
                        "(path=%s interval=%.0fs retained=%d)",
                        ratchets_path, self._ratchet_interval,
                        self._retained_ratchets,
                    )
            except Exception as e:
                logger.warning("Failed to enable ratchets: %s", e)

        # Keep a strong reference so the destination is not garbage-collected.
        # Without this, Python may GC the Destination and RNS will never
        # dispatch incoming links to the callback.
        self._destination_ref = self._destination

        # Register the announce handler so the code auto-discover other IronMesh
        # nodes on the RNS mesh — including ones the code have no LAN connectivity
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

        # Public RPC request handlers — let any RNS client query the
        # node's identity, capability registry, and capability search
        # without speaking the IronMesh wire protocol. Reticulum's
        # request_handler API does the encryption + identity gating;
        # the code just provide the response generators.
        self._register_public_request_handlers()

        # v0.9.2 chunk B: optional shared-secret GROUP destination for
        # O(1) mesh-wide broadcast. Derived deterministically from the
        # daemon passphrase so every peer that enables group broadcast
        # lands on the same destination hash and symmetric key.
        if self._group_broadcast_enabled and self._group_secret:
            try:
                self._start_group_destination()
            except Exception as e:
                logger.warning("Group destination setup failed: %s", e)
                self._group_destination = None
                self._group_identity = None

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

    # -- Public request handlers (capability RPC) --------------------------

    def _register_public_request_handlers(self) -> None:
        """Register the open RPC paths on this node's destination.

        Best-effort: if RNS is too old to expose register_request_handler
        in the form the code expects, the code log and move on rather than failing
        startup. Without these handlers, third-party RNS clients can
        still discover IronMesh nodes via announce; they just can't
        query the capability registry over RNS.
        """
        if self._destination is None:
            return
        if not hasattr(self._destination, "register_request_handler"):
            logger.debug("Destination has no register_request_handler — skipping RPC paths")
            return
        # ALLOW_ALL is a class-level constant on RNS.Destination — read
        # from the class rather than the instance for intent clarity
        # (L3 audit fix). Falls back to None on older RNS versions;
        # register_request_handler tolerates None as "ALLOW_ALL" per
        # its documented default.
        allow_all = getattr(RNS.Destination, "ALLOW_ALL", None)
        try:
            self._destination.register_request_handler(
                RPC_PATH_INFO,
                response_generator=self._rpc_info,
                allow=allow_all,
            )
            self._destination.register_request_handler(
                RPC_PATH_CAP_LIST,
                response_generator=self._rpc_cap_list,
                allow=allow_all,
            )
            self._destination.register_request_handler(
                RPC_PATH_CAP_FIND,
                response_generator=self._rpc_cap_find,
                allow=allow_all,
            )
            # Admin paths are registered with ALLOW_ALL so RNS dispatches
            # the call; the handler then enforces the per-identity check.
            # This allows the allow-list to swap at runtime without
            # re-registering — useful when promoting/demoting admins.
            self._destination.register_request_handler(
                RPC_PATH_ADMIN_STATUS,
                response_generator=self._rpc_admin_status,
                allow=allow_all,
            )
            self._destination.register_request_handler(
                RPC_PATH_ADMIN_PEERS,
                response_generator=self._rpc_admin_peers,
                allow=allow_all,
            )
            self._destination.register_request_handler(
                RPC_PATH_ADMIN_AUDIT,
                response_generator=self._rpc_admin_audit,
                allow=allow_all,
            )
            logger.info(
                "Registered RPC paths: 3 public + 3 admin (admin allow-list: %d entries)",
                len(self._admin_identities),
            )
        except Exception as e:
            logger.warning("Failed to register public RPC handlers: %s", e)

    def _rpc_info(self, path, data, request_id, link_id, remote_identity, requested_at):
        """Respond to /im/info — node identity card.

        All response generators have the RNS-prescribed signature even
        though most arguments are unused; that signature is what RNS
        passes to a request handler.

        Decodes the same announce app_data payload the daemon emits, so
        /im/info reflects the actual advertised feature set (including
        v0.9.2 `hskip`, optional `lxmf`, etc.) rather than a stale
        hardcoded list. Live-test discovered v0.9.2.
        """
        try:
            daemon = self._daemon
            try:
                from . import __version__ as ironmesh_version
            except ImportError:
                ironmesh_version = "unknown"
            # Build the same app_data the announce emits, then decode
            # it to extract the dynamic feature + capability lists.
            try:
                announce = decode_app_data(self._build_app_data()) or {}
            except Exception:
                announce = {}
            payload = {
                "name": getattr(daemon, "name", "ironmesh") if daemon else "ironmesh",
                "version": ironmesh_version,
                "node_id": getattr(daemon, "node_id", "") if daemon else "",
                "capabilities": list(announce.get("c") or []),
                "features": list(announce.get("f") or []),
            }
            return json.dumps(payload, separators=(",", ":")).encode("utf-8")
        except Exception:
            logger.exception("/im/info handler failed")
            return b"{}"

    def _rpc_cap_list(self, path, data, request_id, link_id, remote_identity, requested_at):
        """Respond to /im/cap/list — full capability registry."""
        try:
            registry = getattr(self._daemon, "_capabilities", None)
            if registry is None:
                return json.dumps({"local": [], "remote": {}}).encode("utf-8")
            local = registry.local_capabilities()
            remote: Dict[str, list] = {}
            # _remote is the source of truth for known remote caps;
            # access via attribute since there's no public iterator.
            try:
                for node_id, caps in getattr(registry, "_remote", {}).items():
                    remote[node_id] = sorted(caps)
            except Exception:
                pass
            payload = {"local": local, "remote": remote}
            return json.dumps(payload, separators=(",", ":")).encode("utf-8")
        except Exception:
            logger.exception("/im/cap/list handler failed")
            return b"{}"

    # -- Admin RPC handlers (identity-gated) -------------------------------

    def _check_admin(self, remote_identity) -> bool:
        """Verify the calling identity is in the admin allow-list."""
        if not self._admin_identities:
            return False
        if remote_identity is None:
            return False
        try:
            h = getattr(remote_identity, "hash", None)
            if h is None:
                return False
            hex_hash = (
                RNS.hexrep(h, delimit=False).lower()
                if hasattr(RNS, "hexrep") else h.hex().lower()
            )
            return hex_hash in self._admin_identities
        except Exception:
            return False

    @staticmethod
    def _unauthorized_response() -> bytes:
        return json.dumps(
            {"error": "unauthorized",
             "detail": "RNS identity not in admin allow-list"},
            separators=(",", ":"),
        ).encode("utf-8")

    def _rpc_admin_status(self, path, data, request_id, link_id, remote_identity, requested_at):
        """Respond to /im/admin/status — daemon health snapshot."""
        try:
            if not self._check_admin(remote_identity):
                return self._unauthorized_response()
            daemon = self._daemon
            now = time.time()
            started = getattr(daemon, "_started_at", now) if daemon else now
            metrics = getattr(daemon, "metrics", None) if daemon else None
            payload = {
                "name": getattr(daemon, "name", "ironmesh") if daemon else "ironmesh",
                "node_id": getattr(daemon, "node_id", "") if daemon else "",
                "uptime_s": now - started,
                "peer_count": len(getattr(daemon, "peers", {})) if daemon else 0,
                "rns_discovered_count": len(
                    getattr(daemon, "_rns_discovered", {})) if daemon else 0,
                "messages_sent": getattr(metrics, "messages_sent", 0) if metrics else 0,
                "messages_received": getattr(metrics, "messages_received", 0) if metrics else 0,
                "bytes_sent": getattr(metrics, "bytes_sent", 0) if metrics else 0,
                "bytes_received": getattr(metrics, "bytes_received", 0) if metrics else 0,
                "handshake_successes": getattr(metrics, "handshake_successes", 0) if metrics else 0,
            }
            return json.dumps(payload, separators=(",", ":")).encode("utf-8")
        except Exception:
            logger.exception("/im/admin/status handler failed")
            return b'{"error":"internal"}'

    def _rpc_admin_peers(self, path, data, request_id, link_id, remote_identity, requested_at):
        """Respond to /im/admin/peers — full peer table for admin use."""
        try:
            if not self._check_admin(remote_identity):
                return self._unauthorized_response()
            daemon = self._daemon
            peers = getattr(daemon, "peers", {}) if daemon else {}
            out = []
            for peer_id, state in peers.items():
                try:
                    out.append(state.to_dict())
                except Exception:
                    out.append({"node_id": peer_id, "error": "to_dict_failed"})
            return json.dumps(out, separators=(",", ":")).encode("utf-8")
        except Exception:
            logger.exception("/im/admin/peers handler failed")
            return b'{"error":"internal"}'

    def _rpc_admin_audit(self, path, data, request_id, link_id, remote_identity, requested_at):
        """Respond to /im/admin/audit — last N audit log entries.

        Query body: {"n": 100} (default 100, capped at 1000).
        """
        try:
            if not self._check_admin(remote_identity):
                return self._unauthorized_response()
            n = 100
            if data:
                try:
                    query = json.loads(data.decode("utf-8") if isinstance(data, bytes) else data)
                    if isinstance(query, dict):
                        n = int(query.get("n", 100))
                except Exception:
                    n = 100
            n = max(1, min(n, 1000))
            audit = getattr(self._daemon, "_audit", None) if self._daemon else None
            if audit is None:
                return json.dumps({"entries": []}).encode("utf-8")
            entries = []
            try:
                # Audit objects across IronMesh versions expose either a
                # tail() method or a read_all()/iter() pattern. Try the
                # common shapes; fall back to empty.
                if hasattr(audit, "tail"):
                    entries = list(audit.tail(n))
                elif hasattr(audit, "recent"):
                    entries = list(audit.recent(n))
            except Exception:
                logger.exception("audit log read failed")
            return json.dumps({"count": len(entries), "entries": entries},
                              separators=(",", ":")).encode("utf-8")
        except Exception:
            logger.exception("/im/admin/audit handler failed")
            return b'{"error":"internal"}'

    def _rpc_cap_find(self, path, data, request_id, link_id, remote_identity, requested_at):
        """Respond to /im/cap/find — pattern lookup. Query: {pattern: str}."""
        try:
            registry = getattr(self._daemon, "_capabilities", None)
            if registry is None:
                return json.dumps([]).encode("utf-8")
            pattern = ""
            if data:
                try:
                    if isinstance(data, bytes):
                        query = json.loads(data.decode("utf-8"))
                    else:
                        query = data
                    if isinstance(query, dict):
                        pattern = str(query.get("pattern", ""))
                    elif isinstance(query, str):
                        pattern = query
                except Exception:
                    pattern = ""
            if not pattern:
                return json.dumps([]).encode("utf-8")
            matches = registry.find(pattern)
            payload = [{"node_id": nid, "capability": cap} for nid, cap in matches]
            return json.dumps(payload, separators=(",", ":")).encode("utf-8")
        except Exception:
            logger.exception("/im/cap/find handler failed")
            return b"[]"

    # -- App data construction ---------------------------------------------

    def _build_app_data(self) -> bytes:
        """Build the announce app_data payload from current daemon state.

        Defensive against partially-initialised or mock daemons: any
        non-string field falls back to a sane default so the code never feed
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
        # Feature set advertised in the announce. Peers use this to gate
        # which optional protocol paths to enable for each other.
        # `mesh`     = IronMesh distance-vector routing.
        # `resource` = peer accepts large payloads via RNS Resource.
        # `lxmf`     = peer hosts an LXMF gateway listener.
        # `hskip`    = peer agrees to skip the IronMesh stage-1 handshake
        #              (passphrase challenge / verify) on identified RNS
        #              Links. Both sides must advertise this before any
        #              skip happens; the handshake is otherwise unchanged.
        features = ["mesh", "resource"]
        if getattr(daemon, "_lxmf_enabled", False):
            features.append("lxmf")
        if getattr(daemon, "_rns_skip_handshake", False):
            features.append("hskip")
        # `group` advertises that this node listens on the shared
        # GROUP broadcast destination. Peers gate broadcast sends on
        # the feature to avoid shouting at nodes that haven't opted in.
        if (getattr(self, "_group_broadcast_enabled", False)
                and getattr(self, "_group_destination", None) is not None):
            features.append("group")
        return encode_app_data(name, ironmesh_version, node_id,
                                capabilities, features)

    # -- Group broadcast (v0.9.2 chunk B) ----------------------------------

    @property
    def group_destination_hash_hex(self) -> Optional[str]:
        return self._group_dest_hash_hex

    def _start_group_destination(self) -> None:
        """Create the shared-secret GROUP destination.

        Both the group Identity and the symmetric key are derived from
        the shared secret via HKDF-SHA256 with distinct `info` labels,
        so every peer on the mesh lands on the exact same destination
        hash and can decrypt traffic sent to it.

        RNS.Identity holds 32 bytes of X25519 + 32 bytes of Ed25519
        material; the code derive 64 bytes and feed it via ``from_bytes``
        so the hash is reproducible across hosts and restarts.

        The GROUP destination's symmetric key is raw 32 bytes (256-bit
        AES in RNS's Token); NOT base64-encoded despite what the
        Reticulum docs in some places imply.
        """
        secret = self._group_secret
        if not secret:
            return
        if not isinstance(secret, (bytes, bytearray)):
            secret = str(secret).encode("utf-8")

        # Domain-separated derivations so rotating one material doesn't
        # leak into the other.
        identity_material = _hkdf_sha256(
            bytes(secret),
            salt=b"ironmesh-group-identity-v1",
            info=b"identity",
            length=64,
        )
        group_key = _hkdf_sha256(
            bytes(secret),
            salt=b"ironmesh-group-key-v1",
            info=b"broadcast",
            length=32,
        )

        # Try RNS.Identity.from_bytes — present on modern RNS. If it
        # returns None or raises, the code can't build a deterministic group
        # destination and will skip broadcast.
        try:
            group_identity = RNS.Identity.from_bytes(identity_material)
        except Exception as e:
            logger.warning(
                "RNS.Identity.from_bytes unavailable/failed: %s — "
                "group broadcast disabled on this node", e,
            )
            return
        if group_identity is None:
            logger.warning("RNS.Identity.from_bytes returned None — group broadcast disabled")
            return

        self._group_identity = group_identity

        # v0.9.2 bug fix: when multiple ironmesh daemons run in the
        # same Python process and share the RNS singleton, only the
        # FIRST one can register a given GROUP destination — RNS rejects
        # the second with "Attempt to register an already registered
        # destination". Detect that case and adopt the existing
        # registration so this daemon can also send + receive on the
        # shared GROUP. Live-test discovered.
        dest = None
        existing_dest = None
        # Compute the destination hash deterministically (from identity
        # + app + aspect) so we can match an already-registered one.
        try:
            expected_hash = RNS.Destination.hash_from_name_and_identity(
                f"{_APP_NAME}.broadcast", group_identity,
            )
        except Exception:
            expected_hash = None
        if expected_hash is not None:
            try:
                # RNS.Transport.destinations is the singleton's master
                # list. Match by raw hash — deterministic across daemons
                # that share the singleton + the group identity.
                for d in getattr(RNS.Transport, "destinations", []):
                    try:
                        if (getattr(d, "type", None) == RNS.Destination.GROUP
                                and getattr(d, "hash", None) == expected_hash):
                            existing_dest = d
                            break
                    except Exception:
                        continue
            except Exception:
                existing_dest = None

        if existing_dest is not None:
            logger.info(
                "Reusing existing in-process GROUP destination "
                "(another ironmesh daemon registered it first)"
            )
            dest = existing_dest
        else:
            try:
                dest = RNS.Destination(
                    group_identity,
                    RNS.Destination.IN,
                    RNS.Destination.GROUP,
                    _APP_NAME,
                    "broadcast",
                )
            except Exception as e:
                logger.warning("Failed to create GROUP destination: %s", e)
                return

        # When we adopted an existing in-process destination, the FIRST
        # daemon already loaded the key + registered a callback. Don't
        # touch those again — only the first daemon receives in-process
        # broadcasts. (Multi-Agent-one-process in-process broadcast
        # receive across daemons is a known limitation; the production
        # case is one daemon per process.)
        if existing_dest is None:
            # Load the symmetric group key. RNS Token expects raw 256-bit
            # material; passing anything else raises.
            try:
                dest.load_private_key(group_key)
            except Exception as e:
                logger.warning("load_private_key on GROUP destination failed: %s", e)
                return

            # Register a packet callback so incoming group packets land on
            # the asyncio loop via the daemon hook.
            try:
                dest.set_packet_callback(self._on_group_packet)
            except Exception:
                logger.debug("GROUP destination has no set_packet_callback — receive disabled")

        self._group_destination = dest
        try:
            self._group_dest_hash_hex = RNS.hexrep(dest.hash, delimit=False)
        except Exception:
            self._group_dest_hash_hex = None
        logger.info(
            "GROUP broadcast destination active — hash %s",
            self._group_dest_hash_hex,
        )

    def _on_group_packet(self, data: bytes, packet) -> None:
        """RNS callback fired for an inbound GROUP broadcast packet.

        Runs on the RNS transport thread; bridge to asyncio via the
        daemon's ``_on_rns_group_message`` hook if it exists. Self-sent
        broadcasts can echo back on some RNS versions; the daemon hook
        is expected to dedup on payload hash + sender.
        """
        try:
            if self._loop is None or self._daemon is None:
                return
            cb = getattr(self._daemon, "_on_rns_group_message", None)
            if cb is None:
                return
            payload = bytes(data) if data is not None else b""
            self._loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(cb(payload)),
            )
        except Exception:
            logger.exception("_on_group_packet failed")

    def broadcast_via_group(self, payload: bytes) -> bool:
        """Send a single packet to every peer on the group destination.

        Returns True on a successful send, False if the group destination
        is not active (feature disabled or derivation failed).

        **EXPERIMENTAL — known limitation.** GROUP destinations cannot
        be ``announce()``d in RNS (it raises "Only SINGLE destination
        types can be announced"). Without an announce, the receiving
        host's RNS Transport may not have a route to forward the packet
        to remote registered listeners. This means cross-host group
        broadcast works reliably only when:

          * all participants share the same RNS shared-instance (rnsd
            on a single host with multiple ironmesh daemons), OR
          * RNS Transport on each host has a learned route to the
            group identity via prior unicast traffic.

        For pure cross-LAN broadcast without rnsd, the packet may not
        reach all listeners. If the operator needs guaranteed
        cross-host fan-out, use ``Agent.send_to_capability("*", ...)``
        with a per-peer fan-out instead.

        The OUT destination is created lazily on first call and cached
        — RNS doesn't deduplicate per-call destination creation, and
        cached construction is much cheaper for high-frequency senders.
        """
        if self._group_destination is None:
            return False
        if not isinstance(payload, (bytes, bytearray)):
            payload = str(payload).encode("utf-8")
        try:
            # Cache the OUT destination across calls — fresh construction
            # each call is wasteful and can confuse RNS routing caches.
            out_dest = getattr(self, "_group_out_destination", None)
            if out_dest is None:
                out_dest = RNS.Destination(
                    self._group_identity,
                    RNS.Destination.OUT,
                    RNS.Destination.GROUP,
                    _APP_NAME,
                    "broadcast",
                )
                try:
                    out_dest.load_private_key(
                        _hkdf_sha256(
                            bytes(self._group_secret) if isinstance(self._group_secret, (bytes, bytearray))
                            else str(self._group_secret).encode("utf-8"),
                            salt=b"ironmesh-group-key-v1",
                            info=b"broadcast",
                            length=32,
                        )
                    )
                except Exception as e:
                    # Silent failure here would leave the OUT destination
                    # without its symmetric key — packets would still be
                    # constructed but receivers couldn't decrypt them.
                    # Log at DEBUG so the failure is at least observable
                    # without spamming healthy meshes.
                    logger.debug(
                        "Failed to load group destination private key: %s "
                        "(broadcast packets may not be decryptable)", e,
                    )
                self._group_out_destination = out_dest
            packet = RNS.Packet(out_dest, bytes(payload))
            packet.send()
            return True
        except Exception:
            logger.exception("broadcast_via_group failed")
            return False

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
        exception here would be silently swallowed by RNS, so the code wrap the
        entire body in try/except.

        About the 500 ms sleep: the inbound-handshake race below is real.
        On the server side, RNS fires this callback the instant the Link
        becomes ACTIVE — but on the client side, the symmetric ACTIVE
        notification fires concurrently, and the client still has to
        construct its own RNSLinkAdapter (which wires up its Buffer
        receive callback) before it can read anything the daemon sends.
        If `_handle_connection` is scheduled immediately and starts
        writing PASSPHRASE_CHALLENGE, that data lands on the client's Channel
        before the client's Buffer reader is attached, and the
        handshake hangs waiting for a response that's permanently lost.
        Discovered during live testing: dropping this sleep (a previous "audit
        fix") broke every inbound handshake on the RNS path. The right
        long-term fix is a Channel-level synchronisation primitive
        (handshake on Channel.is_ready_to_send) — until then, this
        modest delay is the working compromise.
        """
        try:
            # Read the remote identity once to avoid a TOCTOU window
            # where the identity could race between the log line and
            # the adapter setup (M4 audit fix).
            ri = None
            try:
                ri = link.get_remote_identity()
            except Exception:
                pass
            remote = RNS.prettyhexrep(ri.hash) if ri is not None else "unknown"
            logger.info("Incoming RNS link from %s", remote)
            adapter = RNSLinkAdapter(link, self._loop, dest_hash_hex=remote,
                                     is_server=True)
            with self._adapters_lock:
                self._active_adapters.append(adapter)
            # Brief pause to let the client side finish constructing
            # its RNSLinkAdapter (and thereby register the Buffer
            # receive callback) before the server starts writing handshake bytes.
            # See the docstring above for the full rationale.
            time.sleep(0.5)
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

        # Resolve path. Prefer RNS's native await_path when present
        # (added in 1.1.x) so the loop blocks on the actual path-response
        # signal rather than busy-polling has_path() on a backoff timer.
        # The code still fall back to the polling path for older RNS — the
        # behaviour is otherwise identical, just chattier on slow links.
        if not RNS.Transport.has_path(dest_hash):
            RNS.Transport.request_path(dest_hash)
            await_path = getattr(RNS.Transport, "await_path", None)
            if await_path is not None:
                try:
                    # await_path is a blocking call into RNS — run in
                    # the default executor so the asyncio loop stays
                    # responsive (path resolution can take seconds on LoRa).
                    ok = await self._loop.run_in_executor(
                        None, lambda: await_path(dest_hash, timeout=timeout),
                    )
                    if not ok and not RNS.Transport.has_path(dest_hash):
                        logger.warning("Path resolution timed out for %s", dest_hash_hex)
                        return None
                except Exception:
                    # await_path absent or signature mismatch — fall through
                    # to the polling loop below.
                    pass
            if not RNS.Transport.has_path(dest_hash):
                # Polling fallback for older RNS. Exponential backoff
                # avoids hammering the network on long LoRa
                # path resolutions.
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

        # v0.9.2 chunk A live-test discovered: the OUTBOUND side must
        # explicitly identify on the link or the SERVER's RNS Link sees
        # remote_identity=None. Without an identified Link, the server's
        # handshake-skip eligibility check (_peer_advertises_hskip)
        # gets None for the identity hash, finds no announce match,
        # and falls back to PASSPHRASE_CHALLENGE — silently disabling
        # the skip even when both sides would otherwise be eligible.
        # `link.identify(self._identity)` is the standard RNS pattern
        # for this; the receiving side's _on_remote_identified callback
        # will then populate the adapter's remote_identity_hash.
        if self._identity is not None and hasattr(link, "identify"):
            try:
                link.identify(self._identity)
            except Exception as e:
                logger.debug("link.identify() on outbound to %s failed: %s",
                             dest_hash_hex, e)

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

        Also prunes closed adapters from ``_active_adapters`` so the
        list doesn't grow unboundedly on a long-running node with many
        connect/disconnect cycles.
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
            # Snapshot + prune closed adapters in one locked pass
            with self._adapters_lock:
                alive = []
                for adapter in self._active_adapters:
                    if getattr(adapter, "_closed", False):
                        continue
                    alive.append(adapter)
                dropped = len(self._active_adapters) - len(alive)
                self._active_adapters = alive
                snapshot = list(alive)
            if dropped:
                logger.debug("Pruned %d closed RNS adapter(s) from active list", dropped)
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
