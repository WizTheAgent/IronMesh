"""IronMesh LXMF listener — Sideband / Nomadnet interop.

Brings up an LXMF delivery identity alongside the IronMesh bridge so
that any LXMF-speaking client (Sideband on a phone, a Nomadnet appbox,
a custom Reticulum app) can message IronMesh agents and vice versa.

The listener is opt-in via the daemon's ``--lxmf`` flag. Without it,
nothing changes — IronMesh continues to use only the Reticulum
peer-to-peer transport. With it, LXMessages addressed to the listener's
delivery identity are forwarded to a configured IronMesh agent, and
outbound LXMessages can be sent by destination hash via
``send_lxmf_to(dest_hash_hex, text)``.

This is also a good neighbourhood feature: the listener's identity is
announced on the Reticulum mesh, which means any nearby Sideband user
can see it and DM it. The whole point of LXMF is that you don't need
to run a server to receive messages — propagation nodes hold them for
you while you're offline.

Optional propagation-node mode (``--lxmf-propagation-node``) turns the
node into LXMF store-and-forward infrastructure: it accepts inbound
messages from peers and synchronises with other propagation nodes.
This mode is only worth running on always-on hosts with persistent
storage (a NAS, a Pi, a VPS).
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Callable, Dict, Optional

logger = logging.getLogger("ironmesh.lxmf")

# Lazy imports — keep the module importable for tests / type-check
# even when the lxmf extra isn't installed.
try:
    import RNS  # type: ignore
    import LXMF  # type: ignore
    _HAS_LXMF = True
except ImportError:
    RNS = None  # type: ignore
    LXMF = None  # type: ignore
    _HAS_LXMF = False


# Loop-prevention prefixes — same scheme as examples/lxmf_gateway.py so
# this listener and the standalone example don't fight each other on a
# host that runs both.
PREFIX_LXMF_TO_IM = b"[LXMF] "
PREFIX_IM_TO_LXMF = "[IM] "


class LXMFListener:
    """Bidirectional IronMesh ↔ LXMF bridge as a daemon-owned module.

    Lifecycle:
      * ``start(loop)`` — initialise RNS + LXMF, register the delivery
        identity, optionally start a propagation node, subscribe to the
        IronMesh MSG bus.
      * ``send_lxmf_to(dest_hash_hex, text)`` — outbound API for code
        running inside the daemon process (used by the seamless
        transport selection in a later phase).
      * ``shutdown()`` — best-effort teardown.

    The daemon owns the lifetime; this class never starts threads on
    its own beyond what RNS / LXMF do internally.
    """

    def __init__(self, daemon, *,
                 storage_path: str = "~/.ironmesh/lxmf",
                 display_name: str = "IronMesh",
                 default_inbound_peer: Optional[str] = None,
                 propagation_node: bool = False,
                 propagation_storage_path: str = "~/.ironmesh/lxmf/propagation",
                 announce_interval: float = 600.0,
                 telemetry_target: Optional[str] = None,
                 telemetry_interval: float = 300.0):
        if not _HAS_LXMF:
            raise RuntimeError(
                "lxmf package is not installed — install with: pip install ironmesh[lxmf]"
            )
        self._daemon = daemon
        self._storage_path = os.path.expanduser(storage_path)
        self._display_name = display_name
        self._default_inbound_peer = default_inbound_peer
        self._propagation_node = propagation_node
        self._propagation_storage_path = os.path.expanduser(propagation_storage_path)
        self._announce_interval = announce_interval
        # Optional telemetry target — a destination hash to receive
        # periodic metrics summaries as LXMessages. Format is plain
        # human-readable text so any LXMF client (Sideband, Nomadnet,
        # custom) can render it without special handling. Sideband-
        # specific telemetry-field encoding is a follow-up.
        self._telemetry_target = (
            telemetry_target.strip().lower().replace(":", "").replace(" ", "")
            if telemetry_target else None
        )
        self._telemetry_interval = telemetry_interval

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._reticulum = None
        self._router: Optional["LXMF.LXMRouter"] = None
        self._delivery_destination = None
        self._announce_task: Optional[asyncio.Task] = None
        self._telemetry_task: Optional[asyncio.Task] = None
        self._shutdown = False

        # Stats surfaced on the dashboard
        self.stats = {
            "lxmf_in": 0, "lxmf_out": 0,
            "im_in": 0, "im_out": 0,
            "drops_loop": 0, "drops_unmapped": 0,
        }

        # Optional inbound-routing map: lxmf_dest_hash_hex -> ironmesh_peer_id.
        # Populated by the daemon (CLI / config); the listener never owns it.
        self.inbound_route: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    def delivery_destination_hash(self) -> Optional[str]:
        """Hex hash of our LXMF delivery identity, once started."""
        if self._delivery_destination is None:
            return None
        return RNS.hexrep(self._delivery_destination.hash, delimit=False)

    # ------------------------------------------------------------------
    # Start / shutdown
    # ------------------------------------------------------------------

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Initialise RNS + LXMF, register identity, subscribe to MSG bus.

        Must run on the asyncio thread. Reuses an existing Reticulum
        singleton if the IronMesh bridge already started one, so we
        don't end up with two competing instances.
        """
        self._loop = loop

        existing = getattr(RNS.Reticulum, "_Reticulum__instance", None)
        if existing is not None:
            logger.info("LXMF listener: reusing existing Reticulum instance")
            self._reticulum = existing
        else:
            logger.info("LXMF listener: initialising Reticulum")
            self._reticulum = RNS.Reticulum()

        os.makedirs(self._storage_path, exist_ok=True)

        identity_path = os.path.join(self._storage_path, "identity")
        if os.path.isfile(identity_path):
            identity = RNS.Identity.from_file(identity_path)
        else:
            identity = RNS.Identity()
            identity.to_file(identity_path)

        self._router = LXMF.LXMRouter(storagepath=self._storage_path)
        self._delivery_destination = self._router.register_delivery_identity(
            identity, display_name=self._display_name,
        )
        self._router.register_delivery_callback(self._on_lxmf_message)

        logger.info(
            "LXMF delivery identity active: %s (display=%r)",
            self.delivery_destination_hash, self._display_name,
        )

        # Initial announce so other LXMF clients can see us
        try:
            self._delivery_destination.announce()
        except Exception as e:
            logger.warning("Initial LXMF announce failed: %s", e)

        # Optional propagation node — turns this host into LXMF
        # store-and-forward for offline peers. Only worth running on
        # always-on hosts with persistent storage.
        if self._propagation_node:
            try:
                os.makedirs(self._propagation_storage_path, exist_ok=True)
                # LXMRouter exposes propagation as a separate enable call.
                # Signature varies by lxmf version, so guard with hasattr.
                if hasattr(self._router, "enable_propagation"):
                    self._router.enable_propagation()
                    logger.info(
                        "LXMF propagation node active (storage=%s)",
                        self._propagation_storage_path,
                    )
                else:
                    logger.warning(
                        "Installed lxmf does not expose enable_propagation; "
                        "propagation-node flag ignored",
                    )
            except Exception as e:
                logger.warning("LXMF propagation node setup failed: %s", e)

        # Subscribe to the daemon's MSG bus so outbound IronMesh→LXMF
        # works for any peer that's been mapped via the inbound_route
        # reverse lookup.
        try:
            self._daemon.bus.subscribe("MSG", self._on_ironmesh_message)
        except Exception:
            logger.exception("Failed to subscribe to MSG bus")

        self._announce_task = loop.create_task(self._announce_loop())
        if self._telemetry_target:
            self._telemetry_task = loop.create_task(self._telemetry_loop())
            logger.info(
                "LXMF telemetry publishing every %.0fs to %s",
                self._telemetry_interval, self._telemetry_target[:16],
            )

    async def _announce_loop(self) -> None:
        """Re-announce the LXMF identity on a longer cadence than IronMesh."""
        while not self._shutdown:
            await asyncio.sleep(self._announce_interval)
            if self._shutdown:
                break
            try:
                self._delivery_destination.announce()
                logger.debug("LXMF identity announce sent")
            except Exception as e:
                logger.warning("LXMF announce failed: %s", e)

    def shutdown(self) -> None:
        """Stop the announce loop. RNS / LXMF clean up via Reticulum's atexit."""
        self._shutdown = True
        if self._announce_task:
            self._announce_task.cancel()
        if self._telemetry_task:
            self._telemetry_task.cancel()

    # ------------------------------------------------------------------
    # Telemetry — periodic metrics summary as an LXMessage
    # ------------------------------------------------------------------

    def build_telemetry_text(self) -> str:
        """Build the text body of a telemetry message.

        Plain human-readable so any LXMF client can render it without
        a custom decoder. Includes a machine-readable header line
        (`# IRONMESH-TELEMETRY v1`) so future automated consumers can
        recognise and parse the format.
        """
        daemon = self._daemon
        now = time.time()
        # Be defensive about every daemon attribute — this telemetry path
        # must never raise. A partially-initialised or mock daemon should
        # still produce valid output, even if some fields come out as 0.
        started_raw = getattr(daemon, "_started_at", now) if daemon else now
        started = started_raw if isinstance(started_raw, (int, float)) else now
        metrics = getattr(daemon, "metrics", None) if daemon else None
        peers_raw = getattr(daemon, "peers", {}) if daemon else {}
        peers = peers_raw if isinstance(peers_raw, dict) else {}
        rns_disc_raw = getattr(daemon, "_rns_discovered", {}) if daemon else {}
        rns_disc = rns_disc_raw if isinstance(rns_disc_raw, dict) else {}
        online_peers = sum(
            1 for s in peers.values() if getattr(s, "is_online", False)
        )
        lines = [
            "# IRONMESH-TELEMETRY v1",
            f"name: {getattr(daemon, 'name', 'ironmesh') if daemon else 'ironmesh'}",
            f"node_id: {getattr(daemon, 'node_id', '') if daemon else ''}",
            f"uptime_s: {now - started:.0f}",
            f"peers_total: {len(peers)}",
            f"peers_online: {online_peers}",
            f"rns_discovered: {len(rns_disc)}",
        ]
        def _metric(name: str) -> int:
            if metrics is None:
                return 0
            val = getattr(metrics, name, 0)
            return val if isinstance(val, (int, float)) else 0
        if metrics is not None:
            lines.extend([
                f"messages_sent: {_metric('messages_sent'):.0f}",
                f"messages_received: {_metric('messages_received'):.0f}",
                f"bytes_sent: {_metric('bytes_sent'):.0f}",
                f"bytes_received: {_metric('bytes_received'):.0f}",
                f"handshake_successes: {_metric('handshake_successes'):.0f}",
            ])
        lines.extend([
            f"lxmf_in: {self.stats['lxmf_in']}",
            f"lxmf_out: {self.stats['lxmf_out']}",
        ])
        return "\n".join(lines) + "\n"

    async def _telemetry_loop(self) -> None:
        """Periodically publish a metrics summary to the configured target."""
        # First publish: short delay so any startup churn settles.
        await asyncio.sleep(min(30.0, self._telemetry_interval))
        while not self._shutdown:
            try:
                text = self.build_telemetry_text()
                ok = await self.send_lxmf_to(
                    self._telemetry_target, text,
                    title="IronMesh Telemetry",
                )
                if not ok:
                    logger.debug("Telemetry publish to %s failed",
                                 self._telemetry_target[:16])
            except Exception:
                logger.exception("telemetry loop error")
            await asyncio.sleep(self._telemetry_interval)
            if self._shutdown:
                break

    # ------------------------------------------------------------------
    # Outbound: IronMesh code calling out to an LXMF destination
    # ------------------------------------------------------------------

    async def send_lxmf_to(self, dest_hash_hex: str, text: str,
                           *, title: Optional[str] = None,
                           timeout: float = 30.0) -> bool:
        """Send an LXMessage to the given destination hash.

        Returns True if the router accepted the outbound message;
        False on path-resolution / identity-recall failure. Actual
        delivery is asynchronous — the LXMRouter handles retries and
        propagation-node fallback transparently.
        """
        if self._router is None or self._delivery_destination is None:
            logger.warning("send_lxmf_to called before start()")
            return False
        try:
            dest_hash = bytes.fromhex(
                dest_hash_hex.replace(":", "").replace(" ", "")
            )
        except ValueError:
            logger.warning("Invalid LXMF destination hash: %s", dest_hash_hex)
            return False
        # Path resolution + identity recall happen on the executor so
        # the asyncio loop stays responsive on slow LoRa paths.
        return await self._loop.run_in_executor(
            None, self._sync_send, dest_hash, text, title, timeout,
        )

    def _sync_send(self, dest_hash: bytes, text: str,
                   title: Optional[str], timeout: float) -> bool:
        if not RNS.Transport.has_path(dest_hash):
            RNS.Transport.request_path(dest_hash)
            await_path = getattr(RNS.Transport, "await_path", None)
            if await_path is not None:
                try:
                    await_path(dest_hash, timeout=timeout)
                except Exception:
                    pass
            else:
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if RNS.Transport.has_path(dest_hash):
                        break
                    time.sleep(0.5)
        if not RNS.Transport.has_path(dest_hash):
            logger.warning("LXMF: no path to %s", dest_hash.hex()[:16])
            return False
        identity = RNS.Identity.recall(dest_hash)
        if identity is None:
            logger.warning("LXMF: cannot recall identity for %s", dest_hash.hex()[:16])
            return False
        dest = RNS.Destination(
            identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
            "lxmf", "delivery",
        )
        try:
            lxm = LXMF.LXMessage(
                dest, self._delivery_destination,
                PREFIX_IM_TO_LXMF + text,
                title=title,
                desired_method=LXMF.LXMessage.DIRECT,
            )
            self._router.handle_outbound(lxm)
            self.stats["lxmf_out"] += 1
            return True
        except Exception as e:
            logger.warning("LXMF outbound to %s failed: %s",
                           dest_hash.hex()[:16], e)
            return False

    # ------------------------------------------------------------------
    # Inbound: LXMF → IronMesh
    # ------------------------------------------------------------------

    def _on_lxmf_message(self, message) -> None:
        """RNS thread: an LXMessage arrived for our delivery identity."""
        try:
            self.stats["lxmf_in"] += 1
            src_hash_hex = RNS.hexrep(message.source_hash, delimit=False).lower()
            content = message.content or b""
            if isinstance(content, bytes):
                try:
                    content_str = content.decode("utf-8")
                except UnicodeDecodeError:
                    content_str = content.decode("utf-8", errors="replace")
            else:
                content_str = str(content)

            # Loop-prevention: ignore messages we ourselves injected.
            if content_str.startswith(PREFIX_IM_TO_LXMF):
                self.stats["drops_loop"] += 1
                return

            # Pick the destination IronMesh peer:
            #   1) explicit per-source mapping in inbound_route
            #   2) configured default inbound peer
            #   3) drop with a warning
            target_peer = (
                self.inbound_route.get(src_hash_hex)
                or self._default_inbound_peer
            )
            if not target_peer:
                self.stats["drops_unmapped"] += 1
                logger.info(
                    "LXMF inbound from unmapped sender %s — dropped. "
                    "Configure --lxmf-default-peer or add a route.",
                    src_hash_hex[:16],
                )
                return

            payload = PREFIX_LXMF_TO_IM + content_str.encode("utf-8")
            if self._loop is not None:
                asyncio.run_coroutine_threadsafe(
                    self._forward_to_ironmesh(target_peer, payload),
                    self._loop,
                )
            self.stats["im_out"] += 1
        except Exception:
            logger.exception("LXMF delivery callback crashed")

    async def _forward_to_ironmesh(self, peer_id: str, payload: bytes) -> None:
        try:
            send_message = getattr(self._daemon, "send_message", None)
            if send_message is None:
                logger.warning("Daemon has no send_message — LXMF inbound dropped")
                return
            await send_message(peer_id, "MSG", payload)
        except Exception as e:
            logger.warning("IronMesh send to %s failed: %s", peer_id[:12], e)

    # ------------------------------------------------------------------
    # Outbound: IronMesh MSG event → LXMF
    # ------------------------------------------------------------------

    def _on_ironmesh_message(self, data) -> None:
        """IronMesh bus: a MSG arrived from one of our peers."""
        try:
            self.stats["im_in"] += 1
            peer_id = data.get("peer_id", "")
            payload = data.get("payload", b"")
            if not isinstance(payload, (bytes, bytearray)):
                return
            if payload.startswith(PREFIX_LXMF_TO_IM):
                self.stats["drops_loop"] += 1
                return

            # Reverse-lookup: which LXMF destination is this IronMesh
            # peer mapped to? The map is the same one inbound_route uses,
            # but we need it in the other direction.
            lxmf_dest_hex = None
            for src_hex, im_peer in self.inbound_route.items():
                if im_peer == peer_id:
                    lxmf_dest_hex = src_hex
                    break
            if not lxmf_dest_hex:
                return  # no LXMF mapping for this peer

            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                logger.info("Non-UTF8 payload from %s — dropping outbound",
                            peer_id[:12])
                return

            if self._loop is not None:
                asyncio.run_coroutine_threadsafe(
                    self.send_lxmf_to(lxmf_dest_hex, text), self._loop,
                )
        except Exception:
            logger.exception("LXMF outbound callback crashed")
