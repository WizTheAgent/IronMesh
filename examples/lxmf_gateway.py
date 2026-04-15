#!/usr/bin/env python3
"""IronMesh ↔ LXMF gateway.

Bridges Reticulum LXMF messaging with IronMesh so that users of
Sideband (iOS/Android) and NomadNet can message IronMesh peers, and
vice versa.

**Architecture**

- Runs an LXMF delivery identity (``LXMRouter.register_delivery_identity``)
- Runs an IronMesh ``BridgeDaemon``
- Maintains bidirectional peer mapping in a JSON config file

**LXMF → IronMesh**
    An LXMessage arrives for our delivery identity. We look up the
    sender's destination hash in the peer map and forward the body to
    the mapped IronMesh peer_id as a MSG.

**IronMesh → LXMF**
    We subscribe to the IronMesh bus's ``MSG`` event.  When a MSG
    arrives from a peer that's mapped to an LXMF destination, we build
    an ``LXMessage`` and hand it to the router.

**Loop prevention**
    Forwarded messages are prefixed with ``[LXMF] `` (when entering
    IronMesh from LXMF) and ``[IM] `` (when leaving IronMesh toward
    LXMF).  The gateway skips any message whose payload already starts
    with either prefix.

Usage::

    python examples/lxmf_gateway.py \\
        --name gateway \\
        --port 8766 \\
        --passphrase-file ~/.ironmesh/passphrase \\
        --config ~/.ironmesh/gateway.json \\
        --display-name "IronMesh Gateway" \\
        --reticulum

Config file format (``gateway.json``)::

    {
      "lxmf_peers": {
        "4679096198d8de9f35ffd41485e90a4a": {
          "alias":          "my-phone",
          "ironmesh_peer":  "611979d276ae2c4d77eac2b826a17975"
        }
      }
    }

The ``lxmf_peers`` key maps LXMF destination hashes (hex, no colons) to
IronMesh peer_ids.  Messages flow bidirectionally for any mapping
listed here.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import threading
import time
from typing import Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ironmesh.bridge import BridgeDaemon

try:
    import RNS
    import LXMF
except ImportError:
    print("Error: `rns` and `lxmf` packages required.")
    print("Install with: pip install ironmesh[rns] lxmf")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("lxmf_gateway")

PREFIX_LXMF_TO_IM = b"[LXMF] "  # prepended when forwarding LXMF→IronMesh
PREFIX_IM_TO_LXMF = "[IM] "      # prepended when forwarding IronMesh→LXMF


class Gateway:
    """Bidirectional LXMF ↔ IronMesh bridge."""

    def __init__(self, daemon: BridgeDaemon, config_path: str,
                 storage_path: str, display_name: str,
                 rns_configdir: Optional[str] = None):
        self.daemon = daemon
        self.config_path = os.path.expanduser(config_path)
        self.storage_path = os.path.expanduser(storage_path)
        self.display_name = display_name
        self.rns_configdir = rns_configdir
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.stats = {"lxmf_in": 0, "lxmf_out": 0, "im_in": 0, "im_out": 0}

        # Peer map: {lxmf_dest_hash_hex -> ironmesh_peer_id}
        self.lxmf_to_im: Dict[str, str] = {}
        # Reverse:    {ironmesh_peer_id -> lxmf_dest_hash_hex}
        self.im_to_lxmf: Dict[str, str] = {}
        self._load_config()

        # RNS + LXMF initialization (deferred to start())
        self.reticulum = None
        self.router = None
        self.delivery_destination = None

    # -- config -----------------------------------------------------------

    def _load_config(self) -> None:
        """Load peer map from JSON config (creates empty if missing)."""
        if not os.path.isfile(self.config_path):
            log.info("Config %s not found — starting with empty peer map",
                     self.config_path)
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w") as f:
                json.dump({"lxmf_peers": {}}, f, indent=2)
            return
        with open(self.config_path) as f:
            cfg = json.load(f)
        for lxmf_hash, entry in cfg.get("lxmf_peers", {}).items():
            # Normalize: strip colons/spaces, lowercase
            h = lxmf_hash.replace(":", "").replace(" ", "").lower()
            im_peer = entry.get("ironmesh_peer")
            if im_peer:
                self.lxmf_to_im[h] = im_peer
                self.im_to_lxmf[im_peer] = h
        log.info("Loaded %d peer mappings from %s",
                 len(self.lxmf_to_im), self.config_path)

    # -- LXMF side --------------------------------------------------------

    def start_lxmf(self) -> None:
        """Initialize RNS + LXMF and register delivery identity."""
        # Reuse the bridge's existing Reticulum singleton if present
        if getattr(RNS.Reticulum, "_Reticulum__instance", None) is not None:
            log.info("Reusing existing Reticulum instance from bridge")
            self.reticulum = RNS.Reticulum._Reticulum__instance
        else:
            log.info("Initializing Reticulum")
            self.reticulum = RNS.Reticulum(configdir=self.rns_configdir)

        # LXMF identity — persist across restarts
        identity_path = os.path.join(self.storage_path, "identity")
        os.makedirs(self.storage_path, exist_ok=True)
        if os.path.isfile(identity_path):
            identity = RNS.Identity.from_file(identity_path)
        else:
            identity = RNS.Identity()
            identity.to_file(identity_path)

        self.router = LXMF.LXMRouter(storagepath=self.storage_path)
        self.delivery_destination = self.router.register_delivery_identity(
            identity, display_name=self.display_name,
        )
        self.router.register_delivery_callback(self._on_lxmf_message)

        dest_hash = RNS.prettyhexrep(self.delivery_destination.hash)
        log.info("LXMF delivery identity active: %s", dest_hash)
        log.info("Other Reticulum users can message this hash.")

        try:
            self.delivery_destination.announce()
            log.info("Initial LXMF identity announce sent")
        except Exception as e:
            log.warning("Initial announce failed: %s", e)

    def _on_lxmf_message(self, message) -> None:
        """RNS thread: called when an LXMessage arrives for our identity."""
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

            # Prevent self-loop: messages we injected carry a prefix
            if content_str.startswith(PREFIX_IM_TO_LXMF):
                return

            im_peer = self.lxmf_to_im.get(src_hash_hex)
            if not im_peer:
                log.info("Unmapped LXMF sender %s — message dropped. "
                         "Add to %s to forward.",
                         src_hash_hex[:16], self.config_path)
                return

            log.info("LXMF→IM: from %s → %s (%d bytes)",
                     src_hash_hex[:16], im_peer[:12], len(content_str))

            # Forward to IronMesh — schedule on the asyncio loop
            payload = PREFIX_LXMF_TO_IM + content_str.encode("utf-8")
            if self.loop is not None:
                asyncio.run_coroutine_threadsafe(
                    self._send_ironmesh(im_peer, payload), self.loop,
                )
            self.stats["im_out"] += 1
        except Exception:
            log.exception("LXMF delivery callback crashed")

    async def _send_ironmesh(self, peer_id: str, payload: bytes) -> None:
        try:
            await self.daemon.send_message(peer_id, "MSG", payload)
        except Exception as e:
            log.warning("IronMesh send to %s failed: %s", peer_id[:12], e)

    # -- IronMesh side ----------------------------------------------------

    def _on_ironmesh_message(self, data) -> None:
        """IronMesh bus thread: called when a MSG arrives."""
        try:
            self.stats["im_in"] += 1
            peer_id = data.get("peer_id", "")
            payload = data.get("payload", b"")
            if not isinstance(payload, (bytes, bytearray)):
                return
            # Prevent self-loop: messages we injected from LXMF side
            if payload.startswith(PREFIX_LXMF_TO_IM):
                return

            lxmf_dest_hex = self.im_to_lxmf.get(peer_id)
            if not lxmf_dest_hex:
                return  # not a mapped peer; no forwarding

            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                log.info("Non-UTF8 payload from %s — dropping", peer_id[:12])
                return

            log.info("IM→LXMF: from %s → %s (%d bytes)",
                     peer_id[:12], lxmf_dest_hex[:16], len(text))

            # Forwarding to LXMF happens synchronously on the RNS side
            # but we should run it in a thread to avoid blocking asyncio.
            if self.loop is not None:
                self.loop.run_in_executor(
                    None, self._forward_to_lxmf, lxmf_dest_hex,
                    PREFIX_IM_TO_LXMF + text,
                )
            self.stats["lxmf_out"] += 1
        except Exception:
            log.exception("IronMesh bus callback crashed")

    def _forward_to_lxmf(self, dest_hash_hex: str, text: str) -> None:
        """Build + send an LXMessage (runs in executor to avoid blocking)."""
        try:
            dest_hash = bytes.fromhex(dest_hash_hex)
            if not RNS.Transport.has_path(dest_hash):
                RNS.Transport.request_path(dest_hash)
                # Wait briefly for path resolution
                for _ in range(10):
                    if RNS.Transport.has_path(dest_hash):
                        break
                    time.sleep(0.5)
            dest_identity = RNS.Identity.recall(dest_hash)
            if dest_identity is None:
                log.warning("Cannot recall LXMF identity for %s",
                            dest_hash_hex[:16])
                return
            dest = RNS.Destination(
                dest_identity, RNS.Destination.OUT,
                RNS.Destination.SINGLE, "lxmf", "delivery",
            )
            lxm = LXMF.LXMessage(
                dest, self.delivery_destination, text,
                desired_method=LXMF.LXMessage.DIRECT,
            )
            self.router.handle_outbound(lxm)
        except Exception as e:
            log.warning("LXMF outbound to %s failed: %s",
                        dest_hash_hex[:16], e)


def main():
    p = argparse.ArgumentParser(description="IronMesh ↔ LXMF gateway")
    p.add_argument("--name", required=True)
    p.add_argument("--port", type=int, default=8766)
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--passphrase-file", default=None)
    p.add_argument("--passphrase-env", default="IRONMESH_PASSPHRASE")
    p.add_argument("--config", default="~/.ironmesh/gateway.json",
                   help="Peer map JSON config (default: ~/.ironmesh/gateway.json)")
    p.add_argument("--storage", default="~/.ironmesh/lxmf_gateway",
                   help="LXMF router storage path")
    p.add_argument("--display-name", default="IronMesh Gateway",
                   help="LXMF display name shown to other Reticulum users")
    p.add_argument("--rns-configdir", default=None)
    p.add_argument("--open-discovery", action="store_true")
    p.add_argument("--allow-plaintext-ws", action="store_true")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--reticulum", action="store_true",
                   help="Also enable the Reticulum peer transport in the "
                        "IronMesh bridge (for direct Reticulum peers).")
    args = p.parse_args()

    passphrase = None
    if args.passphrase_file:
        with open(os.path.expanduser(args.passphrase_file)) as f:
            passphrase = f.read().strip()
    else:
        passphrase = os.environ.get(args.passphrase_env)
    if not passphrase:
        log.error("Set --passphrase-file or %s env var", args.passphrase_env)
        sys.exit(1)

    daemon = BridgeDaemon(
        name=args.name,
        port=args.port,
        bind_address=args.bind,
        passphrase=passphrase,
        open_discovery=args.open_discovery,
        allow_plaintext_ws=args.allow_plaintext_ws,
        gui=args.gui,
        rns_enabled=args.reticulum,
    )

    gw = Gateway(
        daemon=daemon,
        config_path=args.config,
        storage_path=args.storage,
        display_name=args.display_name,
        rns_configdir=args.rns_configdir,
    )

    # Wire bus subscription BEFORE starting the daemon loop
    daemon.bus.subscribe("MSG", gw._on_ironmesh_message)

    loop = daemon.run(background=True)
    gw.loop = loop

    # daemon.run(background=True) only runs _start() once and returns the loop;
    # we MUST drive the loop in a background thread or scheduled coroutines
    # (mDNS auto-connect, server handshakes, LXMF→IM forwarding) will never execute.
    loop_thread = threading.Thread(
        target=loop.run_forever, name="ironmesh-loop", daemon=True,
    )
    loop_thread.start()

    # LXMF start is synchronous + threaded inside RNS — safe after loop is running
    gw.start_lxmf()

    print(f"\nLXMF gateway '{args.name}' online")
    print(f"IronMesh node_id: {daemon.node_id}")
    print(f"Mapped peers:     {len(gw.lxmf_to_im)}  (edit {gw.config_path} to add more)")
    print(f"\nCtrl-C to stop.\n")

    try:
        while True:
            time.sleep(60)
            log.info("Stats: lxmf_in=%d im_out=%d | im_in=%d lxmf_out=%d",
                     gw.stats["lxmf_in"], gw.stats["im_out"],
                     gw.stats["im_in"], gw.stats["lxmf_out"])
    except KeyboardInterrupt:
        pass
    finally:
        try:
            asyncio.run_coroutine_threadsafe(daemon.shutdown(), loop).result(5)
        except Exception:
            pass
        loop.call_soon_threadsafe(loop.stop)
        print("\nGateway stopped.")


if __name__ == "__main__":
    main()
