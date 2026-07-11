"""IronMesh NAT relay server — operator-run rendezvous for WAN meshes.

Implements Option A (pure relay) from ``docs/NAT_TRAVERSAL_DESIGN.md``.
The relay is a dumb forwarder for ``SealedBox`` ciphertext:

* Peers behind NAT open a long-lived outbound WebSocket to the relay.
* Peers register by sending ``{"type": "REGISTER", "node_id": "..."}``
  over that connection.
* Any subsequent frame with ``{"type": "FORWARD", "to": "<node_id>",
  "payload": "<base64>"}`` is routed to the registered peer's socket.
* The relay never holds a session key and never sees plaintext — it
  inspects only the outermost envelope (``type``, ``to``).

Two important properties:

1. **Dumb by design.** The relay does not participate in the IronMesh
   handshake, does not hold peer identity state beyond a node-id →
   socket table, and can be wiped / restarted without data loss.
2. **Metadata-aware, payload-blind.** An operator of the relay sees
   "peer X talks to peer Y, this often, this many bytes" and nothing
   more. Threat-model implications are called out in
   ``THREAT_MODEL.md §5 Cross-asset attacks``.

Operators run it via::

    python -m ironmesh.nat_relay --port 18787 --bind 0.0.0.0

A daemon-side attach flag (``--nat-relay`` on ``ironmesh run``) is a
possible future feature and is **not implemented yet** — today the
relay's ``REGISTER`` / ``FORWARD`` protocol is exercised by the test
suite and available to custom clients (see ``docs/NAT_TRAVERSAL.md``
Option 4 for the current status and recommended alternatives).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
from typing import Dict, Optional

import websockets

from ironmesh.protocol import MAX_FRAME_BYTES

logger = logging.getLogger("ironmesh.nat_relay")

# Bounds on the relay's per-peer connection + forward rates so one
# misbehaving client can't starve the rest of the mesh. Chosen to be
# far above what any honest peer needs for agent messaging.
#
# MAX_FRAME_BYTES is imported from ironmesh.protocol as the single
# source of truth for the wire-level frame ceiling. The relay enforces
# the same cap so a misbehaving client cannot trick the relay into
# buffering frames larger than peers will ever legitimately produce —
# previously the relay carried its own 2 MiB constant which diverged
# from the protocol's 1 MiB ceiling, producing inconsistent acceptance
# across code paths. Audit finding (pre-audit hardening, 2026-05).
MAX_FORWARDS_PER_MINUTE = 6000              # 100/s sustained
MAX_REGISTERED_PEERS = 10_000               # per relay instance


class RelayRegistry:
    """Tracks node_id -> live WebSocket for forwarding.

    Not bound to the asyncio loop — the relay holds it and calls
    register / lookup / deregister synchronously from coroutine
    contexts. All methods are O(1).
    """

    def __init__(self) -> None:
        self._sockets: Dict[str, "websockets.WebSocketServerProtocol"] = {}
        self._registered_at: Dict[str, float] = {}
        self._forward_counts: Dict[str, int] = {}
        self._minute_window_started: float = time.monotonic()

    def register(self, node_id: str, ws) -> bool:
        if len(self._sockets) >= MAX_REGISTERED_PEERS and node_id not in self._sockets:
            return False
        # Replace any stale registration — a reconnecting peer from
        # the same node_id is the common case after a transient drop.
        self._sockets[node_id] = ws
        self._registered_at[node_id] = time.time()
        return True

    def lookup(self, node_id: str):
        return self._sockets.get(node_id)

    def deregister(self, node_id: str) -> None:
        self._sockets.pop(node_id, None)
        self._registered_at.pop(node_id, None)
        self._forward_counts.pop(node_id, None)

    def __len__(self) -> int:
        """Number of currently registered peers."""
        return len(self._sockets)

    def note_forward(self, node_id: str) -> bool:
        """Increment forward counter + enforce the per-minute cap.

        Returns True when the forward is allowed, False when the
        per-peer rate cap is tripped. Window resets every 60 s.
        """
        now = time.monotonic()
        if now - self._minute_window_started > 60.0:
            self._forward_counts.clear()
            self._minute_window_started = now
        current = self._forward_counts.get(node_id, 0) + 1
        if current > MAX_FORWARDS_PER_MINUTE:
            return False
        self._forward_counts[node_id] = current
        return True

    def snapshot(self) -> dict:
        return {
            "peers": len(self._sockets),
            "node_ids": sorted(self._sockets.keys()),
            "forward_counts": dict(self._forward_counts),
        }


class RelayServer:
    def __init__(self, bind: str = "0.0.0.0", port: int = 18787):
        self.bind = bind
        self.port = port
        self.registry = RelayRegistry()
        self._server: Optional[asyncio.AbstractServer] = None

    async def _handle(self, ws):
        registered_node = None
        try:
            async for raw in ws:
                if isinstance(raw, bytes):
                    if len(raw) > MAX_FRAME_BYTES:
                        await self._reject(ws,
                            f"frame too large ({len(raw)} > {MAX_FRAME_BYTES} bytes)")
                        return
                    try:
                        frame = json.loads(raw.decode("utf-8"))
                    except Exception:
                        await self._reject(ws, "invalid frame encoding")
                        return
                else:
                    if len(raw) > MAX_FRAME_BYTES:
                        await self._reject(ws,
                            f"frame too large ({len(raw)} > {MAX_FRAME_BYTES} bytes)")
                        return
                    try:
                        frame = json.loads(raw)
                    except Exception:
                        await self._reject(ws, "invalid frame encoding")
                        return

                if not isinstance(frame, dict):
                    await self._reject(ws, "frame must be a JSON object")
                    return

                ftype = frame.get("type")
                if ftype == "REGISTER":
                    node_id = frame.get("node_id")
                    if not isinstance(node_id, str) or not node_id:
                        await self._reject(ws, "REGISTER requires node_id")
                        return
                    if not self.registry.register(node_id, ws):
                        await self._reject(ws, "registry full")
                        return
                    registered_node = node_id
                    await ws.send(json.dumps({
                        "type": "REGISTER_ACK",
                        "node_id": node_id,
                        "registered_at": time.time(),
                    }))
                    logger.info("relay: registered %s (total=%d)",
                                node_id, len(self.registry))
                    continue

                if ftype == "FORWARD":
                    if registered_node is None:
                        await self._reject(ws, "must REGISTER before FORWARD")
                        return
                    if not self.registry.note_forward(registered_node):
                        await ws.send(json.dumps({
                            "type": "RATE_LIMITED",
                            "retry_after": 60.0,
                        }))
                        continue
                    dst = frame.get("to")
                    if not isinstance(dst, str) or not dst:
                        await self._reject(ws, "FORWARD requires non-empty 'to'")
                        return
                    # v0.9.2 hardening: validate payload type. The relay
                    # should always shuttle a string (typically base64-
                    # encoded sealed envelope); a non-string payload is
                    # either a misbehaving client or a malformed forward.
                    payload = frame.get("payload")
                    if payload is None or not isinstance(payload, str):
                        await self._reject(ws,
                            "FORWARD requires string 'payload'")
                        return
                    target = self.registry.lookup(dst)
                    if target is None:
                        await ws.send(json.dumps({
                            "type": "FORWARD_UNREACHABLE",
                            "to": dst,
                        }))
                        continue
                    # Forward the payload verbatim — the relay never
                    # touches the sealed envelope's contents.
                    try:
                        await target.send(json.dumps({
                            "type": "FORWARD",
                            "from": registered_node,
                            "payload": payload,
                        }))
                    except Exception as e:
                        # v0.9.2: log at INFO (not DEBUG) so operators
                        # see persistent forward failures to a peer.
                        logger.info("relay: forward to %s failed: %s",
                                     dst, e)
                    continue

                if ftype == "PING":
                    await ws.send(json.dumps({"type": "PONG",
                                               "t": time.time()}))
                    continue

                await self._reject(ws, f"unknown frame type: {ftype!r}")
                return
        except websockets.ConnectionClosed:
            pass
        except Exception:
            logger.exception("relay: connection handler crashed")
        finally:
            if registered_node is not None:
                self.registry.deregister(registered_node)
                logger.info("relay: deregistered %s (total=%d)",
                            registered_node, len(self.registry))

    async def _reject(self, ws, reason: str) -> None:
        try:
            await ws.send(json.dumps({"type": "REJECTED", "reason": reason}))
        except Exception:
            pass
        try:
            await ws.close(code=1002, reason=reason[:120])
        except Exception:
            pass

    async def serve(self) -> None:
        logger.info("IronMesh NAT relay listening on ws://%s:%d", self.bind, self.port)
        async with websockets.serve(self._handle, self.bind, self.port,
                                     max_size=MAX_FRAME_BYTES,
                                     ping_interval=30, ping_timeout=10):
            await asyncio.Future()  # run forever


def main() -> int:
    ap = argparse.ArgumentParser(description="IronMesh NAT relay server")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=18787)
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    server = RelayServer(bind=args.bind, port=args.port)
    try:
        asyncio.run(server.serve())
    except KeyboardInterrupt:
        print("\nrelay stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
