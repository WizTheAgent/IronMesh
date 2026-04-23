"""A2A HTTP gateway: bridge from Agent-to-Agent v0.3.0 onto IronMesh.

Wire surface
------------

Three HTTP endpoints, all served by ``http.server`` from stdlib so the
package requires no extra dependencies:

* ``GET  /.well-known/agent-card.json``
* ``POST /a2a/jsonrpc``     (JSON-RPC 2.0; method: ``message/send``)
* ``POST /a2a/v1/inbox``    (raw envelope dispatch)

Authentication
--------------

Bearer token only in v0.9.0 — clients send
``Authorization: Bearer <token>`` and the server compares against the
single token loaded from ``--token`` or the ``IRONMESH_A2A_TOKEN`` env
var. The AgentCard advertises this scheme.

A future v0.9.1 will add HMAC-SHA256 per-peer authentication derived
from the existing ECDH session keys (matches the third-party
``openclaw-a2a-gateway`` reference implementation pattern), with
``X-A2A-{Signature,Timestamp,Nonce,Source-Gateway}`` headers and a
``NonceCache`` for replay protection.

Anti-loop
---------

Inbound envelopes carry a ``route_path`` array of gateway ids; the
server appends its own ``source.gateway_id`` and refuses any envelope
that already contains it. ``hop_count`` is incremented and rejected
above ``MAX_HOPS`` (default 8).

Mesh translation
----------------

Inbound A2A ``message/send`` (or ``command`` envelope) carries a
``destination`` gateway id and a ``payload``. The server looks up the
mapped IronMesh node id (default: identical), then dispatches the
payload as an encrypted MSG via ``daemon.send_message(...)``. Replies
on the same correlation id (or the next inbound MSG from the
destination) are surfaced in the JSON-RPC response, with a
``ttl_seconds`` timeout.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac as _hmac
import json
import logging
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

log = logging.getLogger("ironmesh.a2a")

A2A_PROTOCOL_VERSION = "0.3.0"
A2A_SERVER_NAME = "ironmesh-a2a"
A2A_DEFAULT_TTL_SECONDS = 300
A2A_DEFAULT_MAX_HOPS = 8
A2A_DEFAULT_TIMEOUT_SECONDS = 90.0
A2A_DEFAULT_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB inbound cap

# JSON-RPC error codes
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603

# Adapter-specific
A2A_AUTH_FAILED = -32010
A2A_REPLAY_DETECTED = -32011
A2A_HOP_LIMIT = -32012
A2A_TIMEOUT = -32013
A2A_PEER_UNREACHABLE = -32014


def _ensure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(stream, "reconfigure"):
                cur = (getattr(stream, "encoding", "") or "").lower()
                if not cur.startswith("utf"):
                    stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _ironmesh_version() -> str:
    try:
        import ironmesh
        return getattr(ironmesh, "__version__", "0.0.0")
    except Exception:
        return "0.0.0"


def _looks_like_node_id(s: str) -> bool:
    if not isinstance(s, str) or len(s) != 32:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


class A2AGateway:
    """Owns embedded daemon state, the gateway id, and per-correlation-
    id reply futures.

    The HTTP handler is intentionally thin — it parses the envelope,
    enforces auth/anti-loop, then defers to the gateway's async
    methods which run on the daemon's event loop.
    """

    def __init__(
        self,
        daemon,
        loop: asyncio.AbstractEventLoop,
        gateway_id: str,
        token: Optional[str],
        skills: Optional[List[Dict[str, str]]] = None,
        public_url: Optional[str] = None,
    ):
        self.daemon = daemon
        self.loop = loop
        self.gateway_id = gateway_id
        self.token = token
        self.public_url = public_url or "http://127.0.0.1:18800"
        self.skills = skills or [
            {"id": "chat", "name": "chat", "description": "Encrypted DM bridge to a mesh peer"},
        ]
        # correlation_id → asyncio.Future[str]
        self._reply_futures: Dict[str, asyncio.Future] = {}
        # correlation_id → target peer node id (for the fallback path)
        self._reply_peer: Dict[str, str] = {}
        self._futures_lock = threading.Lock()

        # Subscribe once to the daemon's MSG bus to dispatch replies.
        bus = getattr(self.daemon, "bus", None)
        if bus is not None and hasattr(bus, "subscribe"):
            bus.subscribe("MSG", self._on_inbound_msg)
        else:
            log.warning("daemon has no bus.subscribe — replies will time out")

    # ------------------------------------------------------------------
    # Inbound MSG dispatch (mesh → A2A reply futures)
    # ------------------------------------------------------------------

    def _on_inbound_msg(self, msg_data: Dict[str, Any]) -> None:
        """Resolve reply futures as inbound MSGs arrive.

        Preference: match on JSON envelope ``correlation_id`` (the
        convention MCP's ``ironmesh_request_service`` uses). Fallback:
        when a non-correlation peer (the bundled ``llm_bridge.py``
        example, community agents) replies with plain text, wake the
        single oldest pending future for that peer. Documented as a
        known limitation for mixed-protocol peers — correlation-aware
        peers always resolve precisely.
        """
        peer_id = (msg_data.get("peer_id") or "").lower()
        if not peer_id:
            return
        payload = msg_data.get("payload")
        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
            payload_text = payload
        elif isinstance(payload, (bytes, bytearray)):
            payload_bytes = bytes(payload)
            try:
                payload_text = payload_bytes.decode("utf-8", errors="replace")
            except Exception:
                payload_text = ""
        else:
            return

        # Path 1: correlation match.
        try:
            obj = json.loads(payload_bytes)
            if isinstance(obj, dict):
                cid = obj.get("correlation_id")
                body = obj.get("body")
                if isinstance(cid, str) and isinstance(body, str):
                    with self._futures_lock:
                        fut = self._reply_futures.pop(cid, None)
                    if fut and not fut.done():
                        self.loop.call_soon_threadsafe(fut.set_result, body)
                    return
        except Exception:
            pass

        # Path 2: first pending reply for THIS peer (fallback). Only a
        # fallback — correlation-match above wins when the peer
        # implements the convention. We track in-flight-by-peer via
        # correlation id → peer-node-id mapping; iterate oldest-first.
        with self._futures_lock:
            # Find the oldest future whose metadata says it targets
            # this peer. Metadata is stored in ``_reply_peer`` dict
            # keyed by correlation id; populated at send time.
            candidate_cid: Optional[str] = None
            for cid in list(self._reply_futures.keys()):
                if self._reply_peer.get(cid) == peer_id:
                    candidate_cid = cid
                    break
            fut = self._reply_futures.pop(candidate_cid, None) if candidate_cid else None
            if candidate_cid:
                self._reply_peer.pop(candidate_cid, None)
        if fut and not fut.done():
            self.loop.call_soon_threadsafe(fut.set_result, payload_text)

    # ------------------------------------------------------------------
    # Public API used by the HTTP handler
    # ------------------------------------------------------------------

    def agent_card(self) -> Dict[str, Any]:
        """Return the AgentCard JSON for ``/.well-known/agent-card.json``."""
        return {
            "protocolVersion": A2A_PROTOCOL_VERSION,
            "version": _ironmesh_version(),
            "name": A2A_SERVER_NAME,
            "description": "IronMesh node exposed as an A2A peer",
            "url": f"{self.public_url}/a2a/jsonrpc",
            "skills": self.skills,
            "capabilities": {
                "streaming": False,
                "pushNotifications": False,
                "stateTransitionHistory": False,
            },
            "securitySchemes": (
                {"bearer": {"type": "http", "scheme": "bearer"}}
                if self.token else {}
            ),
            "security": [{"bearer": []}] if self.token else [],
            "supportsAuthenticatedExtendedCard": False,
            "defaultInputModes": ["text"],
            "defaultOutputModes": ["text"],
            "additionalInterfaces": [
                {"url": f"{self.public_url}/a2a/jsonrpc", "transport": "JSONRPC"},
                {"url": f"{self.public_url}/a2a/v1/inbox", "transport": "HTTP+JSON"},
            ],
        }

    def auth_ok(self, header: Optional[str]) -> bool:
        if self.token is None:
            return True  # explicit "no auth required" mode (--no-token)
        if not header or not header.startswith("Bearer "):
            return False
        return _hmac.compare_digest(header[7:].strip(), self.token)

    def append_route(self, route_path: List[str]) -> Tuple[List[str], bool]:
        """Return (new_route_path, is_loop)."""
        if self.gateway_id in route_path:
            return route_path, True
        return route_path + [self.gateway_id], False

    def dispatch_message_send(
        self,
        peer_node_id: str,
        body: str,
        ttl_seconds: float,
    ) -> Dict[str, Any]:
        """Send ``body`` as an encrypted MSG to ``peer_node_id`` and
        block (synchronously, on the calling HTTP thread) for the
        matching reply or a timeout.

        Returns a dict suitable as the JSON-RPC ``result`` field:
        ``{"reply": "...", "elapsed_ms": ...}`` on success, or raises
        ``A2AError`` for known failure modes.
        """
        if not _looks_like_node_id(peer_node_id):
            raise A2AError(JSONRPC_INVALID_PARAMS,
                           f"destination '{peer_node_id}' is not a 32-hex node id")

        correlation_id = uuid.uuid4().hex
        envelope = json.dumps(
            {"correlation_id": correlation_id, "body": body},
            separators=(",", ":"),
        ).encode("utf-8")

        # Register the reply future BEFORE sending so we don't miss the
        # reply. Record the target peer so the fallback path (inbound
        # plain-text from a non-correlation peer) can wake the right
        # future.
        fut: asyncio.Future = self.loop.create_future()
        with self._futures_lock:
            self._reply_futures[correlation_id] = fut
            self._reply_peer[correlation_id] = peer_node_id.lower()

        async def _send():
            await self.daemon.send_message(peer_node_id, "MSG", envelope, "NORMAL")

        t0 = time.time()
        try:
            asyncio.run_coroutine_threadsafe(_send(), self.loop).result(timeout=15)
        except Exception as e:
            with self._futures_lock:
                self._reply_futures.pop(correlation_id, None)
                self._reply_peer.pop(correlation_id, None)
            raise A2AError(A2A_PEER_UNREACHABLE,
                           f"failed to dispatch to {peer_node_id[:16]}…: {e}")

        try:
            reply = asyncio.run_coroutine_threadsafe(
                _await_with_timeout(fut, ttl_seconds), self.loop,
            ).result(timeout=ttl_seconds + 5)
        except (asyncio.TimeoutError, TimeoutError):
            with self._futures_lock:
                self._reply_futures.pop(correlation_id, None)
                self._reply_peer.pop(correlation_id, None)
            raise A2AError(A2A_TIMEOUT,
                           f"no reply from {peer_node_id[:16]}… within {ttl_seconds}s")
        elapsed_ms = int((time.time() - t0) * 1000)
        return {"reply": reply, "elapsed_ms": elapsed_ms}


class A2AError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


async def _await_with_timeout(fut: asyncio.Future, seconds: float):
    return await asyncio.wait_for(fut, timeout=seconds)


# ----------------------------------------------------------------------
# HTTP handler
# ----------------------------------------------------------------------


def _build_handler(gateway: A2AGateway, max_request_bytes: int):
    """Return a BaseHTTPRequestHandler subclass closed over ``gateway``."""

    class A2AHandler(BaseHTTPRequestHandler):

        # Quiet default access logging — emit at debug instead of stderr.
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            log.debug("%s - %s", self.address_string(), format % args)

        def _send_json(self, status: int, body: Any) -> None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-A2A-Protocol-Version", A2A_PROTOCOL_VERSION)
            self.end_headers()
            self.wfile.write(data)

        def _read_body(self) -> Optional[bytes]:
            try:
                clen = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(400, {"error": "invalid Content-Length"})
                return None
            if clen > max_request_bytes:
                self._send_json(413, {"error": f"payload too large (>{max_request_bytes})"})
                return None
            return self.rfile.read(clen)

        # ---- routes ----

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/.well-known/agent-card.json":
                self._send_json(200, gateway.agent_card())
            elif path == "/healthz":
                self._send_json(200, {"ok": True, "version": _ironmesh_version()})
            else:
                self._send_json(404, {"error": "not found", "path": path})

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            auth = self.headers.get("Authorization")
            if not gateway.auth_ok(auth):
                self._send_json(401, {"error": "unauthorized — bearer token required"})
                return

            body = self._read_body()
            if body is None:
                return

            try:
                obj = json.loads(body)
            except json.JSONDecodeError:
                self._send_json(400, {
                    "jsonrpc": "2.0", "id": None,
                    "error": {"code": JSONRPC_PARSE_ERROR, "message": "invalid JSON"},
                })
                return

            if path == "/a2a/jsonrpc":
                self._handle_jsonrpc(obj)
            elif path == "/a2a/v1/inbox":
                self._handle_inbox(obj)
            else:
                self._send_json(404, {"error": "not found", "path": path})

        # ---- JSON-RPC dispatch ----

        def _handle_jsonrpc(self, req: Dict[str, Any]) -> None:
            if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
                self._send_json(200, {
                    "jsonrpc": "2.0", "id": None,
                    "error": {"code": JSONRPC_INVALID_REQUEST,
                              "message": "missing or wrong jsonrpc version"},
                })
                return
            method = req.get("method")
            params = req.get("params") or {}
            req_id = req.get("id")

            if method != "message/send":
                self._send_json(200, {
                    "jsonrpc": "2.0", "id": req_id,
                    "error": {"code": JSONRPC_METHOD_NOT_FOUND,
                              "message": f"unknown method: {method}"},
                })
                return

            try:
                result = self._do_message_send(params)
            except A2AError as e:
                self._send_json(200, {
                    "jsonrpc": "2.0", "id": req_id,
                    "error": {"code": e.code, "message": e.message},
                })
                return
            except Exception as e:
                log.exception("message/send failed")
                self._send_json(200, {
                    "jsonrpc": "2.0", "id": req_id,
                    "error": {"code": JSONRPC_INTERNAL_ERROR, "message": str(e)},
                })
                return
            self._send_json(200, {"jsonrpc": "2.0", "id": req_id, "result": result})

        def _do_message_send(self, params: Dict[str, Any]) -> Dict[str, Any]:
            if not isinstance(params, dict):
                raise A2AError(JSONRPC_INVALID_PARAMS, "params must be an object")
            destination = params.get("destination")
            if not isinstance(destination, str) or not destination:
                raise A2AError(JSONRPC_INVALID_PARAMS,
                               "params.destination (32-hex node id) is required")
            message = params.get("message") or {}
            parts = message.get("parts") if isinstance(message, dict) else None
            text = _extract_text_part(parts) if parts else params.get("text")
            if not isinstance(text, str) or not text:
                raise A2AError(JSONRPC_INVALID_PARAMS,
                               "no text content found — pass params.text or "
                               "params.message.parts=[{kind:'text', text:'…'}]")
            ttl = float(params.get("ttl_seconds") or A2A_DEFAULT_TTL_SECONDS)
            ttl = max(1.0, min(ttl, A2A_DEFAULT_TIMEOUT_SECONDS * 4))
            return gateway.dispatch_message_send(destination.lower(), text, ttl)

        # ---- envelope inbox ----

        def _handle_inbox(self, env: Dict[str, Any]) -> None:
            if not isinstance(env, dict):
                self._send_json(400, {"error": "envelope must be an object"})
                return
            if env.get("protocol_version") and env["protocol_version"] != "a2a/v1":
                self._send_json(400, {
                    "protocol_version": "a2a/v1", "message_type": "error",
                    "error": {"code": JSONRPC_INVALID_PARAMS,
                              "message": f"unsupported protocol_version: {env.get('protocol_version')}"},
                })
                return

            route_path = env.get("route_path") or []
            if not isinstance(route_path, list):
                route_path = []
            new_route, is_loop = gateway.append_route([str(x) for x in route_path])
            if is_loop:
                self._send_json(200, _ack(env, gateway, "rejected", "loop detected"))
                return

            hop_count = int(env.get("hop_count") or 0)
            if hop_count >= A2A_DEFAULT_MAX_HOPS:
                self._send_json(200, _ack(env, gateway, "rejected",
                                          f"hop limit exceeded (>{A2A_DEFAULT_MAX_HOPS})"))
                return

            destination = env.get("destination")
            payload = env.get("payload")
            if not isinstance(destination, str) or not isinstance(payload, dict):
                self._send_json(400, _ack(env, gateway, "rejected",
                                          "destination + payload required"))
                return

            text = payload.get("text")
            if not isinstance(text, str):
                self._send_json(400, _ack(env, gateway, "rejected",
                                          "payload.text required"))
                return

            ttl = float(env.get("ttl_seconds") or A2A_DEFAULT_TTL_SECONDS)
            ttl = max(1.0, min(ttl, A2A_DEFAULT_TIMEOUT_SECONDS * 4))
            try:
                result = gateway.dispatch_message_send(destination.lower(), text, ttl)
            except A2AError as e:
                self._send_json(200, _ack(env, gateway, "rejected", e.message))
                return
            self._send_json(200, _response_envelope(env, gateway, result, new_route))

    return A2AHandler


def _extract_text_part(parts: Any) -> Optional[str]:
    """Pull text out of an A2A v0.3 parts array."""
    if not isinstance(parts, list):
        return None
    for part in parts:
        if not isinstance(part, dict):
            continue
        if part.get("kind") == "text":
            t = part.get("text")
            if isinstance(t, str):
                return t
    return None


def _ack(env: Dict[str, Any], gateway: A2AGateway, status: str, reason: Optional[str]) -> Dict[str, Any]:
    return {
        "protocol_version": "a2a/v1",
        "message_id": uuid.uuid4().hex,
        "correlation_id": env.get("message_id"),
        "source": {"gateway_id": gateway.gateway_id},
        "message_type": "ack",
        "timestamp": time.time(),
        "status": status,
        "reason": reason,
    }


def _response_envelope(env: Dict[str, Any], gateway: A2AGateway, result: Dict[str, Any],
                        route: List[str]) -> Dict[str, Any]:
    return {
        "protocol_version": "a2a/v1",
        "message_id": uuid.uuid4().hex,
        "correlation_id": env.get("message_id"),
        "source": {"gateway_id": gateway.gateway_id},
        "destination": env.get("source", {}).get("gateway_id"),
        "message_type": "response",
        "timestamp": time.time(),
        "route_path": route,
        "hop_count": int(env.get("hop_count") or 0) + 1,
        "payload": {"text": result.get("reply"), "elapsed_ms": result.get("elapsed_ms")},
    }


# ----------------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------------


def main() -> int:
    _ensure_utf8_stdio()
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s [%(name)s] %(message)s")

    p = argparse.ArgumentParser(
        prog="ironmesh-a2a",
        description="A2A v0.3.0 HTTP gateway exposing this IronMesh "
                    "node as an Agent-to-Agent peer. Speaks AgentCard "
                    "+ JSON-RPC + envelope inbox; bridges inbound A2A "
                    "messages onto encrypted mesh MSGs.",
    )
    p.add_argument("--name", default="a2a-agent",
                   help="agent name advertised on the mesh")
    p.add_argument("--mesh-port", type=int, default=8769,
                   help="WebSocket bind port for the embedded daemon")
    p.add_argument("--http-port", type=int, default=18800,
                   help="HTTP bind port for the A2A gateway")
    p.add_argument("--http-bind", default="127.0.0.1",
                   help="HTTP bind interface")
    p.add_argument("--public-url", default=None,
                   help="public URL the AgentCard advertises (defaults "
                        "to http://<bind>:<http-port>)")
    p.add_argument("--gateway-id", default=None,
                   help="gateway identifier in envelopes; defaults to "
                        "the embedded daemon's mesh node id")
    p.add_argument("--token", default=None,
                   help="bearer token clients must present (or set "
                        "IRONMESH_A2A_TOKEN). Pass --no-token to "
                        "disable auth (DEV ONLY).")
    p.add_argument("--no-token", action="store_true",
                   help="disable bearer token check entirely (dev only)")
    p.add_argument("--passphrase-env", default="IRONMESH_PASSPHRASE")
    p.add_argument("--passphrase-file", default=None)
    p.add_argument("--peer", action="append", default=None,
                   metavar="HOST:PORT",
                   help="bootstrap mesh peer hint (repeatable)")
    p.add_argument("--allow-plaintext-ws", action="store_true", default=True)
    p.add_argument("--max-request-bytes", type=int,
                   default=A2A_DEFAULT_RESPONSE_BYTES,
                   help=f"max inbound HTTP body (default {A2A_DEFAULT_RESPONSE_BYTES})")
    p.add_argument(
        "--state-dir",
        default="~/.ironmesh-a2a",
        help="Directory for the embedded daemon's keys/store/audit/"
             "capabilities files. Defaults to ~/.ironmesh-a2a so the "
             "A2A gateway has its own identity separate from any "
             "production ironmesh daemon running on the same host.",
    )
    args = p.parse_args()

    passphrase = None
    if args.passphrase_file:
        with open(os.path.expanduser(args.passphrase_file)) as f:
            passphrase = f.read().strip()
    else:
        passphrase = os.environ.get(args.passphrase_env)
    if not passphrase:
        print(f"ERROR: set --passphrase-file or {args.passphrase_env}",
              file=sys.stderr)
        return 2

    token: Optional[str]
    if args.no_token:
        token = None
        log.warning("bearer-token check disabled — A2A endpoint is unauthenticated (DEV ONLY)")
    else:
        token = args.token or os.environ.get("IRONMESH_A2A_TOKEN")
        if not token:
            print("ERROR: set --token, IRONMESH_A2A_TOKEN, or pass --no-token (dev only)",
                  file=sys.stderr)
            return 2

    peer_hints: List[Tuple[str, int]] = []
    for spec in (args.peer or []):
        for entry in str(spec).split(","):
            entry = entry.strip()
            if not entry:
                continue
            if ":" not in entry:
                print(f"ERROR: --peer expects host:port, got '{entry}'",
                      file=sys.stderr)
                return 2
            host, port_s = entry.rsplit(":", 1)
            try:
                peer_hints.append((host, int(port_s)))
            except ValueError:
                print(f"ERROR: --peer port must be integer, got '{port_s}'",
                      file=sys.stderr)
                return 2

    state_dir = os.path.expanduser(args.state_dir)
    os.makedirs(state_dir, exist_ok=True)
    from ironmesh.bridge import BridgeDaemon

    daemon = BridgeDaemon(
        name=args.name, port=args.mesh_port, bind_address="127.0.0.1",
        passphrase=passphrase,
        allow_plaintext_ws=args.allow_plaintext_ws,
        keys_path=os.path.join(state_dir, "keys.json"),
        db_path=os.path.join(state_dir, "data.db"),
        routes_path=os.path.join(state_dir, "routes.json"),
        capabilities_path=os.path.join(state_dir, "capabilities.json"),
        trust_path=os.path.join(state_dir, "known_peers.json"),
    )
    loop = daemon.run(background=True)
    threading.Thread(target=loop.run_forever, name="a2a-mesh-loop",
                     daemon=True).start()
    time.sleep(0.5)

    # Fire-and-forget peer bootstrap: queue the dial on the daemon's
    # event loop and move on. A blocking await here risks deadlocking
    # the main thread when `connect_to_peer` does post-handshake work
    # (CAPABILITY_ANNOUNCE round-trip, trust-store writes) that needs
    # to progress while the main thread starts the HTTP server. The
    # background reconnect logic keeps peers healthy after boot.
    def _schedule_dial():
        for host, port in peer_hints:
            async def _one(h=host, p=port):
                try:
                    ok = await daemon.connect_to_peer(h, p)
                    log.info("manual peer bootstrap: %s:%d %s",
                             h, p, "connected" if ok else "returned False")
                except Exception as e:
                    log.warning("manual peer bootstrap: %s:%d failed: %s",
                                h, p, e)
            asyncio.run_coroutine_threadsafe(_one(), loop)
    if peer_hints:
        _schedule_dial()

    gateway_id = args.gateway_id or getattr(daemon, "node_id", "unknown")
    public_url = args.public_url or f"http://{args.http_bind}:{args.http_port}"

    gateway = A2AGateway(
        daemon=daemon,
        loop=loop,
        gateway_id=gateway_id,
        token=token,
        public_url=public_url,
    )

    handler_cls = _build_handler(gateway, args.max_request_bytes)
    httpd = ThreadingHTTPServer((args.http_bind, args.http_port), handler_cls)
    log.info("IronMesh A2A gateway listening on http://%s:%d (auth=%s, gateway_id=%s)",
             args.http_bind, args.http_port,
             "bearer" if token else "none",
             gateway_id[:16] + "…")
    log.info("AgentCard: %s/.well-known/agent-card.json", public_url)
    log.info("JSON-RPC:  %s/a2a/jsonrpc", public_url)
    log.info("Inbox:     %s/a2a/v1/inbox", public_url)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        try:
            fut = asyncio.run_coroutine_threadsafe(daemon.shutdown(), loop)
            fut.result(timeout=3)
        except Exception:
            pass
        try:
            loop.call_soon_threadsafe(loop.stop)
        except Exception:
            pass

    return 0
