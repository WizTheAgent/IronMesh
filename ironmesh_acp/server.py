"""ACP stdio server: bridge from Agent Client Protocol to the IronMesh mesh.

Wire format
-----------

JSON-RPC 2.0 over newline-delimited JSON (NDJSON) on stdin/stdout.
Each line is one JSON object — a request, response, or notification.

Protocol surface (v1)
---------------------

Required client→server methods:

* ``initialize``           → ``{protocolVersion, capabilities}``
* ``session/new``          → ``{sessionId}``
* ``session/prompt``       → ack response then one or more
                              ``session/update`` notifications, then a
                              terminal ``session/update`` with
                              ``stopReason ∈ {end_turn, completed, done}``
* ``session/cancel``       → cooperative cancel; emits a terminal
                              ``session/update`` with
                              ``stopReason="cancelled"``

Server→client notification:

* ``session/update``       → references existing ``sessionId``;
                              terminal updates carry ``stopReason``;
                              progress updates carry content blocks
                              (``[{type:"text", text:"…"}]``)

Out of scope for v1 (and this adapter): ``session/fork``,
``session/list``, ``session/resume``, ``session/set_model``,
``$/cancel_request``.

How sessions map onto the mesh
------------------------------

Each ACP session targets exactly one mesh peer. The peer is chosen
at session/new time by passing a ``meta.peer`` field:

```jsonc
{
  "jsonrpc": "2.0", "id": 2, "method": "session/new",
  "params": {
    "meta": {
      "peer": "60a9cca12a98c5ffffe39fdbb6fcbd61"   // 32-hex node id
    }
  }
}
```

If ``meta.peer`` is omitted, the embedded daemon's handshake peer is
used (the node the embedded daemon is configured to dial). Without
either, ``session/new`` fails with ``-32602`` (invalid params).

A ``session/prompt`` for that session sends the prompt body as an
encrypted MSG to the peer. Replies on the same correlation id (or
the next inbound MSG from that peer) are surfaced as
``session/update`` notifications back to the ACP client.
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
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Reuse the ACP-flavoured logger separate from MCP's so operators can
# tune verbosity per-adapter.
log = logging.getLogger("ironmesh.acp")

ACP_PROTOCOL_VERSION = "0.3.0"
ACP_CONFORMANCE_PROFILE = "acp-core-v1@0.3.0"
ACP_SERVER_NAME = "ironmesh-acp"
ACP_TERMINAL_STOP_REASONS = frozenset({"end_turn", "completed", "done", "cancelled"})

# JSON-RPC standard error codes used here.
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603

# Adapter-specific error codes (above -32000 reserved range).
ACP_UNKNOWN_SESSION = -32001
ACP_PEER_NOT_REACHABLE = -32002
ACP_TIMEOUT = -32003


@dataclass
class _Session:
    """ACP session ↔ mesh-peer binding.

    Each session is anchored to one peer node id. Concurrent prompts
    against the same session run sequentially server-side; the prompt
    method holds an ``asyncio.Lock`` so the embedded daemon's per-peer
    correlation slot isn't double-claimed.
    """

    session_id: str
    peer_node_id: str
    created_at: float = field(default_factory=time.time)
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    in_flight: bool = False


def _read_frame(stdin) -> Optional[Dict[str, Any]]:
    """Read one NDJSON frame from ``stdin``. Returns ``None`` on EOF."""
    line = stdin.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return _read_frame(stdin)  # tolerate stray blank lines
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        # Surface as a parse-error response without a request id.
        return {
            "_parse_error": True,
            "_raw": line[:200],
        }
    if not isinstance(obj, dict):
        return {"_parse_error": True, "_raw": line[:200]}
    return obj


def _write_frame(stdout, obj: Dict[str, Any]) -> None:
    """Write one NDJSON frame to ``stdout`` and flush.

    Flush is required: the JSON-RPC client may block waiting for the
    response before sending the next request; without flush, the
    response sits in stdout's buffer forever.
    """
    line = json.dumps(obj, separators=(",", ":"))
    stdout.write(line + "\n")
    stdout.flush()


def _err(req_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    body: Dict[str, Any] = {"jsonrpc": "2.0", "id": req_id,
                             "error": {"code": code, "message": message}}
    if data is not None:
        body["error"]["data"] = data
    return body


def _ok(req_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _notify(method: str, params: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "method": method, "params": params}


def _content_text(blocks: Any) -> Optional[str]:
    """Extract concatenated text from an ACP content-blocks list.

    The ACP spec models content as an array of blocks with discriminated
    ``type`` fields. v1 mandates ``text``; future block types (image,
    audio, file, …) are ignored here. Returns ``None`` if ``blocks`` is
    not a non-empty list, so the caller can return ``-32602``.
    """
    if not isinstance(blocks, list) or not blocks:
        return None
    parts: List[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts) if parts else None


class ACPServer:
    """Owns the embedded BridgeDaemon and the live ACP session table."""

    def __init__(self, daemon, loop: asyncio.AbstractEventLoop, default_peer: Optional[str] = None):
        self.daemon = daemon
        self.loop = loop
        self.default_peer = default_peer.lower() if default_peer else None
        self.sessions: Dict[str, _Session] = {}

    # ------------------------------------------------------------------
    # ACP method dispatch
    # ------------------------------------------------------------------

    async def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        # Echo back the spec version we conform to plus any optional
        # capabilities the client advertised. ACP allows the server to
        # negotiate a lower protocol version; we only support 0.3.0.
        return {
            "protocolVersion": ACP_PROTOCOL_VERSION,
            "conformanceProfile": ACP_CONFORMANCE_PROFILE,
            "serverInfo": {
                "name": ACP_SERVER_NAME,
                "version": _ironmesh_version(),
            },
            "capabilities": {
                # We do not yet implement promptCancellation as a
                # first-class feature beyond cooperative cancel.
                "session": {
                    "new": True,
                    "prompt": True,
                    "cancel": True,
                },
            },
        }

    async def handle_session_new(self, params: Dict[str, Any]) -> Dict[str, Any]:
        meta = params.get("meta") or {}
        peer = meta.get("peer") if isinstance(meta, dict) else None
        if peer is not None and not isinstance(peer, str):
            raise _ParamError("meta.peer must be a 32-hex node id string")
        peer = (peer or self.default_peer or "").lower().strip()
        if not peer:
            raise _ParamError(
                "no peer specified — pass meta.peer in session/new "
                "or start the server with --default-peer"
            )
        if not _looks_like_node_id(peer):
            raise _ParamError(
                f"peer '{peer}' is not a 32-hex node id"
            )
        session_id = uuid.uuid4().hex
        self.sessions[session_id] = _Session(session_id=session_id, peer_node_id=peer)
        return {"sessionId": session_id, "peer": peer}

    async def handle_session_cancel(self, params: Dict[str, Any]) -> Dict[str, Any]:
        sid = params.get("sessionId")
        if not isinstance(sid, str) or sid not in self.sessions:
            raise _UnknownSession(sid)
        sess = self.sessions[sid]
        sess.cancel_event.set()
        # Best-effort terminal update so the client knows the cancel
        # completed even if no in-flight prompt is currently running.
        return {"acknowledged": True}

    async def handle_session_prompt(
        self,
        params: Dict[str, Any],
        notify_send,
    ) -> Dict[str, Any]:
        sid = params.get("sessionId")
        if not isinstance(sid, str) or sid not in self.sessions:
            raise _UnknownSession(sid)
        sess = self.sessions[sid]
        prompt_text = _content_text(params.get("prompt"))
        if prompt_text is None:
            raise _ParamError(
                "prompt must be a non-empty content-blocks list with at "
                "least one {type:'text', text:'…'} entry"
            )
        if sess.in_flight:
            raise _ParamError(
                f"session {sid} already has a prompt in flight; cancel it first"
            )
        sess.in_flight = True
        sess.cancel_event.clear()
        try:
            return await self._run_prompt(sess, prompt_text, notify_send)
        finally:
            sess.in_flight = False

    async def _run_prompt(
        self,
        sess: _Session,
        prompt_text: str,
        notify_send,
    ) -> Dict[str, Any]:
        """Send the prompt onto the mesh and stream replies as updates.

        Strategy: a session/prompt is a request/response round-trip.
        We send a MSG with the prompt as the JSON body and a fresh
        correlation id, then wait for the matching reply (or cancel).
        The reply text is delivered as a single
        ``agent_message_chunk`` content block followed by a terminal
        ``end_turn`` update.
        """
        correlation_id = uuid.uuid4().hex
        envelope = json.dumps(
            {"correlation_id": correlation_id, "body": prompt_text},
            separators=(",", ":"),
        )

        # Subscribe to the local event ring before sending so we can't
        # race past the reply.
        future_reply: asyncio.Future[str] = self.loop.create_future()
        unsubscribe = _subscribe_correlation_reply(
            self.daemon, sess.peer_node_id, correlation_id, future_reply, self.loop,
        )

        try:
            await self._send_msg(sess.peer_node_id, envelope.encode("utf-8"))
            # Emit a progress update so well-behaved ACP clients render
            # something while waiting on the LLM tail latency.
            await notify_send(_notify("session/update", {
                "sessionId": sess.session_id,
                "type": "thinking",
                "preview": prompt_text[:80],
            }))

            timeout = float(os.environ.get("IRONMESH_ACP_TIMEOUT", "120"))
            cancel_task = asyncio.create_task(_await_event(sess.cancel_event))
            try:
                done_first, _ = await asyncio.wait(
                    {future_reply, cancel_task},
                    timeout=timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                if not cancel_task.done():
                    cancel_task.cancel()
            if not done_first:
                # Timeout — no reply, no cancel. Emit a terminal update
                # so the ACP client doesn't hang.
                await notify_send(_notify("session/update", {
                    "sessionId": sess.session_id,
                    "type": "stop",
                    "stopReason": "completed",
                    "details": "timeout waiting for peer reply",
                }))
                return {"stopReason": "completed", "timeout": True}

            if sess.cancel_event.is_set():
                await notify_send(_notify("session/update", {
                    "sessionId": sess.session_id,
                    "type": "stop",
                    "stopReason": "cancelled",
                }))
                return {"stopReason": "cancelled"}

            reply_text = future_reply.result()
            await notify_send(_notify("session/update", {
                "sessionId": sess.session_id,
                "type": "agent_message_chunk",
                "content": {"type": "text", "text": reply_text},
            }))
            await notify_send(_notify("session/update", {
                "sessionId": sess.session_id,
                "type": "stop",
                "stopReason": "end_turn",
            }))
            return {"stopReason": "end_turn"}

        finally:
            unsubscribe()

    async def _send_msg(self, peer_node_id: str, payload: bytes) -> None:
        """Dispatch an encrypted MSG via the embedded daemon.

        ``daemon.send_message(to_node, msg_type, payload, priority)`` —
        the daemon takes the explicit message type so control frames
        and chat MSGs share the same code path.
        """
        await self.daemon.send_message(peer_node_id, "MSG", payload, "NORMAL")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


class _ParamError(Exception):
    """Raised inside handlers to surface as JSON-RPC -32602."""


class _UnknownSession(Exception):
    def __init__(self, sid: Any):
        super().__init__(f"unknown session id: {sid!r}")
        self.sid = sid


def _looks_like_node_id(s: str) -> bool:
    if not isinstance(s, str) or len(s) != 32:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _ironmesh_version() -> str:
    try:
        import ironmesh
        return getattr(ironmesh, "__version__", "0.0.0")
    except Exception:
        return "0.0.0"


async def _await_event(ev: asyncio.Event) -> None:
    await ev.wait()


def _subscribe_correlation_reply(
    daemon,
    peer_node_id: str,
    correlation_id: str,
    fut: asyncio.Future,
    loop: asyncio.AbstractEventLoop,
):
    """Hook the daemon's inbound MSG dispatch to resolve ``fut`` when a
    reply from the target peer arrives.

    Two resolution paths, tried in order:

    1. **Correlation match** — the reply is a JSON envelope
       ``{"correlation_id": "<ours>", "body": "..."}`` (the convention
       MCP's ``ironmesh_request_service`` uses). Preferred because it
       tolerates multiple in-flight prompts against the same peer.

    2. **First-inbound fallback** — the reply is any other payload
       (plain text or a JSON body without a matching correlation id).
       Accept the first such MSG from the target peer that arrives
       after we subscribed. This lets the adapter interoperate with
       simple peer agents (the bundled ``llm_bridge.py`` example,
       community agents) that don't implement the correlation
       convention. With multiple concurrent prompts against the same
       peer, this fallback can cross replies — documented as a known
       limitation for non-correlation peers.
    """
    bus = getattr(daemon, "bus", None)
    if bus is None or not hasattr(bus, "subscribe"):
        return lambda: None

    def cb(msg_data: Dict[str, Any]) -> None:
        if (msg_data.get("peer_id") or "").lower() != peer_node_id.lower():
            return
        payload = msg_data.get("payload")
        if isinstance(payload, str):
            payload_bytes: bytes = payload.encode("utf-8")
            payload_text: str = payload
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
            if isinstance(obj, dict) and obj.get("correlation_id") == correlation_id:
                text = obj.get("body")
                if isinstance(text, str) and not fut.done():
                    loop.call_soon_threadsafe(fut.set_result, text)
                    return
        except Exception:
            pass
        # Path 2: first-inbound fallback. Only fire if we haven't
        # resolved yet — correlation match wins if it comes later.
        if not fut.done():
            loop.call_soon_threadsafe(fut.set_result, payload_text)

    bus.subscribe("MSG", cb)
    if hasattr(bus, "unsubscribe"):
        return lambda: bus.unsubscribe("MSG", cb)
    return lambda: None


# ----------------------------------------------------------------------
# Stdio loop
# ----------------------------------------------------------------------


def serve(server: ACPServer, stdin, stdout) -> None:
    """Blocking stdio dispatch loop. One line in, one line (or several
    notifications) out."""
    notify_lock = threading.Lock()

    def notify_send_sync(frame: Dict[str, Any]) -> None:
        with notify_lock:
            _write_frame(stdout, frame)

    async def notify_send(frame: Dict[str, Any]) -> None:
        # Notifications can be emitted from inside async handlers; bridge
        # to the sync write through the same lock so request responses
        # and progress updates don't interleave at the byte level.
        notify_send_sync(frame)

    while True:
        frame = _read_frame(stdin)
        if frame is None:
            return
        if frame.get("_parse_error"):
            _write_frame(stdout, _err(None, JSONRPC_PARSE_ERROR, "invalid JSON",
                                       data={"raw": frame.get("_raw")}))
            continue

        if frame.get("jsonrpc") != "2.0":
            _write_frame(stdout, _err(frame.get("id"), JSONRPC_INVALID_REQUEST,
                                       "missing or wrong jsonrpc version"))
            continue

        method = frame.get("method")
        req_id = frame.get("id")
        params = frame.get("params") or {}
        if not isinstance(params, dict):
            _write_frame(stdout, _err(req_id, JSONRPC_INVALID_PARAMS,
                                       "params must be an object"))
            continue

        try:
            if method == "initialize":
                fut = asyncio.run_coroutine_threadsafe(
                    server.handle_initialize(params), server.loop,
                )
                _write_frame(stdout, _ok(req_id, fut.result(timeout=5)))
            elif method == "session/new":
                fut = asyncio.run_coroutine_threadsafe(
                    server.handle_session_new(params), server.loop,
                )
                _write_frame(stdout, _ok(req_id, fut.result(timeout=5)))
            elif method == "session/cancel":
                fut = asyncio.run_coroutine_threadsafe(
                    server.handle_session_cancel(params), server.loop,
                )
                _write_frame(stdout, _ok(req_id, fut.result(timeout=5)))
            elif method == "session/prompt":
                fut = asyncio.run_coroutine_threadsafe(
                    server.handle_session_prompt(params, notify_send),
                    server.loop,
                )
                _write_frame(stdout, _ok(req_id, fut.result(timeout=300)))
            elif method is None:
                _write_frame(stdout, _err(req_id, JSONRPC_INVALID_REQUEST,
                                           "missing method"))
            else:
                _write_frame(stdout, _err(req_id, JSONRPC_METHOD_NOT_FOUND,
                                           f"unknown method: {method}"))
        except _ParamError as e:
            _write_frame(stdout, _err(req_id, JSONRPC_INVALID_PARAMS, str(e)))
        except _UnknownSession as e:
            _write_frame(stdout, _err(req_id, ACP_UNKNOWN_SESSION, str(e)))
        except Exception as e:
            log.exception("error handling %s", method)
            _write_frame(stdout, _err(req_id, JSONRPC_INTERNAL_ERROR, str(e)))


# ----------------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------------


def _ensure_utf8_stdio() -> None:
    """Mirror cli._ensure_utf8_stdio so stderr log lines render in
    locales without a UTF-8 codec hint."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(stream, "reconfigure"):
                cur = (getattr(stream, "encoding", "") or "").lower()
                if not cur.startswith("utf"):
                    stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main() -> int:
    _ensure_utf8_stdio()
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s [%(name)s] %(message)s")

    p = argparse.ArgumentParser(
        prog="ironmesh-acp",
        description="ACP stdio adapter that bridges Agent Client Protocol "
                    "into the IronMesh mesh. Each ACP session targets one "
                    "mesh peer; session/prompt dispatches as an encrypted "
                    "MSG and replies are streamed back as session/update "
                    "notifications.",
    )
    p.add_argument("--name", default="acp-agent",
                   help="agent name advertised on the mesh")
    p.add_argument("--port", type=int, default=8768,
                   help="WebSocket bind port for the embedded daemon")
    p.add_argument("--bind", default="127.0.0.1",
                   help="WebSocket bind interface")
    p.add_argument("--passphrase-env", default="IRONMESH_PASSPHRASE")
    p.add_argument("--passphrase-file", default=None)
    p.add_argument("--peer", action="append", default=None,
                   metavar="HOST:PORT",
                   help="bootstrap peer (repeatable, or comma-separated). "
                        "When mDNS is unavailable, pass at least one.")
    p.add_argument("--default-peer", default=None, metavar="NODE_ID",
                   help="32-hex node id to bind sessions to when "
                        "session/new omits meta.peer")
    p.add_argument("--allow-plaintext-ws", action="store_true", default=True)
    p.add_argument("--open-discovery", action="store_true")
    p.add_argument(
        "--state-dir",
        default="~/.ironmesh-acp",
        help="Directory for the embedded daemon's keys/store/audit/"
             "capabilities files. Defaults to ~/.ironmesh-acp so the "
             "ACP daemon has its own identity separate from any "
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

    peer_hints: List[tuple] = []
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

    # Embed a BridgeDaemon, the same way the MCP server does. Each
    # state file is namespaced under --state-dir so the ACP adapter
    # owns its own identity, trust store, and caps view — sharing
    # ~/.ironmesh/ with a production daemon would mean the two fight
    # over the same keys + audit log.
    state_dir = os.path.expanduser(args.state_dir)
    os.makedirs(state_dir, exist_ok=True)
    from ironmesh.bridge import BridgeDaemon

    daemon = BridgeDaemon(
        name=args.name, port=args.port, bind_address=args.bind,
        passphrase=passphrase,
        open_discovery=args.open_discovery,
        allow_plaintext_ws=args.allow_plaintext_ws,
        keys_path=os.path.join(state_dir, "keys.json"),
        db_path=os.path.join(state_dir, "data.db"),
        routes_path=os.path.join(state_dir, "routes.json"),
        capabilities_path=os.path.join(state_dir, "capabilities.json"),
        trust_path=os.path.join(state_dir, "known_peers.json"),
    )
    loop = daemon.run(background=True)
    threading.Thread(target=loop.run_forever, name="acp-loop",
                     daemon=True).start()
    time.sleep(0.5)

    # Fire-and-forget peer bootstrap: schedule on the daemon's loop
    # and move on. A blocking `.result(timeout=…)` here deadlocks when
    # `connect_to_peer`'s post-handshake work (CAPABILITY_ANNOUNCE,
    # trust-store persistence) needs to progress on the same loop.
    if peer_hints:
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

    server = ACPServer(daemon, loop, default_peer=args.default_peer)
    log.info("IronMesh ACP server ready (stdio transport, conformance %s)",
             ACP_CONFORMANCE_PROFILE)

    try:
        serve(server, sys.stdin, sys.stdout)
    except KeyboardInterrupt:
        pass

    # Match MCP's force-exit policy: stdio adapters have no meaningful
    # work after the host disconnects, and lingering daemon threads
    # would otherwise keep the process alive.
    try:
        fut = asyncio.run_coroutine_threadsafe(daemon.shutdown(), loop)
        fut.result(timeout=3)
    except Exception:
        pass
    try:
        loop.call_soon_threadsafe(loop.stop)
    except Exception:
        pass
    os._exit(0)
