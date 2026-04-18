#!/usr/bin/env python3
"""IronMesh MCP server — exposes IronMesh as MCP tools.

Protocol: Model Context Protocol (stdio transport by default).
Client: any MCP host (Claude Desktop, Claude Code, VS Code MCP).

Tools exposed (18 total as of v0.8.4):
    Core:
        ironmesh_list_peers              — enumerate connected + known peers with live metrics
        ironmesh_send_message            — send a MSG to a named peer (by agent name or node_id)
        ironmesh_get_mesh_stats          — full /api/mesh_stats snapshot (lifetime, bytes, retries)
        ironmesh_list_messages           — query the local message store, optionally filtered by peer
        ironmesh_get_audit_log           — read the tamper-evident audit log tail
        ironmesh_get_peer_stats          — drill into one peer's latency/retries/rekey history
        ironmesh_trust_list              — list pinned and revoked peers
        ironmesh_revoke_peer             — revoke a peer (requires confirm parameter)
    OpenClaw bridge (v0.8.4):
        ironmesh_discover_capabilities   — glob-match capabilities advertised across the mesh
        ironmesh_get_peer_capabilities   — query one peer's advertised capability set
        ironmesh_request_service         — REQ/RESP to a peer with correlation-id + timeout
        ironmesh_broadcast               — send a message to all online peers
        ironmesh_subscribe_events        — poll-based event queue with cursor
    Audit-expansion (v0.8.4):
        ironmesh_advertise_capability    — declare a new local capability without restarting
        ironmesh_withdraw_capability     — stop advertising a local capability
        ironmesh_get_my_identity         — return own node_id, name, advertised caps
        ironmesh_pending_requests        — list in-flight REQ/RESP correlation slots
        ironmesh_reply_to_request        — wrap a correlation-id reply so responders don't build envelopes manually

Transport: spawns a local ``ironmesh run`` daemon if one isn't already running,
then attaches as a read/write client via the IronMesh programmatic API. The
MCP server itself doesn't require a network — it talks to the local daemon
over its bus and database.

Run standalone::

    python -m ironmesh_mcp

Or register with Claude Desktop by adding to ``claude_desktop_config.json``::

    {
      "mcpServers": {
        "ironmesh": {
          "command": "python",
          "args": ["-m", "ironmesh_mcp"],
          "env": {"IRONMESH_PASSPHRASE": "your-passphrase"}
        }
      }
    }

Rationale: MCP is the shortest path to making IronMesh a first-class agent
substrate. Any agent that speaks MCP can now send A2A messages over the
local-first mesh without wrapping the IronMesh CLI or parsing its JSON logs.
"""
from __future__ import annotations

import asyncio
import collections
import concurrent.futures
import json
import logging
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ironmesh.bridge import BridgeDaemon  # noqa: E402

log = logging.getLogger("ironmesh.mcp")


# --------------------------------------------------------------------------
# MCP wire protocol — implemented inline to avoid a hard dependency on the
# mcp SDK (which may not be installed). If the user has ``mcp`` available,
# they can swap in the SDK's Server/Tool wrappers; the tool functions below
# are SDK-agnostic.
# --------------------------------------------------------------------------

PROTOCOL_VERSION = "2024-11-05"
# Read version dynamically so SERVER_INFO doesn't lie after the next bump.
try:
    from ironmesh import __version__ as _IRONMESH_VERSION
except Exception:  # pragma: no cover — defensive only
    _IRONMESH_VERSION = "unknown"
SERVER_INFO = {"name": "ironmesh", "version": _IRONMESH_VERSION}


def _read_frame(stream) -> Optional[dict]:
    """Read a single JSON-RPC request from the MCP host (stdio, line-delimited)."""
    line = stream.readline()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError as e:
        log.warning("bad JSON-RPC frame: %s", e)
        return None


def _write_frame(stream, obj: dict) -> None:
    stream.write(json.dumps(obj, default=str) + "\n")
    stream.flush()


# --------------------------------------------------------------------------
# Tool handlers
# --------------------------------------------------------------------------


_EVENT_BUFFER_DEFAULT = 500
_REQUEST_SERVICE_DEFAULT_TIMEOUT = 30.0


class IronMeshMCP:
    """The MCP server state machine + tool implementations."""

    def __init__(self, daemon: BridgeDaemon, loop: asyncio.AbstractEventLoop,
                 event_buffer_size: int = _EVENT_BUFFER_DEFAULT):
        self.daemon = daemon
        self.loop = loop

        # Ring buffer for ironmesh_subscribe_events.
        # Each entry: {"seq": int, "ts": float, "kind": str, "data": dict}
        # Sequence is monotonic across the buffer's lifetime (cursor stable
        # even after eviction — clients pick up from where they left off).
        self._events: collections.deque = collections.deque(maxlen=event_buffer_size)
        self._event_seq: int = 0
        self._event_lock = threading.Lock()

        # Correlation-id table for ironmesh_request_service:
        # in-flight UUID -> threading.Event + slot for response payload.
        # We can't use asyncio.Future safely from the bus thread without
        # going through call_soon_threadsafe, so a thread-Event is simpler
        # and the MCP handler thread is the one that .wait()s anyway.
        self._pending: dict = {}
        self._pending_lock = threading.Lock()

        self._wire_bus_hooks()

    # --- wiring -------------------------------------------------------------

    def _wire_bus_hooks(self) -> None:
        """Subscribe to daemon bus + lifecycle hooks. Idempotent enough —
        if the daemon is recreated under us, the new MCP instance wires fresh."""
        try:
            self.daemon.bus.on_any(self._on_bus_event)
        except Exception:
            log.warning("MCP could not attach to bus (daemon not started?)", exc_info=True)
        # Peer lifecycle — register with hook manager if available
        hooks = getattr(self.daemon, "_hooks", None)
        if hooks is not None:
            async def _on_connect(ctx):
                self._record_event("peer_connected", {
                    "peer_id": ctx.get("peer_id", ""),
                })
            async def _on_disconnect(ctx):
                self._record_event("peer_disconnected", {
                    "peer_id": ctx.get("peer_id", ""),
                })
            try:
                hooks.register("on_peer_connect", _on_connect)
                hooks.register("on_peer_disconnect", _on_disconnect)
            except Exception:
                log.debug("hook registration failed", exc_info=True)

    def _on_bus_event(self, event_type: str, data) -> None:
        """Catch-all listener: record into ring buffer, route correlation
        responses back to ironmesh_request_service waiters."""
        try:
            from collections.abc import Mapping
            payload_bytes = data.get("payload", b"") if isinstance(data, Mapping) else b""
            peer_id = data.get("peer_id", "") if isinstance(data, Mapping) else ""

            self._record_event(f"msg:{event_type}", {
                "peer_id": peer_id,
                "msg_id": data.get("msg_id", "") if isinstance(data, Mapping) else "",
                "size": len(payload_bytes) if isinstance(payload_bytes, (bytes, str)) else 0,
            })

            # Try to decode JSON envelope for correlation_id matching.
            if event_type == "MSG" and payload_bytes:
                if isinstance(payload_bytes, bytes):
                    try:
                        text = payload_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        return
                else:
                    text = str(payload_bytes)
                if not text or text[0] != "{":
                    return
                try:
                    obj = json.loads(text)
                except (json.JSONDecodeError, ValueError):
                    return
                cid = obj.get("correlation_id") if isinstance(obj, dict) else None
                if not cid:
                    return
                with self._pending_lock:
                    slot = self._pending.get(cid)
                if slot is not None:
                    # H1: only the peer the request was addressed to may
                    # close out the slot. Without this, any peer that
                    # observes the correlation_id (it travels in plaintext
                    # inside the encrypted envelope, but a buggy/malicious
                    # peer could still echo it) could steal another
                    # peer's response slot. The wire protocol is
                    # documented in OPENCLAW_MCP_SETUP.md so the cid is
                    # not a secret; peer identity is the trust anchor.
                    expected = slot.get("expected_peer")
                    if expected and peer_id != expected:
                        # Record as a regular event so observability
                        # surfaces unexpected echoes; do not unblock
                        # the waiter.
                        self._record_event("request_service:cross_peer_echo", {
                            "correlation_id": cid,
                            "expected_peer": expected,
                            "actual_peer": peer_id,
                        })
                        return
                    slot["response"] = obj.get("body", obj)
                    slot["from"] = peer_id
                    slot["event"].set()
        except Exception:
            log.exception("MCP bus listener error")

    def _record_event(self, kind: str, data: dict) -> None:
        with self._event_lock:
            self._event_seq += 1
            self._events.append({
                "seq": self._event_seq,
                "ts": time.time(),
                "kind": kind,
                "data": data,
            })

    # --- helpers ------------------------------------------------------------

    def _resolve_target(self, target: str) -> Optional[str]:
        """Translate an agent name OR a 32-hex node_id into a node_id, or
        None if it doesn't match any known peer. The daemon's own node_id
        (sometimes useful for capability lookups) is also matched."""
        if not target:
            return None
        if len(target) == 32 and all(c in "0123456789abcdef" for c in target):
            return target
        if getattr(self.daemon, "node_id", None) == target:
            return target
        # list(...) defensively snapshots the dict — the daemon's loop
        # thread mutates self.daemon.peers on every connect/disconnect,
        # and MCP handlers run on the stdio reader thread. Without the
        # snapshot a concurrent mutation raises
        # `RuntimeError: dictionary changed size during iteration`.
        for pid, p in list(self.daemon.peers.items()):
            if getattr(p, "agent_name", None) == target:
                return pid
        return None

    # --- tool: list_peers ---------------------------------------------------

    def tool_list_peers(self, args: dict) -> list[dict]:
        """Return all currently tracked peers with live metrics."""
        out = []
        # Snapshot — see _resolve_target for the why.
        for pid, p in list(self.daemon.peers.items()):
            out.append({
                "node_id": pid,
                "name": getattr(p, "agent_name", None),
                "address": p.address,
                "online": bool(p.is_online),
                "status": p.status.value if hasattr(p.status, "value") else str(p.status),
                "rtt_ms": p.latency_ms,
                "messages_sent": p.messages_sent,
                "messages_received": p.messages_received,
                "bytes_sent_total": getattr(p, "bytes_sent_total", 0),
                "bytes_received_total": getattr(p, "bytes_received_total", 0),
                "retries_total": getattr(p, "retries_total", 0),
                "session_rekey_count": getattr(p, "session_rekey_count", 0),
                "last_seen": p.last_seen,
                "offline_since": getattr(p, "offline_since", None),
            })
        return out

    # --- tool: send_message --------------------------------------------------

    def tool_send_message(self, args: dict) -> dict:
        """Send a MSG to a peer by name or node_id.

        Args:
            target: agent name or node_id (32-hex)
            payload: string (UTF-8 encoded) or base64 for binary
            priority: "CRITICAL" | "HIGH" | "NORMAL" (default) | "LOW"
            msg_type: defaults to "MSG"
        """
        target = args.get("target")
        payload = args.get("payload", "")
        priority = args.get("priority", "NORMAL")
        msg_type = args.get("msg_type", "MSG")

        if not target:
            return {"error": "target required (agent name or node_id)"}

        # Resolve name → node_id. Use _resolve_target so the snapshot
        # discipline is centralized.
        target_node = self._resolve_target(target)
        if target_node is None:
            known = [getattr(p, "agent_name", pid[:12])
                     for pid, p in list(self.daemon.peers.items())]
            return {"error": f"peer '{target}' not found. Known: {known}"}

        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)

        fut = asyncio.run_coroutine_threadsafe(
            self.daemon.send_message(target_node, msg_type, payload_bytes, priority),
            self.loop,
        )
        try:
            msg_id = fut.result(timeout=10)
        except Exception as e:
            return {"error": f"send failed: {e}"}
        return {
            "ok": True,
            "msg_id": msg_id,
            "target_node_id": target_node,
            "priority": priority,
        }

    # --- tool: get_mesh_stats -----------------------------------------------

    def tool_get_mesh_stats(self, args: dict) -> dict:
        # Error explicitly when the daemon hasn't been started.
        # _build_mesh_stats() will happily return a partial snapshot
        # against a fresh BridgeDaemon (no peers, zero counters), which
        # silently misleads callers into thinking the mesh is empty.
        if not getattr(self.daemon, "_running", False):
            return {"error": "daemon not running — start it before querying mesh stats"}
        return self.daemon._build_mesh_stats()

    # --- tool: get_peer_stats -----------------------------------------------

    def tool_get_peer_stats(self, args: dict) -> dict:
        pid = args.get("node_id") or args.get("target")
        if not pid:
            return {"error": "node_id required"}
        # Allow name lookup — use _resolve_target for the snapshot
        # discipline (avoids "dictionary changed size" under concurrent
        # peer connect/disconnect on the daemon's loop thread).
        if len(pid) != 32:
            resolved = self._resolve_target(pid)
            if resolved is not None:
                pid = resolved
        p = self.daemon.peers.get(pid)
        if p is None:
            return {"error": f"unknown peer {pid}"}
        return {
            "node_id": pid,
            "name": getattr(p, "agent_name", None),
            "online": bool(p.is_online),
            "rtt_ms": p.latency_ms,
            "messages_sent": p.messages_sent,
            "messages_received": p.messages_received,
            "bytes_sent_total": getattr(p, "bytes_sent_total", 0),
            "bytes_received_total": getattr(p, "bytes_received_total", 0),
            "retries_total": getattr(p, "retries_total", 0),
            "retries_by_reason": dict(getattr(p, "retries_by_reason", {})),
            "session_rekey_count": getattr(p, "session_rekey_count", 0),
            "last_seen": p.last_seen,
            "offline_since": getattr(p, "offline_since", None),
            "connected_at": p.connected_at,
            "transport": getattr(p, "transport_type", "websocket"),
            "verified": p.verified,
        }

    # --- tool: list_messages ------------------------------------------------

    def tool_list_messages(self, args: dict) -> list[dict]:
        """Query the local message store."""
        peer = args.get("peer")
        limit = int(args.get("limit", 20))
        fut = asyncio.run_coroutine_threadsafe(
            self.daemon._db.get_messages(peer_id=peer, limit=limit),
            self.loop,
        )
        try:
            rows = fut.result(timeout=5)
        except Exception as e:
            return [{"error": str(e)}]
        out = []
        for r in rows:
            out.append({
                "msg_id": r.get("msg_id"),
                "source": r.get("source"),
                "source_display": r.get("source_display"),
                "destination": r.get("destination"),
                "msg_type": r.get("msg_type"),
                "timestamp": r.get("timestamp"),
                "direction": r.get("direction"),
                "priority": r.get("priority"),
                "size": len(r.get("payload") or b""),
            })
        return out

    # --- tool: get_audit_log ------------------------------------------------

    def tool_get_audit_log(self, args: dict) -> list[dict]:
        limit = int(args.get("limit", 50))
        if not self.daemon._audit:
            return [{"error": "audit log not enabled on this daemon"}]
        log_path = getattr(self.daemon._audit, "path", None)
        if not log_path or not os.path.exists(log_path):
            return []
        entries = []
        # Explicit utf-8. The audit writer emits UTF-8 JSONL; on
        # Windows the platform default (cp1252) corrupts non-ASCII
        # fields like agent names with diacritics or emoji.
        with open(log_path, encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
        for line in lines:
            try:
                entries.append(json.loads(line))
            except Exception:
                entries.append({"raw": line.strip()})
        return entries

    # --- tool: trust_list ---------------------------------------------------

    def tool_trust_list(self, args: dict) -> dict:
        """List pinned + revoked peers from the trust store."""
        try:
            from ironmesh.trust import TrustStore
            if not self.daemon._keypair:
                return {"error": "daemon keypair not loaded"}
            mac_key = self.daemon._keypair.ed25519_secret[:32]
            store = TrustStore(agent_key=mac_key)
            return {
                "pinned": dict(store._peers),
                "revoked": dict(getattr(store, "_revoked", {})),
            }
        except Exception as e:
            return {"error": f"trust list failed: {e}"}

    # --- tool: revoke_peer --------------------------------------------------

    def tool_revoke_peer(self, args: dict) -> dict:
        """Revoke a peer — requires confirm=True to guard against accidents."""
        peer = args.get("peer")
        if not peer:
            return {"error": "peer name required"}
        if not args.get("confirm"):
            return {"error": "set confirm=true to execute; this is destructive"}
        try:
            from ironmesh.trust import TrustStore
            mac_key = self.daemon._keypair.ed25519_secret[:32]
            store = TrustStore(agent_key=mac_key)
            store.revoke_peer(peer)
            return {"ok": True, "revoked": peer}
        except Exception as e:
            return {"error": f"revoke failed: {e}"}

    # --- Cross-agent collaboration tools ------------------------------------

    # tool: discover_capabilities
    def tool_discover_capabilities(self, args: dict) -> list[dict]:
        """Glob-match capabilities advertised across the mesh.

        Args:
            pattern: fnmatch glob, e.g. ``llm:*``, ``role:assistant``, ``*``
        Returns: list of {node_id, agent_name, capability}.
        """
        pattern = args.get("pattern", "*")
        try:
            pairs = self.daemon.find_capability(pattern) or []
        except Exception as e:
            return [{"error": f"discovery failed: {e}"}]
        out = []
        for node_id, capability in pairs:
            name = None
            peer = self.daemon.peers.get(node_id)
            if peer is not None:
                name = getattr(peer, "agent_name", None)
            elif node_id == getattr(self.daemon, "node_id", None):
                name = getattr(self.daemon, "name", None)
            out.append({
                "node_id": node_id,
                "agent_name": name,
                "capability": capability,
            })
        return out

    # tool: get_peer_capabilities
    def tool_get_peer_capabilities(self, args: dict) -> dict:
        """Return one peer's full advertised capability set."""
        target = args.get("target") or args.get("node_id")
        if not target:
            return {"error": "target required (agent name or node_id)"}
        node_id = self._resolve_target(target)
        if node_id is None:
            return {"error": f"unknown peer '{target}'"}
        registry = getattr(self.daemon, "_capabilities", None)
        if registry is None:
            return {"error": "capability registry not available"}
        try:
            all_caps = registry.all()
        except Exception as e:
            return {"error": f"capability lookup failed: {e}"}
        return {
            "node_id": node_id,
            "capabilities": sorted(all_caps.get(node_id, [])),
        }

    # tool: request_service
    def tool_request_service(self, args: dict) -> dict:
        """Send a prompt to a peer and block for the matching reply (D5).

        Wire pattern: a JSON envelope ``{correlation_id, body}`` is sent as
        a MSG. The bus listener watches for an inbound MSG carrying the same
        correlation_id and unblocks this caller.
        """
        target = args.get("target")
        prompt = args.get("prompt", args.get("body", ""))
        timeout = float(args.get("timeout", _REQUEST_SERVICE_DEFAULT_TIMEOUT))
        priority = args.get("priority", "NORMAL")
        if not target:
            return {"error": "target required"}
        if not prompt:
            return {"error": "prompt required"}
        node_id = self._resolve_target(target)
        if node_id is None:
            return {"error": f"unknown peer '{target}'"}
        peer = self.daemon.peers.get(node_id)
        if peer is None or not getattr(peer, "is_online", False):
            return {"error": f"peer {node_id} not online"}

        cid = uuid.uuid4().hex
        envelope = json.dumps({"correlation_id": cid, "body": prompt}).encode("utf-8")

        slot = {
            "event": threading.Event(),
            "response": None,
            "from": None,
            # H1: only the peer the request was addressed to may close
            # the slot. Bus listener checks this.
            "expected_peer": node_id,
        }
        with self._pending_lock:
            self._pending[cid] = slot

        started = time.time()
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self.daemon.send_message(node_id, "MSG", envelope, priority),
                self.loop,
            )
            try:
                msg_id = fut.result(timeout=10)
            except Exception as e:
                return {"error": f"send failed: {e}"}

            if not slot["event"].wait(timeout=timeout):
                return {
                    "timeout": True,
                    "correlation_id": cid,
                    "elapsed_ms": int((time.time() - started) * 1000),
                    "msg_id": msg_id,
                }
            return {
                "ok": True,
                "response": slot["response"],
                "from": slot["from"],
                "correlation_id": cid,
                "elapsed_ms": int((time.time() - started) * 1000),
                "msg_id": msg_id,
            }
        finally:
            with self._pending_lock:
                self._pending.pop(cid, None)

    # tool: broadcast
    def tool_broadcast(self, args: dict) -> dict:
        """Send a MSG to every online peer (excluding self).

        Returns: {sent_to: [...], failed: [{node_id, error}, ...]}.
        """
        payload = args.get("payload", "")
        priority = args.get("priority", "NORMAL")
        msg_type = args.get("msg_type", "MSG")
        timeout = float(args.get("timeout", 10.0))
        if not payload:
            return {"error": "payload required"}
        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)

        own = getattr(self.daemon, "node_id", None)
        targets: list[str] = []
        for pid, peer in list(self.daemon.peers.items()):
            if pid == own:
                continue
            if not getattr(peer, "is_online", False):
                continue
            targets.append(pid)

        # Parallel fan-out via asyncio.gather. The previous
        # implementation called fut.result(timeout=10) per peer in a
        # loop — total deadline N×10s in the worst case. With gather,
        # the slowest peer caps the whole call at ~timeout seconds.
        async def _fanout() -> tuple[list[str], list[dict]]:
            tasks = [
                self.daemon.send_message(pid, msg_type, payload_bytes, priority)
                for pid in targets
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            ok: list[str] = []
            errs: list[dict] = []
            for pid, res in zip(targets, results):
                if isinstance(res, Exception):
                    errs.append({"node_id": pid, "error": str(res)})
                else:
                    ok.append(pid)
            return ok, errs

        try:
            fut = asyncio.run_coroutine_threadsafe(_fanout(), self.loop)
            sent_to, failed = fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            # Some peers may have completed; we don't know which.
            return {"error": f"broadcast exceeded {timeout}s deadline"}
        except Exception as e:
            return {"error": f"broadcast failed: {e}"}
        return {"sent_to": sent_to, "failed": failed, "count": len(sent_to)}

    # tool: subscribe_events
    def tool_subscribe_events(self, args: dict) -> dict:
        """Cursor-based event poll (replaces the streaming subscribe pattern
        that doesn't fit MCP's request/response model).

        Args:
            cursor: integer sequence to read after; omit for from-the-top
            limit: max events to return (default 50)
            kinds: optional list of event-kind prefixes to filter on
                   (e.g. ["peer_connected", "msg:MSG"])
        """
        try:
            cursor = int(args.get("cursor") or 0)
        except (TypeError, ValueError):
            return {"error": "cursor must be an integer"}
        limit = int(args.get("limit") or 50)
        kinds = args.get("kinds")
        if kinds and not isinstance(kinds, list):
            return {"error": "kinds must be a list of strings"}

        with self._event_lock:
            snapshot = list(self._events)
            high = self._event_seq
        # Clamp cursor > high_water_mark to high_water_mark and warn
        # via the response. Without this, a client that lost track of
        # its cursor (or got one from a different MCP session that had
        # higher counters) stays out of sync forever — `next_cursor`
        # falls back to `cursor` itself when no events match.
        clamped = False
        if cursor > high:
            cursor = high
            clamped = True
        events: list[dict] = []
        for ev in snapshot:
            if ev["seq"] <= cursor:
                continue
            if kinds and not any(ev["kind"].startswith(k) for k in kinds):
                continue
            events.append(ev)
            if len(events) >= limit:
                break
        next_cursor = events[-1]["seq"] if events else cursor
        result: dict = {
            "events": events,
            "next_cursor": next_cursor,
            "high_water_mark": high,
            "buffer_size": len(snapshot),
        }
        if clamped:
            result["cursor_clamped"] = True
        return result

    # --- Agent introspection + responder tools ------------------------------

    # tool: advertise_capability
    def tool_advertise_capability(self, args: dict) -> dict:
        """Advertise a capability locally without restarting the daemon.

        Args:
            capability: short string id, by convention `namespace:name`
                        (e.g. ``llm:hermes3``, ``role:assistant``,
                        ``tool:filesystem``).
        """
        cap = args.get("capability")
        if not isinstance(cap, str) or not cap:
            return {"error": "capability (non-empty string) required"}
        try:
            self.daemon.advertise_capability(cap)
        except Exception as e:
            return {"error": f"advertise failed: {e}"}
        registry = getattr(self.daemon, "_capabilities", None)
        local = registry.local_capabilities() if registry is not None else []
        return {"ok": True, "capability": cap, "local_capabilities": list(local)}

    # tool: withdraw_capability
    def tool_withdraw_capability(self, args: dict) -> dict:
        """Stop advertising a previously-announced local capability."""
        cap = args.get("capability")
        if not isinstance(cap, str) or not cap:
            return {"error": "capability (non-empty string) required"}
        registry = getattr(self.daemon, "_capabilities", None)
        if registry is None:
            return {"error": "capability registry not available"}
        try:
            registry.remove_local(cap)
            try:
                registry.save()
            except Exception:
                pass
        except Exception as e:
            return {"error": f"withdraw failed: {e}"}
        return {
            "ok": True,
            "capability": cap,
            "local_capabilities": list(registry.local_capabilities()),
        }

    # tool: get_my_identity
    def tool_get_my_identity(self, args: dict) -> dict:
        """Return our own node_id, agent name, and advertised capabilities.

        Trivial-but-useful — agents otherwise have no first-class way
        to inspect their own mesh identity from inside the MCP host.
        """
        registry = getattr(self.daemon, "_capabilities", None)
        local = list(registry.local_capabilities()) if registry is not None else []
        return {
            "node_id": getattr(self.daemon, "node_id", None),
            "name": getattr(self.daemon, "name", None),
            "capabilities": local,
            "running": bool(getattr(self.daemon, "_running", False)),
        }

    # tool: pending_requests
    def tool_pending_requests(self, args: dict) -> list[dict]:
        """List in-flight ironmesh_request_service correlation slots.

        Useful for observability — answers "is my agent waiting on
        anything right now?" without touching internals.
        """
        out: list[dict] = []
        with self._pending_lock:
            for cid, slot in list(self._pending.items()):
                out.append({
                    "correlation_id": cid,
                    "expected_peer": slot.get("expected_peer"),
                    "waiting": not slot["event"].is_set(),
                })
        return out

    # tool: reply_to_request
    def tool_reply_to_request(self, args: dict) -> dict:
        """First-class responder helper — reply to a peer's REQ/RESP request.

        OpenClaw agents that act as responders previously had to
        manually parse the inbound MSG envelope, extract the
        correlation_id, build a JSON reply, and send it. This wraps
        all of that in one call.

        Args:
            target: peer that sent the original request (agent name
                    or 32-hex node_id)
            correlation_id: cid from the inbound request envelope
            body: response payload (string)
            priority: optional, default NORMAL
        """
        target = args.get("target")
        cid = args.get("correlation_id")
        body = args.get("body", "")
        priority = args.get("priority", "NORMAL")
        if not target:
            return {"error": "target required"}
        if not cid:
            return {"error": "correlation_id required"}
        if body is None:
            return {"error": "body required (use empty string for empty)"}
        node_id = self._resolve_target(target)
        if node_id is None:
            return {"error": f"unknown peer '{target}'"}
        peer = self.daemon.peers.get(node_id)
        if peer is None or not getattr(peer, "is_online", False):
            return {"error": f"peer {node_id} not online"}
        envelope = json.dumps({"correlation_id": cid, "body": body}).encode("utf-8")
        fut = asyncio.run_coroutine_threadsafe(
            self.daemon.send_message(node_id, "MSG", envelope, priority),
            self.loop,
        )
        try:
            msg_id = fut.result(timeout=10)
        except Exception as e:
            return {"error": f"send failed: {e}"}
        return {"ok": True, "msg_id": msg_id, "correlation_id": cid, "to": node_id}


# --------------------------------------------------------------------------
# Tool registry — MCP "tools/list" + "tools/call" routing
# --------------------------------------------------------------------------

TOOL_SPECS = [
    {
        "name": "ironmesh_list_peers",
        "description": "Enumerate connected and known peers on the mesh with live metrics (RTT, retries, bytes).",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "ironmesh_send_message",
        "description": "Send an application message (MSG) to another peer by agent name or 32-hex node_id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "agent name or 32-hex node_id"},
                "payload": {"type": "string", "description": "UTF-8 text payload"},
                "priority": {"type": "string", "enum": ["CRITICAL", "HIGH", "NORMAL", "LOW"], "default": "NORMAL"},
                "msg_type": {"type": "string", "default": "MSG"},
            },
            "required": ["target", "payload"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ironmesh_get_mesh_stats",
        "description": "Full mesh snapshot — uptime, active peers, message lifetime p50/p90/p99, per-peer counters.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "ironmesh_get_peer_stats",
        "description": "Detailed metrics for one peer: RTT, bytes, retries by reason, session rekeys, last-seen.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "ironmesh_list_messages",
        "description": "Query the local encrypted message store (history of sent/received messages).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "peer": {"type": "string", "description": "filter by peer node_id (optional)"},
                "limit": {"type": "integer", "default": 20},
            },
        },
    },
    {
        "name": "ironmesh_get_audit_log",
        "description": "Tail the tamper-evident HMAC-chained audit log (security events).",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 50}},
        },
    },
    {
        "name": "ironmesh_trust_list",
        "description": "List pinned peer identities (TOFU) and any revoked peers.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "ironmesh_revoke_peer",
        "description": "Revoke a peer by name. Prevents future connections from its identity key. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "peer": {"type": "string"},
                "confirm": {"type": "boolean", "default": False},
            },
            "required": ["peer"],
        },
    },
    {
        "name": "ironmesh_discover_capabilities",
        "description": "Glob-match capabilities advertised across the mesh. Use 'llm:*' to find LLM peers, 'role:assistant' for personas, '*' for everything.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "default": "*",
                            "description": "fnmatch glob pattern (e.g. 'llm:*', 'tool:filesystem')"},
            },
        },
    },
    {
        "name": "ironmesh_get_peer_capabilities",
        "description": "Return the full advertised capability set for one peer (by agent name or 32-hex node_id).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "agent name or 32-hex node_id"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "ironmesh_request_service",
        "description": "Send a prompt to a peer and block for the matching reply. Implements REQ/RESP via correlation-id over MSG (timeout returns {timeout: true}).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "agent name or 32-hex node_id"},
                "prompt": {"type": "string", "description": "request body"},
                "timeout": {"type": "number", "default": 30, "description": "seconds to wait for response"},
                "priority": {"type": "string", "enum": ["CRITICAL", "HIGH", "NORMAL", "LOW"], "default": "NORMAL"},
            },
            "required": ["target", "prompt"],
        },
    },
    {
        "name": "ironmesh_broadcast",
        "description": "Send a MSG to every online peer (excluding self). Returns sent_to + failed lists.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload": {"type": "string"},
                "priority": {"type": "string", "enum": ["CRITICAL", "HIGH", "NORMAL", "LOW"], "default": "NORMAL"},
                "msg_type": {"type": "string", "default": "MSG"},
            },
            "required": ["payload"],
        },
    },
    {
        "name": "ironmesh_subscribe_events",
        "description": "Cursor-based event poll: peer connects/disconnects + message arrivals. Keep the next_cursor and pass it back next call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cursor": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 50},
                "kinds": {"type": "array", "items": {"type": "string"},
                          "description": "optional event-kind prefixes to filter on"},
            },
        },
    },
    {
        "name": "ironmesh_advertise_capability",
        "description": "Advertise a capability locally (no daemon restart required). Use 'namespace:name' convention (e.g. 'llm:hermes3', 'role:assistant').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "capability": {"type": "string", "description": "namespace:name capability identifier"},
            },
            "required": ["capability"],
        },
    },
    {
        "name": "ironmesh_withdraw_capability",
        "description": "Stop advertising a previously-announced local capability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "capability": {"type": "string"},
            },
            "required": ["capability"],
        },
    },
    {
        "name": "ironmesh_get_my_identity",
        "description": "Return our own node_id, agent name, advertised capabilities, and running state. Useful for self-introspection from inside an MCP host.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "ironmesh_pending_requests",
        "description": "List in-flight ironmesh_request_service correlation slots — observability into what the agent is currently waiting on.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "ironmesh_reply_to_request",
        "description": "Reply to a peer's REQ/RESP request — wraps the correlation-id JSON envelope so responders don't have to build it manually.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "the peer that sent the request (agent name or 32-hex node_id)"},
                "correlation_id": {"type": "string", "description": "correlation_id from the inbound request envelope"},
                "body": {"type": "string", "description": "response payload"},
                "priority": {"type": "string", "enum": ["CRITICAL", "HIGH", "NORMAL", "LOW"], "default": "NORMAL"},
            },
            "required": ["target", "correlation_id", "body"],
        },
    },
]


def _dispatch(mcp: IronMeshMCP, tool: str, args: dict) -> Any:
    handler_name = "tool_" + tool.replace("ironmesh_", "")
    fn = getattr(mcp, handler_name, None)
    if fn is None:
        return {"error": f"unknown tool: {tool}"}
    return fn(args or {})


# --------------------------------------------------------------------------
# JSON-RPC 2.0 loop (stdio transport — the MCP default)
# --------------------------------------------------------------------------


def serve(daemon: BridgeDaemon, loop: asyncio.AbstractEventLoop,
          stdin=None, stdout=None) -> None:
    """Run the MCP server loop on stdio until EOF."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    mcp = IronMeshMCP(daemon, loop)

    log.info("IronMesh MCP server ready (stdio transport)")
    while True:
        msg = _read_frame(stdin)
        if msg is None:
            break

        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "serverInfo": SERVER_INFO,
                    "capabilities": {"tools": {}},
                }
            elif method == "notifications/initialized":
                # one-way, no response
                continue
            elif method == "tools/list":
                result = {"tools": TOOL_SPECS}
            elif method == "tools/call":
                tool = params.get("name", "")
                args = params.get("arguments", {})
                content = _dispatch(mcp, tool, args)
                # MCP expects content as a list of content blocks
                result = {"content": [{
                    "type": "text",
                    "text": json.dumps(content, indent=2, default=str),
                }]}
            elif method == "ping":
                result = {}
            else:
                _write_frame(stdout, {
                    "jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                })
                continue
        except Exception as e:
            log.exception("error handling %s", method)
            _write_frame(stdout, {
                "jsonrpc": "2.0", "id": mid,
                "error": {"code": -32000, "message": str(e)},
            })
            continue

        if mid is not None:  # notification requests have no id
            _write_frame(stdout, {"jsonrpc": "2.0", "id": mid, "result": result})


def main() -> int:
    """CLI entry point — spin up an embedded BridgeDaemon then serve MCP on stdio."""
    import argparse
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s [%(name)s] %(message)s")

    p = argparse.ArgumentParser()
    p.add_argument("--name", default="mcp-agent")
    p.add_argument("--port", type=int, default=8767)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--passphrase-env", default="IRONMESH_PASSPHRASE")
    p.add_argument("--passphrase-file", default=None)
    p.add_argument("--open-discovery", action="store_true")
    p.add_argument("--allow-plaintext-ws", action="store_true", default=True)
    args = p.parse_args()

    passphrase = None
    if args.passphrase_file:
        with open(os.path.expanduser(args.passphrase_file)) as f:
            passphrase = f.read().strip()
    else:
        passphrase = os.environ.get(args.passphrase_env)
    if not passphrase:
        print(f"ERROR: set --passphrase-file or {args.passphrase_env}", file=sys.stderr)
        return 2

    daemon = BridgeDaemon(
        name=args.name, port=args.port, bind_address=args.bind,
        passphrase=passphrase,
        open_discovery=args.open_discovery,
        allow_plaintext_ws=args.allow_plaintext_ws,
    )
    loop = daemon.run(background=True)
    threading.Thread(target=loop.run_forever, name="mcp-loop",
                     daemon=True).start()
    time.sleep(0.5)

    try:
        serve(daemon, loop)
    except KeyboardInterrupt:
        pass
    loop.call_soon_threadsafe(loop.stop)
    return 0


if __name__ == "__main__":
    sys.exit(main())
