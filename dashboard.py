"""Operator dashboard (GUI) server for the IronMesh bridge daemon.

``GuiMixin`` carries the ``BridgeDaemon`` methods behind the browser
dashboard: the full-state snapshot builder, the token-checked HTTP
handler that serves the dashboard page (see ``dashboard_html.py``),
the GUI WebSocket handler with its push/state loops and event hooks,
the operator command dispatcher, and the dialogue-spawning helper.

``bridge.py`` composes the mixin back into ``BridgeDaemon`` via
inheritance — all state lives on the daemon instance; this module
holds behavior only.
"""

import asyncio
import json
import logging
import time

import websockets

from ironmesh.dashboard_html import GUI_HTML
from ironmesh.handshake import _peer_supports_rekey

logger = logging.getLogger("ironmesh.bridge")


class GuiMixin:
    """Dashboard HTTP/WebSocket serving + operator commands for ``BridgeDaemon``."""

    # ------------------------------------------------------------------
    # GUI Dashboard
    # ------------------------------------------------------------------

    def _build_full_state(self) -> dict:
        """Build complete state snapshot for GUI clients."""
        # v0.8.3: surface the capability registry inverted (cap -> [node_ids])
        # so the dashboard's A2A filter and per-peer capability pills can
        # populate. Previously the GUI checked `state.capabilities` but the
        # backend never emitted it, so the filter silently matched nothing.
        caps_by_name: dict = {}
        if self._capabilities is not None:
            try:
                for node_id, caps in self._capabilities.all().items():
                    for cap in caps:
                        caps_by_name.setdefault(cap, []).append(node_id)
            except Exception:
                caps_by_name = {}
        # v0.8.5.2: enrich peers with their persisted trust_state so the
        # dashboard's PEERS table can show pending/trusted/blocked at a
        # glance instead of only in the separate PENDING TRUST subpanel.
        trust_state_by_peer: dict = {}
        try:
            from ironmesh.trust import TrustStore
            if self._keypair:
                ts = TrustStore(
                    agent_key=self._keypair.ed25519_secret[:32],
                    path=self.trust_path,
                )
                for rec in ts.list_peers():
                    trust_state_by_peer[rec["node_id"]] = rec.get(
                        "trust_state", "trusted",
                    )
        except Exception:
            pass  # GUI degrades gracefully if the trust file is unreadable
        peer_dicts = []
        for p in self.peers.values():
            d = p.to_dict()
            ts = trust_state_by_peer.get(d.get("node_id"))
            if ts is not None:
                d["trust_gate_state"] = ts
            peer_dicts.append(d)
        return {
            "node_id": self.node_id,
            "name": self.name,
            "port": self.port,
            "metrics": self._build_metrics_dict(),
            "peers": peer_dicts,
            "history": self.bus.history(50),
            "capabilities": caps_by_name,
        }

    async def _gui_broadcast(self, msg: dict):
        """Push a JSON message to all connected GUI WebSocket clients."""
        if not self._gui_clients:
            return
        raw = json.dumps(msg, default=str)
        closed = []
        for client in list(self._gui_clients):
            try:
                await client.send(raw)
            except Exception:
                closed.append(client)
        for c in closed:
            self._gui_clients.discard(c)

    async def _gui_state_loop(self):
        """Push full state to all GUI clients every 2 seconds."""
        while self._running:
            await asyncio.sleep(2)
            if self._gui_clients:
                await self._gui_broadcast({
                    "type": "state_update",
                    "data": self._build_full_state(),
                })

    def _wire_gui_hooks(self):
        """Hook into bus events and peer lifecycle to push to GUI clients."""
        def on_bus_event(event_type, data):
            # MessageBus.publish wraps dict payloads in MappingProxyType for
            # immutability, and MappingProxyType is NOT a dict subclass --
            # ``isinstance(data, dict)`` returned False and every GUI event
            # was broadcast with empty peer_id + payload. Use the Mapping ABC
            # instead so both dicts and proxies are accepted.
            from collections.abc import Mapping
            safe = {}
            if isinstance(data, Mapping):
                for k, v in data.items():
                    if isinstance(v, bytes):
                        safe[k] = v.decode("utf-8", errors="replace")
                    else:
                        safe[k] = v
            msg = {
                "type": "message_event",
                "msg_type": event_type,
                "peer_id": safe.get("peer_id", ""),
                "msg_id": safe.get("msg_id", ""),
                "payload": safe.get("payload", ""),
                "timestamp": time.time(),
            }
            if self._gui_clients:
                asyncio.ensure_future(self._gui_broadcast(msg))
        self.bus.on_any(on_bus_event)

        if self._hooks:
            async def on_peer_connect(ctx):
                await self._gui_broadcast({
                    "type": "peer_event",
                    "event": "connected",
                    "peer_id": ctx.get("peer_id", ""),
                    "timestamp": time.time(),
                })
            async def on_peer_disconnect(ctx):
                await self._gui_broadcast({
                    "type": "peer_event",
                    "event": "disconnected",
                    "peer_id": ctx.get("peer_id", ""),
                    "timestamp": time.time(),
                })
            self._hooks.register("on_peer_connect", on_peer_connect)
            self._hooks.register("on_peer_disconnect", on_peer_disconnect)

    def _check_gui_token(self, request) -> bool:
        """Check if the request has a valid GUI token via query param or Authorization header.

        v0.8.5.2: uses constant-time comparison (``hmac.compare_digest``) to
        prevent timing side-channel recovery of the token over the network.
        """
        import hmac as _hmac
        expected = self._gui_token
        # Check ?token= query parameter
        path_str = request.path if hasattr(request, "path") else str(request)
        if "?" in path_str:
            query = path_str.split("?", 1)[1]
            for part in query.split("&"):
                if part.startswith("token="):
                    if _hmac.compare_digest(part[6:], expected):
                        return True
        # Check Authorization: Bearer header
        req_headers = getattr(request, "headers", None)
        if req_headers:
            auth = None
            if hasattr(req_headers, "get"):
                auth = req_headers.get("Authorization") or req_headers.get("authorization")
            if auth and auth.startswith("Bearer "):
                if _hmac.compare_digest(auth[7:], expected):
                    return True
        return False

    async def _gui_process_request(self, connection, request):
        """Route HTTP requests: serve dashboard, metrics JSON, or allow WS upgrade."""
        import websockets.http11

        path = request.path if hasattr(request, "path") else str(request)
        # Strip query string for route matching
        clean_path = path.split("?")[0] if "?" in path else path

        if clean_path == "/ws":
            # Require token for WebSocket upgrade.
            if not self._check_gui_token(request):
                body = b"401 Unauthorized - token required"
                headers = websockets.Headers()
                headers["Content-Type"] = "text/plain"
                headers["Content-Length"] = str(len(body))
                return websockets.http11.Response(401, "Unauthorized", headers, body)
            return None  # Allow WebSocket upgrade

        headers = websockets.Headers()

        if clean_path == "/" or clean_path == "/index.html":
            # Serve HTML without auth — the HTML itself is not sensitive
            from ironmesh import __version__ as _imv
            body = GUI_HTML.replace("{{IRONMESH_VERSION}}", f"v{_imv}").encode()
            headers["Content-Type"] = "text/html; charset=utf-8"
            headers["Content-Length"] = str(len(body))
            return websockets.http11.Response(200, "OK", headers, body)

        # v0.7: PWA manifest for install-to-homescreen support
        if clean_path == "/manifest.json":
            manifest = {
                "name": f"IronMesh — {self.name}",
                "short_name": "IronMesh",
                "start_url": "/",
                "display": "standalone",
                "orientation": "any",
                "background_color": "#0d1117",
                "theme_color": "#0d1117",
                "description": "Encrypted agent-to-agent mesh dashboard",
                "icons": [
                    {
                        "src": "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 192 192'%3E%3Crect width='192' height='192' fill='%230d1117'/%3E%3Ctext x='96' y='120' font-size='100' text-anchor='middle' fill='%233fb950' font-family='monospace'%3E%E2%9F%90%3C/text%3E%3C/svg%3E",
                        "sizes": "192x192",
                        "type": "image/svg+xml",
                    }
                ],
            }
            body = json.dumps(manifest).encode()
            headers["Content-Type"] = "application/manifest+json"
            headers["Content-Length"] = str(len(body))
            return websockets.http11.Response(200, "OK", headers, body)

        # All data endpoints require token.
        if clean_path in ("/metrics", "/api/state", "/api/mesh_stats"):
            if not self._check_gui_token(request):
                body = b"401 Unauthorized - token required"
                headers["Content-Type"] = "text/plain"
                headers["Content-Length"] = str(len(body))
                return websockets.http11.Response(401, "Unauthorized", headers, body)

        if clean_path == "/metrics":
            metrics_dict = self._build_metrics_dict()
            if self._wants_prometheus(path):
                body = self._format_metrics_prometheus(metrics_dict).encode()
                headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
            else:
                body = json.dumps(metrics_dict, indent=2).encode()
                headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
            return websockets.http11.Response(200, "OK", headers, body)

        if clean_path == "/api/state":
            body = json.dumps(self._build_full_state(), indent=2, default=str).encode()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
            return websockets.http11.Response(200, "OK", headers, body)

        if clean_path == "/api/mesh_stats":
            # v0.7.2: compact, machine-friendly snapshot optimised for
            # harness/dashboard polling. Stable schema over releases.
            body = json.dumps(self._build_mesh_stats(), default=str).encode()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
            return websockets.http11.Response(200, "OK", headers, body)

        body = b"404 Not Found"
        headers["Content-Type"] = "text/plain"
        headers["Content-Length"] = str(len(body))
        return websockets.http11.Response(404, "Not Found", headers, body)

    async def _gui_ws_handler(self, websocket):
        """Handle a GUI WebSocket connection: send snapshot, then listen for commands."""
        self._gui_clients.add(websocket)
        try:
            # Send initial snapshot
            await websocket.send(json.dumps({
                "type": "snapshot",
                "data": self._build_full_state(),
            }, default=str))

            async for raw in websocket:
                try:
                    cmd = json.loads(raw)
                    await self._handle_gui_command(cmd, websocket)
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({
                        "type": "send_error", "error": "Invalid JSON",
                    }))
                except Exception as e:
                    await websocket.send(json.dumps({
                        "type": "send_error", "error": str(e),
                    }))
        except websockets.ConnectionClosed:
            pass
        finally:
            self._gui_clients.discard(websocket)

    async def _handle_gui_command(self, cmd: dict, websocket):
        """Process a command from the GUI WebSocket client."""
        action = cmd.get("action")

        if action == "send_message":
            to_node = cmd.get("to_node")
            msg_type = cmd.get("msg_type", "MSG")
            payload = cmd.get("payload", "")
            if not to_node:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "to_node required",
                }))
                return
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            try:
                msg_id = await self.send_message(to_node, msg_type, payload)
                await websocket.send(json.dumps({
                    "type": "send_ack", "msg_id": msg_id,
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": str(e),
                }))

        elif action == "get_history":
            # v0.8.5.6: clamp `limit` to a sane upper bound.
            # Pre-fix, an authenticated GUI client could request
            # `limit=10**9` and force the daemon into a multi-GB SQL
            # SELECT that drove the process to OOM. 5000 is well above
            # any UI's actual paging needs and bounds peak memory at
            # a few MB worth of message rows.
            peer_id = cmd.get("peer_id")
            if peer_id is not None and not isinstance(peer_id, str):
                await websocket.send(json.dumps({
                    "type": "send_error",
                    "error": "peer_id must be a string",
                }))
                return
            try:
                limit = int(cmd.get("limit", 50))
            except (TypeError, ValueError):
                limit = 50
            limit = max(1, min(limit, 5000))
            try:
                messages = await self._db.get_messages(peer_id=peer_id, limit=limit)
                await websocket.send(json.dumps({
                    "type": "history",
                    "messages": messages,
                }, default=str))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": str(e),
                }))

        elif action == "refresh":
            await websocket.send(json.dumps({
                "type": "snapshot",
                "data": self._build_full_state(),
            }, default=str))

        elif action == "broadcast_revocation":
            target = cmd.get("target_node_id")
            reason = cmd.get("reason", "")
            if not target:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "target_node_id required",
                }))
                return
            try:
                await self.broadcast_revocation(target, reason)
                await websocket.send(json.dumps({
                    "type": "revoke_ack", "target": target,
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"Revocation failed: {e}",
                }))

        elif action == "list_pending_trust":
            try:
                pending = await self.list_pending_trust()
                await websocket.send(json.dumps({
                    "type": "pending_trust_list",
                    "pending": pending,
                    "gate_enabled": bool(self.config.require_message_promotion),
                }, default=str))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"list_pending_trust failed: {e}",
                }))

        elif action == "promote_peer":
            target = cmd.get("target_node_id")
            if not target:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "target_node_id required",
                }))
                return
            try:
                result = await self.promote_pending_peer(target)
                await websocket.send(json.dumps({
                    "type": "promote_ack", "target": target, **result,
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"promote failed: {e}",
                }))

        elif action == "block_peer":
            target = cmd.get("target_node_id")
            if not target:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "target_node_id required",
                }))
                return
            try:
                result = await self.block_pending_peer(target)
                await websocket.send(json.dumps({
                    "type": "block_ack", "target": target, **result,
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"block failed: {e}",
                }))

        elif action == "list_pending_cap":
            # v0.8.5.7: dashboard surface for the v0.8.5.6 cap-binding
            # feature. Returns one entry per peer whose currently-
            # announced capability set differs from the baseline.
            try:
                ts = self._open_trust_store()
                if ts is None:
                    await websocket.send(json.dumps({
                        "type": "pending_cap_list", "pending": [],
                    }))
                    return
                rows = []
                for r in ts.list_by_capability_status("pending-cap-change"):
                    baseline = set(r.get("capability_set") or [])
                    pending = set(r.get("pending_set") or [])
                    rows.append({
                        "node_id": r["node_id"],
                        "baseline_hash": r.get("capability_hash"),
                        "pending_hash": r.get("pending_hash"),
                        "baseline_set": sorted(baseline),
                        "pending_set": sorted(pending),
                        "added": sorted(pending - baseline),
                        "removed": sorted(baseline - pending),
                    })
                await websocket.send(json.dumps({
                    "type": "pending_cap_list", "pending": rows,
                }, default=str))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error",
                    "error": f"list_pending_cap failed: {e}",
                }))

        elif action == "cap_promote_peer":
            target = cmd.get("target_node_id")
            if not target:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "target_node_id required",
                }))
                return
            try:
                result = await self.accept_pending_cap_change(target)
                await websocket.send(json.dumps({
                    "type": "cap_promote_ack",
                    "node_id": target,
                    **(result or {}),
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error",
                    "error": f"cap_promote_peer failed: {e}",
                }))

        elif action == "rotate_session":
            peer_id = cmd.get("peer_id")
            if not peer_id:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "peer_id required",
                }))
                return
            state = self.peers.get(peer_id)
            if not state or not state.is_online:
                await websocket.send(json.dumps({
                    "type": "send_error",
                    "error": f"Peer {peer_id} not online",
                }))
                return
            if not _peer_supports_rekey(state.protocol_version):
                await websocket.send(json.dumps({
                    "type": "send_error",
                    "error": f"Peer protocol {state.protocol_version} does not support rekey",
                }))
                return
            try:
                await self._initiate_rekey(peer_id)
                await websocket.send(json.dumps({
                    "type": "rotate_ack", "peer_id": peer_id,
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"Rekey failed: {e}",
                }))

        elif action == "start_dialogue":
            # v0.8.2: in-process orchestrator for AI-to-AI dialogue.
            # Accepts {peer_a, peer_b, seed, max_turns?, budget_seconds?,
            # budget_bytes?} where peer_a and peer_b are node_ids. Spawns
            # a background task that shuttles CONV frames between the two
            # peers and streams transcript events back via the existing
            # gui broadcast path (type="dialogue_event").
            try:
                await self._spawn_dialogue(cmd, websocket)
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"Dialogue failed: {e}",
                }))

        else:
            await websocket.send(json.dumps({
                "type": "send_error", "error": f"Unknown action: {action}",
            }))

    async def _spawn_dialogue(self, cmd: dict, websocket) -> None:
        """Run a bounded AI-to-AI dialogue between two mesh peers.

        Sends the seed to peer_a as turn 0 via a CONV frame, then
        shuttles each response to the other peer until the code see an end
        frame, hit the turn cap, or time out.
        """
        import uuid as _uuid

        from ironmesh.conversation import (
            KIND_PROMPT as _KP,
            Budget as _Budget,
            ConvEnvelope as _CE,
        )

        peer_a = cmd.get("peer_a")
        peer_b = cmd.get("peer_b")
        seed = cmd.get("seed") or ""
        max_turns = int(cmd.get("max_turns", 4))
        turn_timeout = float(cmd.get("turn_timeout", 120.0))
        budget_seconds = cmd.get("budget_seconds")
        budget_bytes = cmd.get("budget_bytes")
        if not peer_a or not peer_b:
            raise ValueError("peer_a and peer_b required")
        if peer_a not in self.peers or peer_b not in self.peers:
            raise ValueError("one or both peers not in peer table")

        conv_id = _uuid.uuid4().hex[:12]
        budget = None
        if budget_seconds is not None or budget_bytes is not None:
            budget = _Budget(
                max_seconds=(float(budget_seconds)
                             if budget_seconds is not None else None),
                max_bytes=(int(budget_bytes)
                           if budget_bytes is not None else None),
            )

        def _name_of(pid: str) -> str:
            state = self.peers.get(pid)
            return getattr(state, "agent_name", None) or pid[:12]

        async def emit(payload: dict) -> None:
            await websocket.send(json.dumps({
                "type": "dialogue_event",
                "conv_id": conv_id,
                **payload,
            }, default=str))

        # Queue incoming CONV envelopes for THIS conversation only.
        q: asyncio.Queue = asyncio.Queue()
        from ironmesh.conversation import ConvEnvelope as _CE_cls

        def _on_conv_event(event_type, data):
            if event_type != "CONV":
                return
            pid = data.get("peer_id", "") if hasattr(data, "get") else ""
            pl = data.get("payload", b"") if hasattr(data, "get") else b""
            if isinstance(pl, str):
                pl = pl.encode("utf-8")
            try:
                env = _CE_cls.decode(pl)
            except Exception:
                return
            if env.conv_id != conv_id:
                return
            q.put_nowait((pid, env))

        self.bus.on_any(_on_conv_event)

        try:
            await emit({
                "event": "started",
                "peer_a": peer_a, "peer_b": peer_b,
                "max_turns": max_turns, "seed": seed,
            })

            # Turn 0: send seed to peer_a.
            first_env = _CE(
                conv_id=conv_id, turn=0, max_turns=max_turns,
                kind=_KP, body=seed,
                from_role="orchestrator", to_role=_name_of(peer_a),
                budget=budget,
            )
            await self.send_message(peer_a, "CONV", first_env.encode())
            await emit({"event": "turn", "turn": 0,
                        "speaker": "ORCHESTRATOR", "body": seed})

            current = peer_a
            other = peer_b
            while True:
                try:
                    pid, env = await asyncio.wait_for(q.get(), timeout=turn_timeout)
                except asyncio.TimeoutError:
                    await emit({"event": "timeout",
                                "waiting_on": _name_of(current),
                                "timeout": turn_timeout})
                    break

                if env.kind in ("end", "error"):
                    await emit({
                        "event": env.kind,
                        "speaker": _name_of(pid),
                        "reason": env.end_reason or env.body,
                    })
                    break

                await emit({
                    "event": "turn", "turn": env.turn,
                    "speaker": _name_of(pid), "body": env.body,
                })

                if env.turn >= max_turns:
                    await emit({"event": "turn_cap_reached", "cap": max_turns})
                    break

                # Relay to the other peer, carrying the same turn.
                current, other = other, current
                next_env = _CE(
                    conv_id=conv_id, turn=env.turn, max_turns=max_turns,
                    kind=_KP, body=env.body,
                    from_role=_name_of(pid), to_role=_name_of(current),
                    budget=budget,
                )
                await self.send_message(current, "CONV", next_env.encode())
        finally:
            # Detach the listener. MessageBus has no explicit off_any API
            # for catch-alls; accept the small per-conversation overhead
            # and just leave a no-op closure behind. Trim the list to
            # avoid growth on long-running processes.
            try:
                self.bus._catch_all.remove(_on_conv_event)
            except ValueError:
                pass
            await emit({"event": "finished"})

    async def _start_gui_server(self):
        """Start the GUI WebSocket+HTTP server on port+1.

        Bind address comes from `self.gui_bind` (default 127.0.0.1).
        Setting it to a non-loopback value emits a loud warning at
        startup because exposing the dashboard directly to a network
        bypasses any reverse-proxy hardening (TLS, rate limits, ACLs).
        See docs/REVERSE_PROXY.md.
        """
        gui_port = self.port + 1
        bind = self.gui_bind
        is_loopback = bind in ("127.0.0.1", "::1", "localhost")
        if not is_loopback:
            logger.warning(
                "INSECURE BIND: GUI dashboard configured to bind %s:%d "
                "(non-loopback). The dashboard's only auth is a bearer "
                "token; without TLS in front of it (reverse proxy or "
                "--tls-cert / --tls-key), the token can be sniffed on "
                "the wire. See docs/REVERSE_PROXY.md for the recommended "
                "deployment pattern.",
                bind, gui_port,
            )
        try:
            self._gui_server = await websockets.serve(
                self._gui_ws_handler,
                bind,
                gui_port,
                process_request=self._gui_process_request,
            )
            logger.info(
                "GUI dashboard at http://%s:%d/ (metrics at /metrics?token=%s)",
                bind, gui_port, self._gui_token,
            )
        except Exception as e:
            logger.warning("GUI server failed to start on port %d: %s", gui_port, e)
