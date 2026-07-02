"""Message routing and delivery for the IronMesh bridge daemon.

``RoutingMixin`` carries the ``BridgeDaemon`` methods on the message
path: inbound frame parsing (binary + legacy JSON) and dispatch,
encrypted control messages, the outbound send pipeline (priority
queueing, offline queue, frame signing/sending), pending-message
flush, unified transport selection for sends by peer name, and
capability-aware routing.

``bridge.py`` composes the mixin back into ``BridgeDaemon`` via
inheritance — all state lives on the daemon instance; this module
holds behavior only.
"""

import asyncio
import base64
import hmac
import json
import logging
import time
import uuid
from typing import Any, Dict, Optional

import nacl.exceptions as nacl_exceptions
import websockets

from ironmesh import (
    crypto as ew_crypto,
    protocol as ew_protocol,
)
from ironmesh.audit import (
    EVENT_CAPABILITY_ANNOUNCE_BAD_SIG,
    EVENT_CAPABILITY_LEARNED,
)
from ironmesh.telemetry import span as _otel_span

logger = logging.getLogger("ironmesh.bridge")


class RoutingMixin:
    """Inbound dispatch + outbound delivery pipeline for ``BridgeDaemon``."""

    # ------------------------------------------------------------------
    # Message handling (encrypted)
    # ------------------------------------------------------------------

    async def _handle_message(self, peer_id: str, raw, transport: str = "ws"):
        """Handle an incoming message from a peer.

        Accepts both binary frames (preferred) and legacy JSON (backward compat).
        Binary frames hide all metadata inside the encrypted envelope.

        ``transport`` (v0.8.5.6) tags the inbound transport so the dedup
        cache can detect cross-transport replay attempts. The WebSocket
        path passes ``"ws"``; the Reticulum path passes ``"rns"``.
        """
        peer_state = self.peers.get(peer_id)
        if not peer_state or not peer_state.session_key:
            logger.warning("No session key for peer %s — dropping message", peer_id)
            return

        # Rate limiting — global daemon-wide cap first (defense in depth
        # for hostile-peer exposure), then per-peer cap.
        if (
            self._global_msg_rate_limiter is not None
            and not self._global_msg_rate_limiter.consume()
        ):
            self.metrics.rate_limits_triggered += 1
            self.metrics.global_msg_rate_limit_total += 1
            logger.warning(
                "Global message rate cap exceeded (%.1f msg/s); "
                "dropping inbound from %s",
                self._max_msgs_per_sec,
                peer_id,
            )
            # v0.9.3: emit a sampled audit event (≤ one per 10 s) so a
            # flood doesn't dominate the chain. The aggregate dropped-
            # message count is still visible via the Prometheus counter.
            try:
                from ironmesh.audit import EVENT_GLOBAL_RATE_LIMIT_TRIGGERED
                now = time.monotonic()
                last = getattr(self, "_global_cap_audit_last_ts", 0.0)
                if now - last >= 10.0:
                    self._global_cap_audit_last_ts = now
                    if self._audit is not None:
                        self._audit.log(EVENT_GLOBAL_RATE_LIMIT_TRIGGERED, {
                            "peer_id": peer_id,
                            "max_msgs_per_sec": self._max_msgs_per_sec,
                            "node_id": self.node_id,
                        })
            except ImportError:
                pass
            try:
                await self._send_encrypted_control(
                    peer_id, ew_protocol.MessageType.RATE_LIMITED
                )
            except (websockets.exceptions.ConnectionClosed, OSError, RuntimeError, ValueError):
                # Best-effort RATE_LIMITED notify to a global-cap
                # offender. ValueError covers the encrypted-control
                # send path's input-validation raises (no session
                # key, malformed peer state, etc.) — same drop-and-
                # return outcome regardless.
                pass
            return

        rate_limiter = self._peer_rate_limiters.get(peer_id)
        if rate_limiter and not rate_limiter.consume():
            self.metrics.rate_limits_triggered += 1
            logger.warning("Rate limited peer %s", peer_id)
            try:
                await self._send_encrypted_control(
                    peer_id, ew_protocol.MessageType.RATE_LIMITED
                )
            except (websockets.exceptions.ConnectionClosed, OSError, RuntimeError, ValueError):
                # Per-peer rate-limit notify — same pattern as the
                # global-cap notify above.
                pass
            return

        # Detect binary vs JSON wire format
        if isinstance(raw, bytes) and len(raw) >= ew_protocol.Frame.HEADER_SIZE and raw[:2] == ew_protocol.Frame.MAGIC:
            return await self._handle_binary_frame(peer_id, raw, peer_state,
                                                    transport=transport)
        elif isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError:
                logger.warning("Unrecognized binary data from %s — dropping", peer_id)
                return
        return await self._handle_json_message(peer_id, raw, peer_state,
                                                transport=transport)

    async def _handle_binary_frame(self, peer_id: str, raw: bytes, peer_state,
                                    transport: str = "ws"):
        """Handle a binary wire-format frame (preferred path).

        ``transport`` (v0.8.5.6) propagates to the dedup cache for
        cross-transport replay detection.
        """
        if not peer_state.identity_public:
            logger.warning("Cannot verify binary frame from %s — no identity key", peer_id)
            return
        try:
            from nacl.signing import VerifyKey
            verify_key = VerifyKey(peer_state.identity_public)
            frame = ew_protocol.Frame.deserialize_and_decrypt(
                raw, peer_state.session_key, verify_key=verify_key
            )
        except Exception as e:
            logger.warning("Binary frame rejected from %s: %s", peer_id, e)
            return

        sequence = frame.sequence
        timestamp = frame.timestamp

        # Replay protection
        if sequence <= 0:
            logger.warning("Rejected binary frame from %s with seq=%d", peer_id, sequence)
            return
        rejection = self._replay_guard.check(peer_id, sequence, timestamp)
        if rejection:
            logger.warning("Replay detected from %s: %s", peer_id, rejection)
            return

        # Dispatch to common handler
        await self._dispatch_message(peer_id, peer_state, frame, transport=transport)

    async def _handle_json_message(self, peer_id: str, raw: str, peer_state,
                                    transport: str = "ws"):
        """Handle a legacy JSON message (backward compat).

        ``transport`` (v0.8.5.6) propagates to the dedup cache.
        """
        # Parse the incoming message
        msg = json.loads(raw)
        msg_id = msg.get("msg_id", str(uuid.uuid4()))

        # Decrypt payload — plaintext is NEVER accepted after handshake
        encrypted_b64 = msg.get("encrypted_payload")
        if not encrypted_b64:
            logger.warning("Rejected plaintext message from %s — encryption required after handshake", peer_id)
            return
        try:
            encrypted_bytes = base64.b64decode(encrypted_b64)
            payload = ew_crypto.decrypt_message(peer_state.session_key, encrypted_bytes)
        except Exception as e:
            logger.warning("Decryption failed from %s: %s", peer_id, e)
            return

        # Replay protection — all post-handshake messages must have sequence > 0
        sequence = msg.get("sequence", 0)
        timestamp = msg.get("timestamp", time.time())
        if sequence <= 0:
            logger.warning("Rejected message from %s with seq=%d — sequence required", peer_id, sequence)
            return
        rejection = self._replay_guard.check(peer_id, sequence, timestamp)
        if rejection:
            logger.warning("Replay detected from %s: %s", peer_id, rejection)
            return

        # Mandatory signature verification — all messages must be signed
        signed_b64 = msg.get("signature")
        if not signed_b64:
            logger.warning("Rejected unsigned message from %s — signature required", peer_id)
            return
        if not peer_state.identity_public:
            logger.warning("Cannot verify signature from %s — no identity key", peer_id)
            return
        try:
            from nacl.signing import VerifyKey
            verify_key = VerifyKey(peer_state.identity_public)
            # Detached signature verification — sig binds directly to received encrypted bytes
            ew_crypto.verify_detached(verify_key, encrypted_bytes, base64.b64decode(signed_b64))
        except Exception as e:
            logger.warning("Signature verification FAILED from %s: %s", peer_id, e)
            return

        # Synthesize Frame from JSON envelope and dispatch to common handler
        msg["msg_id"] = msg_id
        frame = ew_protocol.Frame.from_json_message(msg, payload)
        frame.sequence = sequence
        frame.timestamp = timestamp
        await self._dispatch_message(peer_id, peer_state, frame, transport=transport)

    async def _dispatch_message(self, peer_id: str, peer_state,
                                frame: "ew_protocol.Frame",
                                transport: str = "ws"):
        """Common message dispatch — shared by binary frame and JSON paths.

        Args:
            peer_id: ID of the immediate peer (NOT necessarily the original source).
            peer_state: PeerState for the immediate peer.
            frame: Decrypted Frame with full metadata (msg_type, msg_id, payload,
                   source, destination, ttl, hops, source_signature, e2e_payload).
        """
        msg_type = frame.msg_type
        msg_id = frame.msg_id
        payload = frame.payload

        # v0.5.2: decompress LoRa-compressed payloads
        if getattr(frame, 'routing', {}).get("compressed"):
            import gzip
            try:
                payload = gzip.decompress(payload)
                frame.payload = payload
            except Exception as e:
                logger.warning("Failed to decompress LoRa payload from %s: %s",
                               peer_id, e)

        # v0.4: ROUTE_ANNOUNCE is control-plane; handle and return without
        # bus-publishing or storing in history.
        if msg_type == ew_protocol.MessageType.ROUTE_ANNOUNCE:
            peer_state.last_seen = time.time()
            if self._mesh is not None:
                await self._mesh.handle_route_announce(peer_id, payload)
            return

        # v0.4: ROUTE_UNREACHABLE is also control-plane.
        if msg_type == ew_protocol.MessageType.ROUTE_UNREACHABLE:
            peer_state.last_seen = time.time()
            logger.info("ROUTE_UNREACHABLE from %s: %s", peer_id, payload[:200])
            return

        # v0.9.2 chunk B (cross-host fan-out): GROUP_BROADCAST frames
        # carry mesh-wide broadcast payloads. They route to
        # _on_rns_group_message — NOT the regular MSG pipeline — so
        # they share the same dedup window as the same-segment RNS
        # GROUP packet. A peer that receives the same payload via both
        # the local-segment GROUP packet AND the per-peer fan-out
        # processes it exactly once.
        if msg_type == ew_protocol.MessageType.GROUP_BROADCAST:
            peer_state.last_seen = time.time()
            try:
                await self._on_rns_group_message(payload)
            except Exception:
                logger.exception("GROUP_BROADCAST handler failed")
            return

        # v0.4: CAPABILITY_ANNOUNCE — learn remote capabilities and propagate
        # via mesh routing if destined for "*". Don't bus-publish: capabilities
        # are control plane.
        if msg_type == ew_protocol.MessageType.CAPABILITY_ANNOUNCE:
            peer_state.last_seen = time.time()
            if self._capabilities is not None:
                try:
                    # v0.8.5.6: validate types up front so
                    # downstream code that uses `origin` as a dict key
                    # (TrustStore.get_peer, CapabilityRegistry._remote)
                    # can't be tripped up by a malicious peer sending
                    # `{"origin": [1,2,3], "capabilities": [...]}`.
                    if not isinstance(payload, (bytes, bytearray, str)):
                        return
                    if isinstance(payload, (bytes, bytearray)) and \
                            len(payload) > 1_048_576:
                        logger.warning(
                            "CAPABILITY_ANNOUNCE from %s too large: %d bytes",
                            peer_id, len(payload),
                        )
                        return
                    data = ew_protocol.safe_json_loads(payload)
                    if not isinstance(data, dict):
                        return
                    origin = data.get("origin", peer_id)
                    if not isinstance(origin, str) or not origin:
                        return
                    caps = data.get("capabilities", [])
                    if not isinstance(caps, list):
                        return
                    # Drop non-string / empty cap tokens before letting
                    # them reach the registry. Cap a sanity-bound on
                    # the number of caps to limit per-announce work.
                    caps = [c for c in caps
                            if isinstance(c, str) and c]
                    if len(caps) > 1024:
                        logger.warning(
                            "CAPABILITY_ANNOUNCE from %s claims %d "
                            "caps; truncating to 1024",
                            peer_id, len(caps),
                        )
                        caps = caps[:1024]

                    # Signed-envelope verification. An announce body
                    # whose ``origin`` differs from the sending peer MUST
                    # carry an inner Ed25519 signature from ``origin`` over
                    # the canonical bytes; otherwise the announce is dropped
                    # (audit-logged + metric incremented). Direct-from-peer
                    # announces (``origin == peer_id``) without a signature
                    # remain accepted for back-compat with the pre-signing announce shape.
                    signature_b64 = data.get("signature")
                    has_sig = isinstance(signature_b64, str) and signature_b64
                    if origin != peer_id and not has_sig:
                        logger.warning(
                            "CAPABILITY_ANNOUNCE from %s about %s lacks "
                            "inner signature — dropping (relay impersonation "
                            "guard)",
                            peer_id, origin,
                        )
                        if self._audit:
                            try:
                                self._audit.log(
                                    EVENT_CAPABILITY_ANNOUNCE_BAD_SIG,
                                    {
                                        "peer_id": peer_id,
                                        "origin": origin,
                                        "reason": "missing-sig",
                                    },
                                )
                            except Exception:
                                pass
                        self.metrics.capability_announce_bad_signature_total += 1
                        return
                    if has_sig:
                        # Verify the inner signature using origin's
                        # pinned Ed25519 identity key. Unknown origin →
                        # drop (we don't TOFU-pin third-party origins
                        # from announce bodies; the origin must first be
                        # known via its own direct connection).
                        origin_pub_b64 = self._get_peer_identity_key(origin)
                        if not origin_pub_b64:
                            logger.warning(
                                "CAPABILITY_ANNOUNCE from %s about %s — "
                                "origin identity key not pinned; dropping",
                                peer_id, origin,
                            )
                            if self._audit:
                                try:
                                    self._audit.log(
                                        EVENT_CAPABILITY_ANNOUNCE_BAD_SIG,
                                        {
                                            "peer_id": peer_id,
                                            "origin": origin,
                                            "reason": "unknown-origin",
                                        },
                                    )
                                except Exception:
                                    pass
                            self.metrics.capability_announce_bad_signature_total += 1
                            return
                        announced_at = data.get("announced_at")
                        version = data.get("version")
                        if (not isinstance(announced_at, (int, float))
                                or not isinstance(version, int)):
                            logger.warning(
                                "CAPABILITY_ANNOUNCE from %s about %s — "
                                "malformed announced_at/version; dropping",
                                peer_id, origin,
                            )
                            self.metrics.capability_announce_bad_signature_total += 1
                            return

                        # Freshness window — bounds the replay window of
                        # a stolen signed announce. Default 300s, tunable
                        # via config.capability_announce_max_age.
                        max_age = float(getattr(
                            self.config, "capability_announce_max_age", 300.0,
                        ))
                        age = time.time() - float(announced_at)
                        if age > max_age:
                            logger.info(
                                "CAPABILITY_ANNOUNCE from %s about %s "
                                "stale (%.1fs > %.1fs); dropping",
                                peer_id, origin, age, max_age,
                            )
                            if self._audit:
                                try:
                                    self._audit.log(
                                        EVENT_CAPABILITY_ANNOUNCE_BAD_SIG,
                                        {
                                            "peer_id": peer_id,
                                            "origin": origin,
                                            "reason": "stale",
                                            "age": age,
                                        },
                                    )
                                except Exception:
                                    pass
                            self.metrics.capability_announce_bad_signature_total += 1
                            return

                        # Replay-dedup — second copy of the same
                        # ``(origin, announced_at)`` is a no-op.
                        dedup_key = f"{origin}|{float(announced_at):.6f}"
                        if dedup_key in self._announce_dedup:
                            self._announce_dedup.move_to_end(dedup_key)
                            return
                        self._announce_dedup[dedup_key] = time.time()
                        while len(self._announce_dedup) > self._ANNOUNCE_DEDUP_MAX:
                            self._announce_dedup.popitem(last=False)

                        # Verify signature against origin's pinned key.
                        try:
                            from nacl.signing import VerifyKey
                            vk = VerifyKey(base64.b64decode(origin_pub_b64))
                            try:
                                signature = base64.b64decode(signature_b64)
                            except (ValueError, TypeError) as e:
                                raise ValueError(f"malformed signature b64: {e}")
                            canonical = ew_protocol.canonical_capability_announce_bytes(
                                origin=origin,
                                capabilities=caps,
                                announced_at=float(announced_at),
                                version=int(version),
                            )
                            ew_crypto.verify_detached_with_context(
                                vk,
                                ew_crypto.SIG_CTX_CAPABILITY_ANNOUNCE,
                                canonical,
                                signature,
                            )
                        except (nacl_exceptions.BadSignatureError, ValueError, TypeError) as e:
                            logger.warning(
                                "CAPABILITY_ANNOUNCE from %s about %s — "
                                "signature verification FAILED (%s)",
                                peer_id, origin, e,
                            )
                            if self._audit:
                                try:
                                    self._audit.log(
                                        EVENT_CAPABILITY_ANNOUNCE_BAD_SIG,
                                        {
                                            "peer_id": peer_id,
                                            "origin": origin,
                                            "reason": "bad-sig",
                                        },
                                    )
                                except Exception:
                                    pass
                            self.metrics.capability_announce_bad_signature_total += 1
                            return

                        # Signature verified. Cache the envelope verbatim so
                        # the announce loop can replay it to other neighbors
                        # within the freshness window.
                        try:
                            self._signed_announce_cache[origin] = {
                                "payload": bytes(payload) if isinstance(payload, (bytes, bytearray)) else payload.encode("utf-8"),
                                "announced_at": float(announced_at),
                            }
                            self._signed_announce_cache.move_to_end(origin)
                            while len(self._signed_announce_cache) > self._SIGNED_ANNOUNCE_CACHE_MAX:
                                self._signed_announce_cache.popitem(last=False)
                        except Exception as e:
                            logger.debug("signed-announce cache update failed: %s", e)

                    if origin != self.node_id:
                        delta = self._capabilities.learn_remote(origin, caps)
                        if delta:
                            # Persist learned remote caps so a daemon
                            # restart doesn't lose them. Wrapped in
                            # try/except because announce-path latency
                            # must not be coupled to disk health.
                            try:
                                self._capabilities.save()
                            except Exception:
                                pass
                            if self._audit:
                                try:
                                    self._audit.log(EVENT_CAPABILITY_LEARNED, {
                                        "origin": origin,
                                        "capabilities": list(caps),
                                    })
                                except Exception:
                                    pass
                        # v0.8.5.6: bind the observed capability set to the
                        # origin peer's pinned trust record. If it differs
                        # from the last-accepted baseline, demote the peer
                        # to pending-cap-change and emit an audit event.
                        # Only do this for peers that are already pinned
                        # (i.e. this code has completed TOFU with them) — otherwise
                        # there's no trust record to bind against.
                        if isinstance(caps, list):
                            try:
                                ts = self._open_trust_store()
                                if ts is not None and ts.get_peer(origin) is not None:
                                    result = ts.observe_capabilities(origin, caps)
                                    self._handle_cap_observation(
                                        origin, result, trust_store=ts,
                                    )
                            except Exception as e:
                                logger.debug(
                                    "cap-binding observe failed for %s: %s",
                                    origin, e,
                                )
                except Exception as e:
                    logger.debug("Bad CAPABILITY_ANNOUNCE from %s: %s", peer_id, e)
            return

        # v0.4: Relay decision — if the destination is not us (and not a
        # broadcast), forward via the mesh router. Forwarded messages are
        # NOT bus-published locally and NOT stored in inbound history.
        if (frame.destination
                and frame.destination not in (self.node_id, "*", "")
                and self._mesh is not None):
            peer_state.last_seen = time.time()
            try:
                await self._mesh.relay_message(
                    frame, from_peer=peer_id, transport=transport,
                )
            except Exception as e:
                logger.warning("Relay failed for %s -> %s: %s",
                               frame.source, frame.destination, e)
            return

        # v0.4: E2E unseal — if the destination is us and the frame carries
        # an e2e_payload, decrypt it with this listener's identity key. Replace
        # frame.payload (and the local payload variable) with the plaintext
        # so subsequent handlers see the original message body.
        if frame.e2e_payload is not None and self._keypair is not None:
            try:
                from ironmesh import mesh_crypto
                # v0.9.4 Phase 2: prefer the master-seed X25519 secret
                # when available; falls back to legacy derivation on
                # legacy v1/v2 keystores.
                plaintext = mesh_crypto.unseal_from_source(
                    frame.e2e_payload,
                    self._keypair.ed25519_secret,
                    my_x25519_secret=self._keypair.get_x25519_secret()
                        if self._keypair.x25519_seed is not None
                        else None,
                )
                frame.payload = plaintext
                payload = plaintext
            except Exception as e:
                logger.warning("E2E unseal failed from source %s: %s",
                               frame.source, e)
                if self._audit:
                    try:
                        from ironmesh.audit import EVENT_E2E_DECRYPT_FAILURE
                        self._audit.log(EVENT_E2E_DECRYPT_FAILURE, {
                            "source": frame.source, "msg_id": msg_id,
                        })
                    except Exception:
                        pass
                return

        # v0.8.5: pending-trust message gate. Only user-payload frames are
        # gated — control frames (REKEY/HEARTBEAT/etc.) short-circuit
        # earlier in this function. The originator the code judge against is the
        # frame source if present (so relayed messages from a pending peer
        # still get gated), otherwise the immediate peer.
        gate_action = await self._gate_inbound_msg(peer_id, frame)
        if gate_action == "queue":
            peer_state.last_seen = time.time()
            return
        if gate_action == "drop":
            peer_state.last_seen = time.time()
            return
        # action == "deliver" → fall through to normal handling

        # Store in history
        await self._db.store_message(
            msg_id=msg_id, source=peer_id,
            source_display=peer_id,
            destination=self.node_id, msg_type=msg_type,
            payload=payload, direction="inbound",
            priority="NORMAL",
        )

        # Publish to bus
        self.bus.publish(msg_type, {"peer_id": peer_id, "msg_id": msg_id,
                                     "type": msg_type, "payload": payload})

        # Update peer state
        peer_state.messages_received += 1
        peer_state.last_seen = time.time()
        peer_state.bytes_received_total += len(payload) if payload else 0
        self.metrics.messages_received += 1

        # v0.7.2: sample message lifetime for the Prometheus summary.
        # Frame timestamps are wall-clock seconds — negative/outlier values
        # from clock skew are clamped at the recv side.
        try:
            ts = getattr(frame, "timestamp", None)
            if ts is not None:
                delta = time.time() - float(ts)
                if 0.0 <= delta <= 300.0:  # clamp 5 min max
                    self._lifetime_samples.append(delta)
        except Exception:
            pass

        # Fire hook
        if self._hooks:
            try:
                await self._hooks.fire("post_receive", {
                    "peer_id": peer_id, "msg_type": msg_type,
                    "msg_id": msg_id, "payload": payload,
                })
            except Exception:
                pass

        # Handle specific message types
        if msg_type == ew_protocol.MessageType.KEY_ROTATE:
            logger.info("Peer %s rotated keys — re-handshake required", peer_id)
            peer_state.transition(ew_protocol.PeerState.Status.HANDSHAKING)
            return

        if msg_type == ew_protocol.MessageType.REKEY_REQUEST:
            await self._handle_rekey_request(peer_id, payload, peer_state)
            return

        if msg_type == ew_protocol.MessageType.REKEY_RESPONSE:
            await self._handle_rekey_response(peer_id, payload, peer_state)
            return

        if msg_type == ew_protocol.MessageType.REVOCATION:
            await self._handle_revocation(peer_id, payload, peer_state)
            return

        if msg_type == ew_protocol.MessageType.ACK:
            logger.debug("ACK from %s for %s", peer_id, msg_id)
            return

        if msg_type == ew_protocol.MessageType.PING:
            await self._send_encrypted_control(
                peer_id, ew_protocol.MessageType.PONG
            )
            return

        if msg_type == ew_protocol.MessageType.PONG:
            sent_at = self._pending_pings.pop(peer_id, None)
            if sent_at is not None:
                rtt_ms = (time.monotonic() - sent_at) * 1000
                peer_state.latency_ms = rtt_ms
            return

        logger.info("From %s [%s]: %s", peer_id, msg_type, msg_id)

    # ------------------------------------------------------------------
    # Encrypted control messages (#3, #4: no plaintext after handshake)
    # ------------------------------------------------------------------

    async def _send_encrypted_control(self, peer_id: str, msg_type: str,
                                       extra_fields: dict = None):
        """Send an encrypted + signed control message via binary frame.

        All post-handshake messages use binary wire format — no plaintext
        or JSON metadata exposed on the wire.
        """
        control_payload = {"type": msg_type, "from": self.node_id}
        if extra_fields:
            control_payload.update(extra_fields)
        payload_bytes = json.dumps(control_payload, separators=(",", ":")).encode()

        frame = ew_protocol.Frame(
            msg_type=msg_type,
            payload=payload_bytes,
            source=self.node_id,
        )
        await self._send_frame(peer_id, frame)

    # ------------------------------------------------------------------
    # Sending messages
    # ------------------------------------------------------------------

    async def send_message(self, to_node: str, msg_type: str, payload: bytes,
                          priority: str = "NORMAL") -> str:
        """Send a message to a peer. Direct → routed → queued, in that order.

        Order of delivery attempts:
            1. Direct WebSocket if peer is connected with active session.
            2. v0.4 mesh route if MeshRouter has a known next hop.
            3. Offline queue (legacy fallback).
        """
        with _otel_span(
            "ironmesh.send_message",
            **{
                "ironmesh.peer.node_id": to_node[:32] if to_node else "",
                "ironmesh.message.type": msg_type,
                "ironmesh.message.priority": priority,
                "ironmesh.message.size_bytes": len(payload) if payload else 0,
            },
        ) as _sp:
            return await self._send_message_inner(
                to_node, msg_type, payload, priority, _sp,
            )

    async def _send_message_inner(self, to_node, msg_type, payload, priority,
                                  _otel_sp=None):
        msg_id = str(uuid.uuid4())

        # Store in history
        await self._db.store_message(
            msg_id=msg_id, source=self.node_id, source_display=self.name,
            destination=to_node, msg_type=msg_type, payload=payload,
            direction="outbound", priority=priority,
        )

        peer_state = self.peers.get(to_node)
        ws = self.ws_clients.get(to_node)

        # Fire pre-send hook (best effort, regardless of path)
        if self._hooks:
            try:
                await self._hooks.fire("pre_send", {
                    "peer_id": to_node, "msg_type": msg_type,
                    "msg_id": msg_id, "payload": payload,
                })
            except Exception:
                pass

        # v0.4: Build a routing-aware Frame. If the code can look up the
        # destination's identity public key, e2e-seal the payload so relays
        # cannot read it.
        e2e_payload = None
        dest_pubkey = self._lookup_dest_identity(to_node)
        if dest_pubkey is not None and to_node != self.node_id:
            try:
                from ironmesh import mesh_crypto
                # v0.9.4 Phase 2: prefer the peer's advertised X25519
                # identity public when their HELLO binding verified;
                # otherwise legacy ed25519_to_curve25519 derivation
                # runs inside seal_to_destination.
                dest_x25519 = None
                peer_state_lookup = self.peers.get(to_node)
                if peer_state_lookup is not None:
                    dest_x25519 = getattr(
                        peer_state_lookup, "x25519_identity_public", None,
                    )
                e2e_payload = mesh_crypto.seal_to_destination(
                    payload, dest_pubkey, dest_x25519_pub=dest_x25519,
                )
            except Exception as e:
                logger.debug("E2E seal failed for %s: %s — falling back to per-hop only",
                             to_node, e)
                e2e_payload = None

        # v0.5.2: LoRa QoS — compress large payloads for RNS peers
        compressed = False
        if (peer_state and peer_state.transport_type == "rns"
                and self._lora_max_payload > 0
                and len(payload) > self._lora_max_payload):
            self.metrics.lora_oversized_messages += 1
            import gzip
            try:
                shrunk = gzip.compress(payload, compresslevel=9)
                if len(shrunk) <= self._lora_max_payload:
                    logger.info("LoRa QoS: compressed %d -> %d bytes for %s",
                                len(payload), len(shrunk), to_node)
                    payload = shrunk
                    compressed = True
                else:
                    logger.warning("LoRa QoS: payload %d bytes (compressed %d) "
                                   "exceeds max %d for %s",
                                   len(payload), len(shrunk),
                                   self._lora_max_payload, to_node)
            except Exception as e:
                logger.warning("LoRa QoS compression failed: %s", e)

        frame = ew_protocol.Frame(
            msg_type=msg_type,
            payload=payload,
            msg_id=msg_id,
            source=self.node_id,
            destination=to_node,
            priority=priority,
        )
        frame.e2e_payload = e2e_payload
        frame.ttl = self.config.max_hops
        frame.hops = []
        if compressed:
            frame.routing["compressed"] = True

        # 1. Direct WebSocket
        if ws and peer_state and peer_state.session_key:
            try:
                await self._send_frame(to_node, frame)
                peer_state.messages_sent += 1
                peer_state.bytes_sent_total += len(payload) if payload else 0
                self.metrics.messages_sent += 1
                self.metrics.messages_delivered += 1
                logger.info("Sent %s -> %s [%s] (direct)", msg_type, to_node, msg_id)
                return msg_id
            except Exception as e:
                peer_state.record_retry("direct_send_failed")
                logger.warning("Direct send failed to %s, trying mesh: %s", to_node, e)

        # 2. v0.4 routed delivery via MeshRouter
        if self._mesh is not None:
            next_hop = self._mesh.get_route(to_node)
            if next_hop is not None and next_hop != to_node:
                try:
                    await self._send_frame(next_hop, frame)
                    # v0.7.2: credit the NEXT-HOP peer state with bytes + counter
                    # parity with direct send path so /api/mesh_stats is accurate
                    next_peer = self.peers.get(next_hop)
                    if next_peer is not None:
                        next_peer.bytes_sent_total += len(payload) if payload else 0
                    self.metrics.messages_sent += 1
                    self.metrics.messages_delivered += 1
                    logger.info("Sent %s -> %s via %s [%s] (routed)",
                                msg_type, to_node, next_hop, msg_id)
                    return msg_id
                except Exception as e:
                    # Record retry against next-hop and ultimate destination
                    # for visibility into where the delivery broke.
                    next_peer = self.peers.get(next_hop)
                    if next_peer is not None:
                        next_peer.record_retry("routed_send_failed")
                    if peer_state is not None:
                        peer_state.record_retry("routed_send_failed")
                    logger.warning("Routed send via %s failed: %s", next_hop, e)

        # 3. Offline queue (legacy fallback)
        self.metrics.messages_failed += 1
        if peer_state is not None:
            peer_state.record_retry("queued_offline")
        admitted = await self._db.queue_for_peer(
            to_node, msg_id, self.node_id, msg_type, payload, priority,
        )
        if admitted is False:
            # v0.7.2: offline queue refused admission (cap hit + all higher
            # priority). Surface as an explicit failure so the caller can
            # re-attempt later with CRITICAL or back off.
            if peer_state is not None:
                peer_state.record_retry("queue_full_dropped")
            logger.warning(
                "Offline queue refused %s for %s (cap hit, lower priority than all queued)",
                msg_id, to_node,
            )
        return msg_id

    def _get_peer_identity_key(self, node_id: str) -> Optional[str]:
        """Return base64 Ed25519 identity public key for ``node_id``, or None.

        Used by signed CAPABILITY_ANNOUNCE verification — needs the
        base64 form so we can pass it through nacl `VerifyKey(base64.b64decode(...))`.
        Consults the live peer registry first (live `identity_public` is
        already decoded bytes — re-encode for the caller); falls back to
        the on-disk trust store, where the pubkey is stored base64. Returns
        None if neither source has the origin pinned — caller's contract
        is to drop the unverifiable announce.
        """
        peer = self.peers.get(node_id)
        if peer is not None and getattr(peer, "identity_public", None):
            try:
                return base64.b64encode(peer.identity_public).decode("ascii")
            except (TypeError, ValueError):
                pass
        try:
            ts = self._open_trust_store()
            if ts is not None:
                record = ts.get_peer(node_id)
                if isinstance(record, dict):
                    pub = record.get("pubkey")
                    if isinstance(pub, str) and pub:
                        return pub
        except (OSError, ValueError, RuntimeError) as e:
            logger.debug(
                "trust-store lookup for %s failed: %s", node_id, e,
            )
        return None

    def _lookup_dest_identity(self, node_id: str) -> Optional[bytes]:
        """Return the destination's Ed25519 identity public key, or None.

        Checks the live peer registry first (for direct peers this code has handshook
        with), then falls back to the TOFU pinned peer table. Returns None for
        unknown destinations — caller must then fall back to per-hop crypto only.
        """
        peer = self.peers.get(node_id)
        if peer is not None and getattr(peer, "identity_public", None):
            return peer.identity_public
        # TOFU pinned peers — keyed by agent name, value carries fingerprint
        # which is the same identifier as node_id when the code look up by name.
        # Use constant-time comparison even though both sides are public data:
        # auditors flag plain `==` on identity-comparison surfaces uniformly,
        # and using `compare_digest` here keeps the trust-evaluation paths
        # internally consistent (the rest of the file already uses it).
        for name, info in self._pinned_peers.items():
            stored_fp = info.get("fingerprint")
            if not isinstance(stored_fp, str):
                continue
            if hmac.compare_digest(stored_fp, node_id):
                pub = info.get("identity_public")
                if pub:
                    return pub
        return None

    async def _send_frame(self, peer_id: str, frame: ew_protocol.Frame):
        """Send a Frame to a connected peer using binary wire format.

        Binary format hides message metadata (type, source, msg_id) inside
        the encrypted payload — only sequence, timestamp, and msg_id hash
        are visible on the wire. Signature is appended as 64-byte Ed25519.
        """
        ws = self.ws_clients.get(peer_id)
        peer_state = self.peers.get(peer_id)
        if not ws or not peer_state:
            return

        if not peer_state.session_key:
            logger.warning("Cannot send frame to %s — no session key", peer_id)
            return

        frame.sequence = peer_state.next_sequence()

        # v0.4: Only attach an inner source signature when the code are the original
        # source. Relays must not re-sign — they preserve the source signature
        # set by the originator. encrypt_and_serialize is also a no-op when
        # frame.source_signature is already set, but the code make the intent
        # explicit here.
        source_signing_key = None
        if frame.source == self.node_id and frame.source_signature is None:
            source_signing_key = self._keypair.get_signing_key()

        try:
            raw = frame.encrypt_and_serialize(
                peer_state.session_key,
                signing_key=self._keypair.get_signing_key(),
                source_signing_key=source_signing_key,
            )
            # v0.7.2: per-peer bandwidth throttle. Block briefly if the peer
            # would exceed its allocated bytes/sec; drop with audit if the
            # required wait exceeds the max_wait ceiling (prevents unbounded
            # buffering under attack).
            if not await self._gate_peer_bandwidth(peer_id, len(raw)):
                # Dropped — don't increment bytes_sent. Counter already
                # incremented inside the gate so /metrics is accurate.
                peer_state.record_retry("bandwidth_throttled")
                return
            # v0.6.1: 5-second send timeout prevents blocked sockets from
            # hanging the heartbeat loop. On timeout the code treat the peer as
            # disconnected and trigger cleanup.
            try:
                await asyncio.wait_for(ws.send(raw), timeout=5.0)
                self.metrics.bytes_sent += len(raw)
            except asyncio.TimeoutError:
                logger.warning("Send timeout to %s — marking offline", peer_id)
                self.ws_clients.pop(peer_id, None)
                if peer_id in self.peers:
                    self.peers[peer_id].transition(ew_protocol.PeerState.Status.OFFLINE)
                    self.peers[peer_id].session_key = None
                try:
                    await ws.close()
                except Exception:
                    pass
        except Exception as e:
            # v0.9.2: ConnectionClosed / ConnectionClosedOK during normal
            # shutdown is the expected termination path — every queued
            # route-announce hits a peer whose WS just closed. Downgrade
            # to DEBUG for those cases so a graceful 50-node shutdown
            # doesn't flood operator logs with WARNINGs. Unexpected
            # errors still surface at WARNING.
            if isinstance(e, websockets.ConnectionClosed):
                logger.debug("Send to %s on closed connection: %s", peer_id, e)
            else:
                logger.warning("Failed to send frame to %s: %s", peer_id, e)
            # v0.6.1: on send error, also transition offline to avoid spamming
            # "failed to send" on a dead connection.
            if peer_id in self.peers and self.peers[peer_id].is_online:
                self.ws_clients.pop(peer_id, None)
                self.peers[peer_id].transition(ew_protocol.PeerState.Status.OFFLINE)
                self.peers[peer_id].session_key = None

    # ------------------------------------------------------------------
    # Pending message flush
    # ------------------------------------------------------------------

    async def _flush_pending(self, peer_id: str):
        """Flush all pending messages for a newly-connected peer."""
        try:
            pending = await self._db.get_pending_for_peer(peer_id)
            if not pending:
                return

            logger.info("Flushing %d pending messages to %s", len(pending), peer_id)
            peer_state = self.peers.get(peer_id)
            for msg in pending:
                frame = ew_protocol.Frame(
                    msg_type=msg["msg_type"],
                    payload=msg["payload"],
                    source=msg["source"],
                    destination=peer_id,
                    priority=msg["priority"],
                )
                await self._send_frame(peer_id, frame)
                await self._db.mark_delivered(peer_id, msg["msg_id"])
                # v0.9.0: parity with direct + routed send paths — the
                # flush path previously bypassed both per-peer and
                # daemon-level counters, so messages_sent_total
                # under-reported any traffic that went through the
                # offline-queue path. Caught during the v0.9.0
                # stress run on the live mesh.
                payload_len = len(msg.get("payload") or b"")
                if peer_state is not None:
                    peer_state.messages_sent += 1
                    peer_state.bytes_sent_total += payload_len
                self.metrics.messages_sent += 1
                self.metrics.messages_delivered += 1
            logger.info("All pending messages delivered to %s", peer_id)
        except Exception as e:
            logger.warning("Error flushing pending messages for %s: %s", peer_id, e)

    # ------------------------------------------------------------------
    # v0.9.1: unified transport selection — Agent SDK + OpenClaw + ACP/A2A
    # ------------------------------------------------------------------
    #
    # The daemon already has three transport options for outbound:
    #   * WebSocket (always-on)
    #   * RNS Link  (when --reticulum)
    #   * LXMF      (when --lxmf)
    #
    # Callers historically had to know which transport a given peer was
    # reachable on and address them by node_id. The unified API below
    # collapses all three into a single "send to alice" call:
    #
    #   1. If an IronMesh peer named "alice" is currently online, send
    #      via whatever transport the existing session uses (WS or RNS).
    #   2. Else if an "alice" announce was heard over RNS but no Link
    #      has been established yet, auto-establish the Link and send.
    #   3. Else if "alice" looks like an LXMF destination hash and the
    #      LXMF listener is running, send via LXMF.
    #   4. Else raise ValueError — no reachable transport.
    #
    # All four agent-facing surfaces (Agent SDK, OpenClaw channel,
    # ironmesh-acp, ironmesh-a2a) end up calling this single resolver,
    # so adding a transport in the future (e.g. Yggdrasil) is a one-
    # site change rather than a per-adapter rewrite.

    def _find_online_peer_by_name(self, name: str) -> Optional[str]:
        """Return the node_id of an online peer with the given agent name."""
        if not name:
            return None
        for pid, state in self.peers.items():
            if not state.is_online:
                continue
            if getattr(state, "agent_name", None) == name:
                return pid
        return None

    def _find_rns_discovered_by_name(self, name: str) -> Optional[dict]:
        """Return the RNS announce-discovered entry for an agent name."""
        if not name:
            return None
        # Snapshot — RNS announce handler mutates this dict on the RNS
        # Transport thread.
        for entry in list(self._rns_discovered.values()):
            if entry.get("name") == name:
                return entry
        return None

    @staticmethod
    def _looks_like_lxmf_hash(value: str) -> bool:
        """Heuristic: 32-byte (64-hex-char) destination hashes look like LXMF."""
        if not isinstance(value, str):
            return False
        clean = value.strip().replace(":", "").replace(" ", "")
        if len(clean) != 32 and len(clean) != 64:
            return False
        try:
            int(clean, 16)
            return True
        except ValueError:
            return False

    def unified_peers(self) -> list:
        """Merged view of every reachable peer across all transports.

        Returns one entry per peer with a ``reachable_via`` list naming
        the transports that can reach them right now. The same peer may
        appear via multiple transports (e.g. discovered via RNS announce
        AND currently connected via WebSocket). The Agent SDK exposes
        this as the canonical peer list.
        """
        out: Dict[str, Dict[str, Any]] = {}

        # Online peers via WS or RNS Link
        for pid, state in self.peers.items():
            if not state.is_online:
                continue
            name = getattr(state, "agent_name", None)
            entry = out.setdefault(pid, {
                "node_id": pid, "name": name, "reachable_via": [],
                "transport": getattr(state, "transport_type", None),
                "rns_dest_hash": getattr(state, "rns_dest_hash", None),
                "estimated_rtt_ms": (
                    getattr(state, "rns_estimated_rtt_ms", None)
                    or state.latency_ms
                ),
                "estimated_bps": getattr(state, "rns_estimated_bps", None),
                "rns_hops": getattr(state, "rns_hops", None),
            })
            entry["reachable_via"].append(state.transport_type)

        # RNS-discovered peers not yet connected. Snapshot — RNS
        # announce handler mutates this dict on the RNS Transport thread.
        for entry in list(self._rns_discovered.values()):
            node_id = entry.get("node_id")
            name = entry.get("name")
            if not node_id:
                continue
            existing = out.get(node_id)
            if existing is not None:
                if "rns_announce" not in existing["reachable_via"]:
                    existing["reachable_via"].append("rns_announce")
                # Backfill announce-only metadata onto the connected entry
                existing.setdefault("rns_dest_hash", entry.get("dest_hash"))
                existing.setdefault("rns_hops", entry.get("hops"))
                continue
            out[node_id] = {
                "node_id": node_id,
                "name": name,
                "reachable_via": ["rns_announce"],
                "transport": None,
                "rns_dest_hash": entry.get("dest_hash"),
                "rns_hops": entry.get("hops"),
                "estimated_rtt_ms": None,
                "estimated_bps": None,
            }

        return list(out.values())

    async def send_to_name(self, name: str, payload,
                            msg_type: str = "MSG",
                            priority: str = "NORMAL") -> dict:
        with _otel_span(
            "ironmesh.send_to_name",
            **{
                "ironmesh.peer.name": name,
                "ironmesh.message.type": msg_type,
                "ironmesh.message.priority": priority,
                "ironmesh.message.size_bytes": (
                    len(payload) if isinstance(payload, (bytes, bytearray)) else len(str(payload))
                ),
            },
        ):
            return await self._send_to_name_impl(name, payload, msg_type, priority)

    async def _send_to_name_impl(self, name: str, payload,
                                  msg_type: str = "MSG",
                                  priority: str = "NORMAL") -> dict:
        """Unified send: pick the best available transport for ``name``.

        Tier order: existing online peer → auto-Link an RNS-discovered
        peer → LXMF if ``name`` is a destination hash. Returns a small
        dict describing which transport was used so callers can log /
        retry intelligently.

        Raises ``ValueError`` if no transport can reach the name.
        """
        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        else:
            payload_bytes = payload

        # Tier 1: existing online peer (WS or RNS Link)
        node_id = self._find_online_peer_by_name(name)
        if node_id:
            msg_id = await self.send_message(node_id, msg_type,
                                              payload_bytes, priority)
            transport = getattr(
                self.peers[node_id], "transport_type", "websocket",
            )
            return {"transport": transport, "target": node_id,
                    "msg_id": msg_id, "tier": 1}

        # Tier 2: RNS-discovered, not yet connected → auto-Link.
        #
        # Subtle correctness point: ``_connect_and_track_rns`` calls
        # ``_do_client_handshake`` which runs an indefinite message
        # loop AFTER the handshake — it only returns when the
        # connection closes. The resolver therefore cannot await it directly
        # here (discovered during testing bug — `send_to_name` would never
        # complete until the auto-Link tore down at idle timeout).
        #
        # Instead: kick the connect off as a background task, then
        # poll self.peers for the expected node_id to appear. When it
        # does, the regular `send_message` path takes over and the
        # call returns. The background task continues to own the message
        # loop for inbound traffic, exactly like a normal connection.
        rns_entry = self._find_rns_discovered_by_name(name)
        if rns_entry and self._reticulum is not None:
            dest_hash = rns_entry.get("dest_hash")
            expected_node_id = rns_entry.get("node_id")
            if dest_hash and expected_node_id:
                logger.info(
                    "send_to_name: auto-establishing RNS Link to %s for first send",
                    name,
                )
                if expected_node_id not in self.peers or not self.peers[expected_node_id].is_online:
                    asyncio.ensure_future(self._connect_and_track_rns(dest_hash))
                # Poll for the peer to come online. Connect time is
                # path resolution (often instant on LAN, up to ~10 s
                # on LoRa) plus the IronMesh handshake (~1 s on LAN,
                # several seconds on LoRa). 30 s gives a generous
                # ceiling without making the SDK feel hung.
                deadline = time.monotonic() + 30.0
                while time.monotonic() < deadline:
                    state = self.peers.get(expected_node_id)
                    if state is not None and state.is_online and state.session_key:
                        msg_id = await self.send_message(
                            expected_node_id, msg_type, payload_bytes, priority,
                        )
                        return {"transport": "rns", "target": expected_node_id,
                                "msg_id": msg_id, "tier": 2}
                    await asyncio.sleep(0.2)
                logger.warning(
                    "send_to_name: timed out waiting for %s (node=%s) to come online via RNS",
                    name, expected_node_id,
                )

        # Tier 3: LXMF — if name is a destination hash and LXMF is up
        if self._lxmf is not None and self._looks_like_lxmf_hash(name):
            text = payload_bytes.decode("utf-8", errors="replace")
            ok = await self._lxmf.send_lxmf_to(name, text)
            if ok:
                return {"transport": "lxmf", "target": name,
                        "msg_id": None, "tier": 3}

        raise ValueError(
            f"No reachable transport for peer name={name!r}. "
            f"Tried: online peers, {len(self._rns_discovered)} RNS-discovered, "
            f"LXMF={'available' if self._lxmf else 'disabled'}."
        )

    # ------------------------------------------------------------------
    # v0.9.2 chunk E: capability-aware routing
    # ------------------------------------------------------------------
    #
    # `send_to_capability(pattern, payload)` resolves a capability glob
    # to one (or many) qualifying peers and dispatches via the same
    # transport-selection layer that backs `send_to_name`. Three
    # strategies are supported:
    #
    #   first   — pick the first matching peer (lowest measured RTT
    #             among online peers, falling back to enumeration order
    #             for offline-but-discovered)
    #   random  — pick a random match (load distribution)
    #   all     — fan-out to every match in parallel; return list of
    #             per-target results
    #
    # The local node is NEVER picked even when it satisfies the
    # capability — agents calling this always want a remote peer.

    def _capability_candidates(self, pattern: str) -> list:
        """Return [(node_id, capability)] of remote peers matching the pattern."""
        if self._capabilities is None:
            return []
        candidates = []
        for node_id, cap in self._capabilities.find(pattern):
            if node_id == self.node_id:
                continue  # never route to self
            candidates.append((node_id, cap))
        return candidates

    def _rank_candidates(self, candidates: list, strategy: str) -> list:
        """Order candidates by the chosen strategy. Returns the ordered list."""
        if not candidates:
            return []
        if strategy == "random":
            import random as _random
            ordered = list(candidates)
            _random.shuffle(ordered)
            return ordered
        if strategy == "all":
            return list(candidates)
        # 'first' — prefer online peers with the lowest measured RTT
        def _key(entry):
            node_id, _cap = entry
            state = self.peers.get(node_id)
            online = state is not None and state.is_online
            rtt = (state.latency_ms if online and state.latency_ms is not None else float("inf"))
            return (0 if online else 1, rtt)
        return sorted(candidates, key=_key)

    async def send_to_capability(self, pattern: str, payload,
                                  msg_type: str = "MSG",
                                  priority: str = "NORMAL",
                                  strategy: str = "first") -> dict:
        with _otel_span(
            "ironmesh.send_to_capability",
            **{
                "ironmesh.cap.pattern": pattern,
                "ironmesh.cap.strategy": strategy,
                "ironmesh.message.type": msg_type,
                "ironmesh.message.priority": priority,
            },
        ):
            return await self._send_to_capability_impl(
                pattern, payload, msg_type, priority, strategy,
            )

    async def _send_to_capability_impl(self, pattern: str, payload,
                                         msg_type: str = "MSG",
                                         priority: str = "NORMAL",
                                         strategy: str = "first") -> dict:
        """Send to any peer advertising a capability matching ``pattern``.

        ``pattern`` is an fnmatch-style glob (e.g. ``"llm:*"``,
        ``"tool:filesystem"``). The strategy controls fan-out:

          * ``"first"`` — pick the best-ranked match (default). Returns
            the same descriptor shape as :meth:`send_to_name` plus a
            ``capability`` field naming the matched cap.
          * ``"random"`` — pick a random match. Same return shape.
          * ``"all"`` — dispatch to every match in parallel. Returns
            ``{"transport": "fanout", "results": [<per-target descriptors>],
              "capability": pattern}``.

        Raises ``ValueError`` if no peer advertises a matching
        capability (or all matches fail when strategy=all).
        """
        self.metrics.capability_routes_attempted += 1
        candidates = self._capability_candidates(pattern)
        if not candidates:
            self.metrics.capability_routes_no_match += 1
            raise ValueError(
                f"No peer advertises a capability matching {pattern!r}"
            )
        ordered = self._rank_candidates(candidates, strategy)

        if strategy == "all":
            results = []
            for node_id, cap in ordered:
                state = self.peers.get(node_id)
                name = getattr(state, "agent_name", None) if state else None
                target = name or node_id
                try:
                    res = await self.send_to_name(target, payload,
                                                   msg_type=msg_type,
                                                   priority=priority)
                    res["capability"] = cap
                    results.append(res)
                except Exception as e:
                    results.append({"target": target, "capability": cap,
                                    "error": f"{type(e).__name__}: {e}"})
            success = sum(1 for r in results if "error" not in r)
            if success == 0:
                raise ValueError(
                    f"All {len(results)} candidates for {pattern!r} failed"
                )
            self.metrics.capability_routes_succeeded += 1
            return {"transport": "fanout", "results": results,
                    "capability": pattern, "success": success,
                    "total": len(results)}

        # 'first' or 'random' — try ordered, returning on first success
        last_err = None
        for node_id, cap in ordered:
            state = self.peers.get(node_id)
            name = getattr(state, "agent_name", None) if state else None
            target = name or node_id
            try:
                res = await self.send_to_name(target, payload,
                                               msg_type=msg_type,
                                               priority=priority)
                res["capability"] = cap
                res["strategy"] = strategy
                self.metrics.capability_routes_succeeded += 1
                return res
            except Exception as e:
                last_err = e
                logger.debug(
                    "send_to_capability(%r) target %s failed: %s — trying next",
                    pattern, target, e,
                )
        raise ValueError(
            f"No reachable peer for capability {pattern!r} "
            f"(tried {len(ordered)} candidates; last error: {last_err})"
        )
