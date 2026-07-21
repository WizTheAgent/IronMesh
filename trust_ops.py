"""Peer trust operations for the IronMesh bridge daemon.

``TrustOpsMixin`` carries the ``BridgeDaemon`` methods that manage a
peer's standing over its lifetime: the signed revocation broadcast and
its inbound handler, the pending-trust message gate with its operator
actions (promote / block / list), capability-set continuity
observation, and the trust-on-first-use (TOFU) identity check that
runs during the handshake.

``bridge.py`` composes the mixin back into ``BridgeDaemon`` via
inheritance — all state lives on the daemon instance; this module
holds behavior only.
"""

import asyncio
import base64
import json
import logging
import time
from typing import Optional

import websockets

from ironmesh import (
    crypto as ew_crypto,
    protocol as ew_protocol,
)
from ironmesh.audit import (
    EVENT_INVITE_ACCEPTED,
    EVENT_INVITE_REJECTED,
    EVENT_MSG_GATED_DROP,
    EVENT_MSG_GATED_QUEUE,
    EVENT_PEER_BLOCKED,
    EVENT_PEER_CAP_ACCEPTED,
    EVENT_PEER_CAP_BASELINE,
    EVENT_PEER_CAP_BINDING_PARTIAL,
    EVENT_PEER_CAP_SET_CHANGED,
    EVENT_PEER_PROMOTED,
    EVENT_TOFU_MISMATCH,
    EVENT_TOFU_NEW,
)
from ironmesh.telemetry import emit_event as _otel_span_event

logger = logging.getLogger("ironmesh.bridge")


class TrustOpsMixin:
    """Revocation, pending-trust gating, and TOFU for ``BridgeDaemon``."""

    # ------------------------------------------------------------------
    # v0.6.0: Signed peer revocation broadcast
    # ------------------------------------------------------------------

    async def broadcast_revocation(self, target_node_id: str, reason: str = "") -> None:
        """Create a signed REVOCATION message and send to all online peers."""
        from ironmesh.trust import TrustStore
        timestamp = time.time()
        # Sign: target_node_id || revoker_node_id || str(int(timestamp))
        msg_bytes = (
            target_node_id + self.node_id + str(int(timestamp))
        ).encode()
        signature = ew_crypto.sign_detached(
            self._keypair.get_signing_key(), msg_bytes
        )
        payload = {
            "target_node_id": target_node_id,
            "revoker_node_id": self.node_id,
            "timestamp": int(timestamp),
            "reason": reason,
            "signature": base64.b64encode(signature).decode(),
        }
        # Also mark locally
        mac_key = self._keypair.ed25519_secret[:32]
        ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        ts.mark_revoked(target_node_id, self.node_id, timestamp, reason)
        # Broadcast to all online peers
        for pid, state in list(self.peers.items()):
            if not state.is_online or pid == target_node_id:
                continue
            try:
                await self._send_encrypted_control(
                    pid, ew_protocol.MessageType.REVOCATION, payload
                )
            except Exception as e:
                logger.warning("Failed to send REVOCATION to %s: %s", pid, e)
        logger.warning("Broadcast REVOCATION for %s (reason: %s)",
                       target_node_id, reason or "none")

    async def _handle_revocation(self, peer_id: str, payload, peer_state) -> None:
        """Validate and apply a signed REVOCATION message from a trusted peer."""
        try:
            data = json.loads(payload) if isinstance(payload, (bytes, str)) else {}
        except (json.JSONDecodeError, TypeError):
            return
        target = data.get("target_node_id")
        revoker = data.get("revoker_node_id")
        timestamp = data.get("timestamp")
        signature_b64 = data.get("signature")
        reason = data.get("reason", "")
        if not (target and revoker and timestamp and signature_b64):
            logger.warning("Invalid REVOCATION from %s: missing fields", peer_id)
            return

        # Revoker must match the immediate sender (simple trust model —
        # accept only revocations signed by the peer sending it).
        if revoker != peer_id:
            logger.warning("REVOCATION from %s signed by %s — rejecting",
                           peer_id, revoker)
            return

        # Verify signature using the sender's pinned Ed25519 identity key
        if not peer_state or not peer_state.identity_public:
            logger.warning("No pinned identity for revoker %s", revoker)
            return
        msg_bytes = (target + revoker + str(int(timestamp))).encode()
        try:
            from nacl.signing import VerifyKey
            vk = VerifyKey(peer_state.identity_public)
            ew_crypto.verify_detached(
                vk,
                msg_bytes,
                base64.b64decode(signature_b64),
            )
        except Exception as e:
            logger.warning("REVOCATION signature invalid from %s: %s", revoker, e)
            return

        # Apply locally
        from ironmesh.trust import TrustStore
        mac_key = self._keypair.ed25519_secret[:32]
        ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        ts.mark_revoked(target, revoker, float(timestamp), reason)
        logger.warning("Accepted REVOCATION for %s from %s (reason: %s)",
                       target, revoker, reason or "none")

        # If the target is currently connected, disconnect it
        if target in self.ws_clients:
            ws = self.ws_clients.pop(target, None)
            if ws:
                try:
                    await ws.close()
                except (websockets.exceptions.ConnectionClosed, OSError, RuntimeError):
                    # Revocation cleanup path — same pattern as the
                    # finally-block close. The connection is being
                    # forcibly terminated; transient close failures
                    # don't change the outcome.
                    pass
            if target in self.peers:
                self.peers[target].transition(ew_protocol.PeerState.Status.OFFLINE)
                self.peers[target].session_key = None

    # ------------------------------------------------------------------
    # v0.8.5: Pending-trust message gate
    # ------------------------------------------------------------------

    # Frame types eligible for the gate. Control frames (REKEY, HEARTBEAT,
    # ROUTE_*, CAPABILITY_*) handle themselves earlier in dispatch.
    _GATED_MSG_TYPES: frozenset = frozenset({"MSG", "REQ", "RESP"})

    async def _gate_inbound_msg(self, peer_id: str,
                                 frame: "ew_protocol.Frame") -> str:
        """Decide whether to deliver, queue, or drop an inbound user MSG.

        Returns one of:
          "deliver" — fall through to normal handling
          "queue"   — enqueued in pending_trust_messages, do not store/publish
          "drop"    — sender is blocked, silently dropped

        Gate is a no-op when ``require_message_promotion`` is False or the
        frame is not a user-payload type.

        Trust judgement keys on ``peer_id`` — the wire-authenticated peer
        whose identity key signed the frame. ``frame.source`` looks
        appealing for relayed messages but is unauthenticated metadata
        on both the JSON and binary paths (the peer's signature covers
        the encrypted payload, not the source field). A pending peer
        could otherwise forge ``source = self.node_id`` and bypass the
        gate via the self-loopback exemption below. v0.9.0 may add
        source_signature verification so relays gate on the originator.
        """
        if not self.config.require_message_promotion:
            return "deliver"
        if frame.msg_type not in self._GATED_MSG_TYPES:
            return "deliver"

        originator = peer_id
        # Don't gate ourselves (loopback / self-test).
        if originator == self.node_id:
            return "deliver"

        try:
            from ironmesh.trust import TrustStore
            mac_key = self._keypair.ed25519_secret[:32]
            ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        except Exception as e:
            # Fail closed: a broken trust store is a security event, not a
            # reason to bypass the gate. Drop pending-class traffic until
            # an operator fixes the file.
            logger.error("Trust gate: failed to open TrustStore (%s) — failing closed (drop)", e)
            return "drop"

        state = ts.get_trust_state(originator)
        if state == "trusted":
            return "deliver"
        if state == "blocked":
            self.metrics.messages_received_blocked = (
                getattr(self.metrics, "messages_received_blocked", 0) + 1
            )
            # v0.8.5.2: surface to operators via /api/mesh_stats.
            self._db.pending_trust_dropped += 1
            logger.debug("Trust gate: dropping MSG from blocked peer %s",
                         originator[:12])
            # v0.8.5.2: rate-limit audit writes for blocked peers to
            # 1 per peer per second. Without this cap, a malicious
            # blocked peer sending 1000 MSGs/sec could grow the audit
            # log at ~200 KB/sec, rotating older entries out within
            # ~4 minutes (MAX_ARCHIVES=5, max_bytes=10MB each). The
            # attacker could then use the flood to obscure earlier
            # forensic evidence. Counter-only path keeps per-peer
            # drop totals visible via /api/mesh_stats without growing
            # the audit chain.
            now = time.time()
            last_audit = self._gate_audit_last_write.get(originator, 0.0)
            if now - last_audit >= 1.0:
                self._gate_audit_last_write[originator] = now
                if self._audit:
                    try:
                        self._audit.log(EVENT_MSG_GATED_DROP, {
                            "peer_id": originator,
                            "msg_id": frame.msg_id,
                            "msg_type": frame.msg_type,
                            "reason": "blocked",
                        })
                    except Exception:
                        pass
            return "drop"

        # state == "pending" — queue the wire payload for later drain.
        try:
            queued = await self._db.queue_pending_trust(
                source_node_id=originator,
                msg_id=frame.msg_id,
                msg_type=frame.msg_type,
                payload=frame.payload,
                priority=getattr(frame, "priority", "NORMAL") or "NORMAL",
                cap=int(self.config.pending_trust_queue_cap or 100),
            )
            if queued:
                queued_count = await self._db.pending_trust_count_for(originator)
                # Surface to GUI clients so an operator can react.
                try:
                    await self._gui_broadcast({
                        "type": "pending_trust",
                        "source_node_id": originator,
                        "queued_count": queued_count,
                        "msg_id": frame.msg_id,
                    })
                except Exception:
                    pass
                if self._audit:
                    try:
                        self._audit.log(EVENT_MSG_GATED_QUEUE, {
                            "peer_id": originator,
                            "trust_state": "pending",
                            "msg_id": frame.msg_id,
                            "msg_type": frame.msg_type,
                            "queued_count": queued_count,
                        })
                    except Exception:
                        pass
        except Exception as e:
            # Storage failure is bad but should not crash dispatch — log
            # and fail-closed (drop) so a pending peer can't bypass the
            # gate by tripping a storage error.
            logger.error("Trust gate: queue_pending_trust failed for %s msg=%s: %s",
                         originator, frame.msg_id, e)
            return "drop"
        return "queue"

    async def promote_pending_peer(self, target_node_id: str) -> dict:
        """Operator action: promote a pending peer to trusted, drain its queue.

        Returns ``{"ok": bool, "drained": int, "error": str | None}``. The
        drained messages are re-stored in history and re-published to the
        bus in arrival order, exactly as if they had arrived just now —
        downstream consumers (GUI, MCP subscribers, OpenClaw) see them
        through the normal inbound path.
        """
        from ironmesh.trust import TrustStore
        try:
            mac_key = self._keypair.ed25519_secret[:32]
            ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        except Exception as e:
            return {"ok": False, "drained": 0, "error": f"trust store: {e}"}
        if not ts.set_trust_state(target_node_id, "trusted"):
            return {"ok": False, "drained": 0,
                    "error": f"peer {target_node_id} not in trust store"}
        drained = await self._db.drain_pending_trust(target_node_id)
        for m in drained:
            try:
                await self._db.store_message(
                    msg_id=m["msg_id"], source=target_node_id,
                    source_display=target_node_id,
                    destination=self.node_id, msg_type=m["msg_type"],
                    payload=m["payload"], direction="inbound",
                    priority=m["priority"],
                )
                self.bus.publish(m["msg_type"], {
                    "peer_id": target_node_id,
                    "msg_id": m["msg_id"],
                    "type": m["msg_type"],
                    "payload": m["payload"],
                })
            except Exception as e:
                logger.warning("Promote-drain re-publish failed for %s msg=%s: %s",
                               target_node_id, m["msg_id"], e)
        self._emit_audit_with_reservation(
            "peer_promoted", EVENT_PEER_PROMOTED, {
                "peer_id": target_node_id,
                "drained": len(drained),
            },
        )
        logger.info("Promoted peer %s to trusted (drained %d queued)",
                    target_node_id, len(drained))
        return {"ok": True, "drained": len(drained), "error": None}

    async def block_pending_peer(self, target_node_id: str) -> dict:
        """Operator action: mark a peer as blocked (local-only quiet block).

        Drops any currently-queued pending messages and prevents future
        MSGs from being delivered. Distinct from broadcast_revocation —
        that propagates a signed REVOCATION to the network; this is a
        unilateral local block that doesn't interact with peer keys.
        """
        from ironmesh.trust import TrustStore
        try:
            mac_key = self._keypair.ed25519_secret[:32]
            ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        except Exception as e:
            return {"ok": False, "discarded": 0, "error": f"trust store: {e}"}
        if not ts.set_trust_state(target_node_id, "blocked"):
            return {"ok": False, "discarded": 0,
                    "error": f"peer {target_node_id} not in trust store"}
        discarded = await self._db.discard_pending_trust(target_node_id)
        self._emit_audit_with_reservation(
            "peer_blocked", EVENT_PEER_BLOCKED, {
                "peer_id": target_node_id,
                "discarded": discarded,
            },
        )
        logger.info("Blocked peer %s (discarded %d queued)",
                    target_node_id, discarded)
        return {"ok": True, "discarded": discarded, "error": None}

    async def list_pending_trust(self) -> list:
        """Return one entry per peer awaiting promotion, with queued count
        and identity metadata. Used by GUI dashboard + MCP tool."""
        from ironmesh.trust import TrustStore
        try:
            mac_key = self._keypair.ed25519_secret[:32]
            ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        except (OSError, ValueError, RuntimeError) as e:
            # Trust store unreadable: filesystem error, corrupt
            # envelope, missing keypair. The GUI/MCP caller gets an
            # empty list rather than a crash — same defensive posture
            # the rest of these helpers carry.
            logger.debug("Pending-peers summary trust store open failed: %s", e)
            return []
        # Union: peers in trust store with state=pending + peers with
        # queued messages even if missing from store (defensive).
        store_pending = {p["node_id"]: p for p in ts.list_by_trust_state("pending")}
        queue_summary = await self._db.list_pending_trust_summary()
        out = []
        seen: set = set()
        for q in queue_summary:
            nid = q["source_node_id"]
            seen.add(nid)
            rec = store_pending.get(nid, {})
            out.append({
                "node_id": nid,
                "fingerprint": rec.get("fingerprint", ""),
                "first_seen": rec.get("first_seen"),
                "last_seen": rec.get("last_seen"),
                "queued_count": q["queued_count"],
                "oldest_queued_at": q["oldest_queued_at"],
                "newest_queued_at": q["newest_queued_at"],
            })
        # Pending peers in the store with no queued messages right now.
        for nid, rec in store_pending.items():
            if nid in seen:
                continue
            out.append({
                "node_id": nid,
                "fingerprint": rec.get("fingerprint", ""),
                "first_seen": rec.get("first_seen"),
                "last_seen": rec.get("last_seen"),
                "queued_count": 0,
                "oldest_queued_at": None,
                "newest_queued_at": None,
            })
        return out

    # ------------------------------------------------------------------
    # v0.8.5.6: capability-set binding
    # ------------------------------------------------------------------

    def _open_trust_store(self):
        """Open a fresh TrustStore bound to this daemon's identity key.

        Mirrors the pattern used by the other trust-touching methods in
        this class — TrustStore is constructed on demand rather than
        held as an instance attribute, because its on-disk state is the
        single source of truth and another daemon (or the operator CLI)
        may have mutated it since the last call. Returns ``None`` if
        the keypair isn't loaded yet (early startup).
        """
        if self._keypair is None:
            return None
        try:
            from ironmesh.trust import TrustStore
            mac_key = self._keypair.ed25519_secret[:32]
            return TrustStore(agent_key=mac_key, path=self.trust_path)
        except Exception as exc:
            logger.debug("_open_trust_store failed: %s", exc)
            return None

    def _handle_cap_observation(self, peer_id: str, result: dict,
                                trust_store=None) -> None:
        """React to a TrustStore.observe_capabilities result.

        The three non-error cases:
            - first-observation: log a baseline audit event; no state change
            - match: no action
            - changed: stash the pending set, demote the peer to
              pending-cap-change, emit PEER_CAP_SET_CHANGED

        ``trust_store`` is the same store used to compute ``result`` —
        passed in to avoid reopening + re-MAC-verifying on the hot path.
        Falls back to opening a fresh one if not supplied.
        """
        status = result.get("status")
        if status == "first-observation":
            # Observability: counter mirror for the baseline pinning
            # event (the cap-binding TOFU-for-caps moment). OTel span
            # is independent of the counter path and fires regardless
            # of audit-log health.
            _otel_span_event("peer.cap.baseline", peer_id, {
                "capability_hash": (result.get("hash") or "")[:16],
                "capability_count": len(result.get("set") or []),
            })
            self._emit_audit_with_reservation(
                "peer_cap_baseline", EVENT_PEER_CAP_BASELINE, {
                    "peer": peer_id,
                    "capability_hash": result.get("hash"),
                    "capability_count": len(result.get("set") or []),
                },
            )
            return
        if status == "match":
            return
        if status == "pending-match":
            # Peer is already demoted and just re-announced the same
            # pending set. Stay silent — the change was already recorded.
            return
        if status == "reverted":
            # Peer reverted to the accepted baseline while in
            # pending-cap-change. Trust store has already cleared the
            # pending stash. The code don't auto-promote (that's an operator
            # decision — they may want to investigate the flap) but we
            # DO surface the revert in the audit log.
            if self._audit:
                try:
                    self._audit.log(EVENT_PEER_CAP_SET_CHANGED, {
                        "peer": peer_id,
                        "old_hash": result.get("cleared_pending_hash"),
                        "new_hash": result.get("hash"),
                        "added": [],
                        "removed": [],
                        "trust_state_effective":
                            "pending-cap-change (reverted to baseline)",
                        "note": "peer reverted to previously-accepted "
                                "capability set; operator action still "
                                "required to re-promote",
                    })
                except (RuntimeError, AttributeError) as e:
                    # GUI broadcast best-effort: RuntimeError from a
                    # closed event loop during shutdown; AttributeError
                    # if _gui_broadcast was never wired. The capability
                    # revert outcome doesn't depend on whether the GUI
                    # received the heads-up.
                    logger.debug("GUI cap-revert broadcast skipped: %s", e)
            logger.info(
                "Peer %s reverted to baseline capability set — "
                "pending stash cleared, trust state unchanged",
                peer_id,
            )
            return
        if status == "changed":
            # v0.8.5.6: both the stash and the demote must
            # succeed before the code fire PEER_CAP_SET_CHANGED. Pre-fix,
            # stash/demote failures were silently downgraded to
            # debug logs while the audit event still fired claiming
            # "trust_state_effective: pending-cap-change" — leaving
            # an operator following the audit trail to later find
            # that cap-promote returns "no pending capability change"
            # because the stash never reached disk. Now the code propagate
            # failures and fire a distinct PEER_CAP_BINDING_PARTIAL
            # event so the audit trail stays truthful.
            ts = trust_store if trust_store is not None else self._open_trust_store()
            stashed = False
            demoted = False
            demote_needed = False
            if ts is not None:
                try:
                    stashed = bool(ts.stash_pending_capability_change(
                        peer_id, result.get("new_set") or [],
                    ))
                except Exception as exc:
                    logger.warning(
                        "stash_pending_capability_change FAILED for %s: %s",
                        peer_id, exc,
                    )
                try:
                    current = ts.get_trust_state(peer_id)
                    demote_needed = (current != "pending-cap-change")
                    if demote_needed:
                        demoted = bool(ts.set_trust_state(
                            peer_id, "pending-cap-change",
                        ))
                    else:
                        # Already pending-cap-change; no demote needed.
                        demoted = True
                except Exception as exc:
                    logger.warning(
                        "trust-state demote FAILED for %s: %s",
                        peer_id, exc,
                    )
            fully_applied = stashed and demoted
            event = (EVENT_PEER_CAP_SET_CHANGED if fully_applied
                     else EVENT_PEER_CAP_BINDING_PARTIAL)
            counter_name = ("peer_cap_set_changed" if fully_applied
                            else "peer_cap_binding_partial")
            _otel_span_event(
                "peer.cap.set_changed" if fully_applied
                else "peer.cap.binding_partial",
                peer_id, {
                    "added": len(result.get("added") or []),
                    "removed": len(result.get("removed") or []),
                    "stashed": stashed,
                    "demoted": demoted,
                },
            )
            self._emit_audit_with_reservation(
                counter_name, event, {
                    "peer": peer_id,
                    "old_hash": result.get("old_hash"),
                    "new_hash": result.get("new_hash"),
                    "added": list(result.get("added") or []),
                    "removed": list(result.get("removed") or []),
                    "trust_state_effective":
                        "pending-cap-change" if fully_applied
                        else "unchanged (persistence failure)",
                    "stashed": stashed,
                    "demoted": demoted,
                },
            )
            # v0.8.5.7: push incremental notification to the dashboard
            # so the operator doesn't need to refresh the panel manually.
            if fully_applied and self._gui_clients:
                try:
                    asyncio.ensure_future(self._gui_broadcast({
                        "type": "cap_change_detected",
                        "peer": peer_id,
                        "added": list(result.get("added") or []),
                        "removed": list(result.get("removed") or []),
                        "old_hash": result.get("old_hash"),
                        "new_hash": result.get("new_hash"),
                    }))
                except (RuntimeError, AttributeError) as e:
                    # GUI cap-change broadcast best-effort — same
                    # rationale as the revert case above.
                    logger.debug("GUI cap-change broadcast skipped: %s", e)
            if fully_applied:
                logger.warning(
                    "Peer %s demoted to pending-cap-change: "
                    "+%d cap(s), -%d cap(s)",
                    peer_id, len(result.get("added") or []),
                    len(result.get("removed") or []),
                )
            else:
                logger.error(
                    "Peer %s cap change detected but not fully applied "
                    "(stashed=%s, demoted=%s). Trust state unchanged. "
                    "This typically indicates a disk / lock error — "
                    "check trust store integrity and retry.",
                    peer_id, stashed, demoted,
                )

    async def accept_pending_cap_change(self, node_id: str) -> dict:
        """Operator action: accept the pending capability-set change for
        a peer that was demoted to pending-cap-change. Re-promotes the
        peer to the prior trust state (or "trusted" if none known) and
        records the new capability baseline.

        Returns a small status dict suitable for CLI / MCP / dashboard
        surface. Raises ValueError if the peer isn't actually in
        pending-cap-change.
        """
        ts = self._open_trust_store()
        if ts is None:
            return {"ok": False, "error": "trust store unavailable"}
        rec = ts.get_peer(node_id)
        if rec is None:
            return {"ok": False, "error": "unknown peer"}
        current_state = ts.get_trust_state(node_id)
        if current_state != "pending-cap-change":
            return {"ok": False, "error": f"peer is in state {current_state}"}
        if rec.get("capability_hash_pending") is None:
            return {"ok": False, "error": "no pending capability change"}
        # Accept the pending set as the new baseline
        old_hash = rec.get("capability_hash")
        new_hash = rec.get("capability_hash_pending")
        accepted = ts.accept_capability_change(node_id)
        if not accepted:
            return {"ok": False, "error": "accept_capability_change returned False"}
        ts.set_trust_state(node_id, "trusted")
        _otel_span_event("peer.cap.accepted", node_id, {
            "new_hash": (new_hash or "")[:16],
        })
        self._emit_audit_with_reservation(
            "peer_cap_accepted", EVENT_PEER_CAP_ACCEPTED, {
                "peer": node_id,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "trust_state_effective": "trusted",
            },
        )
        return {"ok": True, "old_hash": old_hash, "new_hash": new_hash}

    # ------------------------------------------------------------------
    # TOFU (Trust-On-First-Use)
    # ------------------------------------------------------------------

    async def _check_tofu(self, peer_id: str, identity_public_b64: Optional[str],
                          invite_token_str: Optional[str] = None):
        """Check TOFU key pinning for a peer. Raises on mismatch (possible MITM).

        #12: This is called BEFORE the peer is added to self.peers/self.ws_clients,
        so on mismatch the code just raise — the caller never populates the dicts.

        Invite path (``invite_token_str`` present): this node is the
        INVITER. It is authoritative for single-use consumption. Before
        pinning it (a) verifies the token was signed by ITS OWN identity
        key — a token this node did not issue is rejected — (b) checks the
        token is not expired, (c) checks the single-use ledger and rejects
        an already-consumed nonce, then (d) pins the joiner as ``pending``
        (regardless of the global gate) with ``pinned_via="invite"`` and
        (e) marks the nonce spent. An invited joiner is ALWAYS gated for
        explicit operator approval — deny-by-default stays intact.
        """
        if not identity_public_b64:
            return

        # Inviter-authoritative invite validation happens BEFORE the pin.
        # Returns the parsed token (to mark spent after a successful pin)
        # or None on the ordinary (no-invite) path. Raises ConnectionError
        # to fail the handshake closed on any invalid / spent / expired
        # / forged token.
        invite_token = self._validate_incoming_invite(peer_id, invite_token_str)

        try:
            from ironmesh.trust import TrustStore
            # TrustStore requires an agent_key; assertion enforces
            # daemon bootstrap order (keys must load first).
            if not self._keypair:
                raise RuntimeError("TrustStore requires the daemon keypair to be loaded")
            mac_key = self._keypair.ed25519_secret[:32]
            trust = TrustStore(agent_key=mac_key, path=self.trust_path)
            # v0.6: refuse connection from revoked peers
            if trust.is_revoked(peer_id):
                logger.warning("REVOKED peer %s attempted to connect — refusing",
                               peer_id)
                raise ConnectionError(f"Peer {peer_id} is revoked")
            result = trust.verify_peer(peer_id, identity_public_b64)
            if result == "new":
                # v0.8.5: when require_message_promotion is on, brand-new
                # peers are pinned in "pending" state — their MSGs queue
                # until an operator promotes. Default-off preserves the
                # pre-v0.8.5 behavior (peers are immediately trusted).
                #
                # Invite path: an invited joiner is ALWAYS pinned "pending"
                # regardless of the global gate — the token gets them past
                # first-contact identity verification, not past operator
                # approval. Provenance is recorded so audit/UX can show the
                # peer arrived via an invite.
                gate_on = bool(getattr(self.config, "require_message_promotion", False))
                if invite_token is not None:
                    initial_state = "pending"
                    pinned_via = "invite"
                else:
                    initial_state = "pending" if gate_on else "trusted"
                    pinned_via = None
                trust.pin_peer(peer_id, identity_public_b64,
                               trust_state=initial_state,
                               pinned_via=pinned_via)
                logger.info("TOFU: Pinned new peer %s (state=%s, via=%s)",
                            peer_id, initial_state, pinned_via or "tofu")
                # Consume the single-use invite ONLY after a successful
                # pin, so a failure between validation and pin does not
                # burn the token.
                if invite_token is not None:
                    self._invite_ledger.mark_spent(invite_token)
                    if self._audit:
                        self._audit.log(EVENT_INVITE_ACCEPTED, {
                            "peer_id": peer_id,
                            "nonce": invite_token.nonce,
                            "trust_state": initial_state,
                        })
                if self._audit:
                    self._audit.log(EVENT_TOFU_NEW, {
                        "peer_id": peer_id,
                        "trust_state": initial_state,
                    })
            elif result == "mismatch":
                if self._audit:
                    self._audit.log(EVENT_TOFU_MISMATCH, {"peer_id": peer_id})
                logger.critical(
                    "TOFU VIOLATION: Peer %s identity key changed! Possible MITM attack. "
                    "Disconnecting peer. Use 'ironmesh trust revoke %s' then reconnect "
                    "if the key change is legitimate.", peer_id, peer_id
                )
                # Clean up if peer was already in dicts (legacy path)
                ws = self.ws_clients.pop(peer_id, None)
                if ws:
                    try:
                        await ws.send(json.dumps({
                            "type": ew_protocol.MessageType.ERROR,
                            "error": "Identity key mismatch — possible MITM. Connection refused.",
                            "code": ew_protocol.ErrorCode.AUTH_FAILED,
                        }))
                        await ws.close()
                    except (websockets.exceptions.ConnectionClosed, OSError, RuntimeError):
                        # TOFU-mismatch tear-down: refusal is already
                        # decided. The notify-and-close is courtesy;
                        # transport failures here don't change the
                        # security outcome.
                        pass
                self.peers.pop(peer_id, None)
                self._peer_rate_limiters.pop(peer_id, None)
                raise ConnectionError(f"TOFU mismatch for peer {peer_id}")
        except ImportError:
            pass  # trust module not yet available
        except ConnectionError:
            raise  # Re-raise TOFU mismatch (intentional fail-closed)
        except ValueError as e:
            # Malformed input data reached the TOFU check (e.g. bad
            # base64 identity key). Log at WARNING — this is a security
            # event surface, not a debug-level curiosity — and refuse
            # the connection. Fail-closed: a peer whose identity we
            # cannot evaluate must not be trusted. The previous
            # `except Exception as e: logger.debug(...)` here let any
            # non-ConnectionError pass silently, which is too permissive
            # for the TOFU pinning code path. Programmer errors,
            # OSError on the trust-store backing file, RuntimeError on
            # missing keypair bootstrap, etc. now propagate so the
            # daemon surfaces them at the caller instead of treating
            # them as "trust verified".
            logger.warning(
                "TOFU check failed for %s (%s) — refusing connection",
                peer_id, e,
            )
            raise ConnectionError(f"TOFU check failed for peer {peer_id}: {e}")

    def _get_invite_ledger(self):
        """Lazily build the single-use invite ledger. Co-located with the
        trust store (see ``BridgeDaemon.__init__``)."""
        if self._invite_ledger is None:
            from ironmesh.invite import InviteLedger
            self._invite_ledger = InviteLedger(self._invite_ledger_path)
        return self._invite_ledger

    def _validate_incoming_invite(self, peer_id: str,
                                  invite_token_str: Optional[str]):
        """Inviter-side invite validation. Returns the parsed token to be
        consumed after a successful pin, or None on the ordinary path.

        Fails the handshake closed (``ConnectionError``) on any token that
        is malformed, not issued by THIS node, expired, or already spent.
        """
        if not invite_token_str:
            return None

        from ironmesh import invite as ew_invite

        try:
            token = ew_invite.parse_invite(invite_token_str)
        except ew_invite.InviteError as exc:
            self._audit_invite_reject(peer_id, None, "malformed", str(exc))
            raise ConnectionError(f"invalid invite from peer {peer_id}: {exc}")

        # The token MUST have been signed by THIS node's identity — an
        # inviter only honours invites it issued. This also verifies the
        # signature under SIG_CTX_INVITE (domain-separated).
        our_key_b64 = self._keypair.get_public_key_base64() if self._keypair else None
        if not our_key_b64 or token.inviter_key != our_key_b64:
            self._audit_invite_reject(peer_id, token.nonce, "not_our_invite",
                                      "invite not issued by this node")
            raise ConnectionError(
                f"invite from peer {peer_id} was not issued by this node"
            )
        try:
            token.verify_signature()
        except ew_invite.InviteError as exc:
            self._audit_invite_reject(peer_id, token.nonce, "bad_signature", str(exc))
            raise ConnectionError(f"invite signature invalid from peer {peer_id}: {exc}")

        if token.is_expired():
            self._audit_invite_reject(peer_id, token.nonce, "expired",
                                      "invite expired")
            raise ConnectionError(f"invite from peer {peer_id} is expired")

        ledger = self._get_invite_ledger()
        try:
            ledger.check_and_reject_if_spent(token)
        except ew_invite.InviteSpent as exc:
            self._audit_invite_reject(peer_id, token.nonce, "spent", str(exc))
            raise ConnectionError(f"invite from peer {peer_id} already consumed")

        return token

    def _audit_invite_reject(self, peer_id, nonce, reason, detail):
        if self._audit:
            self._audit.log(EVENT_INVITE_REJECTED, {
                "peer_id": peer_id,
                "nonce": nonce,
                "reason": reason,
                "detail": detail,
            })
