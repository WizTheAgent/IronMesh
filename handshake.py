"""Handshake and session-key establishment for the IronMesh bridge daemon.

This module holds the protocol version constants and comparison
helpers, plus ``HandshakeMixin`` — the ``BridgeDaemon`` methods for the
client side of the connection handshake (passphrase auth + ephemeral
ECDH), outbound connection establishment over WebSocket and RNS Link,
the X25519 key-binding advertisement/verification, the handshake-skip
eligibility checks for identified RNS Links, and in-session key
rotation (REKEY).

``bridge.py`` composes the mixin back into ``BridgeDaemon`` via
inheritance — all state lives on the daemon instance; this module
holds behavior only.
"""

import asyncio
import base64
import hmac
import json
import logging
import ssl
import time
import uuid
from typing import Optional

import nacl.exceptions as nacl_exceptions
import websockets

# Optional Reticulum transport (only loaded when --reticulum is enabled)
try:
    from ironmesh.reticulum_transport import RNSLinkAdapter
except ImportError:
    RNSLinkAdapter = None  # type: ignore[assignment,misc]

from ironmesh import (
    crypto as ew_crypto,
    keys as ew_keys,
    protocol as ew_protocol,
)
from ironmesh.telemetry import emit_event as _otel_span_event

logger = logging.getLogger("ironmesh.bridge")

PROTOCOL_VERSION = "ironmesh/0.9"
MIN_MESH_VERSION = "ironmesh/0.4"  # Peers below this version cannot relay
# Peers at this version or newer sign/verify the HELLO with the
# domain-separated context signature (crypto.SIG_CTX_HELLO). Older peers
# use the legacy attached signature — see _peer_supports_hello_ctx.
HELLO_CTX_MIN_VERSION = "ironmesh/0.9"


def _parse_protocol_version(v: str) -> tuple:
    """Parse 'ironmesh/X.Y' into a (major, minor) tuple. Returns (0, 0) on parse failure."""
    if not v:
        return (0, 0)
    try:
        prefix, ver = v.split("/", 1)
        major_s, minor_s = ver.split(".", 1)
        return (int(major_s), int(minor_s.split(".")[0]))
    except (ValueError, IndexError):
        return (0, 0)


def _peer_supports_mesh(peer_version: str) -> bool:
    """Return True if the peer is at least ironmesh/0.4 (mesh-capable)."""
    return _parse_protocol_version(peer_version) >= _parse_protocol_version(MIN_MESH_VERSION)


def _peer_supports_rekey(peer_version: str) -> bool:
    """Return True if the peer supports in-session rekeying (v0.5+)."""
    return _parse_protocol_version(peer_version) >= (0, 5)


def _peer_supports_hello_ctx(peer_version: str) -> bool:
    """Return True if the peer's advertised version uses the
    domain-separated HELLO signature (ironmesh/0.9+).

    The advertised version travels INSIDE the signed canonical HELLO
    body, so once a peer's identity is pinned an attacker cannot strip
    or rewrite the version to force the legacy signature path without
    invalidating the signature — tampering fails closed rather than
    downgrading. See docs/PROTOCOL_SPEC.md for the full downgrade
    analysis (including the honest TOFU first-contact limitation).
    """
    return (
        _parse_protocol_version(peer_version)
        >= _parse_protocol_version(HELLO_CTX_MIN_VERSION)
    )


class HandshakeMixin:
    """Client handshake, outbound connection, and rekey for ``BridgeDaemon``."""

    # ------------------------------------------------------------------
    # v0.5.2: Session key rotation (REKEY)
    # ------------------------------------------------------------------

    async def _rekey_loop(self):
        """Periodically rotate session keys with online v0.5+ peers.

        To avoid simultaneous rekey (both sides initiate at the same
        interval), only the node with the lexicographically smaller
        node_id initiates.  The other side just responds.
        """
        if self._rekey_interval <= 0:
            return
        while self._running:
            await asyncio.sleep(self._rekey_interval)
            for peer_id, state in list(self.peers.items()):
                if not state.is_online or not state.session_key:
                    continue
                if not _peer_supports_rekey(state.protocol_version):
                    continue
                # Tie-breaker: only the smaller node_id initiates
                if self.node_id >= peer_id:
                    continue
                try:
                    await self._initiate_rekey(peer_id)
                except Exception as e:
                    state.record_retry("rekey_failed")
                    logger.warning("Rekey failed for %s: %s", peer_id, e)

    async def _initiate_rekey(self, peer_id: str):
        """Send REKEY_REQUEST with a new ephemeral X25519 public key."""
        peer_state = self.peers.get(peer_id)
        if not peer_state:
            return
        new_private, new_public = ew_keys.generate_ephemeral()
        rekey_id = str(uuid.uuid4())
        peer_state._pending_rekey_private = new_private
        peer_state._pending_rekey_id = rekey_id
        await self._send_encrypted_control(
            peer_id, ew_protocol.MessageType.REKEY_REQUEST, {
                "new_ephemeral_public": base64.b64encode(bytes(new_public)).decode(),
                "rekey_id": rekey_id,
            },
        )
        logger.info("REKEY_REQUEST sent to %s (id=%s)", peer_id, rekey_id[:8])

    async def _handle_rekey_request(self, peer_id: str, payload, peer_state):
        """Respond to REKEY_REQUEST: derive new session key, send the ephemeral."""
        try:
            data = json.loads(payload) if isinstance(payload, (bytes, str)) else {}
        except (json.JSONDecodeError, TypeError):
            data = {}
        peer_pub_b64 = data.get("new_ephemeral_public")
        rekey_id = data.get("rekey_id", "")
        if not peer_pub_b64:
            logger.warning("Invalid REKEY_REQUEST from %s", peer_id)
            return
        from nacl.public import PublicKey as X25519Pub
        peer_pub = X25519Pub(base64.b64decode(peer_pub_b64))
        my_private, my_public = ew_keys.generate_ephemeral()
        new_key = ew_crypto.ecdh_exchange(my_private, peer_pub)
        ew_crypto.secure_wipe(my_private)
        # Respond with OLD key (still active), then switch
        await self._send_encrypted_control(
            peer_id, ew_protocol.MessageType.REKEY_RESPONSE, {
                "new_ephemeral_public": base64.b64encode(bytes(my_public)).decode(),
                "rekey_id": rekey_id,
            },
        )
        peer_state.session_key = new_key
        peer_state.session_rekey_count += 1
        peer_state.last_rekey_at = time.time()
        peer_state.next_send_seq = 1
        self._replay_guard.reset_peer(peer_id)
        self._pending_pings.pop(peer_id, None)
        self.metrics.session_rekeys += 1
        logger.info("Session rekeyed with %s (id=%s, count=%d)",
                    peer_id, rekey_id[:8], peer_state.session_rekey_count)

    async def _handle_rekey_response(self, peer_id: str, payload, peer_state):
        """Complete rekey: derive new session key from peer's ephemeral."""
        try:
            data = json.loads(payload) if isinstance(payload, (bytes, str)) else {}
        except (json.JSONDecodeError, TypeError):
            data = {}
        peer_pub_b64 = data.get("new_ephemeral_public")
        rekey_id = data.get("rekey_id", "")
        if peer_state._pending_rekey_id != rekey_id:
            logger.warning("Rekey ID mismatch from %s", peer_id)
            return
        if not peer_pub_b64 or not peer_state._pending_rekey_private:
            logger.warning("Invalid REKEY_RESPONSE from %s", peer_id)
            return
        from nacl.public import PublicKey as X25519Pub
        peer_pub = X25519Pub(base64.b64decode(peer_pub_b64))
        new_key = ew_crypto.ecdh_exchange(peer_state._pending_rekey_private, peer_pub)
        ew_crypto.secure_wipe(peer_state._pending_rekey_private)
        peer_state._pending_rekey_private = None
        peer_state._pending_rekey_id = None
        peer_state.session_key = new_key
        peer_state.session_rekey_count += 1
        peer_state.last_rekey_at = time.time()
        peer_state.next_send_seq = 1
        self._replay_guard.reset_peer(peer_id)
        self._pending_pings.pop(peer_id, None)
        self.metrics.session_rekeys += 1
        logger.info("Session rekeyed (initiator) with %s (id=%s, count=%d)",
                    peer_id, rekey_id[:8], peer_state.session_rekey_count)

    def _hello_x25519_advertisement(self) -> dict:
        """v0.9.4 Phase 2: return the dict fragment to merge into outgoing
        HELLO frames. Empty dict when the daemon's keypair is in the
        legacy v1/v2 shape (no master-seed format). Both fields
        published unsigned-in-canonical-HELLO but cryptographically
        bound via the Ed25519-signed ``x25519_binding_signature`` —
        receivers verify the binding under the peer's pinned Ed25519
        identity before trusting the advertised X25519 public.
        """
        if (self._keypair is None
                or self._keypair.x25519_public is None
                or self._keypair.x25519_binding_signature is None):
            return {}
        return {
            "x25519_public_b64": base64.b64encode(
                self._keypair.x25519_public,
            ).decode("ascii"),
            "x25519_binding_signature_b64": base64.b64encode(
                self._keypair.x25519_binding_signature,
            ).decode("ascii"),
        }

    def _verify_peer_x25519_binding(
        self,
        peer_identity_b64: Optional[str],
        peer_x25519_public_b64: Optional[str],
        peer_x25519_binding_b64: Optional[str],
    ) -> Optional[bytes]:
        """Verify a peer's advertised X25519 binding (Phase 2).

        Returns the verified ``x25519_public`` bytes when both fields
        are present AND the binding signature verifies under
        ``peer_identity_b64`` with ``SIG_CTX_X25519_BINDING``. Returns
        None otherwise — caller's contract is to fall back to the
        legacy ``ed25519_to_curve25519`` derivation. A return of None
        is NOT a security incident; it's the expected path for
        pre-v0.9.4 peers.
        """
        if not peer_identity_b64:
            return None
        if not peer_x25519_public_b64 or not peer_x25519_binding_b64:
            return None
        try:
            from nacl.signing import VerifyKey

            from ironmesh.crypto import (
                SIG_CTX_X25519_BINDING,
                verify_detached_with_context,
            )
            vk = VerifyKey(base64.b64decode(peer_identity_b64))
            pub = base64.b64decode(peer_x25519_public_b64)
            sig = base64.b64decode(peer_x25519_binding_b64)
            if len(pub) != 32 or len(sig) != 64:
                return None
            verify_detached_with_context(vk, SIG_CTX_X25519_BINDING, pub, sig)
            return pub
        except (nacl_exceptions.BadSignatureError, ValueError, TypeError) as e:
            logger.warning(
                "X25519 binding verification FAILED — advertised key "
                "ignored, falling back to legacy derivation (%s)", e,
            )
            return None

    # ------------------------------------------------------------------
    # ironmesh/0.9: RNS link binding (HELLO <-> RNS Link coupling)
    # ------------------------------------------------------------------
    #
    # On the Reticulum transport, the HELLO's Ed25519 signature proves
    # control of the claimed IronMesh identity but — before 0.9 — said
    # nothing about the RNS link it travelled on, so the RNS-layer
    # identity and the IronMesh identity were decoupled. ironmesh/0.9
    # closes that gap: 0.9+ peers include the hex link id of the RNS
    # Link (``rns_link_id``) inside the signed HELLO canonical body, and
    # the receiver checks the claim against the link the HELLO actually
    # arrived on. The link id is per-session (the truncated hash of the
    # link-request packet, observed identically by both endpoints), so a
    # signed HELLO can never be relayed onto a different RNS link — in
    # particular on the handshake-skip path, where the IronMesh channel
    # binding is a constant sentinel and would otherwise be replayable.
    #
    # The field never appears on the WebSocket path: WebSocket HELLOs
    # keep the five-key canonical body, and a WebSocket HELLO that
    # carries ``rns_link_id`` is rejected outright.

    def _rns_hello_link_binding(self, websocket, peer_version: str) -> Optional[str]:
        """Sender side: the ``rns_link_id`` value to bind into an outgoing
        HELLO, or None when the field must be omitted.

        Included only when the connection is an RNS Link AND the peer
        advertised ironmesh/0.9+ (pre-0.9 peers reconstruct the five-key
        canonical body and would fail signature verification on a
        six-key one). On the WebSocket path this always returns None.
        """
        if RNSLinkAdapter is None or not isinstance(websocket, RNSLinkAdapter):
            return None
        if not _peer_supports_hello_ctx(peer_version):
            return None
        link_id = getattr(websocket, "link_id_hex", None)
        if not isinstance(link_id, str) or not link_id:
            logger.warning(
                "RNS link id unavailable — sending HELLO without the "
                "rns_link_id binding; a 0.9+ peer will reject this handshake",
            )
            return None
        return link_id

    def _evaluate_rns_hello_binding(
        self, websocket, hello_msg: dict, peer_version: str, skip_used: bool,
    ) -> tuple:
        """Receiver side: enforce the RNS link-binding policy on a HELLO.

        Returns ``(ok, claimed_binding, reason)``. ``claimed_binding`` is
        the exact ``rns_link_id`` string to feed into the canonical-body
        reconstruction (None when the field is legitimately absent);
        callers MUST still verify the HELLO signature over that canonical
        body — this check authenticates nothing by itself, it only pins
        the claim to the link the HELLO arrived on.

        Policy:

        - WebSocket transport: the field MUST be absent (it is defined
          only for RNS Links); presence is a protocol violation.
        - RNS, field present: must equal the local link's id.
        - RNS, field absent: rejected when the peer advertised
          ironmesh/0.9+ (the 0.9 RNS contract requires the binding),
          when stage 1 was skipped (the skip path is refused without a
          binding), or when the operator set ``rns_require_link_binding``.
          Otherwise the peer is pre-0.9 and the legacy behavior applies
          — the RNS/IronMesh identity-binding residual remains scoped to
          exactly these peers (see SECURITY.md).
        """
        claimed = hello_msg.get("rns_link_id")
        is_rns = RNSLinkAdapter is not None and isinstance(websocket, RNSLinkAdapter)
        if not is_rns:
            # Explicitly not implied: the WebSocket path never carries
            # the binding field. Reject rather than ignore, so a
            # confused (or probing) peer fails loudly.
            if claimed is not None:
                return (False, None,
                        "rns_link_id is only valid on the Reticulum transport")
            return (True, None, "")
        if claimed is not None:
            if not isinstance(claimed, str) or not claimed:
                return (False, None, "malformed rns_link_id")
            local = getattr(websocket, "link_id_hex", None)
            if not isinstance(local, str) or not local:
                return (False, None,
                        "local RNS link id unavailable — cannot verify the "
                        "claimed binding")
            if not hmac.compare_digest(
                claimed.lower().encode("utf-8"), local.lower().encode("utf-8"),
            ):
                return (False, None,
                        "rns_link_id does not match the link the HELLO "
                        "arrived on")
            return (True, claimed, "")
        # Field absent.
        if skip_used:
            return (False, None,
                    "handshake skip requires the rns_link_id binding")
        if _peer_supports_hello_ctx(peer_version):
            return (False, None,
                    "peers advertising ironmesh/0.9+ must bind the HELLO "
                    "to the RNS link")
        if getattr(self, "_rns_require_link_binding", False):
            return (False, None,
                    "rns_require_link_binding is enabled and the peer sent "
                    "no binding")
        return (True, None, "")

    # ------------------------------------------------------------------
    # Outbound connection (client-side handshake)
    # ------------------------------------------------------------------

    async def _do_client_handshake(self, ws, label: str) -> Optional[str]:
        """Run the client-side passphrase auth + ephemeral ECDH + message loop.

        This is the transport-agnostic core of the outbound handshake.
        ``ws`` can be a real WebSocket or an ``RNSLinkAdapter`` — it only
        needs ``send()``, ``recv()``, ``remote_address``, and ``async for``.

        Returns the peer_id on success, or None on failure.
        """
        # v0.9.2 chunk A — server-driven Stage-1 skip (corrected design
        # after the v0.9.2-pre-r1 unilateral-decision bug). The client
        # NEVER decides skip on its own; it always reads the server's
        # first message and dispatches:
        #
        #   SKIP_OFFER          → server has elected to skip, use the
        #                         channel binding it sent and go straight
        #                         to HELLO. No PASSPHRASE_RESPONSE step.
        #   PASSPHRASE_CHALLENGE → full challenge / verify flow.
        #
        # This guarantees both sides agree before HELLO is sent, even
        # when one side has the peer's hskip-announce in
        # `_rns_discovered` and the other does not. The previous
        # unilateral check race would crash the handshake with
        # `Expected HELLO, got PASSPHRASE_CHALLENGE` — fixed here.
        raw = await asyncio.wait_for(ws.recv(), timeout=30)
        msg = json.loads(raw)
        first_type = msg.get("type")

        # ironmesh/0.9 — the server advertises its protocol version in its
        # first message (both SKIP_OFFER and PASSPHRASE_CHALLENGE carry
        # ``protocol_version``). This is where the client learns, BEFORE
        # producing its HELLO signature, whether the server understands the
        # domain-separated HELLO signature. Missing field (pre-advertisement
        # servers) parses as (0, 0) → legacy path. Note this advertisement
        # is unsigned: an attacker who strips it makes the client fall back
        # to the legacy signature, but a 0.9+ server then REJECTS that HELLO
        # (the client's own 0.9 version inside the signed body demands the
        # context signature), so tampering here is denial, not downgrade.
        server_advertised_version = msg.get("protocol_version", "")

        skip_stage1 = (first_type == ew_protocol.MessageType.SKIP_OFFER)

        if skip_stage1:
            cb_hex = msg.get("channel_binding")
            if not cb_hex:
                self._inc_metric("handshake_skips_rejected")
                logger.warning(
                    "SKIP_OFFER from %s missing channel_binding — abort", label,
                )
                return None
            try:
                server_nonce = bytes.fromhex(cb_hex)
            except ValueError:
                self._inc_metric("handshake_skips_rejected")
                logger.warning(
                    "SKIP_OFFER from %s carried non-hex channel_binding — abort",
                    label,
                )
                return None
            # Defense-in-depth: the offered channel binding MUST equal
            # the deterministic sentinel. A peer that offers anything
            # else is either misbehaving or an attacker trying to
            # downgrade the binding. Reject the connection rather than
            # accept an attacker-chosen sentinel.
            expected = ew_protocol.Handshake.skip_channel_binding()
            if not hmac.compare_digest(server_nonce, expected):
                self._inc_metric("handshake_skips_rejected")
                logger.warning(
                    "SKIP_OFFER from %s carried wrong channel_binding "
                    "(possible downgrade attempt) — abort",
                    label,
                )
                return None
            # ironmesh/0.9: REFUSE to skip stage 1 unless the RNS link
            # binding can be produced and verified. The skip path signs a
            # constant channel-binding sentinel, so without the per-link
            # rns_link_id the HELLO would be replayable across links.
            # Three refusal conditions:
            #  1. Not an RNS Link at all — a WebSocket server has no
            #     business offering a skip (it would bypass the
            #     passphrase stage entirely).
            #  2. The local link id is unreadable — the binding cannot be
            #     produced or checked.
            #  3. The server advertised a pre-0.9 version — it cannot
            #     produce a bound HELLO, so the skip would run without
            #     the binding. Legacy hskip peers must either upgrade or
            #     run the full stage-1 handshake.
            if (RNSLinkAdapter is None
                    or not isinstance(ws, RNSLinkAdapter)
                    or not getattr(ws, "link_id_hex", None)):
                self._inc_metric("handshake_skips_rejected")
                logger.warning(
                    "SKIP_OFFER from %s refused — no verifiable RNS link "
                    "id on this connection (handshake skip requires the "
                    "RNS link binding)",
                    label,
                )
                return None
            if not _peer_supports_hello_ctx(server_advertised_version):
                self._inc_metric("handshake_skips_rejected")
                logger.warning(
                    "SKIP_OFFER from %s refused — server advertised %r, "
                    "but the handshake skip requires the ironmesh/0.9+ "
                    "RNS link binding",
                    label, server_advertised_version,
                )
                return None
            self._inc_metric("handshake_skips_activated")
            logger.debug(
                "Handshake skip ACK for %s — server offered, client accepted",
                label,
            )
            _otel_span_event(
                "handshake.skip.activated",
                getattr(ws, "remote_identity_hash", "unknown"),
                {"ironmesh.skip.side": "client", "ironmesh.transport": "rns",
                 "ironmesh.peer.label": label},
            )
        elif first_type == ew_protocol.MessageType.PASSPHRASE_CHALLENGE:
            # Stage 1: legacy challenge / verify flow.
            server_nonce = bytes.fromhex(msg["nonce"])

            # Send proof
            proof = ew_protocol.Handshake.compute_passphrase_proof(
                self.passphrase, server_nonce
            )
            await ws.send(json.dumps({
                "type": ew_protocol.MessageType.PASSPHRASE_CHALLENGE,
                "from": self.node_id,
                "proof": proof,
            }))

            # Wait for verification + mutual auth
            raw = await asyncio.wait_for(ws.recv(), timeout=30)
            msg = json.loads(raw)
            if msg.get("type") != ew_protocol.MessageType.PASSPHRASE_VERIFIED:
                logger.warning("Auth rejected by %s", label)
                return None

            # Verify server also knows the passphrase (mutual auth)
            server_proof = msg.get("server_proof")
            if server_proof:
                expected_server_proof = ew_protocol.Handshake.compute_passphrase_proof(
                    self.passphrase, server_nonce[::-1]
                )
                if not hmac.compare_digest(server_proof, expected_server_proof):
                    logger.warning("Mutual auth failed — server proof invalid at %s", label)
                    return None
                logger.debug("Mutual auth verified with %s", label)
        else:
            logger.warning(
                "Expected SKIP_OFFER or PASSPHRASE_CHALLENGE from %s, got %s",
                label, first_type,
            )
            return None

        # Stage 2: Ephemeral ECDH
        my_ephemeral_private, my_ephemeral_public = ew_keys.generate_ephemeral()

        # Sign the HELLO with Ed25519 + channel binding via server_nonce.
        # ironmesh/0.9 — signature scheme is gated on the server's
        # advertised version: 0.9+ gets the domain-separated detached
        # signature under SIG_CTX_HELLO; older servers get the legacy
        # attached signature so mixed-version meshes keep working.
        my_ephemeral_b64 = base64.b64encode(bytes(my_ephemeral_public)).decode()
        my_identity_b64 = self._keypair.get_public_key_base64()
        # ironmesh/0.9: on RNS Links to 0.9+ servers, bind this HELLO to
        # the specific RNS link it travels on (None on the WebSocket
        # path or toward pre-0.9 servers — the field is then omitted and
        # the canonical body keeps its five-key form).
        my_link_binding = self._rns_hello_link_binding(
            ws, server_advertised_version,
        )
        hello_canonical = ew_protocol.canonical_hello_bytes(
            channel_binding=server_nonce.hex(),
            ephemeral_public=my_ephemeral_b64,
            identity_public=my_identity_b64,
            name=self.name,
            protocol_version=PROTOCOL_VERSION,
            rns_link_id=my_link_binding,
        )
        if _peer_supports_hello_ctx(server_advertised_version):
            signature = ew_crypto.sign_detached_with_context(
                self._keypair.get_signing_key(),
                ew_crypto.SIG_CTX_HELLO,
                hello_canonical,
            )
        else:
            signature = ew_crypto.sign_message(
                self._keypair.get_signing_key(), hello_canonical
            )
        outgoing_hello = {
            "type": ew_protocol.MessageType.HELLO,
            "from": self.node_id,
            "name": self.name,
            "ephemeral_public": my_ephemeral_b64,
            "identity_public": my_identity_b64,
            "protocol_version": PROTOCOL_VERSION,
            "channel_binding": server_nonce.hex(),
            "signature": base64.b64encode(signature).decode(),
        }
        if my_link_binding is not None:
            outgoing_hello["rns_link_id"] = my_link_binding
        # v0.9.4 Phase 2 advertisement — same shape as the server-side
        # HELLO. See _hello_x25519_advertisement docstring for compat
        # rationale.
        outgoing_hello.update(self._hello_x25519_advertisement())
        await ws.send(json.dumps(outgoing_hello))

        # Receive server's HELLO
        raw = await asyncio.wait_for(ws.recv(), timeout=30)
        msg = json.loads(raw)
        if msg.get("type") != ew_protocol.MessageType.HELLO:
            logger.warning("Expected HELLO, got %s", msg.get("type"))
            return None

        claimed_peer_id = msg.get("from")
        peer_name = msg.get("name", claimed_peer_id)
        peer_ephemeral_b64 = msg.get("ephemeral_public")
        peer_identity_b64 = msg.get("identity_public")

        if not peer_ephemeral_b64:
            logger.warning("Server HELLO missing ephemeral_public")
            return None

        # ironmesh/0.9: enforce the RNS link-binding policy BEFORE the
        # signature check — the returned claimed binding (if any) is part
        # of the canonical body the signature is verified over, so a
        # matching-but-forged claim still fails at the signature step.
        bind_ok, server_claimed_binding, bind_reason = (
            self._evaluate_rns_hello_binding(
                ws, msg, msg.get("protocol_version", ""), skip_stage1,
            )
        )
        if not bind_ok:
            logger.warning(
                "Server HELLO link-binding check FAILED for %s: %s",
                label, bind_reason,
            )
            return None

        # Verify server's HELLO signature.
        # ironmesh/0.9 — the server's advertised version (inside the signed
        # canonical body) selects the scheme: 0.9+ REQUIRES the detached
        # domain-separated signature, older versions use the legacy attached
        # form. Because the version travels inside the signed bytes, a
        # tampered version fails verification under either scheme.
        peer_sig_b64 = msg.get("signature")
        hello_sig_scheme = "unsigned"
        if peer_identity_b64 and peer_sig_b64:
            try:
                from nacl.signing import VerifyKey
                verify_key = VerifyKey(base64.b64decode(peer_identity_b64))
                # Reconstruct canonical from server's HELLO fields
                server_hello_version = msg.get("protocol_version", "")
                server_canonical = ew_protocol.canonical_hello_bytes(
                    channel_binding=msg.get("channel_binding", ""),
                    ephemeral_public=peer_ephemeral_b64,
                    identity_public=peer_identity_b64,
                    name=peer_name,
                    protocol_version=server_hello_version,
                    rns_link_id=server_claimed_binding,
                )
                if _peer_supports_hello_ctx(server_hello_version):
                    ew_crypto.verify_detached_with_context(
                        verify_key,
                        ew_crypto.SIG_CTX_HELLO,
                        server_canonical,
                        base64.b64decode(peer_sig_b64),
                    )
                    hello_sig_scheme = "context-v1"
                else:
                    extracted = ew_crypto.verify_signature(
                        verify_key, base64.b64decode(peer_sig_b64)
                    )
                    if extracted != server_canonical:
                        raise ValueError("Server HELLO signature payload does not match canonical form")
                    hello_sig_scheme = "legacy"
                logger.debug("Server HELLO signature verified (%s)", hello_sig_scheme)
            except Exception as e:
                logger.warning("Server HELLO signature FAILED: %s", e)
                return None
        elif peer_identity_b64 and not peer_sig_b64:
            logger.warning("Server sent identity key but no signature — rejecting")
            return None

        # ironmesh/0.9: the skip path must end in a SIGNED server HELLO —
        # otherwise the link binding (and the constant skip sentinel)
        # would be unauthenticated. "Present and verified" means covered
        # by the HELLO signature, not merely matching.
        if skip_stage1 and hello_sig_scheme == "unsigned":
            logger.warning(
                "Server HELLO from %s is unsigned — handshake skip "
                "requires a signed, link-bound HELLO",
                label,
            )
            return None

        # Derive peer_id from identity key
        if peer_identity_b64:
            peer_id = ew_keys.get_fingerprint(base64.b64decode(peer_identity_b64))
        else:
            peer_id = claimed_peer_id

        from nacl.public import PublicKey as X25519PublicKey
        peer_ephemeral_public = X25519PublicKey(base64.b64decode(peer_ephemeral_b64))
        session_key = ew_crypto.ecdh_exchange(my_ephemeral_private, peer_ephemeral_public)
        ew_crypto.secure_wipe(my_ephemeral_private)
        del my_ephemeral_private  # Forward secrecy

        # TOFU check BEFORE adding peer to dicts.
        await self._check_tofu(peer_id, peer_identity_b64)

        # Set up peer state (only after TOFU passes)
        address = f"{ws.remote_address[0]}:{ws.remote_address[1]}"
        peer_state = ew_protocol.PeerState(
            node_id=peer_id, address=address
        )
        peer_state.session_key = session_key
        peer_state.ephemeral_public = base64.b64decode(peer_ephemeral_b64)
        peer_state.identity_public = base64.b64decode(peer_identity_b64) if peer_identity_b64 else None
        peer_state.verified = True
        # ironmesh/0.9: record which HELLO signature scheme the peer used
        # ("context-v1", "legacy", or "unsigned") for observability + tests.
        peer_state.hello_sig_scheme = hello_sig_scheme
        # v0.9.4 Phase 2: capture peer's advertised X25519 identity public
        # iff the binding signature verifies under their pinned Ed25519.
        peer_state.x25519_identity_public = self._verify_peer_x25519_binding(
            peer_identity_b64,
            msg.get("x25519_public_b64"),
            msg.get("x25519_binding_signature_b64"),
        )

        # v0.4: protocol version negotiation
        peer_protocol = msg.get("protocol_version", "ironmesh/0.3")

        # v0.6: reject peers below configured minimum
        if _parse_protocol_version(peer_protocol) < _parse_protocol_version(self._min_protocol_version):
            logger.warning(
                "Rejecting peer %s on %s (below min %s)",
                peer_id, peer_protocol, self._min_protocol_version,
            )
            self.metrics.handshake_failures += 1
            return None

        peer_state.protocol_version = peer_protocol
        peer_state.supports_mesh = _peer_supports_mesh(peer_protocol)
        peer_state.is_relay_capable = peer_state.supports_mesh
        peer_state.agent_name = peer_name
        if not peer_state.supports_mesh:
            logger.info("Peer %s on %s — mesh forwarding disabled (direct only)",
                        peer_id, peer_protocol)

        # Atomic duplicate-check + peer-state assignment.
        async with self._peer_lock:
            # Guard against duplicate connections (both sides connect simultaneously).
            # v0.5: allow WebSocket to upgrade an existing RNS connection.
            existing_state = self.peers.get(peer_id)
            if existing_state and existing_state.is_online and peer_id in self.ws_clients:
                new_is_rns = RNSLinkAdapter is not None and isinstance(ws, RNSLinkAdapter)
                old_is_rns = existing_state.transport_type == "rns"
                if not new_is_rns and old_is_rns:
                    logger.info("Upgrading %s from RNS to WebSocket", peer_id)
                    old_ws = self.ws_clients.pop(peer_id, None)
                    if old_ws:
                        try:
                            await old_ws.close()
                        except Exception:
                            pass
                else:
                    logger.debug("Already connected to %s via %s, dropping outbound duplicate",
                                 peer_id, existing_state.transport_type)
                    return None

            peer_state.transition(ew_protocol.PeerState.Status.ONLINE)
            self.peers[peer_id] = peer_state
            self.ws_clients[peer_id] = ws
            self._peer_rate_limiters[peer_id] = ew_protocol.TokenBucket(rate=20.0, burst=100)
            self._replay_guard.reset_peer(peer_id)
            self._known_peer_addresses[peer_id] = address

        # v0.5: track transport type for failover
        if RNSLinkAdapter is not None and isinstance(ws, RNSLinkAdapter):
            peer_state.transport_type = "rns"
            rns_hash = label.replace("rns:", "") if label.startswith("rns:") else None
            if rns_hash:
                peer_state.rns_dest_hash = rns_hash
                self._known_rns_hashes[peer_id] = rns_hash
        else:
            peer_state.transport_type = "websocket"
            peer_state.ws_address = address

        await self._db.upsert_peer(
            peer_id, identity_public_b64=peer_identity_b64,
            address=address,
        )

        self.metrics.handshake_successes += 1
        self._reset_backoff(peer_id)  # v0.6
        logger.info("Connected to peer %s at %s via %s", peer_id, label,
                    peer_state.transport_type)

        # Pin peer fingerprint + address for mDNS verification
        if peer_identity_b64:
            fp = ew_keys.get_fingerprint(base64.b64decode(peer_identity_b64))
            if peer_name:
                self._pinned_peers[peer_name] = {
                    "fingerprint": fp,
                    "address": address,
                    "peer_id": peer_id,
                }

        # Flush pending
        asyncio.ensure_future(self._flush_pending(peer_id))

        # Message loop. On exit (socket closed or error), tear down the
        # peer state so reconnect paths see OFFLINE and can re-dial. v0.8.1
        # fix: previously the client side left the peer as ONLINE forever
        # once the message loop ended, which blocked the reconnect loop
        # (which skips peers not in OFFLINE state).
        try:
            # v0.8.5.6: tag inbound transport.
            _transport_name = (
                "rns" if RNSLinkAdapter is not None
                and isinstance(ws, RNSLinkAdapter)
                else "ws"
            )
            async for raw in ws:
                try:
                    self.metrics.bytes_received += len(raw)
                    await self._handle_message(
                        peer_id, raw, transport=_transport_name,
                    )
                except Exception as e:
                    logger.warning("Error from %s: %s", peer_id, e)
        finally:
            # Scope the teardown to the owning connection -- same
            # duplicate-handshake race as _handle_connection.
            owned_session = False
            async with self._peer_lock:
                if self.ws_clients.get(peer_id) is ws:
                    self.ws_clients.pop(peer_id, None)
                    self._peer_rate_limiters.pop(peer_id, None)
                    if peer_id in self.peers:
                        self.peers[peer_id].transition(
                            ew_protocol.PeerState.Status.OFFLINE,
                        )
                        self.peers[peer_id].session_key = None
                    owned_session = True
            if owned_session:
                if self._hooks:
                    try:
                        await self._hooks.fire(
                            "on_peer_disconnect", {"peer_id": peer_id},
                        )
                    except Exception:
                        pass
                asyncio.ensure_future(self._try_transport_failover(peer_id))

        return peer_id

    def _build_client_ssl_context(self) -> ssl.SSLContext:
        """Build the outbound WSS context based on operator settings.

        Two modes:

        - **Default (mesh mode):** ``check_hostname=False``, ``CERT_NONE``.
          TLS provides line-level confidentiality; peer authentication runs
          at the application layer (passphrase HMAC + Ed25519 + TOFU). This
          matches how mesh peers historically interoperate without a shared
          CA, but it does not authenticate the WSS endpoint itself.
        - **Strict mode** (``strict_tls=True``): ``check_hostname=True``,
          ``CERT_REQUIRED``. If ``pinned_ca_path`` is set, that bundle is
          loaded as the trust anchor; otherwise the system trust store is
          used. Use this when WSS endpoints are issued real certificates
          (operator CA, public ACME, etc.) and the operator wants the
          transport-level identity check on top of the application-layer
          handshake.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if self._strict_tls:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            if self._pinned_ca_path:
                ctx.load_verify_locations(cafile=self._pinned_ca_path)
            else:
                ctx.load_default_certs()
        else:
            # Mesh-default: peers verify each other at the application layer.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def connect_to_peer(self, host: str, port: int) -> Optional[str]:
        """Connect to a remote peer as client, performing full handshake.

        Attempts wss:// (TLS) first. Falls back to ws:// only if
        _allow_plaintext_ws is True. This protects the handshake from
        passive eavesdropping.
        """
        ws = None
        uri = None
        # Try TLS first
        try:
            uri = f"wss://{host}:{port}"
            client_ssl = self._build_client_ssl_context()
            ws = await asyncio.wait_for(
                websockets.connect(uri, ssl=client_ssl, max_size=self.max_message_size, ping_interval=20, ping_timeout=10),
                timeout=10,
            )
            logger.info("TLS connection established to %s:%d", host, port)
        except Exception as tls_err:
            if not self._allow_plaintext_ws:
                logger.warning(
                    "TLS connection failed to %s:%d and plaintext is disabled: %s",
                    host, port, tls_err)
                return None
            # Fallback to plaintext
            logger.warning(
                "TLS unavailable for %s:%d, falling back to ws:// (INSECURE): %s",
                host, port, tls_err)
            try:
                uri = f"ws://{host}:{port}"
                ws = await asyncio.wait_for(
                    websockets.connect(uri, max_size=self.max_message_size, ping_interval=20, ping_timeout=10),
                    timeout=10,
                )
            except Exception as plain_err:
                logger.warning("Plaintext connection also failed to %s:%d: %s", host, port, plain_err)
                return None
        try:
            async with ws:
                return await self._do_client_handshake(ws, f"{host}:{port}")

        except Exception as e:
            logger.debug("Connect to %s:%d failed: %s", host, port, e)
            return None

    async def _connect_rns_peer(self, dest_hash: str) -> Optional[str]:
        """Connect to a peer over Reticulum (LoRa/RNS).

        Resolves the destination, creates an RNS link, wraps it in an
        ``RNSLinkAdapter``, then runs the standard IronMesh handshake.
        """
        if not self._reticulum:
            logger.warning("Cannot connect to RNS peer — Reticulum transport not active")
            return None
        try:
            adapter = await self._reticulum.connect_to_destination(dest_hash)
            if not adapter:
                return None
            return await self._do_client_handshake(adapter, f"rns:{dest_hash}")
        except Exception as e:
            logger.warning("RNS connect to %s failed: %s", dest_hash, e)
            return None

    async def _connect_and_track_rns(self, dest_hash: str):
        """Connect to an RNS peer and remember the hash for reconnection."""
        peer_id = await self._connect_rns_peer(dest_hash)
        if peer_id:
            self._known_rns_hashes[peer_id] = dest_hash
        return peer_id

    # ------------------------------------------------------------------
    # v0.9.2: handshake-skip eligibility (chunk A)
    # ------------------------------------------------------------------
    #
    # Both server-side and client-side handshake paths consult these
    # helpers to decide whether to take the shortened skip path. The
    # decision must agree on both ends or the handshake will deadlock —
    # the tie-breaker is the announce app_data: both peers must
    # advertise the `hskip` feature, AND the local daemon must have
    # opted in via rns_skip_handshake, AND the transport must be an
    # RNS Link with a known remote Identity hash. Anything else falls
    # back to the full handshake.

    def _peer_advertises_hskip(self, identity_hash_hex: Optional[str]) -> bool:
        """Did the peer with this RNS Identity hash advertise hskip?"""
        if not identity_hash_hex:
            return False
        # Snapshot — RNS announce handler mutates this dict on the RNS
        # Transport thread; iterating live can raise RuntimeError mid-
        # handshake under busy-mesh conditions.
        for entry in list(self._rns_discovered.values()):
            if entry.get("identity_hash") == identity_hash_hex:
                return "hskip" in entry.get("features", [])
        return False

    def _handshake_skip_eligible_server(self, websocket) -> bool:
        """Server-side check before sending the PASSPHRASE_CHALLENGE."""
        if not getattr(self, "_rns_skip_handshake", False):
            return False
        if RNSLinkAdapter is None or not isinstance(websocket, RNSLinkAdapter):
            return False
        # ironmesh/0.9: never offer the skip on a link whose id the local
        # side cannot read — the skip path requires verifying the peer's
        # rns_link_id binding against this link, and an unverifiable
        # binding means the offer would only ever end in a rejected HELLO.
        # Falling back to the full stage-1 handshake is the useful outcome.
        if not getattr(websocket, "link_id_hex", None):
            return False
        return self._peer_advertises_hskip(
            getattr(websocket, "remote_identity_hash", None)
        )

    async def _await_remote_identity(self, websocket, timeout: float = 1.0) -> bool:
        """Briefly poll for the RNS Link's remote_identity_hash to be set.

        v0.9.2 chunk A live-test discovered: when an outbound peer
        calls `link.identify()` immediately after the link becomes
        ACTIVE, the identify-proof packet may arrive on the server's
        RNS thread AFTER `_handle_connection` has already started its
        eligibility check. The check then sees `remote_identity_hash =
        None` and falls back to the legacy challenge/verify flow,
        silently disabling the skip even when both sides would otherwise
        be eligible.

        This polls the adapter's `remote_identity_hash` for up to
        ``timeout`` seconds (default 1.0s — RNS identify proofs land
        in tens of milliseconds on LAN, well under a second on LoRa).
        Returns True if identity was populated, False on timeout.
        """
        if RNSLinkAdapter is None or not isinstance(websocket, RNSLinkAdapter):
            return False
        if getattr(websocket, "remote_identity_hash", None):
            return True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if getattr(websocket, "remote_identity_hash", None):
                return True
            await asyncio.sleep(0.05)
        return getattr(websocket, "remote_identity_hash", None) is not None

    def _handshake_skip_eligible_client(self, websocket) -> bool:
        """Client-side check before waiting for the PASSPHRASE_CHALLENGE."""
        if not getattr(self, "_rns_skip_handshake", False):
            return False
        if RNSLinkAdapter is None or not isinstance(websocket, RNSLinkAdapter):
            return False
        return self._peer_advertises_hskip(
            getattr(websocket, "remote_identity_hash", None)
        )
