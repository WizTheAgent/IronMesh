"""Regression tests for the v0.9.5 pre-release QA fixes.

These lock down bugs found in the intense pre-launch review that the existing
suite did not cover:

  * Decompression-bomb ceiling on LoRa-QoS payloads (`_bounded_gunzip`).
  * The compression x inner-source-signature interaction that silently dropped
    every >128 B e2e message on RNS/LoRa in the default mode: an e2e frame must
    NOT be LoRa-compressed, because the inner source signature is verified
    post-unseal over the uncompressed plaintext.
  * The asymmetric dual-key rekey window: the INITIATOR must also retain the
    retiring key so an old-key frame arriving after REKEY_RESPONSE (routine on
    RNS, which reorders large frames onto an independent stream) still decrypts
    instead of being silently dropped — and the window must NOT be torn down by
    the first new-key frame.
"""

import base64
import json
import os
import time

import pytest

from ironmesh.bridge import BridgeDaemon
from ironmesh.keys import generate_keypair, generate_ephemeral
from ironmesh.protocol import Frame, MessageType, PeerState
from ironmesh import routing as ew_routing

STRONG_PASSPHRASE = "audit-test-passphrase-12"


# ---------------------------------------------------------------------------
# Decompression bomb ceiling
# ---------------------------------------------------------------------------

class TestBoundedGunzip:
    def test_legit_payload_roundtrips(self):
        import gzip
        body = b"the quick brown fox " * 100
        out = ew_routing._bounded_gunzip(gzip.compress(body),
                                         ew_routing._MAX_DECOMPRESSED_BYTES)
        assert out == body

    def test_bomb_rejected(self):
        import gzip
        # ~64 MiB of zeros compresses to a few KiB — the classic bomb.
        bomb = gzip.compress(b"\x00" * (64 * 1024 * 1024))
        assert len(bomb) < 100_000
        with pytest.raises(ValueError):
            ew_routing._bounded_gunzip(bomb, ew_routing._MAX_DECOMPRESSED_BYTES)

    def test_output_capped_just_over_limit(self):
        import gzip
        cap = 4096
        over = gzip.compress(b"A" * (cap + 1))
        with pytest.raises(ValueError):
            ew_routing._bounded_gunzip(over, cap)
        # exactly at the cap is fine
        exact = gzip.compress(b"A" * cap)
        assert ew_routing._bounded_gunzip(exact, cap) == b"A" * cap


# ---------------------------------------------------------------------------
# Compression x e2e inner-source signature (Finding A — silent RNS drop)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestE2ENotCompressed:
    async def test_e2e_frame_to_rns_peer_is_not_compressed(self, tmp_path):
        """An e2e-sealed frame to an RNS peer, larger than the LoRa cap, must
        go out UNcompressed — otherwise the inner sig (over the compressed
        wire bytes) fails the destination's post-unseal verify (over the
        uncompressed plaintext) and the frame is silently dropped."""
        from unittest.mock import AsyncMock

        d = BridgeDaemon(name="S", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "s.db"))
        d._keypair = generate_keypair("S")
        d._db = AsyncMock()          # store_message is a no-op for this test
        d._lora_max_payload = 128

        dest = generate_keypair("R")
        peer = PeerState(node_id="R", address="127.0.0.1:9")
        peer.session_key = os.urandom(32)
        peer.identity_public = dest.ed25519_public   # -> e2e seal engages
        peer.transport_type = "rns"                  # -> compression path eligible
        peer.verified = True
        d.peers["R"] = peer

        sent = {}
        ws = AsyncMock()
        ws.send.side_effect = lambda data: sent.__setitem__("frame", data)
        d.ws_clients["R"] = ws

        big = b"P" * 300  # > lora_max_payload
        await d._send_message_inner("R", MessageType.MSG, big, priority=0)

        assert "frame" in sent, "frame was not transmitted"
        wire = Frame.deserialize_and_decrypt(
            sent["frame"], peer.session_key,
            verify_key=d._keypair.get_verify_key())
        # The e2e-sealed frame must NOT carry the 'compressed' routing flag...
        assert not wire.routing.get("compressed"), \
            "e2e frame was LoRa-compressed — inner sig will fail post-unseal"
        assert wire.e2e_payload is not None
        # ...and the destination must recover the exact plaintext + verify the
        # inner source signature over it.
        from ironmesh import mesh_crypto
        recovered = mesh_crypto.unseal_from_source(
            wire.e2e_payload, dest.ed25519_secret)
        assert recovered == big
        wire.payload = recovered
        rcv = BridgeDaemon(name="R", passphrase=STRONG_PASSPHRASE,
                           db_path=str(tmp_path / "r.db"))
        rcv._keypair = dest
        rcv.peers["Sid"] = PeerState(node_id="Sid", address="x")
        rcv.peers["Sid"].identity_public = d._keypair.ed25519_public
        # The source of the frame is d.node_id; register it so the verify key
        # resolves, then confirm inner-source verification passes.
        wire.source = d.node_id
        rcv.peers[d.node_id] = PeerState(node_id=d.node_id, address="x")
        rcv.peers[d.node_id].identity_public = d._keypair.ed25519_public
        assert rcv._verify_inner_source("relaypeer", wire) is True


# ---------------------------------------------------------------------------
# Rekey dual-key transition (F1 symmetry, F2 no eager teardown)
# ---------------------------------------------------------------------------

def _wire(sender_kp, session_key, seq, src, dst, payload=b"hi"):
    f = Frame(msg_type=MessageType.MSG, payload=payload,
              msg_id=f"m{seq}", source=src, destination=dst)
    f.sequence = seq
    f.timestamp = time.time()
    return f.encrypt_and_serialize(
        session_key,
        signing_key=sender_kp.get_signing_key(),
        source_signing_key=sender_kp.get_signing_key())


def _post_rekey_state(daemon, peer_id, peer_state, old_key, new_key):
    """Reproduce the state both rekey handlers leave behind: retain old key in
    a grace window (via the shared helper), switch to new, reset the fresh
    epoch's replay state."""
    peer_state.session_key = old_key
    daemon._begin_rekey_transition(peer_id, peer_state)
    peer_state.session_key = new_key
    peer_state.session_rekey_count += 1   # handlers increment after _begin
    daemon._replay_guard.reset_peer(peer_id)


@pytest.mark.asyncio
class TestRekeyDualKeySymmetric:
    def _receiver(self, tmp_path, sender_kp):
        d = BridgeDaemon(name="R", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "r.db"))
        d._keypair = generate_keypair("R")
        from unittest.mock import AsyncMock
        d._dispatch_message = AsyncMock()
        peer = PeerState(node_id="S", address="127.0.0.1:9")
        peer.identity_public = sender_kp.ed25519_public
        peer.verified = True
        d.peers["S"] = peer
        return d, peer

    async def test_old_key_frame_in_window_decrypts(self, tmp_path):
        """F1: the initiator (which retains prev via the symmetric helper) must
        decrypt + dispatch an old-key frame arriving after the switch."""
        S = generate_keypair("S")
        d, peer = self._receiver(tmp_path, S)
        old_key, new_key = os.urandom(32), os.urandom(32)
        _post_rekey_state(d, "S", peer, old_key, new_key)
        raw = _wire(S, old_key, seq=1, src="S", dst=d.node_id, payload=b"under-old")
        await d._handle_binary_frame("S", raw, peer)
        assert d._dispatch_message.await_count == 1, \
            "old-key frame in window was dropped (F1 asymmetry regression)"

    async def test_new_key_frame_does_not_tear_down_window(self, tmp_path):
        """F2: a new-key frame must NOT retire the window while old-key frames
        may still be in flight."""
        S = generate_keypair("S")
        d, peer = self._receiver(tmp_path, S)
        old_key, new_key = os.urandom(32), os.urandom(32)
        _post_rekey_state(d, "S", peer, old_key, new_key)
        # new-key frame arrives first
        await d._handle_binary_frame(
            "S", _wire(S, new_key, seq=1, src="S", dst=d.node_id), peer)
        assert peer.prev_session_key is not None, \
            "window torn down by first new-key frame (F2 regression)"
        # then an old-key frame still in the window
        await d._handle_binary_frame(
            "S", _wire(S, old_key, seq=2, src="S", dst=d.node_id, payload=b"late-old"), peer)
        assert d._dispatch_message.await_count == 2, \
            "late old-key frame dropped after new-key frame (F2 regression)"

    async def test_old_key_frame_dropped_after_deadline(self, tmp_path):
        """Once the monotonic grace deadline passes, the retiring key is
        retired and an old-key frame is dropped (and the window cleaned up)."""
        S = generate_keypair("S")
        d, peer = self._receiver(tmp_path, S)
        old_key, new_key = os.urandom(32), os.urandom(32)
        _post_rekey_state(d, "S", peer, old_key, new_key)
        peer.rekey_transition_until = time.monotonic() - 1.0  # window expired
        await d._handle_binary_frame(
            "S", _wire(S, old_key, seq=1, src="S", dst=d.node_id), peer)
        assert d._dispatch_message.await_count == 0, "expired old-key frame delivered"
        assert peer.prev_session_key is None, "expired window not cleaned up"

    async def test_initiator_handler_opens_dual_key_window(self, tmp_path):
        """The actual F1 fix: _handle_rekey_response (the INITIATOR handler)
        must retain the old key in a grace window, not just switch keys."""
        S = generate_keypair("S")
        d, peer = self._receiver(tmp_path, S)
        old = os.urandom(32)
        peer.session_key = old
        my_priv, _my_pub = generate_ephemeral()
        peer._pending_rekey_private = my_priv
        peer._pending_rekey_id = "rk1"
        _peer_priv, peer_pub = generate_ephemeral()
        payload = json.dumps({
            "new_ephemeral_public": base64.b64encode(bytes(peer_pub)).decode(),
            "rekey_id": "rk1",
        }).encode()
        await d._handle_rekey_response("S", payload, peer)
        assert peer.prev_session_key == old, \
            "initiator handler did not retain the old key (F1 regression)"
        assert peer.session_key != old
        assert peer.rekey_transition_until > time.monotonic()

    async def test_double_rekey_resets_prior_snapshot(self, tmp_path):
        """A rapid second rekey inside the window must retire the prior epoch's
        replay snapshot rather than orphan it (F6)."""
        S = generate_keypair("S")
        d, peer = self._receiver(tmp_path, S)
        k0, k1 = os.urandom(32), os.urandom(32)
        _post_rekey_state(d, "S", peer, k0, k1)
        first_epoch = peer.prev_epoch_key
        # second rekey before the first window elapsed (distinct epoch name)
        d._begin_rekey_transition("S", peer)
        assert first_epoch not in d._replay_guard._peers, \
            "prior epoch snapshot orphaned on double-rekey (F6)"
        assert peer.prev_epoch_key != first_epoch


# ---------------------------------------------------------------------------
# Dispatch-level e2e integration (the CRITICAL coverage gap: fault-injecting
# the post-unseal verify previously left the whole suite green)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestE2EDispatchIntegration:
    def _receiver(self, tmp_path, origin_kp):
        from unittest.mock import AsyncMock, MagicMock
        dest = generate_keypair("dest")
        d = BridgeDaemon(name="R", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "r.db"))
        d._keypair = dest
        d._db = AsyncMock()
        d.bus = MagicMock()
        d._mesh = None  # skip dedup/relay branches -> terminal local delivery
        d.peers["origin"] = PeerState(node_id="origin", address="x")
        d.peers["origin"].identity_public = origin_kp.ed25519_public
        relay_ps = PeerState(node_id="relay", address="y")
        return d, dest, relay_ps

    def _e2e_frame(self, dest_kp, dest_node_id, plaintext, sign_kp, strip):
        from ironmesh import mesh_crypto
        from ironmesh.crypto import (
            SIG_CTX_FRAME_INNER_SOURCE, sign_detached_with_context)
        from ironmesh.protocol import canonical_inner_source_bytes
        f = Frame(msg_type=MessageType.MSG,
                  payload=(b"" if strip else plaintext),
                  msg_id="mm", source="origin", destination=dest_node_id)
        # Seal to the destination's advertised master-seed X25519 key when it
        # has one (matching the real send path), so the receiver's master-seed
        # unseal succeeds rather than trying legacy derivation.
        dest_x25519 = (dest_kp.x25519_public
                       if getattr(dest_kp, "x25519_seed", None) is not None
                       else None)
        f.e2e_payload = mesh_crypto.seal_to_destination(
            plaintext, dest_kp.ed25519_public, dest_x25519_pub=dest_x25519)
        canon = canonical_inner_source_bytes(
            f.source, f.destination, f.msg_id, plaintext)
        f.source_signature = sign_detached_with_context(
            sign_kp.get_signing_key(), SIG_CTX_FRAME_INNER_SOURCE, canon)
        f.source_sig_scheme = Frame.SOURCE_SIG_SCHEME_V2
        return f

    async def test_valid_e2e_delivers(self, tmp_path):
        O = generate_keypair("origin")
        d, dest, relay_ps = self._receiver(tmp_path, O)
        f = self._e2e_frame(dest, d.node_id, b"secret-body", sign_kp=O, strip=False)
        await d._dispatch_message("relay", relay_ps, f)
        assert d.bus.publish.called, "valid e2e frame was not delivered"

    async def test_forged_e2e_dropped_by_dispatch(self, tmp_path):
        # Sealed to the destination (attacker can seal to a public key), but
        # the inner sig is by the attacker while claiming source='origin'.
        O = generate_keypair("origin")
        attacker = generate_keypair("attacker")
        d, dest, relay_ps = self._receiver(tmp_path, O)
        f = self._e2e_frame(dest, d.node_id, b"spoofed", sign_kp=attacker, strip=False)
        await d._dispatch_message("relay", relay_ps, f)
        assert not d.bus.publish.called, \
            "forged e2e frame was DELIVERED by dispatch (fail-open regression)"

    async def test_stripped_frame_survives_precheck_and_delivers(self, tmp_path):
        # payload=b"" (strict-mode wire form) must survive the chokepoint
        # e2e-skip and deliver after post-unseal verify — not be black-holed.
        O = generate_keypair("origin")
        d, dest, relay_ps = self._receiver(tmp_path, O)
        f = self._e2e_frame(dest, d.node_id, b"strict-body", sign_kp=O, strip=True)
        assert f.payload == b""
        await d._dispatch_message("relay", relay_ps, f)
        assert d.bus.publish.called, \
            "stripped e2e frame was black-holed (should deliver post-unseal)"


# ---------------------------------------------------------------------------
# Strict-mode ties the protocol floor to >= 0.9 (wire-compat F2)
# ---------------------------------------------------------------------------

class TestStrictProtocolFloor:
    def test_strict_raises_floor_to_0_9(self, tmp_path):
        d = BridgeDaemon(name="a", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "a.db"),
                         e2e_strict_confidentiality=True)
        assert d._min_protocol_version == "ironmesh/0.9", \
            "strict mode must raise the floor so no pre-0.9 node gets a stripped frame"

    def test_default_keeps_floor(self, tmp_path):
        d = BridgeDaemon(name="b", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "b.db"))
        assert d._min_protocol_version == "ironmesh/0.3"


# ---------------------------------------------------------------------------
# Rekey collision resolution (F3: dashboard rotate bypasses the loop tiebreak)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRekeyCollision:
    def _daemon_with_pending(self, tmp_path, peer_id):
        from unittest.mock import AsyncMock
        d = BridgeDaemon(name="R", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "r.db"))
        d._keypair = generate_keypair("R")
        d._send_encrypted_control = AsyncMock()
        peer = PeerState(node_id=peer_id, address="x")
        peer.session_key = os.urandom(32)
        my_priv, _ = generate_ephemeral()
        peer._pending_rekey_private = my_priv
        peer._pending_rekey_id = "our-pending"
        d.peers[peer_id] = peer
        return d, peer

    @staticmethod
    def _request_payload():
        _priv, pub = generate_ephemeral()
        return json.dumps({
            "new_ephemeral_public": base64.b64encode(bytes(pub)).decode(),
            "rekey_id": "their-request",
        }).encode()

    async def test_smaller_id_wins_ignores_peer_request(self, tmp_path):
        d, peer = self._daemon_with_pending(tmp_path, peer_id="z" * 40)
        assert d.node_id < "z" * 40
        await d._handle_rekey_request("z" * 40, self._request_payload(), peer)
        assert d._send_encrypted_control.await_count == 0, \
            "smaller-id node should ignore the competing request (not respond)"
        assert peer._pending_rekey_id == "our-pending", "should keep our pending rekey"

    async def test_larger_id_defers_and_responds(self, tmp_path):
        d, peer = self._daemon_with_pending(tmp_path, peer_id="0" * 40)
        assert d.node_id > "0" * 40
        await d._handle_rekey_request("0" * 40, self._request_payload(), peer)
        assert d._send_encrypted_control.await_count == 1, \
            "larger-id node should defer and respond to the peer's request"
        assert peer._pending_rekey_id is None, "should abandon our pending rekey"


# ---------------------------------------------------------------------------
# Owner-only key-file restriction is best-effort (does not raise)
# ---------------------------------------------------------------------------

class TestRestrictFileToOwner:
    def test_best_effort_no_raise_and_posix_mode(self, tmp_path):
        from ironmesh.keys import restrict_file_to_owner
        p = tmp_path / "k.json"
        p.write_bytes(b"secret")
        restrict_file_to_owner(str(p))  # must never raise
        assert p.exists()
        if os.name != "nt":
            import stat
            assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
