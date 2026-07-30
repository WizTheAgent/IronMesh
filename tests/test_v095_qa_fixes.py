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
