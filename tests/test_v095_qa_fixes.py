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
        """Dual-key RECEIVE path: with the grace window open (set up via
        _begin_rekey_transition, exactly as both handlers do), an old-key frame
        arriving after the switch must decrypt + dispatch. (The handlers that
        OPEN the window are covered by test_initiator_handler_opens_dual_key_window
        and test_responder_handler_opens_dual_key_window.)"""
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

    def test_windows_invokes_icacls_owner_only(self, tmp_path, monkeypatch):
        """The v0.9.5 fix IS the Windows icacls ACL — verify it's actually
        invoked (not a no-op). Platform-independent via monkeypatch so it
        guards the Windows path even when the suite runs on POSIX."""
        import ironmesh.keys as keys_mod
        calls = []

        class _R:
            returncode = 0
            stderr = b""

        def fake_run(args, **kw):
            calls.append(args)
            return _R()

        monkeypatch.setattr(keys_mod.os, "name", "nt")
        monkeypatch.setattr("subprocess.run", fake_run)  # function does a local `import subprocess`
        monkeypatch.setenv("USERNAME", "testuser")
        p = tmp_path / "k.json"
        p.write_bytes(b"secret")
        keys_mod.restrict_file_to_owner(str(p))
        assert calls, "icacls was never invoked on the Windows path (silent no-op)"
        argv = calls[-1]
        assert argv[0] == "icacls"
        assert "/inheritance:r" in argv and "/grant:r" in argv
        assert "testuser:F" in argv

    def test_windows_icacls_failure_is_swallowed(self, tmp_path, monkeypatch):
        """A non-zero icacls exit must be logged, not raised (best-effort)."""
        import ironmesh.keys as keys_mod

        class _R:
            returncode = 5
            stderr = b"denied"

        monkeypatch.setattr(keys_mod.os, "name", "nt")
        monkeypatch.setattr("subprocess.run", lambda a, **k: _R())
        monkeypatch.setenv("USERNAME", "testuser")
        p = tmp_path / "k.json"
        p.write_bytes(b"secret")
        keys_mod.restrict_file_to_owner(str(p))  # must not raise


# ---------------------------------------------------------------------------
# Dispatch-level LoRa decompression: terminal decompresses+delivers; a relay
# forwards the compressed frame intact; a decompression bomb is dropped.
# (Locks the decompress-relocation + bomb-cap wiring at the real dispatch site.)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDispatchDecompression:
    @staticmethod
    def _compressed_nonE2E_frame(origin_kp, dest, plaintext):
        import gzip
        from ironmesh.protocol import canonical_inner_source_bytes
        from ironmesh.crypto import (
            SIG_CTX_FRAME_INNER_SOURCE, sign_detached_with_context)
        comp = gzip.compress(plaintext)
        f = Frame(msg_type=MessageType.MSG, payload=comp, msg_id="m1",
                  source="origin", destination=dest)
        f.routing["compressed"] = True
        canon = canonical_inner_source_bytes("origin", dest, "m1", comp)  # signed over COMPRESSED
        f.source_signature = sign_detached_with_context(
            origin_kp.get_signing_key(), SIG_CTX_FRAME_INNER_SOURCE, canon)
        f.source_sig_scheme = Frame.SOURCE_SIG_SCHEME_V2
        return f, comp, plaintext

    def _daemon(self, tmp_path, origin_kp):
        from unittest.mock import AsyncMock, MagicMock
        d = BridgeDaemon(name="R", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "r.db"))
        d._keypair = generate_keypair("R")
        d._db = AsyncMock(); d.bus = MagicMock()
        d.peers["origin"] = PeerState(node_id="origin", address="x")
        d.peers["origin"].identity_public = origin_kp.ed25519_public
        return d

    async def test_terminal_decompresses_and_delivers(self, tmp_path):
        O = generate_keypair("origin")
        d = self._daemon(tmp_path, O); d._mesh = None
        f, comp, plain = self._compressed_nonE2E_frame(O, d.node_id, b"Z" * 300)
        await d._dispatch_message("relaypeer",
                                  PeerState(node_id="relaypeer", address="y"), f)
        assert f.payload == plain, "terminal node did not decompress"
        assert d.bus.publish.called, "terminal compressed frame not delivered"

    async def test_relay_forwards_compressed_intact(self, tmp_path):
        from unittest.mock import AsyncMock, MagicMock
        O = generate_keypair("origin")
        d = self._daemon(tmp_path, O)
        d._mesh = MagicMock()
        d._mesh.relay_message = AsyncMock()
        d._mesh.dedup = MagicMock()
        d._mesh.dedup.check_and_add = MagicMock(return_value=False)
        f, comp, plain = self._compressed_nonE2E_frame(O, "faraway-node", b"Z" * 300)
        await d._dispatch_message("relaypeer",
                                  PeerState(node_id="relaypeer", address="y"), f)
        assert f.payload == comp, "relay decompressed in place (invalidates next-hop sig)"
        assert d._mesh.relay_message.called, "relay did not forward"
        assert not d.bus.publish.called, "relay delivered a non-terminal frame"

    async def test_decompression_bomb_dropped(self, tmp_path):
        import gzip
        from ironmesh.protocol import canonical_inner_source_bytes
        from ironmesh.crypto import (
            SIG_CTX_FRAME_INNER_SOURCE, sign_detached_with_context)
        O = generate_keypair("origin")
        d = self._daemon(tmp_path, O); d._mesh = None
        bomb = gzip.compress(b"\x00" * (64 * 1024 * 1024))  # ~64 MiB -> tiny
        f = Frame(msg_type=MessageType.MSG, payload=bomb, msg_id="m1",
                  source="origin", destination=d.node_id)
        f.routing["compressed"] = True
        canon = canonical_inner_source_bytes("origin", d.node_id, "m1", bomb)
        f.source_signature = sign_detached_with_context(
            O.get_signing_key(), SIG_CTX_FRAME_INNER_SOURCE, canon)
        f.source_sig_scheme = Frame.SOURCE_SIG_SCHEME_V2
        await d._dispatch_message("relaypeer",
                                  PeerState(node_id="relaypeer", address="y"), f)
        assert not d.bus.publish.called, "decompression bomb was delivered (not fail-closed)"


# ---------------------------------------------------------------------------
# Responder-handler symmetry: _handle_rekey_request must ALSO open the
# dual-key window (previously only the initiator handler was asserted).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestResponderRekeyWindow:
    async def test_responder_handler_opens_dual_key_window(self, tmp_path):
        from unittest.mock import AsyncMock
        d = BridgeDaemon(name="R", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "r.db"))
        d._keypair = generate_keypair("R")
        d._send_encrypted_control = AsyncMock()
        peer_id = "z" * 40  # ensure no collision path (peer has no pending on us)
        peer = PeerState(node_id=peer_id, address="x")
        old = os.urandom(32)
        peer.session_key = old
        d.peers[peer_id] = peer
        _priv, pub = generate_ephemeral()
        payload = json.dumps({
            "new_ephemeral_public": base64.b64encode(bytes(pub)).decode(),
            "rekey_id": "rk-resp",
        }).encode()
        await d._handle_rekey_request(peer_id, payload, peer)
        assert peer.prev_session_key == old, \
            "responder handler did not open the dual-key window"
        assert peer.session_key != old
        assert peer.rekey_transition_until > time.monotonic()


# ---------------------------------------------------------------------------
# WO8 Phase 2 — named regression tests
#
# (1) Rekey reorder-interleaving: RNS reorders large frames onto an independent
#     stream, so during the dual-key grace window old-key and new-key frames can
#     arrive scrambled and interleaved. Every valid frame must still decrypt +
#     dispatch, and a replayed sequence inside an epoch must still be dropped.
#     Prior tests only sent 1-2 frames in order.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRekeyReorderInterleaving:
    def _receiver(self, tmp_path, sender_kp):
        from unittest.mock import AsyncMock
        d = BridgeDaemon(name="R", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "r.db"))
        d._keypair = generate_keypair("R")
        d._dispatch_message = AsyncMock()
        peer = PeerState(node_id="S", address="127.0.0.1:9")
        peer.identity_public = sender_kp.ed25519_public
        peer.verified = True
        d.peers["S"] = peer
        return d, peer

    async def test_interleaved_old_and_new_epoch_frames_all_deliver(self, tmp_path):
        """Old-key and new-key frames INTERLEAVED across the grace window all
        deliver. Each epoch keeps its own strict-monotonic replay counter (the
        guard drops any seq <= last-seen within an epoch), so the reordering the
        dual-key window must absorb is at the KEY/epoch level: alternating
        old/new frames, each epoch advancing independently."""
        S = generate_keypair("S")
        d, peer = self._receiver(tmp_path, S)
        old_key, new_key = os.urandom(32), os.urandom(32)
        _post_rekey_state(d, "S", peer, old_key, new_key)

        # Two epochs interleaved in arrival; each epoch's own sequence is
        # monotonic (new: 10,11,12 ; old: 20,21,22).
        arrivals = [
            (new_key, 10), (old_key, 20), (new_key, 11),
            (old_key, 21), (new_key, 12), (old_key, 22),
        ]
        for key, seq in arrivals:
            raw = _wire(S, key, seq=seq, src="S", dst=d.node_id,
                        payload=f"f{seq}".encode())
            await d._handle_binary_frame("S", raw, peer)

        assert d._dispatch_message.await_count == len(arrivals), \
            "an interleaved in-window frame was dropped (dual-key epoch routing)"
        assert peer.prev_session_key is not None, \
            "grace window closed early under interleaving"

    async def test_replayed_sequence_within_epoch_is_dropped(self, tmp_path):
        """Reorder tolerance must not become replay tolerance: re-delivering an
        already-seen sequence in the same epoch is dropped."""
        S = generate_keypair("S")
        d, peer = self._receiver(tmp_path, S)
        old_key, new_key = os.urandom(32), os.urandom(32)
        _post_rekey_state(d, "S", peer, old_key, new_key)

        raw = _wire(S, new_key, seq=30, src="S", dst=d.node_id, payload=b"orig")
        await d._handle_binary_frame("S", raw, peer)
        assert d._dispatch_message.await_count == 1
        # Exact same encrypted frame again (same epoch, same seq) — replay.
        await d._handle_binary_frame("S", raw, peer)
        assert d._dispatch_message.await_count == 1, \
            "replayed in-epoch sequence was delivered a second time"


# ---------------------------------------------------------------------------
# (2) Strict-floor handshake-refusal: when --e2e-strict-confidentiality raises
#     the floor to ironmesh/0.9, a peer advertising a pre-0.9 version must be
#     refused. Both server enforcement sites (handshake.py and bridge.py's
#     websocket HELLO handler) apply the SAME predicate:
#         _parse_protocol_version(peer) < _parse_protocol_version(min)  -> refuse
#     This pins the refusal boundary against a REAL strict-mode daemon's
#     configured floor and the REAL version parser (TestStrictProtocolFloor only
#     asserts the floor VALUE, not that sub-floor versions are refused).
# ---------------------------------------------------------------------------

class TestStrictFloorHandshakeRefusal:
    def _floor(self, tmp_path, strict):
        from ironmesh.handshake import _parse_protocol_version
        d = BridgeDaemon(name="a", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "a.db"),
                         e2e_strict_confidentiality=strict)
        return _parse_protocol_version(d._min_protocol_version)

    def test_strict_floor_refuses_pre_0_9_peers(self, tmp_path):
        from ironmesh.handshake import _parse_protocol_version
        floor = self._floor(tmp_path, strict=True)
        assert floor == (0, 9)
        for v in ("ironmesh/0.3", "ironmesh/0.4", "ironmesh/0.6", "ironmesh/0.8"):
            assert _parse_protocol_version(v) < floor, \
                f"{v} must be refused under the strict 0.9 floor"

    def test_strict_floor_admits_0_9_and_newer(self, tmp_path):
        from ironmesh.handshake import _parse_protocol_version
        floor = self._floor(tmp_path, strict=True)
        for v in ("ironmesh/0.9", "ironmesh/0.10", "ironmesh/1.0"):
            assert not (_parse_protocol_version(v) < floor), \
                f"{v} must be admitted under the strict 0.9 floor"

    def test_default_floor_preserves_legacy_interop(self, tmp_path):
        from ironmesh.handshake import _parse_protocol_version
        floor = self._floor(tmp_path, strict=False)
        # Default floor must NOT refuse the bundled reference clients (0.6) — the
        # opt-in-off design keeps wire-compat with pre-0.9 nodes.
        assert not (_parse_protocol_version("ironmesh/0.6") < floor)
