"""Security stress harness — five adversarial areas, each with an explicit
pass criterion and the exact input that would FAIL it.

This suite is deliberately assertive about *negative* behaviour: for every
security control it drives the exact malicious input the control exists to
reject, and asserts both the raised error AND the absence of any side effect
(no peer pinned, no token surviving, no partial write, no firewall command).
A control that merely "returns cleanly" is not enough — the tests below fail
if the bad input is accepted OR if a good control input is rejected.

Areas
-----
1. Invite adversarial input fails closed (malformed / wrong-context /
   expired / spent / bad-sig / wrong-inviter / corrupt ledger) + QR content.
2. Invite crash-window — the MARK-FIRST ordering. Crash-after-mark,
   pin-save-failure, torn-pin-write, and a mark-first vs pin-first
   quantification.
3. Multi-hop tampered-frame inner-source-signature (source / destination /
   msg_id tamper each drop and increment the counter by exactly 1).
4. Profile / alias resolution (five postures + three aliases; explicit-flag
   override; secure == tactical byte-identical).
5. doctor --fix guardrails (SSH network-fix refusal, never-auto-firewall,
   idempotent local fixes).
"""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ironmesh import crypto as ew_crypto
from ironmesh import invite as ew_invite
from ironmesh.keys import generate_keypair
from ironmesh.trust import TrustStore, TrustStoreError


# ===========================================================================
# Shared daemon stub (mirrors test_invite.py::_make_inviter_daemon so the
# stress cases drive the SAME production methods the unit suite drives).
# ===========================================================================

def _make_inviter_daemon(tmp_path, *, gate_on=False):
    from ironmesh.bridge import BridgeDaemon

    keypair = generate_keypair("inviter")
    trust_path = str(tmp_path / "known_peers.json")
    ledger_path = str(tmp_path / "invite_ledger.json")

    daemon = SimpleNamespace(
        config=SimpleNamespace(require_message_promotion=gate_on),
        _keypair=keypair,
        trust_path=trust_path,
        _invite_ledger_path=ledger_path,
        _invite_ledger=None,
        _audit=None,
        peers={},
        ws_clients={},
        _peer_rate_limiters={},
    )
    for name in ("_check_tofu", "_validate_incoming_invite",
                 "_get_invite_ledger", "_audit_invite_reject"):
        attr = getattr(BridgeDaemon, name)
        setattr(daemon, name, attr.__get__(daemon, daemon.__class__))
    return daemon, keypair, trust_path, ledger_path


def _read_trust(trust_path, keypair, node_id):
    mac = keypair.ed25519_secret[:32]
    ts = TrustStore(agent_key=mac, path=trust_path)
    return ts.get_peer(node_id)


def _peer_count(trust_path, keypair):
    mac = keypair.ed25519_secret[:32]
    return len(TrustStore(agent_key=mac, path=trust_path).list_peers())


# ===========================================================================
# AREA 1 — Invite adversarial input fails closed
#
# PASS: every adversarial token is REJECTED with a raised error and pins NO
#       peer in any state; a corrupt ledger RAISES on load.
# FAIL: any bad token pins a peer, or the corrupt ledger loads as empty
#       (which would let every past nonce replay once).
# ===========================================================================

class TestArea1InviteAdversarialInput:
    async def _expect_rejected_no_pin(self, tmp_path, token_str):
        """Present ``token_str`` to the inviter and assert it is refused with
        a ConnectionError AND that zero peers were pinned as a side effect."""
        daemon, keypair, trust_path, _ = _make_inviter_daemon(tmp_path)
        joiner = generate_keypair("joiner")
        before = _peer_count(trust_path, keypair)
        with pytest.raises(ConnectionError):
            await daemon._check_tofu(joiner.get_fingerprint(),
                                     joiner.get_public_key_base64(),
                                     token_str)
        # THE failing input: if _check_tofu had pinned the joiner despite the
        # bad token, this assert trips. Proven: no peer landed in ANY state.
        assert _peer_count(trust_path, keypair) == before
        assert _read_trust(trust_path, keypair, joiner.get_fingerprint()) is None

    @pytest.mark.asyncio
    async def test_malformed_token_rejected_no_pin(self, tmp_path):
        # Would FAIL if: "ironmesh-invite-v1:garbage" parsed to a token and pinned.
        await self._expect_rejected_no_pin(tmp_path, "ironmesh-invite-v1:garbage")

    @pytest.mark.asyncio
    async def test_wrong_context_signature_rejected_no_pin(self, tmp_path):
        # Forge by signing the EXACT canonical invite bytes under SIG_CTX_HELLO
        # instead of SIG_CTX_INVITE. verify_signature must refuse it (domain sep).
        daemon, keypair, trust_path, _ = _make_inviter_daemon(tmp_path)
        tok = ew_invite.create_invite(keypair, "host:8765")
        wrong_sig = ew_crypto.sign_detached_with_context(
            keypair.get_signing_key(), ew_crypto.SIG_CTX_HELLO, tok.canonical_bytes())
        forged = ew_invite.InviteToken(
            **{**tok.to_dict(), "signature": base64.b64encode(wrong_sig).decode()})
        # Direct proof at the model layer: the forged sig does not verify.
        with pytest.raises(ew_invite.InviteBadSignature):
            forged.verify_signature()
        # ...and the inviter path refuses it + pins nobody.
        # Would FAIL if a HELLO-context signature were accepted as an invite.
        await self._expect_rejected_no_pin(tmp_path, forged.to_string())

    @pytest.mark.asyncio
    async def test_expired_token_rejected_no_pin(self, tmp_path):
        daemon, keypair, trust_path, _ = _make_inviter_daemon(tmp_path)
        expired = ew_invite.create_invite(keypair, "host:8765",
                                          ttl_seconds=1, now=0.0)
        # is_expired is true well past expires_at + skew.
        assert expired.is_expired(now=expired.expires_at
                                  + ew_invite.INVITE_CLOCK_SKEW + 1)
        # Would FAIL if a token whose expiry is in the past were pinned.
        await self._expect_rejected_no_pin(tmp_path, expired.to_string())

    @pytest.mark.asyncio
    async def test_already_spent_token_rejected_no_pin(self, tmp_path):
        # First join consumes the nonce; a fresh joiner presenting the SAME
        # token must be rejected outright with no new pin.
        daemon, keypair, trust_path, ledger_path = _make_inviter_daemon(tmp_path)
        joiner1 = generate_keypair("joiner1")
        tok = ew_invite.create_invite(keypair, "host:8765")
        await daemon._check_tofu(joiner1.get_fingerprint(),
                                 joiner1.get_public_key_base64(), tok.to_string())
        assert daemon._get_invite_ledger().is_spent(tok.nonce)
        count_after_first = _peer_count(trust_path, keypair)
        joiner2 = generate_keypair("joiner2")
        with pytest.raises(ConnectionError):
            await daemon._check_tofu(joiner2.get_fingerprint(),
                                     joiner2.get_public_key_base64(),
                                     tok.to_string())
        # Would FAIL if the second (replay) join pinned joiner2.
        assert _peer_count(trust_path, keypair) == count_after_first
        assert _read_trust(trust_path, keypair, joiner2.get_fingerprint()) is None

    @pytest.mark.asyncio
    async def test_bad_signature_rejected_no_pin(self, tmp_path):
        # Mutate a signed field (endpoint) AFTER signing → signature breaks.
        daemon, keypair, trust_path, _ = _make_inviter_daemon(tmp_path)
        tok = ew_invite.create_invite(keypair, "host:8765")
        tampered = ew_invite.InviteToken(**{**tok.to_dict(), "endpoint": "evil:9999"})
        with pytest.raises(ew_invite.InviteBadSignature):
            tampered.verify_signature()
        # Would FAIL if a token with a mutated endpoint still pinned a peer.
        await self._expect_rejected_no_pin(tmp_path, tampered.to_string())

    @pytest.mark.asyncio
    async def test_wrong_inviter_rejected_no_pin(self, tmp_path):
        # A token validly signed by a DIFFERENT node — the inviter only honours
        # invites it issued ("not issued by this node").
        daemon, keypair, trust_path, _ = _make_inviter_daemon(tmp_path)
        other = generate_keypair("other-inviter")
        foreign = ew_invite.create_invite(other, "host:8765")
        # Would FAIL if a foreign-signed (but otherwise valid) token pinned.
        await self._expect_rejected_no_pin(tmp_path, foreign.to_string())

    def test_corrupt_ledger_raises_on_load_not_empty(self, tmp_path):
        # A truncated / non-JSON ledger file must RAISE on load — NOT silently
        # start empty. Starting empty would forget every consumed nonce and let
        # every past invite replay exactly once.
        led_path = tmp_path / "invite_ledger.json"

        # (a) non-JSON garbage
        led_path.write_text("this is not json {{{")
        with pytest.raises((ValueError, OSError)):
            ew_invite.InviteLedger(str(led_path))

        # (b) truncated JSON
        led_path.write_text('{"version": 1, "spent": {"abc": ')
        with pytest.raises((ValueError, OSError)):
            ew_invite.InviteLedger(str(led_path))

        # Control: a real ledger with a spent nonce survives a reload as spent.
        # This is the exact condition the corrupt case protects — if load
        # silently reset to empty, is_spent would wrongly return False.
        led_path.unlink()
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "host:8765")
        ew_invite.InviteLedger(str(led_path)).mark_spent(tok)
        assert ew_invite.InviteLedger(str(led_path)).is_spent(tok.nonce)

    def test_qr_png_content_round_trip_no_passphrase(self, tmp_path):
        # Re-assert the CONTENT check (mirrors test_invite.py::TestQR::
        # test_png_writes_valid_token_png): the invite PNG is byte-identical to
        # segno.make(token) and carries no passphrase — a content proof, not
        # merely a magic-byte check.
        from ironmesh import qr as ew_qr
        if not ew_qr.is_available():
            pytest.skip("[qr] extra (segno) not installed")
        import segno

        SECRET_PASSPHRASE = "do-not-leak-this-passphrase-1234567890"
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "mesh-node-a:8765", profile="lan")
        token_str = tok.to_string()

        # no-leak: neither the token string nor any payload field carries the
        # passphrase (would FAIL if a future field leaked a secret into the QR).
        assert SECRET_PASSPHRASE not in token_str
        payload = ew_invite.parse_invite(token_str).to_dict()
        assert SECRET_PASSPHRASE not in json.dumps(payload)
        assert "passphrase" not in payload and "secret" not in payload

        out = tmp_path / "invite.png"
        assert ew_qr.png_qr(token_str, str(out)) is True
        data = out.read_bytes()
        assert data[:8] == b"\x89PNG\r\n\x1a\n"
        assert len(data) > 100
        # Content round-trip: identical to a QR built from EXACTLY the token.
        # Would FAIL if the PNG encoded anything other than the token string.
        expected = tmp_path / "expected.png"
        segno.make(token_str, error="l").save(str(expected), scale=6, border=4)
        assert out.read_bytes() == expected.read_bytes()


# ===========================================================================
# AREA 2 — Invite crash-window (MARK-FIRST). The crux.
#
# Reports four results:
#   * crash-after-mark   → the SAME token retried is rejected outright
#                          (replay window CLOSED).
#   * pin-save-failure   → pin raises TrustStoreError → ConnectionError, peer
#                          in NEITHER memory NOR disk, token BURNED.
#   * torn-pin-write     → os.replace crash mid-write leaves the on-disk store
#                          UNCHANGED (no partial record on reopen).
#   * mark-first vs pin-first quantification.
# ===========================================================================

class TestArea2InviteCrashWindow:

    @pytest.mark.asyncio
    async def test_crash_after_mark_closes_replay_window(self, tmp_path):
        """Simulate a crash AFTER mark_spent but BEFORE the pin lands. With
        mark-first the token is already spent, so retrying the SAME token is
        rejected outright (InviteSpent → ConnectionError) — the replay window
        is CLOSED.

        Would FAIL if: after the crash the same token could be presented again
        by a second node and reach `pending` (a one-shot crash-replay).
        """
        daemon, keypair, trust_path, ledger_path = _make_inviter_daemon(tmp_path)
        joiner1 = generate_keypair("joiner1")
        tok = ew_invite.create_invite(keypair, "host:8765")

        # Patch pin_peer to raise a NON-TrustStoreError AbortException AFTER
        # mark-first has run — i.e. the process "crashes" between mark and pin.
        class _Crash(BaseException):
            pass

        with patch.object(TrustStore, "pin_peer",
                          side_effect=_Crash("simulated crash after mark")):
            with pytest.raises(_Crash):
                await daemon._check_tofu(joiner1.get_fingerprint(),
                                         joiner1.get_public_key_base64(),
                                         tok.to_string())

        # The token was marked spent BEFORE the crash — durable on disk.
        assert daemon._get_invite_ledger().is_spent(tok.nonce)
        # No peer was pinned (the crash pre-empted the pin).
        assert _read_trust(trust_path, keypair, joiner1.get_fingerprint()) is None

        # RETRY the SAME token from a FRESH daemon (as if restarted) with a
        # DIFFERENT joiner — must be rejected outright as already-consumed.
        daemon2 = SimpleNamespace(
            config=SimpleNamespace(require_message_promotion=False),
            _keypair=keypair, trust_path=trust_path,
            _invite_ledger_path=ledger_path, _invite_ledger=None,
            _audit=None, peers={}, ws_clients={}, _peer_rate_limiters={})
        from ironmesh.bridge import BridgeDaemon
        for name in ("_check_tofu", "_validate_incoming_invite",
                     "_get_invite_ledger", "_audit_invite_reject"):
            attr = getattr(BridgeDaemon, name)
            setattr(daemon2, name, attr.__get__(daemon2, daemon2.__class__))

        joiner2 = generate_keypair("joiner2")
        with pytest.raises(ConnectionError):
            await daemon2._check_tofu(joiner2.get_fingerprint(),
                                      joiner2.get_public_key_base64(),
                                      tok.to_string())
        # Replay window CLOSED: neither joiner landed anywhere.
        assert _read_trust(trust_path, keypair, joiner2.get_fingerprint()) is None
        assert _peer_count(trust_path, keypair) == 0

    @pytest.mark.asyncio
    async def test_pin_save_failure_clean_no_half_state(self, tmp_path):
        """Make the pin's underlying disk write fail (monkeypatch
        _atomic_write → False). pin_peer must raise TrustStoreError, roll the
        in-memory record back, and _check_tofu must translate it to
        ConnectionError. Result: the peer is in NEITHER memory NOR disk, and
        the invite token is BURNED (mark-first).

        Would FAIL if: the join half-succeeds (peer in memory but not disk),
        the daemon crashes with an unhandled error, or the token survives.
        """
        daemon, keypair, trust_path, ledger_path = _make_inviter_daemon(tmp_path)
        joiner = generate_keypair("joiner")
        tok = ew_invite.create_invite(keypair, "host:8765")

        with patch.object(TrustStore, "_atomic_write", return_value=False):
            with pytest.raises(ConnectionError):
                await daemon._check_tofu(joiner.get_fingerprint(),
                                         joiner.get_public_key_base64(),
                                         tok.to_string())

        # On disk: nothing pinned (the write was refused).
        assert _read_trust(trust_path, keypair, joiner.get_fingerprint()) is None
        assert _peer_count(trust_path, keypair) == 0
        # In memory: a FRESH TrustStore reload also shows nothing (rollback
        # means memory and disk agree — both un-pinned).
        mac = keypair.ed25519_secret[:32]
        assert TrustStore(agent_key=mac,
                          path=trust_path).get_peer(joiner.get_fingerprint()) is None
        # Token BURNED (mark-first): the operator must reissue.
        assert daemon._get_invite_ledger().is_spent(tok.nonce)

    def test_pin_peer_direct_save_failure_rolls_back(self, tmp_path):
        """Unit-level proof of the fail-loud contract independent of the
        invite path: pin_peer with a failing write raises TrustStoreError and
        leaves the in-memory dict clean (no orphan record).

        Would FAIL if pin_peer swallowed the failure and left the record in
        memory (the exact half-state the fail-loud change removes).
        """
        kp = generate_keypair("node")
        mac = kp.ed25519_secret[:32]
        trust_path = str(tmp_path / "known_peers.json")
        ts = TrustStore(agent_key=mac, path=trust_path)
        peer_key = generate_keypair("peer").get_public_key_base64()
        with patch.object(ts, "_atomic_write", return_value=False):
            with pytest.raises(TrustStoreError):
                ts.pin_peer("peer-node", peer_key)
        # In-memory rollback: the record is gone.
        assert ts.get_peer("peer-node") is None
        # On disk: never written.
        assert TrustStore(agent_key=mac,
                          path=trust_path).get_peer("peer-node") is None

    def test_torn_pin_write_leaves_store_unchanged(self, tmp_path):
        """Crash MID pin-write: os.replace (inside _atomic_write) raises after
        the tmp file is written but before the atomic rename. The on-disk trust
        store must be UNCHANGED — reopening reads the old complete state and NO
        partial/torn pin. The orphaned .tmp is irrelevant.

        Would FAIL if a partial/torn record were readable on reopen.
        """
        kp = generate_keypair("node")
        mac = kp.ed25519_secret[:32]
        trust_path = str(tmp_path / "known_peers.json")

        # Establish a known-good baseline: one durably pinned peer.
        ts = TrustStore(agent_key=mac, path=trust_path)
        first_key = generate_keypair("first").get_public_key_base64()
        ts.pin_peer("first-peer", first_key)
        baseline_bytes = (tmp_path / "known_peers.json").read_bytes()
        assert _read_trust(trust_path, kp, "first-peer") is not None

        # Now attempt a SECOND pin whose atomic rename crashes mid-flight.
        real_replace = os.replace

        def _boom(src, dst, *a, **k):
            # Let unrelated replaces (e.g. lock housekeeping) through; crash
            # only on the trust-store rename.
            if os.path.abspath(dst) == os.path.abspath(ts.path):
                raise OSError("simulated crash before atomic rename")
            return real_replace(src, dst, *a, **k)

        ts2 = TrustStore(agent_key=mac, path=trust_path)
        second_key = generate_keypair("second").get_public_key_base64()
        with patch("ironmesh.trust.os.replace", side_effect=_boom):
            # _atomic_write catches the OSError and returns False → pin_peer
            # raises TrustStoreError (fail-loud), so the torn write never
            # yields a half-committed record.
            with pytest.raises(TrustStoreError):
                ts2.pin_peer("second-peer", second_key)

        # Reopen from disk: the file is byte-identical to the baseline, the
        # first peer is intact, and the torn second peer is absent.
        assert (tmp_path / "known_peers.json").read_bytes() == baseline_bytes
        reopened = TrustStore(agent_key=mac, path=trust_path)
        assert reopened.get_peer("first-peer") is not None
        assert reopened.get_peer("second-peer") is None

    @pytest.mark.asyncio
    async def test_mark_first_vs_pin_first_quantified(self, tmp_path):
        """QUANTIFY the security difference between the shipped MARK-FIRST
        ordering and the OLD PIN-FIRST ordering by reproducing pin-first in the
        test and counting how many nodes reach `pending` off ONE token across a
        crash between the two operations.

        MARK-FIRST (shipped): crash between mark and pin → the token is spent →
          a second node presenting it is rejected outright → 0 replays reach
          pending.
        PIN-FIRST (old): crash between pin and mark → the token is NOT spent →
          a second, different node presenting the same token reaches `pending`
          → exactly 1 replay lands.

        Would FAIL if mark-first allowed >0 replays, or if the reproduced
        pin-first did not exhibit the >=1 replay it is designed to show.
        """
        from ironmesh.bridge import BridgeDaemon

        # ---- MARK-FIRST arm (shipped code, crash after mark) ---------------
        mf_dir = tmp_path / "mf"
        mf_dir.mkdir(exist_ok=True)
        d1, kp1, tp1, lp1 = _make_inviter_daemon(mf_dir)
        j1 = generate_keypair("mf-j1")
        tok1 = ew_invite.create_invite(kp1, "host:8765")

        class _Crash(BaseException):
            pass

        with patch.object(TrustStore, "pin_peer",
                          side_effect=_Crash("crash after mark")):
            with pytest.raises(_Crash):
                await d1._check_tofu(j1.get_fingerprint(),
                                     j1.get_public_key_base64(), tok1.to_string())
        # Second node retries the same token → rejected outright.
        j1b = generate_keypair("mf-j1b")
        with pytest.raises(ConnectionError):
            await d1._check_tofu(j1b.get_fingerprint(),
                                 j1b.get_public_key_base64(), tok1.to_string())
        mark_first_replays_reaching_pending = 0
        for j in (j1, j1b):
            rec = _read_trust(tp1, kp1, j.get_fingerprint())
            if rec is not None and rec.get("trust_state") == "pending":
                mark_first_replays_reaching_pending += 1

        # ---- PIN-FIRST arm (OLD ordering reproduced in-test) ---------------
        pf_dir = tmp_path / "pf"
        pf_dir.mkdir(exist_ok=True)
        d2, kp2, tp2, lp2 = _make_inviter_daemon(pf_dir)
        j2 = generate_keypair("pf-j2")
        tok2 = ew_invite.create_invite(kp2, "host:8765")

        # Reproduce the OLD pin-first ordering directly against the primitives:
        # pin the joiner, then "crash" before marking the token spent.
        token2 = d2._validate_incoming_invite(j2.get_fingerprint(), tok2.to_string())
        assert token2 is not None
        ts2 = TrustStore(agent_key=kp2.ed25519_secret[:32], path=tp2)
        ts2.pin_peer(j2.get_fingerprint(), j2.get_public_key_base64(),
                     trust_state="pending", pinned_via="invite")
        # <-- CRASH HERE, before ledger.mark_spent(token2). Token still unspent.
        assert not d2._get_invite_ledger().is_spent(tok2.nonce)

        # A SECOND, different node presents the SAME (still-unspent) token.
        j2b = generate_keypair("pf-j2b")
        token2b = d2._validate_incoming_invite(j2b.get_fingerprint(),
                                               tok2.to_string())
        # Under pin-first the validator does NOT reject (token unspent), so the
        # replay proceeds to a pending pin.
        assert token2b is not None
        ts2b = TrustStore(agent_key=kp2.ed25519_secret[:32], path=tp2)
        ts2b.pin_peer(j2b.get_fingerprint(), j2b.get_public_key_base64(),
                      trust_state="pending", pinned_via="invite")
        pin_first_replays_reaching_pending = 0
        for j in (j2, j2b):
            rec = _read_trust(tp2, kp2, j.get_fingerprint())
            if rec is not None and rec.get("trust_state") == "pending":
                pin_first_replays_reaching_pending += 1
        # The replay node specifically reached pending off the reused token.
        assert _read_trust(tp2, kp2, j2b.get_fingerprint()) is not None

        # The concrete numbers this area reports.
        # MARK-FIRST: j1 never pinned (crash pre-empted the pin) and j1b was
        # rejected outright as already-spent — so ZERO nodes reached pending
        # off the crashed token.
        assert mark_first_replays_reaching_pending == 0
        # Pin-first: BOTH the original and the replay landed pending = 2 total
        # pins off ONE token, i.e. exactly 1 REPLAY beyond the intended single
        # use.
        assert pin_first_replays_reaching_pending == 2
        pin_first_extra_replays = pin_first_replays_reaching_pending - 1
        assert pin_first_extra_replays == 1
        # Store for the reporter.
        TestArea2InviteCrashWindow._MARK_FIRST_REPLAYS = 0
        TestArea2InviteCrashWindow._PIN_FIRST_EXTRA_REPLAYS = pin_first_extra_replays


# ===========================================================================
# AREA 3 — Multi-hop tampered-frame inner-source-signature
#
# PASS: each tampered field (source, destination, msg_id) is DROPPED at the
#       destination and inner_source_sig_drops increments by EXACTLY 1 per
#       tampered field; an untampered control frame delivers; a v1
#       (payload-only) peer BELOW the 0.9 floor still interoperates.
# FAIL: a tampered field is accepted, the counter delta != 1, or v1-below-floor
#       breaks.
# ===========================================================================

SRC_ID = "aa" * 16
RELAY_ID = "bb" * 16


def _build_routing_daemon(*, known_sources, min_protocol="ironmesh/0.9"):
    from ironmesh.routing import RoutingMixin
    daemon = SimpleNamespace(
        peers={nid: SimpleNamespace(identity_public=keys.ed25519_public)
               for nid, keys in known_sources.items()},
        _pinned_peers={},
        _min_protocol_version=min_protocol,
        _audit=None,
        metrics=SimpleNamespace(inner_source_sig_drops=0),
        node_id="self" + "0" * 28,
        _counter_lock=threading.Lock(),
    )
    for name in ("_verify_inner_source", "_lookup_source_verify_key",
                 "_lookup_dest_identity", "_inner_source_allow_v1",
                 "_audit_inner_source_drop", "_SOURCE_SIG_REQUIRED_TYPES"):
        attr = getattr(RoutingMixin, name)
        if callable(attr):
            setattr(daemon, name, attr.__get__(daemon, daemon.__class__))
        else:
            setattr(daemon, name, attr)
    return daemon


def _frame_v2(src_keys, *, source=SRC_ID, destination="dst", msg_id="m1",
              payload=b"hello"):
    from ironmesh.protocol import Frame, MessageType
    from ironmesh.crypto import SIG_CTX_FRAME_INNER_SOURCE, sign_detached_with_context
    from ironmesh.protocol import canonical_inner_source_bytes
    f = Frame(msg_type=MessageType.MSG, payload=payload, msg_id=msg_id,
              source=source, destination=destination)
    canon = canonical_inner_source_bytes(f.source, f.destination, f.msg_id, f.payload)
    f.source_signature = sign_detached_with_context(
        src_keys.get_signing_key(), SIG_CTX_FRAME_INNER_SOURCE, canon)
    f.source_sig_scheme = Frame.SOURCE_SIG_SCHEME_V2
    return f


class TestArea3TamperedFrameInnerSource:
    def test_each_tampered_field_drops_and_counts_exactly_one(self):
        """source, then destination, then msg_id tampered in turn — each is a
        separate hostile-relay frame that must DROP and bump the counter by
        exactly 1. The counter delta per tampered field is the load-bearing
        number this area reports.

        Would FAIL if any single tampered field were accepted (delivered), or
        if the counter moved by 0 or >1 for one tampered field.
        """
        src = generate_keypair("src")
        daemon = _build_routing_daemon(known_sources={SRC_ID: src})
        deltas = {}

        # --- source re-attribution: relay rewrites source to another KNOWN peer
        other = generate_keypair("other")
        daemon_src = _build_routing_daemon(
            known_sources={SRC_ID: src, RELAY_ID: other})
        f = _frame_v2(src, source=SRC_ID)
        f.source = RELAY_ID  # bound sig covered SRC_ID; vk now resolves to other
        before = daemon_src.metrics.inner_source_sig_drops
        assert daemon_src._verify_inner_source("hop", f) is False
        deltas["source"] = daemon_src.metrics.inner_source_sig_drops - before

        # --- destination redirection
        f = _frame_v2(src, destination="dst-A")
        f.destination = "dst-B"
        before = daemon.metrics.inner_source_sig_drops
        assert daemon._verify_inner_source(RELAY_ID, f) is False
        deltas["destination"] = daemon.metrics.inner_source_sig_drops - before

        # --- msg_id replay-relabel
        f = _frame_v2(src, msg_id="orig")
        f.msg_id = "replayed"
        before = daemon.metrics.inner_source_sig_drops
        assert daemon._verify_inner_source(RELAY_ID, f) is False
        deltas["msg_id"] = daemon.metrics.inner_source_sig_drops - before

        assert deltas == {"source": 1, "destination": 1, "msg_id": 1}
        TestArea3TamperedFrameInnerSource._COUNTER_DELTAS = deltas

    def test_untampered_control_frame_delivers(self):
        # An untampered v2 frame from a known source over a relay is delivered
        # AND flagged authenticated — the control that proves the drop path is
        # not just dropping everything. Would FAIL if a valid frame were dropped.
        src = generate_keypair("src")
        daemon = _build_routing_daemon(known_sources={SRC_ID: src})
        f = _frame_v2(src, source=SRC_ID, destination="dst", msg_id="ok")
        before = daemon.metrics.inner_source_sig_drops
        assert daemon._verify_inner_source(RELAY_ID, f) is True
        assert f.source_authenticated is True
        assert daemon.metrics.inner_source_sig_drops == before  # no drop

    def test_control_plane_frame_exempt(self):
        # A control-plane type (HELLO) is exempt: it authenticates via its own
        # mechanism, so a relayed one with no inner sig must NOT be dropped.
        from ironmesh.protocol import Frame, MessageType
        daemon = _build_routing_daemon(known_sources={})
        f = Frame(msg_type=MessageType.HELLO, payload=b"x", msg_id="c1",
                  source=SRC_ID, destination="*")
        before = daemon.metrics.inner_source_sig_drops
        assert daemon._verify_inner_source(RELAY_ID, f) is True
        assert daemon.metrics.inner_source_sig_drops == before

    def test_v1_below_floor_interoperates(self):
        """A v1 (payload-only) inner-signature peer BELOW the ironmesh/0.9
        floor still interoperates (accepted). This is the mixed-version-mesh
        compatibility guarantee.

        Would FAIL if raising the semantic floor broke pre-0.9 peers below it.
        """
        from ironmesh.protocol import Frame, MessageType
        src = generate_keypair("src")
        daemon = _build_routing_daemon(known_sources={SRC_ID: src},
                                       min_protocol="ironmesh/0.4")
        f = Frame(msg_type=MessageType.MSG, payload=b"legacy", msg_id="v1",
                  source=SRC_ID, destination="*")
        f.source_signature = bytes(src.get_signing_key().sign(f.payload).signature)
        # scheme left as None → treated as v1
        before = daemon.metrics.inner_source_sig_drops
        assert daemon._verify_inner_source(RELAY_ID, f) is True
        assert f.source_authenticated is True
        assert daemon.metrics.inner_source_sig_drops == before

    def test_v1_at_floor_09_refused(self):
        # Contrast: at floor >= 0.9 the unbound v1 form IS refused (+1 drop).
        # This proves the floor gate is live, so the below-floor acceptance
        # above is a real compatibility carve-out, not a dead branch.
        from ironmesh.protocol import Frame, MessageType
        src = generate_keypair("src")
        daemon = _build_routing_daemon(known_sources={SRC_ID: src},
                                       min_protocol="ironmesh/0.9")
        f = Frame(msg_type=MessageType.MSG, payload=b"legacy", msg_id="v1",
                  source=SRC_ID, destination="*")
        f.source_signature = bytes(src.get_signing_key().sign(f.payload).signature)
        before = daemon.metrics.inner_source_sig_drops
        assert daemon._verify_inner_source(RELAY_ID, f) is False
        assert daemon.metrics.inner_source_sig_drops == before + 1


# ===========================================================================
# AREA 4 — Profile / alias resolution
#
# PASS: each of five postures + three aliases resolves; an explicit flag always
#       overrides the profile default (with a warning); secure and tactical
#       produce BYTE-IDENTICAL args; secure produces the same args as before.
# FAIL: any profile mutates a flag the operator set explicitly, or
#       secure/tactical args differ.
# ===========================================================================

class TestArea4ProfileResolution:
    _FLAGS = ("reticulum", "require_message_promotion",
              "open_discovery", "allow_plaintext_ws")

    def _fresh_args(self, profile):
        # Defaults mirror argparse store_true defaults (all False).
        return SimpleNamespace(
            profile=profile,
            reticulum=False,
            require_message_promotion=False,
            open_discovery=False,
            allow_plaintext_ws=False,
        )

    def _apply(self, profile):
        from ironmesh.cli import _apply_profile
        args = self._fresh_args(profile)
        warnings = _apply_profile(args)
        return args, warnings

    @pytest.mark.parametrize("profile", [
        "lan", "lora", "homelab", "tactical", "custom",  # five postures
        "secure", "dev", "offline",                      # three aliases
    ])
    def test_each_profile_resolves(self, profile):
        # Would FAIL if a named profile raised or returned a non-list of warnings.
        args, warnings = self._apply(profile)
        assert isinstance(warnings, list)
        # spot-check the documented positive mutations
        if profile in ("lora", "offline"):
            assert args.reticulum is True
        if profile in ("tactical", "secure"):
            assert args.require_message_promotion is True
        if profile == "dev":
            assert args.open_discovery is True and args.allow_plaintext_ws is True
        if profile in ("lan", "homelab", "custom"):
            # No opinionated mutation of these flags.
            assert args.require_message_promotion is False

    def test_secure_and_tactical_byte_identical(self):
        """secure and tactical must produce byte-identical args today (their
        only mutation is require_message_promotion=True).

        Would FAIL if either grew a divergent mutation without the other.
        """
        sec, _ = self._apply("secure")
        tac, _ = self._apply("tactical")
        sec_flags = {f: getattr(sec, f) for f in self._FLAGS}
        tac_flags = {f: getattr(tac, f) for f in self._FLAGS}
        assert sec_flags == tac_flags
        # And the concrete expected posture (pins the "same as before" contract).
        assert sec_flags == {
            "reticulum": False, "require_message_promotion": True,
            "open_discovery": False, "allow_plaintext_ws": False,
        }

    def test_explicit_flag_overrides_profile_with_warning(self):
        """An explicit --open-discovery / --allow-plaintext-ws set by the
        operator survives a hardened profile AND emits a warning.

        Would FAIL if the profile silently reset an operator-set flag to its
        hardened default (a profile stomping explicit intent).
        """
        from ironmesh.cli import _apply_profile
        args = self._fresh_args("tactical")
        args.open_discovery = True       # operator explicitly loosened
        args.allow_plaintext_ws = True   # operator explicitly loosened
        warnings = _apply_profile(args)
        # Explicit intent preserved.
        assert args.open_discovery is True
        assert args.allow_plaintext_ws is True
        # ...and both overrides are surfaced as warnings.
        joined = " ".join(warnings).lower()
        assert "open-discovery" in joined
        assert "plaintext-ws" in joined

    def test_profile_never_clears_an_explicit_true(self):
        """A profile must not clear a flag the operator turned ON, even for a
        flag the profile itself would set. E.g. dev sets open_discovery=True;
        with it already True the value stays True (idempotent, non-destructive).

        Would FAIL if a profile flipped an explicitly-True flag back to False.
        """
        from ironmesh.cli import _apply_profile
        args = self._fresh_args("secure")
        args.require_message_promotion = True  # operator already set it
        _apply_profile(args)
        assert args.require_message_promotion is True


# ===========================================================================
# AREA 5 — doctor --fix guardrails
#
# PASS: over SSH a network fix is REFUSED unless --allow-remote-network-fix;
#       firewall rules are NEVER auto-applied (no subprocess call without
#       explicit confirmation); idempotent local fixes run TWICE with the
#       second a no-op.
# FAIL: a network fix runs over SSH without the flag, any firewall command
#       executes unconfirmed, or a second --fix run mutates correct state.
# ===========================================================================

class TestArea5DoctorFixGuardrails:
    def _posture(self):
        from ironmesh import cli
        return {
            "os": "linux", "over_ssh": False, "mdns_ok": True,
            "mdns_detail": "", "port_bindable": True,
            "firewall_hint": cli._firewall_command("linux", 8765),
        }

    def test_network_fix_refused_over_ssh_without_flag(self, monkeypatch, capsys):
        """Over SSH, the firewall fix is REFUSED unless the opt-in flag is set
        — AND no firewall command runs.

        Would FAIL if a network --fix ran over SSH without the flag.
        """
        from ironmesh import cli
        monkeypatch.setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")
        with patch("subprocess.call") as sub:
            args = SimpleNamespace(fix=True, allow_remote_network_fix=False)
            applied = cli._doctor_fix_firewall(args, self._posture())
        assert applied is False
        assert "FIX REFUSED" in capsys.readouterr().out
        sub.assert_not_called()

    def test_firewall_never_auto_applied_without_confirmation(self, monkeypatch):
        """No firewall/network command (ufw / iptables / firewall-cmd / netsh)
        may execute without an explicit interactive 'y'. Monkeypatch a
        subprocess sink and assert it is NEVER called across: no-TTY, declined,
        and SSH-opt-in-but-declined.

        Would FAIL if any of these silently shelled out to a firewall command.
        """
        from ironmesh import cli

        calls = []

        def _sink(*a, **k):
            calls.append((a, k))
            return 0

        # (a) no TTY → cannot confirm → never runs.
        for v in ("SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"):
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        with patch("subprocess.call", _sink):
            args = SimpleNamespace(fix=True, allow_remote_network_fix=False)
            assert cli._doctor_fix_firewall(args, self._posture()) is False

        # (b) TTY but declined 'n' → never runs.
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda *a, **k: "n")
        with patch("subprocess.call", _sink):
            args = SimpleNamespace(fix=True, allow_remote_network_fix=False)
            assert cli._doctor_fix_firewall(args, self._posture()) is False

        # (c) SSH + opt-in flag BUT declined → the confirmation gate is
        #     independent of the SSH flag; still never runs.
        monkeypatch.setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda *a, **k: "n")
        with patch("subprocess.call", _sink):
            args = SimpleNamespace(fix=True, allow_remote_network_fix=True)
            assert cli._doctor_fix_firewall(args, self._posture()) is False

        # Across every path above, the firewall sink was NEVER invoked.
        assert calls == []

    def test_chmod_fix_idempotent_second_run_noop(self, tmp_path, monkeypatch):
        """The local chmod fix runs TWICE; the second run is a no-op (mode is
        already 0600, so no state change).

        Would FAIL if a second --fix run mutated already-correct state.
        """
        from ironmesh import cli
        if os.name != "posix":
            pytest.skip("chmod perms only meaningful on POSIX")
        pf = tmp_path / "passphrase"
        pf.write_text("a-real-passphrase-1234")
        os.chmod(str(pf), 0o644)
        monkeypatch.setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")  # local fix OK over SSH
        args = SimpleNamespace()
        assert cli._doctor_fix_passphrase_perms(str(pf), args) is True
        assert (os.stat(str(pf)).st_mode & 0o777) == 0o600
        mode_after_first = os.stat(str(pf)).st_mode
        # Second run: already 0600 → still returns True but no state change.
        assert cli._doctor_fix_passphrase_perms(str(pf), args) is True
        assert os.stat(str(pf)).st_mode == mode_after_first

    def test_missing_key_fix_idempotent_never_overwrites(self, tmp_path):
        """The missing-key regen fix creates a key when absent, and on a second
        run refuses to overwrite (returns None, bytes unchanged).

        Would FAIL if the second run regenerated/overwrote an existing key.
        """
        from ironmesh import cli
        kp_path = tmp_path / "keys.json"
        args = SimpleNamespace(keys_passphrase="pp-1234567890ab",
                               keys_passphrase_file=None,
                               passphrase_file=None, name="fixnode")
        # First run: absent → creates.
        result = cli._doctor_fix_missing_keys(str(kp_path), args)
        assert result is not None
        assert kp_path.is_file()
        before = kp_path.read_bytes()
        # Second run: present → no-op, never overwrites.
        assert cli._doctor_fix_missing_keys(str(kp_path), args) is None
        assert kp_path.read_bytes() == before

    def test_missing_config_fix_idempotent_second_run_noop(self, tmp_path,
                                                           monkeypatch):
        """The missing-config create fix writes a config when absent, and on a
        second run is a no-op (returns False, bytes unchanged).

        Would FAIL if the second run rewrote/overwrote an existing config.
        """
        from ironmesh import cli
        cfg_path = tmp_path / "config.json"
        monkeypatch.setattr("ironmesh.config.DEFAULT_CONFIG_PATH", str(cfg_path))
        args = SimpleNamespace(name="cfgnode")
        assert cli._doctor_fix_missing_config(args) is True
        assert cfg_path.is_file()
        before = cfg_path.read_bytes()
        assert cli._doctor_fix_missing_config(args) is False
        assert cfg_path.read_bytes() == before
