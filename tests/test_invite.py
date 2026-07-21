"""Tests for the ephemeral single-use bootstrap invite-token system.

Covers the token model (create/validate round-trip, expiry, signature +
domain separation, identity match, per-profile expiry), the inviter-side
single-use ledger and its enforcement at the TOFU pin point (forced
pending regardless of the global gate + the ``pinned_via`` provenance
marker), the QR degradation path, and the ``setup --from-invite``
validation path.
"""

from __future__ import annotations

import base64
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ironmesh import crypto as ew_crypto
from ironmesh import invite as ew_invite
from ironmesh import protocol as ew_protocol
from ironmesh import qr as ew_qr
from ironmesh.keys import generate_keypair
from ironmesh.trust import TrustStore


# ---------------------------------------------------------------------------
# Token model
# ---------------------------------------------------------------------------

class TestInviteToken:
    def test_create_validate_round_trip(self):
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "mesh-node-a:8765", profile="lan",
                                      allowed_peers="alice,bob")
        s = tok.to_string()
        assert s.startswith(ew_invite.INVITE_PREFIX)
        parsed = ew_invite.parse_invite(s)
        assert parsed.nonce == tok.nonce
        assert parsed.inviter_key == kp.get_public_key_base64()
        assert parsed.endpoint == "mesh-node-a:8765"
        assert parsed.allowed_peers == "alice,bob"
        # Full joiner-side validation with the matching identity passes.
        ew_invite.validate_invite(
            parsed, presented_identity_b64=kp.get_public_key_base64())

    def test_never_carries_passphrase(self):
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "host:8765", profile="lan")
        # The serialized token body must not contain any passphrase-like key.
        blob = tok.to_string().lower()
        # (Sanity: the only secret-ish material is a signature, not a secret.)
        for banned in ("passphrase", "secret", "private"):
            assert banned not in blob

    def test_expiry_rejected(self):
        kp = generate_keypair("inviter")
        # Issued at t=0 with a 1s TTL; validate far in the future.
        tok = ew_invite.create_invite(kp, "host:8765", ttl_seconds=1, now=0.0)
        assert tok.is_expired(now=10_000)
        with pytest.raises(ew_invite.InviteExpired):
            ew_invite.validate_invite(tok, now=10_000)

    def test_signature_tamper_rejected(self):
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "host:8765")
        bad = ew_invite.InviteToken(
            **{**tok.to_dict(),
               "signature": base64.b64encode(b"x" * 64).decode()})
        with pytest.raises(ew_invite.InviteBadSignature):
            bad.verify_signature()

    def test_wrong_context_signature_rejected(self):
        """A signature made under a DIFFERENT domain context (HELLO) over the
        exact same canonical bytes must NOT verify as an invite — proving
        SIG_CTX_INVITE domain separation binds."""
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "host:8765")
        wrong_sig = ew_crypto.sign_detached_with_context(
            kp.get_signing_key(), ew_crypto.SIG_CTX_HELLO, tok.canonical_bytes())
        forged = ew_invite.InviteToken(
            **{**tok.to_dict(),
               "signature": base64.b64encode(wrong_sig).decode()})
        with pytest.raises(ew_invite.InviteBadSignature):
            forged.verify_signature()

    def test_identity_mismatch_rejected(self):
        kp = generate_keypair("inviter")
        other = generate_keypair("someone-else")
        tok = ew_invite.create_invite(kp, "host:8765")
        assert tok.matches_identity(kp.get_public_key_base64())
        assert not tok.matches_identity(other.get_public_key_base64())
        with pytest.raises(ew_invite.InviteIdentityMismatch):
            ew_invite.validate_invite(
                tok, presented_identity_b64=other.get_public_key_base64())

    def test_body_tamper_breaks_signature(self):
        """Changing any signed field (e.g. endpoint) invalidates the sig."""
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "host:8765")
        tampered = ew_invite.InviteToken(
            **{**tok.to_dict(), "endpoint": "evil:9999"})
        with pytest.raises(ew_invite.InviteBadSignature):
            tampered.verify_signature()

    def test_malformed_rejected(self):
        for bad in ("", "nope", "ironmesh-invite-v1:!!!not-base64"):
            with pytest.raises(ew_invite.InviteMalformed):
                ew_invite.parse_invite(bad)

    @pytest.mark.parametrize("profile,seconds", [
        ("tactical", 300.0),
        ("lan", 900.0),
        ("homelab", 900.0),
        ("lora", 1800.0),
        ("offline", 1800.0),
        (None, 900.0),
        ("unknown-profile", 900.0),
    ])
    def test_per_profile_expiry_defaults(self, profile, seconds):
        assert ew_protocol.invite_max_age_for_profile(profile) == seconds
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "host:8765", profile=profile, now=0.0)
        assert tok.expires_at - tok.issued_at == seconds

    def test_explicit_ttl_overrides_profile(self):
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "host:8765", profile="tactical",
                                      ttl_seconds=42.0, now=0.0)
        assert tok.expires_at - tok.issued_at == 42.0


# ---------------------------------------------------------------------------
# Single-use ledger
# ---------------------------------------------------------------------------

class TestInviteLedger:
    def test_mark_spent_then_reject(self, tmp_path):
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "host:8765")
        led = ew_invite.InviteLedger(str(tmp_path / "ledger.json"))
        assert not led.is_spent(tok.nonce)
        led.check_and_reject_if_spent(tok)  # first use OK
        led.mark_spent(tok)
        assert led.is_spent(tok.nonce)
        with pytest.raises(ew_invite.InviteSpent):
            led.check_and_reject_if_spent(tok)

    def test_ledger_persists_across_reload(self, tmp_path):
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "host:8765")
        path = str(tmp_path / "ledger.json")
        ew_invite.InviteLedger(path).mark_spent(tok)
        assert ew_invite.InviteLedger(path).is_spent(tok.nonce)

    def test_expired_entries_pruned(self, tmp_path):
        kp = generate_keypair("inviter")
        old = ew_invite.create_invite(kp, "host:8765", ttl_seconds=1, now=0.0)
        led = ew_invite.InviteLedger(str(tmp_path / "ledger.json"))
        led.mark_spent(old, now=0.0)
        assert led.is_spent(old.nonce)
        # Force a prune far in the future — the long-expired entry drops.
        led._prune(now=1e9)
        assert not led.is_spent(old.nonce)


# ---------------------------------------------------------------------------
# Inviter-side enforcement at the TOFU pin point (_check_tofu)
# ---------------------------------------------------------------------------

def _make_inviter_daemon(tmp_path, *, gate_on):
    """Minimal daemon stub exposing _check_tofu + the invite helpers,
    bound from the real TrustOpsMixin methods (same pattern as
    test_trust_gate's _build_daemon)."""
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
    return daemon, keypair, trust_path


def _read_trust(trust_path, keypair, node_id):
    mac = keypair.ed25519_secret[:32]
    ts = TrustStore(agent_key=mac, path=trust_path)
    return ts.get_peer(node_id)


@pytest.mark.asyncio
class TestInviterSideEnforcement:
    async def _pin_via_invite(self, daemon, keypair, tmp_path, *, gate_on):
        """Simulate a joiner presenting a valid invite to the inviter."""
        joiner = generate_keypair("joiner")
        joiner_id = joiner.get_fingerprint()
        joiner_key_b64 = joiner.get_public_key_base64()
        # The inviter signs the token with ITS OWN key.
        tok = ew_invite.create_invite(keypair, "host:8765", profile="lan")
        await daemon._check_tofu(joiner_id, joiner_key_b64, tok.to_string())
        return joiner_id, joiner_key_b64, tok

    async def test_invited_joiner_lands_pending_even_with_gate_off(self, tmp_path):
        # Global gate OFF — an ordinary new peer would be pinned "trusted".
        daemon, keypair, trust_path = _make_inviter_daemon(tmp_path, gate_on=False)
        jid, _, _ = await self._pin_via_invite(daemon, keypair, tmp_path,
                                               gate_on=False)
        rec = _read_trust(trust_path, keypair, jid)
        assert rec is not None
        assert rec["trust_state"] == "pending"  # forced, despite gate off
        assert rec.get("pinned_via") == "invite"  # provenance marker set

    async def test_provenance_absent_on_plain_tofu(self, tmp_path):
        daemon, keypair, trust_path = _make_inviter_daemon(tmp_path, gate_on=False)
        joiner = generate_keypair("plain")
        await daemon._check_tofu(joiner.get_fingerprint(),
                                 joiner.get_public_key_base64(), None)
        rec = _read_trust(trust_path, keypair, joiner.get_fingerprint())
        assert rec["trust_state"] == "trusted"  # ordinary path, gate off
        assert "pinned_via" not in rec

    async def test_single_use_second_join_rejected(self, tmp_path):
        daemon, keypair, trust_path = _make_inviter_daemon(tmp_path, gate_on=False)
        joiner = generate_keypair("joiner")
        jid = joiner.get_fingerprint()
        jkey = joiner.get_public_key_base64()
        tok = ew_invite.create_invite(keypair, "host:8765")
        # First join consumes the token.
        await daemon._check_tofu(jid, jkey, tok.to_string())
        assert daemon._get_invite_ledger().is_spent(tok.nonce)
        # A second presentation of the SAME token nonce is rejected.
        joiner2 = generate_keypair("joiner2")
        with pytest.raises(ConnectionError):
            await daemon._check_tofu(joiner2.get_fingerprint(),
                                     joiner2.get_public_key_base64(),
                                     tok.to_string())

    async def test_expired_invite_rejected_inviter_side(self, tmp_path):
        daemon, keypair, trust_path = _make_inviter_daemon(tmp_path, gate_on=False)
        joiner = generate_keypair("joiner")
        expired = ew_invite.create_invite(keypair, "host:8765",
                                          ttl_seconds=1, now=0.0)
        with pytest.raises(ConnectionError):
            await daemon._check_tofu(joiner.get_fingerprint(),
                                     joiner.get_public_key_base64(),
                                     expired.to_string())

    async def test_invite_not_issued_by_this_node_rejected(self, tmp_path):
        """A token signed by a DIFFERENT node is rejected — the inviter only
        honours invites it issued."""
        daemon, keypair, trust_path = _make_inviter_daemon(tmp_path, gate_on=False)
        other = generate_keypair("other-inviter")
        foreign = ew_invite.create_invite(other, "host:8765")
        joiner = generate_keypair("joiner")
        with pytest.raises(ConnectionError):
            await daemon._check_tofu(joiner.get_fingerprint(),
                                     joiner.get_public_key_base64(),
                                     foreign.to_string())

    async def test_malformed_invite_rejected(self, tmp_path):
        daemon, keypair, trust_path = _make_inviter_daemon(tmp_path, gate_on=False)
        joiner = generate_keypair("joiner")
        with pytest.raises(ConnectionError):
            await daemon._check_tofu(joiner.get_fingerprint(),
                                     joiner.get_public_key_base64(),
                                     "ironmesh-invite-v1:garbage")


# ---------------------------------------------------------------------------
# Joiner-side verified-first-use (matches_identity is the pin check)
# ---------------------------------------------------------------------------

class TestVerifiedFirstUse:
    def test_matching_server_identity_accepted(self):
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "host:8765")
        # The handshake presents the inviter's real key → match.
        assert tok.matches_identity(kp.get_public_key_base64())

    def test_mismatched_server_identity_rejected(self):
        kp = generate_keypair("inviter")
        imposter = generate_keypair("imposter")
        tok = ew_invite.create_invite(kp, "host:8765")
        # An imposter at the endpoint presents a different key → no match,
        # so the joiner refuses (verified-first-use, not blind TOFU).
        assert not tok.matches_identity(imposter.get_public_key_base64())
        assert not tok.matches_identity(None)


# ---------------------------------------------------------------------------
# QR transport (ASCII path works without the optional dep)
# ---------------------------------------------------------------------------

class TestQR:
    def test_ascii_degrades_without_dep(self):
        # In the test environment the [qr] extra is not installed, so the
        # ASCII path degrades to (None, note) — never raises.
        art, note = ew_qr.render_for_terminal("ironmesh-invite-v1:abc")
        if ew_qr.is_available():
            assert art is not None and note is None
        else:
            assert art is None
            assert note and "token string" in note.lower()

    def test_png_returns_false_without_dep(self, tmp_path):
        if ew_qr.is_available():
            pytest.skip("[qr] extra installed — PNG path exercised elsewhere")
        assert ew_qr.png_qr("x", str(tmp_path / "out.png")) is False


# ---------------------------------------------------------------------------
# setup --from-invite validation path
# ---------------------------------------------------------------------------

class TestSetupFromInvite:
    def _run(self, tmp_path, token_str, env_pass="joiner-pass-1234567890"):
        from ironmesh import cli
        kp = tmp_path / "jkeys.json"
        pp = tmp_path / "jpass"
        argv = [
            "ironmesh", "setup", "--non-interactive", "--passphrase-from-env",
            "--keys-path", str(kp), "--passphrase-file", str(pp),
            "--name", "joiner", "--port", "9100",
            "--from-invite", token_str,
        ]
        with patch.dict(os.environ, {"IRONMESH_SETUP_PASSPHRASE": env_pass},
                        clear=False), patch.object(sys, "argv", argv):
            return cli.main()

    def test_valid_invite_accepted(self, tmp_path):
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "mesh-node-a:8765", profile="tactical",
                                      allowed_peers="alice")
        rc = self._run(tmp_path, tok.to_string())
        assert rc == 0
        assert (tmp_path / "jkeys.json").is_file()

    def test_expired_invite_rejected(self, tmp_path, capsys):
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "host:8765", ttl_seconds=1, now=0.0)
        rc = self._run(tmp_path, tok.to_string())
        assert rc == 1
        assert "expired" in capsys.readouterr().out.lower()

    def test_malformed_invite_rejected(self, tmp_path, capsys):
        rc = self._run(tmp_path, "not-a-real-token")
        assert rc == 1
        assert "invalid invite" in capsys.readouterr().out.lower()

    def test_invite_profile_hint_adopted(self, tmp_path, capsys):
        kp = generate_keypair("inviter")
        tok = ew_invite.create_invite(kp, "mesh-node-b:8765", profile="tactical")
        rc = self._run(tmp_path, tok.to_string())
        assert rc == 0
        out = capsys.readouterr().out
        # tactical profile => the printed run command enables the gate.
        assert "--require-message-promotion" in out
