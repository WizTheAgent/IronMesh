"""Phase 2 tests — HELLO ``x25519_public_b64`` advertisement.

Covers the user-approved scope:
1. v0.9.4 node advertises field correctly.
2. v0.9.4 node ignores unknown field gracefully.
3. v0.9.4 receiver prefers advertised key over legacy-derived.
4. v0.9.4 receiver falls back to legacy-derived when field absent.
5. Mixed mesh interop (v0.9.4 + v0.9.4 nodes communicate cleanly).
6. Auto-migration on first start from legacy file.
7. TOFU fingerprint survives auto-migration.

Plus integrity checks on the binding signature itself: a swapped
advertised key with a forged binding under the wrong identity is
rejected; the legacy fallback path still works for receivers that
encounter it.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os

import pytest
from nacl.signing import SigningKey, VerifyKey

from ironmesh import crypto as ew_crypto, mesh_crypto
from ironmesh.bridge import BridgeDaemon, ensure_agent_keys
from ironmesh.keys import (
    HKDF_INFO_X25519,
    _compute_x25519_binding,
    _hkdf_sha256,
    _x25519_public_from_seed,
    generate_keypair,
    save_keys,
)

# ----------------------------------------------------------------------
# 1. v0.9.4 advertisement is well-formed
# ----------------------------------------------------------------------


def _make_daemon(tmp_path, name="p2-test"):
    return BridgeDaemon(
        name=name,
        passphrase="phase2-test-passphrase-12",
        keys_path=str(tmp_path / "keys.json"),
        db_path=str(tmp_path / "test.db"),
    )


class TestAdvertisementShape:
    def test_master_seed_daemon_publishes_both_fields(self, tmp_path):
        d = _make_daemon(tmp_path)
        # bridge daemons load their keys lazily during start(); the
        # tests directly inject a master-seed keypair to exercise the
        # advertisement helper without spinning the event loop.
        d._keypair = generate_keypair("alice", master_seed_format=True)
        adv = d._hello_x25519_advertisement()
        assert set(adv.keys()) == {"x25519_public_b64", "x25519_binding_signature_b64"}
        # Decode + sanity-check shapes.
        pub = base64.b64decode(adv["x25519_public_b64"])
        sig = base64.b64decode(adv["x25519_binding_signature_b64"])
        assert len(pub) == 32
        assert len(sig) == 64

    def test_legacy_daemon_publishes_nothing(self, tmp_path):
        d = _make_daemon(tmp_path)
        d._keypair = generate_keypair("alice", master_seed_format=False)
        assert d._hello_x25519_advertisement() == {}


# ----------------------------------------------------------------------
# 2 + 4. v0.9.4 nodes ignore unknown HELLO fields gracefully
# ----------------------------------------------------------------------


class TestForwardCompat:
    def test_unknown_hello_fields_are_safe_for_json_loads(self):
        # Sanity: the HELLO is a flat JSON object; unknown fields are
        # accessed via msg.get(...), so v0.9.4 receivers naturally
        # ignore x25519_public_b64 / x25519_binding_signature_b64.
        hello = {
            "type": "HELLO",
            "from": "node-id",
            "name": "n",
            "ephemeral_public": "eph",
            "identity_public": "id",
            "protocol_version": "ironmesh/0.6",
            "channel_binding": "abcd",
            "signature": "sig",
            "x25519_public_b64": "ignored",
            "x25519_binding_signature_b64": "ignored",
        }
        roundtrip = json.loads(json.dumps(hello))
        # Pre-v0.9.4 code accesses only the original 7 fields.
        assert roundtrip["ephemeral_public"] == "eph"
        # And nothing about the new fields raises.
        for k in (
            "type", "from", "name", "ephemeral_public", "identity_public",
            "protocol_version", "channel_binding", "signature",
        ):
            assert k in roundtrip


# ----------------------------------------------------------------------
# 3 + 4. Receiver verification — prefer advertised, fall back to legacy
# ----------------------------------------------------------------------


class TestReceiverVerification:
    def test_verify_accepts_valid_advertisement(self, tmp_path):
        d = _make_daemon(tmp_path)
        sk = SigningKey.generate()
        keys = generate_keypair("alice", master_seed_format=True)
        # Use a fresh master-seed keypair and re-derive everything from
        # it to model what a peer would advertise.
        result = d._verify_peer_x25519_binding(
            peer_identity_b64=base64.b64encode(keys.ed25519_public).decode(),
            peer_x25519_public_b64=base64.b64encode(keys.x25519_public).decode(),
            peer_x25519_binding_b64=base64.b64encode(keys.x25519_binding_signature).decode(),
        )
        # Suppress the unused-sk lint
        _ = sk
        assert result == keys.x25519_public

    def test_verify_rejects_swapped_x25519_under_different_identity(self, tmp_path):
        # Attacker scenario: an MITM swaps x25519_public_b64 to a key
        # they hold the secret for, but they don't have the legitimate
        # peer's Ed25519 secret, so they can't produce a valid binding.
        d = _make_daemon(tmp_path)
        legit = generate_keypair("legit", master_seed_format=True)
        attacker = generate_keypair("attacker", master_seed_format=True)
        result = d._verify_peer_x25519_binding(
            peer_identity_b64=base64.b64encode(legit.ed25519_public).decode(),
            peer_x25519_public_b64=base64.b64encode(attacker.x25519_public).decode(),
            peer_x25519_binding_b64=base64.b64encode(attacker.x25519_binding_signature).decode(),
        )
        assert result is None

    def test_verify_returns_none_for_legacy_peer(self, tmp_path):
        d = _make_daemon(tmp_path)
        legit = generate_keypair("legit", master_seed_format=True)
        # Legacy peer: no x25519 fields in HELLO at all.
        result = d._verify_peer_x25519_binding(
            peer_identity_b64=base64.b64encode(legit.ed25519_public).decode(),
            peer_x25519_public_b64=None,
            peer_x25519_binding_b64=None,
        )
        assert result is None

    def test_verify_returns_none_for_malformed_inputs(self, tmp_path):
        d = _make_daemon(tmp_path)
        # Wrong-length identity / public / sig all fall back safely.
        assert d._verify_peer_x25519_binding(
            peer_identity_b64="not-b64-or-too-short",
            peer_x25519_public_b64="x" * 44,
            peer_x25519_binding_b64="y" * 88,
        ) is None
        assert d._verify_peer_x25519_binding(
            peer_identity_b64=None, peer_x25519_public_b64="x", peer_x25519_binding_b64="y",
        ) is None


# ----------------------------------------------------------------------
# E2E sealing — prefer advertised key, fall back to legacy
# ----------------------------------------------------------------------


class TestE2ESealingFallback:
    def test_legacy_path_seal_and_unseal_roundtrip(self):
        recipient = generate_keypair("legacy", master_seed_format=False)
        sealed = mesh_crypto.seal_to_destination(
            b"hello", recipient.ed25519_public,
        )
        plain = mesh_crypto.unseal_from_source(sealed, recipient.ed25519_secret)
        assert plain == b"hello"

    def test_master_seed_path_seal_and_unseal_roundtrip(self):
        recipient = generate_keypair("ms", master_seed_format=True)
        sealed = mesh_crypto.seal_to_destination(
            b"hello",
            recipient.ed25519_public,
            dest_x25519_pub=recipient.x25519_public,
        )
        # Receiver opens with their master-seed X25519 secret.
        plain = mesh_crypto.unseal_from_source(
            sealed,
            recipient.ed25519_secret,
            my_x25519_secret=recipient.get_x25519_secret(),
        )
        assert plain == b"hello"

    def test_master_seed_seal_not_openable_with_legacy_secret(self):
        # The master-seed X25519 subkey is a DIFFERENT key from the
        # ed25519_to_curve25519 fallback. Sealing with the advertised
        # key + opening with the legacy secret must fail.
        recipient = generate_keypair("ms", master_seed_format=True)
        sealed = mesh_crypto.seal_to_destination(
            b"hello",
            recipient.ed25519_public,
            dest_x25519_pub=recipient.x25519_public,
        )
        with pytest.raises(ValueError, match="E2E decryption failed"):
            # Force the legacy path on the receiver — should fail
            # because the sealer used a different X25519 public.
            mesh_crypto.unseal_from_source(
                sealed,
                recipient.ed25519_secret,
                my_x25519_secret=None,  # legacy fallback
            )

    def test_master_seed_seal_falls_back_to_legacy_when_no_x25519_pub(self):
        # Mixed-mesh: a v0.9.4 sender talking to a v0.9.4 receiver has
        # no advertised X25519 from the peer, so it passes None and
        # the legacy derivation path runs at seal time. The legacy
        # receiver opens with legacy derivation. Roundtrip works.
        recipient = generate_keypair("legacy", master_seed_format=False)
        sealed = mesh_crypto.seal_to_destination(
            b"hello", recipient.ed25519_public, dest_x25519_pub=None,
        )
        plain = mesh_crypto.unseal_from_source(
            sealed, recipient.ed25519_secret, my_x25519_secret=None,
        )
        assert plain == b"hello"


# ----------------------------------------------------------------------
# 5. Mixed mesh — v0.9.4 sender to v0.9.4 receiver, and vice versa
# ----------------------------------------------------------------------


class TestMixedMeshInterop:
    def test_v0_9_5_sender_seals_to_v0_9_4_receiver(self):
        # v0.9.4 receiver has no x25519_public on the wire → the v0.9.4
        # sender (correctly) passes None for dest_x25519_pub →
        # seal_to_destination derives via legacy → receiver opens with
        # legacy. Plaintext recovered.
        v94_recipient = generate_keypair("v94", master_seed_format=False)
        sealed = mesh_crypto.seal_to_destination(
            b"hello-from-v95", v94_recipient.ed25519_public,
            dest_x25519_pub=None,
        )
        plain = mesh_crypto.unseal_from_source(
            sealed, v94_recipient.ed25519_secret,
        )
        assert plain == b"hello-from-v95"

    def test_v0_9_4_sender_seals_to_v0_9_5_receiver(self):
        # Symmetric path: v0.9.4 sender uses legacy derivation. v0.9.4
        # receiver with a master-seed keypair MUST still open it
        # because the legacy X25519 is just ed25519_to_curve25519 of
        # the recipient's Ed25519, which the receiver can re-derive.
        v95_recipient = generate_keypair("v95", master_seed_format=True)
        # v0.9.4 sender: doesn't know about x25519_public_b64; calls
        # seal_to_destination with the recipient's Ed25519 only.
        sealed = mesh_crypto.seal_to_destination(
            b"hello-from-v94", v95_recipient.ed25519_public,
        )
        # v0.9.4 receiver opens. Because the sender used legacy
        # derivation, the receiver MUST also use legacy (the
        # ed25519_to_curve25519 path) — passing my_x25519_secret=None
        # routes through that path.
        plain = mesh_crypto.unseal_from_source(
            sealed, v95_recipient.ed25519_secret, my_x25519_secret=None,
        )
        assert plain == b"hello-from-v94"


# ----------------------------------------------------------------------
# 6 + 7. Auto-migration on first start + TOFU fingerprint survival
# ----------------------------------------------------------------------


class TestAutoMigrationOnFirstStart:
    def test_legacy_file_auto_migrates_to_master_seed(self, tmp_path):
        path = str(tmp_path / "keys.json")
        # Pre-populate with a legacy v1/v2 file.
        legacy = generate_keypair("alice", master_seed_format=False)
        save_keys(legacy, path, passphrase="phase2-test-passphrase-12")
        legacy_fp = legacy.get_fingerprint()
        legacy_ed_seed = legacy.ed25519_secret

        # Daemon-style load via ensure_agent_keys (the real bootstrap path).
        loaded = asyncio.run(
            ensure_agent_keys(path, passphrase="phase2-test-passphrase-12"),
        )

        # Master-seed format now active.
        assert loaded.is_master_seed_format()
        # TOFU fingerprint preserved byte-for-byte.
        assert loaded.get_fingerprint() == legacy_fp
        assert loaded.ed25519_secret == legacy_ed_seed
        # .legacy.bak exists.
        assert os.path.exists(path + ".legacy.bak")

    def test_master_seed_file_does_not_re_migrate(self, tmp_path):
        path = str(tmp_path / "keys.json")
        keys = generate_keypair("alice", master_seed_format=True)
        save_keys(keys, path, passphrase="phase2-test-passphrase-12")
        # First load auto-migrates from legacy IF legacy; this file is
        # already master-seed, so the migration branch must NOT fire.
        loaded = asyncio.run(
            ensure_agent_keys(path, passphrase="phase2-test-passphrase-12"),
        )
        assert loaded.is_master_seed_format()
        # No .legacy.bak created on a no-op load.
        assert not os.path.exists(path + ".legacy.bak")

    def test_auto_migration_failure_is_non_fatal(self, tmp_path, monkeypatch):
        # If migrate_keys_to_master_seed raises, the daemon must still
        # start on the legacy keys — auto-migration is best-effort.
        path = str(tmp_path / "keys.json")
        legacy = generate_keypair("alice", master_seed_format=False)
        save_keys(legacy, path, passphrase="phase2-test-passphrase-12")

        import ironmesh.keys as _keys
        def _boom(*_a, **_k):
            raise OSError("simulated migration failure")
        monkeypatch.setattr(_keys, "migrate_keys_to_master_seed", _boom)

        loaded = asyncio.run(
            ensure_agent_keys(path, passphrase="phase2-test-passphrase-12"),
        )
        # Daemon loaded the legacy keys despite the failed migration.
        assert loaded.ed25519_secret == legacy.ed25519_secret
        assert not loaded.is_master_seed_format()


# ----------------------------------------------------------------------
# Sanity — binding signature reproducibility / determinism
# ----------------------------------------------------------------------


class TestBindingSignatureContract:
    def test_binding_is_deterministic_for_same_inputs(self):
        # Same ed25519 + same x25519 -> same binding signature (Ed25519
        # is deterministic). Guards against accidental swap to a
        # randomized signing scheme that would break interop.
        ed_secret = SigningKey.generate()
        ed_bytes = bytes(ed_secret)
        hkdf_salt = b"\x01" * 16
        x25519_seed = _hkdf_sha256(ed_bytes, hkdf_salt, HKDF_INFO_X25519, length=32)
        x25519_pub = _x25519_public_from_seed(x25519_seed)
        b1 = _compute_x25519_binding(ed_bytes, x25519_pub)
        b2 = _compute_x25519_binding(ed_bytes, x25519_pub)
        assert b1 == b2

    def test_binding_uses_capability_announce_context_separately(self):
        # Domain-separation sanity: SIG_CTX_X25519_BINDING is its own
        # label; a signature produced under it must NOT verify under
        # any other label.
        ed_secret = SigningKey.generate()
        ed_bytes = bytes(ed_secret)
        hkdf_salt = b"\x01" * 16
        x25519_seed = _hkdf_sha256(ed_bytes, hkdf_salt, HKDF_INFO_X25519, length=32)
        x25519_pub = _x25519_public_from_seed(x25519_seed)
        binding = _compute_x25519_binding(ed_bytes, x25519_pub)

        from nacl.exceptions import BadSignatureError
        # Try to verify under a DIFFERENT context label — must fail.
        with pytest.raises(BadSignatureError):
            ew_crypto.verify_detached_with_context(
                VerifyKey(bytes(ed_secret.verify_key)),
                ew_crypto.SIG_CTX_CAPABILITY_ANNOUNCE,  # wrong label
                x25519_pub,
                binding,
            )
