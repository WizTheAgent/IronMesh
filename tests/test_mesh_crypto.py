"""Tests for ironmesh.mesh_crypto — end-to-end NaCl SealedBox layer."""

import pytest

from ironmesh import mesh_crypto
from ironmesh.keys import generate_keypair


class TestSealUnsealRoundtrip:
    def test_seal_unseal_roundtrip(self):
        """A message sealed to a node can be unsealed only by that node."""
        recipient = generate_keypair("recipient")
        plaintext = b"top secret payload"
        sealed = mesh_crypto.seal_to_destination(plaintext, recipient.ed25519_public)
        recovered = mesh_crypto.unseal_from_source(sealed, recipient.ed25519_secret)
        assert recovered == plaintext

    def test_seal_unseal_empty_payload(self):
        recipient = generate_keypair("r")
        sealed = mesh_crypto.seal_to_destination(b"", recipient.ed25519_public)
        assert mesh_crypto.unseal_from_source(sealed, recipient.ed25519_secret) == b""

    def test_seal_unseal_large_payload(self):
        recipient = generate_keypair("r")
        plaintext = b"A" * 65536
        sealed = mesh_crypto.seal_to_destination(plaintext, recipient.ed25519_public)
        assert mesh_crypto.unseal_from_source(sealed, recipient.ed25519_secret) == plaintext


class TestRejection:
    def test_unseal_with_wrong_key_fails(self):
        """Decryption with the wrong recipient key must fail."""
        intended = generate_keypair("intended")
        attacker = generate_keypair("attacker")
        sealed = mesh_crypto.seal_to_destination(b"private", intended.ed25519_public)
        with pytest.raises(ValueError, match="E2E decryption failed"):
            mesh_crypto.unseal_from_source(sealed, attacker.ed25519_secret)

    def test_tampered_ciphertext_fails(self):
        """Bit-flips in the ciphertext are caught by Poly1305."""
        recipient = generate_keypair("r")
        sealed = bytearray(
            mesh_crypto.seal_to_destination(b"hello", recipient.ed25519_public)
        )
        sealed[-1] ^= 0xFF  # tamper with the auth tag
        with pytest.raises(ValueError):
            mesh_crypto.unseal_from_source(bytes(sealed), recipient.ed25519_secret)

    def test_invalid_pubkey_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            mesh_crypto.seal_to_destination(b"hello", b"too short")


class TestEphemeralKeysUnique:
    def test_ephemeral_keys_unique_per_message(self):
        """SealedBox uses fresh ephemeral keys per encryption — same plaintext
        produces different ciphertexts each time."""
        recipient = generate_keypair("r")
        plaintext = b"identical"
        ciphertexts = {
            mesh_crypto.seal_to_destination(plaintext, recipient.ed25519_public)
            for _ in range(20)
        }
        # All 20 should be distinct (statistical certainty)
        assert len(ciphertexts) == 20

    def test_different_recipients_different_ciphertexts(self):
        a = generate_keypair("a")
        b = generate_keypair("b")
        c1 = mesh_crypto.seal_to_destination(b"x", a.ed25519_public)
        c2 = mesh_crypto.seal_to_destination(b"x", b.ed25519_public)
        assert c1 != c2


class TestRelayCannotDecrypt:
    def test_relay_cannot_decrypt_e2e_payload(self):
        """A relay node holding only the per-hop session key cannot decrypt
        an e2e SealedBox addressed to a different node."""
        sender = generate_keypair("sender")
        relay = generate_keypair("relay")  # represents an intermediate hop
        destination = generate_keypair("destination")

        sealed = mesh_crypto.seal_to_destination(
            b"only for destination", destination.ed25519_public
        )

        # Relay attempts to unseal — must fail
        with pytest.raises(ValueError):
            mesh_crypto.unseal_from_source(sealed, relay.ed25519_secret)
        # Sender (who holds neither the destination nor the ephemeral private) also cannot
        with pytest.raises(ValueError):
            mesh_crypto.unseal_from_source(sealed, sender.ed25519_secret)
        # Destination CAN
        assert mesh_crypto.unseal_from_source(sealed, destination.ed25519_secret) == b"only for destination"


class TestCanSealTo:
    def test_can_seal_to_valid(self):
        kp = generate_keypair()
        assert mesh_crypto.can_seal_to(kp.ed25519_public) is True

    def test_can_seal_to_none(self):
        assert mesh_crypto.can_seal_to(None) is False

    def test_can_seal_to_short(self):
        assert mesh_crypto.can_seal_to(b"abc") is False
