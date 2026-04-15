"""Tests for ironmesh.crypto — ECDH, SecretBox, signing."""

import pytest
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey
from nacl.exceptions import CryptoError

from ironmesh.crypto import (
    decrypt_json,
    decrypt_message,
    ecdh_exchange,
    encrypt_json,
    encrypt_message,
    generate_ephemeral_keypair,
    make_secretbox,
    sign_message,
    verify_signature,
)


class TestECDH:
    def test_ecdh_exchange_produces_shared_secret(self):
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        secret_a = ecdh_exchange(priv_a, pub_b)
        secret_b = ecdh_exchange(priv_b, pub_a)
        assert secret_a == secret_b
        assert len(secret_a) == 32

    def test_ecdh_different_keys_produce_different_secrets(self):
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        priv_c, pub_c = generate_ephemeral_keypair()
        secret_ab = ecdh_exchange(priv_a, pub_b)
        secret_ac = ecdh_exchange(priv_a, pub_c)
        assert secret_ab != secret_ac

    def test_ephemeral_keypair_uniqueness(self):
        _, pub_a = generate_ephemeral_keypair()
        _, pub_b = generate_ephemeral_keypair()
        assert bytes(pub_a) != bytes(pub_b)


class TestSecretBox:
    def test_encrypt_decrypt_roundtrip(self, shared_secret):
        plaintext = b"Hello, IronMesh!"
        ciphertext = encrypt_message(shared_secret, plaintext)
        decrypted = decrypt_message(shared_secret, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_produces_different_ciphertext(self, shared_secret):
        plaintext = b"Same message"
        ct1 = encrypt_message(shared_secret, plaintext)
        ct2 = encrypt_message(shared_secret, plaintext)
        assert ct1 != ct2  # Different nonces

    def test_decrypt_with_wrong_key_fails(self, shared_secret):
        plaintext = b"Secret data"
        ciphertext = encrypt_message(shared_secret, plaintext)
        wrong_key = bytes(32)  # All zeros
        with pytest.raises(CryptoError):
            decrypt_message(wrong_key, ciphertext)

    def test_decrypt_tampered_ciphertext_fails(self, shared_secret):
        plaintext = b"Integrity check"
        ciphertext = encrypt_message(shared_secret, plaintext)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0xFF
        with pytest.raises(CryptoError):
            decrypt_message(shared_secret, bytes(tampered))

    def test_empty_plaintext(self, shared_secret):
        ciphertext = encrypt_message(shared_secret, b"")
        decrypted = decrypt_message(shared_secret, ciphertext)
        assert decrypted == b""

    def test_large_plaintext(self, shared_secret):
        plaintext = os.urandom(1_000_000)  # 1MB
        ciphertext = encrypt_message(shared_secret, plaintext)
        decrypted = decrypt_message(shared_secret, ciphertext)
        assert decrypted == plaintext

    def test_make_secretbox(self, shared_secret):
        box = make_secretbox(shared_secret)
        ct = box.encrypt(b"test")
        pt = box.decrypt(ct)
        assert pt == b"test"


class TestSigning:
    def test_sign_and_verify(self):
        sk = SigningKey.generate()
        vk = sk.verify_key
        message = b"Sign me"
        signed = sign_message(sk, message)
        verified = verify_signature(vk, signed)
        assert verified == message

    def test_verify_with_wrong_key_fails(self):
        sk1 = SigningKey.generate()
        sk2 = SigningKey.generate()
        signed = sign_message(sk1, b"Test")
        with pytest.raises(Exception):  # BadSignatureError
            verify_signature(sk2.verify_key, signed)

    def test_tampered_signed_message_fails(self):
        sk = SigningKey.generate()
        signed = sign_message(sk, b"Original")
        tampered = bytearray(signed)
        tampered[-1] ^= 0xFF
        with pytest.raises(Exception):
            verify_signature(sk.verify_key, bytes(tampered))


class TestJSONHelpers:
    def test_encrypt_decrypt_json(self, shared_secret):
        obj = {"msg": "hello", "count": 42, "nested": {"a": [1, 2, 3]}}
        encrypted = encrypt_json(obj, shared_secret)
        decrypted = decrypt_json(encrypted, shared_secret)
        assert decrypted == obj

    def test_encrypt_json_returns_string(self, shared_secret):
        encrypted = encrypt_json({"test": True}, shared_secret)
        assert isinstance(encrypted, str)


import os  # needed for large_plaintext test
