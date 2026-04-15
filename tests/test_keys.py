"""Tests for ironmesh.keys — key generation, save/load, passphrase protection."""

import json
import os
import pytest

from ironmesh.keys import (
    AgentKeys,
    ed25519_to_curve25519_public,
    generate_ephemeral,
    generate_keypair,
    get_fingerprint,
    load_keys,
    save_keys,
)


class TestKeyGeneration:
    def test_generate_keypair(self):
        keys = generate_keypair()
        assert len(keys.ed25519_secret) == 32
        assert len(keys.ed25519_public) == 32
        assert keys.ed25519_secret != keys.ed25519_public

    def test_generate_keypair_with_name(self):
        keys = generate_keypair("test-agent")
        assert keys.agent_name == "test-agent"

    def test_keypair_uniqueness(self):
        k1 = generate_keypair()
        k2 = generate_keypair()
        assert k1.ed25519_public != k2.ed25519_public

    def test_fingerprint(self):
        keys = generate_keypair()
        fp = keys.get_fingerprint()
        assert isinstance(fp, str)
        assert len(fp) == 32
        # Fingerprint should be hex
        int(fp, 16)

    def test_public_key_base64(self):
        keys = generate_keypair()
        b64 = keys.get_public_key_base64()
        import base64
        decoded = base64.b64decode(b64)
        assert decoded == keys.ed25519_public

    def test_get_signing_key(self):
        keys = generate_keypair()
        sk = keys.get_signing_key()
        # Sign and verify roundtrip
        signed = sk.sign(b"test")
        keys.get_verify_key().verify(signed)


class TestEphemeralKeys:
    def test_generate_ephemeral(self):
        priv, pub = generate_ephemeral()
        assert priv is not None
        assert pub is not None
        assert len(bytes(pub)) == 32

    def test_ephemeral_uniqueness(self):
        _, pub1 = generate_ephemeral()
        _, pub2 = generate_ephemeral()
        assert bytes(pub1) != bytes(pub2)


class TestEd25519ToCurve25519:
    def test_conversion(self):
        keys = generate_keypair()
        curve_pub = ed25519_to_curve25519_public(keys.ed25519_public)
        assert len(curve_pub) == 32
        assert curve_pub != keys.ed25519_public


class TestKeyPersistence:
    def test_save_and_load(self, keys_path):
        keys = generate_keypair("test-save")
        save_keys(keys, keys_path, allow_plaintext=True)
        loaded = load_keys(keys_path)
        assert loaded.ed25519_secret == keys.ed25519_secret
        assert loaded.ed25519_public == keys.ed25519_public
        assert loaded.agent_name == "test-save"

    def test_save_creates_directory(self, tmp_path):
        path = str(tmp_path / "subdir" / "keys.json")
        keys = generate_keypair()
        save_keys(keys, path, allow_plaintext=True)
        assert os.path.exists(path)

    def test_load_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            load_keys("/nonexistent/path/keys.json")

    def test_save_format_is_json(self, keys_path):
        keys = generate_keypair()
        save_keys(keys, keys_path, allow_plaintext=True)
        with open(keys_path) as f:
            data = json.load(f)
        assert "ed25519_public" in data
        assert "version" in data
        assert data["version"] == 2

    def test_load_validates_key_length(self, keys_path):
        # Write invalid key data
        with open(keys_path, "w") as f:
            import base64
            json.dump({
                "version": 2,
                "ed25519_secret": base64.b64encode(b"short").decode(),
                "ed25519_public": base64.b64encode(b"short").decode(),
                "encrypted": False,
            }, f)
        with pytest.raises(ValueError, match="Invalid Ed25519 public key length"):
            load_keys(keys_path)

    def test_load_validates_key_match(self, keys_path):
        import base64
        keys1 = generate_keypair()
        keys2 = generate_keypair()
        # Save with mismatched keys
        with open(keys_path, "w") as f:
            json.dump({
                "version": 2,
                "ed25519_secret": base64.b64encode(keys1.ed25519_secret).decode(),
                "ed25519_public": base64.b64encode(keys2.ed25519_public).decode(),
                "encrypted": False,
            }, f)
        with pytest.raises(ValueError, match="does not match"):
            load_keys(keys_path)


class TestPassphraseProtection:
    def test_save_and_load_with_passphrase(self, keys_path):
        keys = generate_keypair("encrypted")
        save_keys(keys, keys_path, passphrase="my-secret")
        loaded = load_keys(keys_path, passphrase="my-secret")
        assert loaded.ed25519_secret == keys.ed25519_secret
        assert loaded.ed25519_public == keys.ed25519_public

    def test_load_encrypted_without_passphrase_fails(self, keys_path):
        keys = generate_keypair()
        save_keys(keys, keys_path, passphrase="my-secret")
        with pytest.raises(ValueError, match="encrypted but no passphrase"):
            load_keys(keys_path)

    def test_load_with_wrong_passphrase_fails(self, keys_path):
        keys = generate_keypair()
        save_keys(keys, keys_path, passphrase="correct")
        with pytest.raises(ValueError, match="Wrong passphrase"):
            load_keys(keys_path, passphrase="wrong")

    def test_encrypted_file_has_salt(self, keys_path):
        keys = generate_keypair()
        save_keys(keys, keys_path, passphrase="test")
        with open(keys_path) as f:
            data = json.load(f)
        assert data["encrypted"] is True
        assert "salt" in data
        assert "ed25519_secret_encrypted" in data
        assert "ed25519_secret" not in data


class TestFingerprint:
    def test_get_fingerprint(self):
        keys = generate_keypair()
        fp = get_fingerprint(keys.ed25519_public)
        assert len(fp) == 32
        assert fp == keys.get_fingerprint()
