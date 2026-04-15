"""Tests for ironmesh.bridge — daemon lifecycle, handshake, message routing."""

import asyncio
import base64
import json
import os
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from ironmesh.bridge import BridgeDaemon, ensure_agent_keys, rotate_keys, Metrics
from ironmesh.keys import generate_keypair, generate_ephemeral
from ironmesh.crypto import ecdh_exchange, encrypt_message
from ironmesh.protocol import MessageType, PeerState


@pytest.mark.asyncio
class TestEnsureAgentKeys:
    async def test_generates_new_keys(self, keys_path):
        keys = await ensure_agent_keys(keys_path)
        assert len(keys.ed25519_secret) == 32
        assert len(keys.ed25519_public) == 32
        assert os.path.exists(keys_path)

    async def test_loads_existing_keys(self, keys_path):
        keys1 = await ensure_agent_keys(keys_path)
        keys2 = await ensure_agent_keys(keys_path)
        assert keys1.ed25519_public == keys2.ed25519_public

    async def test_rotate_keys(self, keys_path):
        keys1 = await ensure_agent_keys(keys_path)
        keys2 = await rotate_keys(keys_path)
        assert keys1.ed25519_public != keys2.ed25519_public


class TestMetrics:
    def test_initial_values(self):
        m = Metrics()
        assert m.messages_sent == 0
        assert m.messages_received == 0

    def test_to_dict(self):
        m = Metrics()
        m.messages_sent = 10
        d = m.to_dict()
        assert d["messages_sent"] == 10
        assert "uptime_seconds" in d


class TestBridgeDaemonInit:
    def test_no_passphrase_raises(self):
        """BridgeDaemon refuses to start without an explicit passphrase."""
        import pytest
        with pytest.raises(ValueError, match="Passphrase is required"):
            BridgeDaemon(name="test")

    def test_default_config_with_passphrase(self):
        d = BridgeDaemon(name="test", passphrase="my-secret-long-12")
        assert d.name == "test"
        assert d.port == 8765
        assert d.passphrase == "my-secret-long-12"

    def test_custom_config(self, tmp_path):
        d = BridgeDaemon(
            name="custom",
            port=9999,
            passphrase="secret-pass-12",
            keys_path=str(tmp_path / "keys.json"),
            db_path=str(tmp_path / "test.db"),
        )
        assert d.name == "custom"
        assert d.port == 9999
        assert d.passphrase == "secret-pass-12"


@pytest.mark.asyncio
class TestBridgeHandshake:
    async def test_full_handshake_flow(self, keys_path, db_path):
        """Test that the handshake establishes matching session keys on both sides."""
        # This tests the crypto flow without actual WebSocket connections

        # Generate identity keys for two agents
        keys_a = generate_keypair("alice")
        keys_b = generate_keypair("bob")

        # Generate ephemeral keys for this session
        eph_priv_a, eph_pub_a = generate_ephemeral()
        eph_priv_b, eph_pub_b = generate_ephemeral()

        # Each side derives the shared secret
        secret_a = ecdh_exchange(eph_priv_a, eph_pub_b)
        secret_b = ecdh_exchange(eph_priv_b, eph_pub_a)

        # Both sides should derive the same session key
        assert secret_a == secret_b

        # Verify messages can be encrypted/decrypted with the shared key
        plaintext = b"Hello from Alice to Bob!"
        encrypted = encrypt_message(secret_a, plaintext)
        from ironmesh.crypto import decrypt_message
        decrypted = decrypt_message(secret_b, encrypted)
        assert decrypted == plaintext

    async def test_different_sessions_different_keys(self):
        """Each session should produce different ephemeral keys."""
        eph_priv_1, eph_pub_1 = generate_ephemeral()
        eph_priv_2, eph_pub_2 = generate_ephemeral()
        assert bytes(eph_pub_1) != bytes(eph_pub_2)
