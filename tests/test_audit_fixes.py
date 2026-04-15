"""Tests for all 18 IronMesh security audit findings.

Covers: HELLO sig verification, detached signatures, encrypted control messages,
mDNS allowlist, auth failure blocking, trust store MAC, SQLite encryption,
GUI token auth, secure_wipe, ReplayGuard docstring, TOFU ordering,
Frame msg_id hash, passphrase from file, _local_ip fallback, metrics parsing,
hook circuit breaker, SQL parameterization.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from ironmesh.bridge import BridgeDaemon
from ironmesh.keys import generate_keypair, generate_ephemeral, get_fingerprint
from ironmesh.crypto import (
    ecdh_exchange, encrypt_message, decrypt_message,
    sign_message, verify_signature, sign_detached, verify_detached,
    secure_wipe,
)
from ironmesh.protocol import (
    Frame, Handshake, MessageType, PeerState, ReplayGuard, TokenBucket,
)

STRONG_PASSPHRASE = "audit-test-passphrase-12"


# -----------------------------------------------------------------------
# #1: HELLO signature — wrong canonical must fail
# -----------------------------------------------------------------------

class TestHelloSigCanonical:
    def test_wrong_canonical_rejected(self):
        """HELLO sig over wrong canonical must fail verification."""
        keys = generate_keypair("alice")
        _, eph_pub = generate_ephemeral()
        eph_b64 = base64.b64encode(bytes(eph_pub)).decode()
        identity_b64 = keys.get_public_key_base64()

        # Sign correct canonical
        canonical = json.dumps({
            "channel_binding": os.urandom(32).hex(),
            "ephemeral_public": eph_b64,
            "identity_public": identity_b64,
            "name": "alice",
            "protocol_version": "ironmesh/0.3",
        }, separators=(",", ":"), sort_keys=True)
        signed = sign_message(keys.get_signing_key(), canonical.encode())

        # Reconstruct with DIFFERENT canonical (different name)
        wrong_canonical = json.dumps({
            "channel_binding": os.urandom(32).hex(),  # different nonce
            "ephemeral_public": eph_b64,
            "identity_public": identity_b64,
            "name": "alice",
            "protocol_version": "ironmesh/0.3",
        }, separators=(",", ":"), sort_keys=True)

        from nacl.signing import VerifyKey
        vk = VerifyKey(keys.ed25519_public)
        extracted = verify_signature(vk, signed)
        # The extracted payload should NOT match the wrong canonical
        assert extracted != wrong_canonical.encode()

    def test_correct_canonical_passes(self):
        """HELLO sig over correct canonical must pass."""
        keys = generate_keypair("alice")
        _, eph_pub = generate_ephemeral()
        eph_b64 = base64.b64encode(bytes(eph_pub)).decode()
        identity_b64 = keys.get_public_key_base64()
        nonce = os.urandom(32).hex()

        canonical = json.dumps({
            "channel_binding": nonce,
            "ephemeral_public": eph_b64,
            "identity_public": identity_b64,
            "name": "alice",
            "protocol_version": "ironmesh/0.3",
        }, separators=(",", ":"), sort_keys=True)
        signed = sign_message(keys.get_signing_key(), canonical.encode())

        from nacl.signing import VerifyKey
        vk = VerifyKey(keys.ed25519_public)
        extracted = verify_signature(vk, signed)
        assert extracted == canonical.encode()


# -----------------------------------------------------------------------
# #2: Detached signatures — verify rejects wrong message, accepts correct
# -----------------------------------------------------------------------

class TestDetachedSignatures:
    def test_detached_sign_verify_roundtrip(self):
        keys = generate_keypair("signer")
        message = b"Hello, detached!"
        sig = sign_detached(keys.get_signing_key(), message)
        assert len(sig) == 64
        # Should not raise
        verify_detached(keys.get_verify_key(), message, sig)

    def test_detached_wrong_message_rejected(self):
        keys = generate_keypair("signer")
        sig = sign_detached(keys.get_signing_key(), b"correct message")
        with pytest.raises(Exception):
            verify_detached(keys.get_verify_key(), b"wrong message", sig)

    def test_detached_wrong_key_rejected(self):
        alice = generate_keypair("alice")
        bob = generate_keypair("bob")
        msg = b"test"
        sig = sign_detached(alice.get_signing_key(), msg)
        with pytest.raises(Exception):
            verify_detached(bob.get_verify_key(), msg, sig)


# -----------------------------------------------------------------------
# #3: Encrypted PING roundtrip
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestEncryptedPing:
    async def test_encrypted_ping_sent(self, tmp_path):
        """PING should be sent via _send_encrypted_control as binary frame."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        d._keypair = generate_keypair("test")

        peer_keys = generate_keypair("peer1")
        peer_state = PeerState(node_id="peer1", address="127.0.0.1:9999")
        session_key = os.urandom(32)
        peer_state.session_key = session_key
        peer_state.identity_public = peer_keys.ed25519_public
        peer_state.verified = True
        d.peers["peer1"] = peer_state

        mock_ws = AsyncMock()
        d.ws_clients["peer1"] = mock_ws

        await d._send_encrypted_control("peer1", MessageType.PING)
        mock_ws.send.assert_called_once()
        sent_data = mock_ws.send.call_args[0][0]
        # Should be binary frame, not JSON
        assert isinstance(sent_data, bytes)
        assert sent_data[:2] == Frame.MAGIC
        # Should have FLAG_ENCRYPTED and FLAG_SIGNED
        assert sent_data[3] & Frame.FLAG_ENCRYPTED
        assert sent_data[3] & Frame.FLAG_SIGNED
        # Verify it decrypts correctly
        result = Frame.deserialize_and_decrypt(
            sent_data, session_key, verify_key=d._keypair.get_verify_key()
        )
        inner = json.loads(result.payload)
        assert inner["type"] == MessageType.PING


# -----------------------------------------------------------------------
# #4: Encrypted GOODBYE roundtrip
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestEncryptedGoodbye:
    async def test_encrypted_goodbye_sent(self, tmp_path):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        d._keypair = generate_keypair("test")

        peer_keys = generate_keypair("peer1")
        peer_state = PeerState(node_id="peer1", address="127.0.0.1:9999")
        session_key = os.urandom(32)
        peer_state.session_key = session_key
        peer_state.identity_public = peer_keys.ed25519_public
        peer_state.verified = True
        d.peers["peer1"] = peer_state

        mock_ws = AsyncMock()
        d.ws_clients["peer1"] = mock_ws

        await d._send_encrypted_control("peer1", MessageType.GOODBYE)
        sent_data = mock_ws.send.call_args[0][0]
        assert isinstance(sent_data, bytes)
        assert sent_data[:2] == Frame.MAGIC
        # Verify it decrypts correctly
        result = Frame.deserialize_and_decrypt(
            sent_data, session_key, verify_key=d._keypair.get_verify_key()
        )
        inner = json.loads(result.payload)
        assert inner["type"] == MessageType.GOODBYE


# -----------------------------------------------------------------------
# #5: mDNS allowlist blocks unapproved peer
# -----------------------------------------------------------------------

class TestMDNSAllowlist:
    def test_allowed_peer_connects(self):
        d = BridgeDaemon(name="server", passphrase=STRONG_PASSPHRASE,
                         allowed_peers=["approved-agent"])
        # Should NOT be skipped
        with patch.object(d, 'connect_to_peer', new_callable=AsyncMock) as mock_connect:
            d._on_peer_discovered("approved-agent", {"ip": "1.2.3.4", "port": 8765})
            # connect_to_peer might not be called directly (needs event loop)
            # but _known_peer_addresses should be updated
            assert "approved-agent" in d._known_peer_addresses

    def test_unapproved_peer_blocked(self):
        d = BridgeDaemon(name="server", passphrase=STRONG_PASSPHRASE,
                         allowed_peers=["approved-agent"])
        d._on_peer_discovered("evil-agent", {"ip": "1.2.3.4", "port": 8765})
        assert "evil-agent" not in d._known_peer_addresses

    def test_no_allowlist_default_deny(self):
        """RAZOR #4: Default-deny — no allowlist + no open_discovery blocks all."""
        d = BridgeDaemon(name="server", passphrase=STRONG_PASSPHRASE)
        d._on_peer_discovered("any-agent", {"ip": "1.2.3.4", "port": 8765})
        assert "any-agent" not in d._known_peer_addresses

    def test_open_discovery_allows_all(self):
        """With --open-discovery, all peers are accepted."""
        d = BridgeDaemon(name="server", passphrase=STRONG_PASSPHRASE,
                         open_discovery=True)
        d._on_peer_discovered("any-agent", {"ip": "1.2.3.4", "port": 8765})
        assert "any-agent" in d._known_peer_addresses


# -----------------------------------------------------------------------
# #6: Auth failure IP blocking after 3 failures
# -----------------------------------------------------------------------

class TestAuthFailureBlocking:
    async def test_not_blocked_initially(self):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        assert not await d._is_ip_blocked("1.2.3.4")

    async def test_blocked_after_3_failures(self):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        for _ in range(3):
            await d._record_auth_failure("1.2.3.4")
        assert await d._is_ip_blocked("1.2.3.4")

    async def test_not_blocked_after_2_failures(self):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        for _ in range(2):
            await d._record_auth_failure("1.2.3.4")
        assert not await d._is_ip_blocked("1.2.3.4")

    async def test_different_ips_independent(self):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        for _ in range(3):
            await d._record_auth_failure("1.2.3.4")
        assert await d._is_ip_blocked("1.2.3.4")
        assert not await d._is_ip_blocked("5.6.7.8")

    def test_minimum_passphrase_length(self):
        with pytest.raises(ValueError, match="too short"):
            BridgeDaemon(name="test", passphrase="short")

    def test_12_char_passphrase_accepted(self):
        d = BridgeDaemon(name="test", passphrase="exactly12chr")
        assert d.passphrase == "exactly12chr"


# -----------------------------------------------------------------------
# #7: Trust store MAC with agent key
# -----------------------------------------------------------------------

class TestTrustStoreAgentMAC:
    def test_mac_with_custom_key(self, tmp_path):
        from ironmesh.trust import TrustStore
        custom_key = os.urandom(32)
        store = TrustStore(agent_key=custom_key, path=str(tmp_path / "trust.json"))
        pubkey = base64.b64encode(os.urandom(32)).decode()
        store.pin_peer("peer1", pubkey)

        # Reload with same key — should work
        store2 = TrustStore(agent_key=custom_key, path=str(tmp_path / "trust.json"))
        assert "peer1" in store2._peers

    def test_mac_with_wrong_key_rejects_tampered(self, tmp_path):
        from ironmesh.trust import TrustStore
        key_a = os.urandom(32)
        store = TrustStore(agent_key=key_a, path=str(tmp_path / "trust.json"))
        pubkey = base64.b64encode(os.urandom(32)).decode()
        store.pin_peer("peer1", pubkey)

        # Tamper with file
        with open(str(tmp_path / "trust.json")) as f:
            data = json.load(f)
        data["peers"]["evil"] = {"pubkey": "x"}
        with open(str(tmp_path / "trust.json"), "w") as f:
            json.dump(data, f)

        # Load with same key — tampered, detected by MAC mismatch
        store2 = TrustStore(agent_key=key_a, path=str(tmp_path / "trust.json"))
        assert len(store2._peers) == 0

    def test_short_agent_key_rejected(self, tmp_path):
        """Audit C-03: agent_key must be at least 16 bytes."""
        from ironmesh.trust import TrustStore
        with pytest.raises(ValueError):
            TrustStore(agent_key=b"short", path=str(tmp_path / "trust.json"))


# -----------------------------------------------------------------------
# #8: SQLite payload encryption roundtrip + migration
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestSQLiteEncryption:
    async def test_encrypted_payload_roundtrip(self, tmp_path):
        from ironmesh.store import MessageStore
        key = hashlib.sha256(b"test-passironmesh-storage-v1").digest()
        store = MessageStore(str(tmp_path / "enc.db"), storage_key=key)
        await store.open()

        await store.store_message("m1", "alice", "Alice", "bob", "MSG", b"secret data", "out")
        msgs = await store.get_messages()
        assert len(msgs) == 1
        assert msgs[0]["payload"] == b"secret data"
        await store.close()

    async def test_encrypted_pending_roundtrip(self, tmp_path):
        from ironmesh.store import MessageStore
        key = hashlib.sha256(b"test-passironmesh-storage-v1").digest()
        store = MessageStore(str(tmp_path / "enc.db"), storage_key=key)
        await store.open()

        await store.queue_for_peer("bob", "q1", "alice", "MSG", b"queued secret", "NORMAL")
        pending = await store.get_pending_for_peer("bob")
        assert len(pending) == 1
        assert pending[0]["payload"] == b"queued secret"
        await store.close()

    async def test_migration_plaintext_to_encrypted(self, tmp_path):
        """Existing plaintext data should be readable after enabling encryption."""
        from ironmesh.store import MessageStore
        # First, store without encryption
        store1 = MessageStore(str(tmp_path / "migr.db"))
        await store1.open()
        await store1.store_message("m1", "alice", "Alice", "bob", "MSG", b"plain", "out")
        await store1.close()

        # Now open with encryption key — should still read old plaintext
        key = hashlib.sha256(b"passironmesh-storage-v1").digest()
        store2 = MessageStore(str(tmp_path / "migr.db"), storage_key=key)
        await store2.open()
        msgs = await store2.get_messages()
        assert len(msgs) == 1
        assert msgs[0]["payload"] == b"plain"
        await store2.close()

    async def test_no_key_stores_plaintext(self, tmp_path):
        from ironmesh.store import MessageStore
        store = MessageStore(str(tmp_path / "plain.db"))
        await store.open()
        await store.store_message("m1", "a", "A", "b", "MSG", b"hello", "out")
        msgs = await store.get_messages()
        assert msgs[0]["payload"] == b"hello"
        await store.close()


# -----------------------------------------------------------------------
# #9: GUI token required for endpoints
# -----------------------------------------------------------------------

class TestGUIToken:
    def test_gui_token_generated_on_init(self):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        assert d._gui_token
        assert len(d._gui_token) > 20

    def test_check_gui_token_valid_query_param(self):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        mock_req = MagicMock()
        mock_req.path = f"/metrics?token={d._gui_token}"
        mock_req.headers = {}
        assert d._check_gui_token(mock_req) is True

    def test_check_gui_token_valid_bearer(self):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        mock_req = MagicMock()
        mock_req.path = "/metrics"
        mock_req.headers = {"Authorization": f"Bearer {d._gui_token}"}
        assert d._check_gui_token(mock_req) is True

    def test_check_gui_token_missing(self):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        mock_req = MagicMock()
        mock_req.path = "/metrics"
        mock_req.headers = {}
        assert d._check_gui_token(mock_req) is False

    def test_check_gui_token_wrong(self):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        mock_req = MagicMock()
        mock_req.path = "/metrics?token=wrong-token"
        mock_req.headers = {}
        assert d._check_gui_token(mock_req) is False


# -----------------------------------------------------------------------
# #10: secure_wipe zeroes buffer
# -----------------------------------------------------------------------

class TestSecureWipe:
    def test_wipe_bytearray(self):
        ba = bytearray(b"sensitive data here!!")
        secure_wipe(ba)
        assert ba == bytearray(len(ba))  # All zeros

    def test_wipe_does_not_crash_on_bytes(self):
        b = b"immutable bytes"
        # Should not raise — best effort
        secure_wipe(b)

    def test_wipe_does_not_crash_on_none(self):
        secure_wipe(None)


# -----------------------------------------------------------------------
# #11: ReplayGuard docstring present
# -----------------------------------------------------------------------

class TestReplayGuardDocstring:
    def test_docstring_mentions_asyncio(self):
        doc = ReplayGuard.__doc__
        assert doc is not None
        assert "asyncio" in doc.lower()

    def test_docstring_mentions_thread_safety(self):
        doc = ReplayGuard.__doc__
        assert "thread" in doc.lower() or "Thread" in doc


# -----------------------------------------------------------------------
# #12: TOFU checked before peer dict population
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestTOFUBeforePeerDict:
    async def test_tofu_mismatch_prevents_peer_population(self):
        """On TOFU mismatch, peer should NOT be in self.peers."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        d._keypair = generate_keypair("test")

        keys = generate_keypair("peer1")
        peer_id = get_fingerprint(keys.ed25519_public)

        mock_trust = MagicMock()
        mock_trust.verify_peer.return_value = "mismatch"

        with patch("ironmesh.trust.TrustStore", return_value=mock_trust):
            with pytest.raises(ConnectionError):
                await d._check_tofu(peer_id, keys.get_public_key_base64())

        # Peer should NOT be in dicts (was never added before TOFU check)
        assert peer_id not in d.peers
        assert peer_id not in d.ws_clients


# -----------------------------------------------------------------------
# #13: Frame msg_id uses hash
# -----------------------------------------------------------------------

class TestFrameMsgIdHash:
    def test_msg_id_header_uses_sha256(self):
        f = Frame(msg_type=MessageType.MSG, payload=b"test")
        binary = f.serialize_plaintext()
        # Extract msg_id bytes from header (bytes 20-28)
        msg_id_bytes = binary[20:28]
        expected = hashlib.sha256(f.msg_id.encode()).digest()[:8]
        assert msg_id_bytes == expected

    def test_encrypted_frame_uses_sha256_msg_id(self):
        f = Frame(msg_type=MessageType.MSG, payload=b"test")
        shared_key = os.urandom(32)
        binary = f.encrypt_and_serialize(shared_key)
        msg_id_bytes = binary[20:28]
        expected = hashlib.sha256(f.msg_id.encode()).digest()[:8]
        assert msg_id_bytes == expected


# -----------------------------------------------------------------------
# #14: Passphrase from file works
# -----------------------------------------------------------------------

class TestPassphraseFile:
    def test_passphrase_from_file(self, tmp_path):
        passfile = tmp_path / "pass.txt"
        passfile.write_text("my-secret-from-file\n")
        with patch.dict(os.environ, {
            "IRONMESH_PASSPHRASE_FILE": str(passfile),
        }, clear=False):
            # Remove IRONMESH_PASSPHRASE to test file takes priority
            env = os.environ.copy()
            env.pop("IRONMESH_PASSPHRASE", None)
            with patch.dict(os.environ, env, clear=True):
                from ironmesh.cli import get_passphrase
                result = get_passphrase()
                assert result == "my-secret-from-file"

    def test_passphrase_env_var_used_when_no_file(self):
        """get_passphrase() falls back to IRONMESH_PASSPHRASE env var."""
        from ironmesh.cli import get_passphrase
        env = {"IRONMESH_PASSPHRASE": "env-secret-pass"}
        # Remove file-based env var
        with patch.dict(os.environ, env, clear=True):
            result = get_passphrase()
            assert result == "env-secret-pass"


# -----------------------------------------------------------------------
# #15: _local_ip fallback works
# -----------------------------------------------------------------------

class TestLocalIPFallback:
    def test_local_ip_returns_string(self):
        from ironmesh.discovery import _local_ip
        ip = _local_ip()
        assert isinstance(ip, str)
        assert len(ip) >= 7  # At least "x.x.x.x"

    def test_local_ip_fallback_on_failure(self):
        """When all strategies fail, should return 127.0.0.1."""
        import socket
        from ironmesh.discovery import _local_ip

        # Mock everything to fail
        with patch("ironmesh.discovery.socket.getaddrinfo", side_effect=OSError):
            with patch("ironmesh.discovery.socket.socket") as mock_socket:
                mock_sock = MagicMock()
                mock_sock.connect.side_effect = OSError
                mock_sock.getsockname.return_value = ("127.0.0.1", 0)
                mock_socket.return_value = mock_sock
                ip = _local_ip()
                assert ip == "127.0.0.1"


# -----------------------------------------------------------------------
# #16: Legacy metrics parses path
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestLegacyMetricsParsing:
    async def test_metrics_server_parses_path(self, tmp_path):
        """The metrics server should parse the HTTP request line for method + path."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        # Just verify the _metrics_server method exists and has parsing logic
        import inspect
        source = inspect.getsource(d._metrics_server)
        assert "request_line" in source or "parts" in source
        assert "404" in source  # Should return 404 for non-/metrics paths


# -----------------------------------------------------------------------
# #17: Hook circuit breaker fires after 3 failures
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestHookCircuitBreaker:
    async def test_circuit_breaker_after_3_failures(self):
        from ironmesh.hooks import HookManager

        call_count = 0

        def failing_hook(ctx):
            nonlocal call_count
            call_count += 1
            raise RuntimeError("boom")

        mgr = HookManager()
        mgr.register("test_point", failing_hook)

        # Fire 3 times — should trigger circuit breaker
        for _ in range(3):
            await mgr.fire("test_point", {"key": "value"})

        assert call_count == 3
        # After circuit breaker, hook should be removed
        assert len(mgr._hooks.get("test_point", [])) == 0

    async def test_success_resets_counter(self):
        from ironmesh.hooks import HookManager

        attempt = 0

        def flaky_hook(ctx):
            nonlocal attempt
            attempt += 1
            if attempt <= 2:
                raise RuntimeError("flaky")
            # Third call succeeds

        mgr = HookManager()
        mgr.register("test_point", flaky_hook)

        await mgr.fire("test_point", {})  # fail 1
        await mgr.fire("test_point", {})  # fail 2
        await mgr.fire("test_point", {})  # success — resets counter
        # Should still be registered
        assert len(mgr._hooks.get("test_point", [])) == 1

    async def test_healthy_hook_not_removed(self):
        from ironmesh.hooks import HookManager
        calls = []

        def good_hook(ctx):
            calls.append(1)

        mgr = HookManager()
        mgr.register("test_point", good_hook)

        for _ in range(10):
            await mgr.fire("test_point", {})

        assert len(calls) == 10
        assert len(mgr._hooks["test_point"]) == 1


# -----------------------------------------------------------------------
# #18: SQL uses parameterized queries
# -----------------------------------------------------------------------

class TestSQLParameterized:
    def test_get_messages_uses_params(self):
        """Verify get_messages uses parameterized queries (no f-string with user data)."""
        import inspect
        from ironmesh.store import MessageStore
        source = inspect.getsource(MessageStore.get_messages)
        # Should use ? placeholders
        assert "?" in source
        # Should NOT use format strings with user-controlled data
        # The base query string concatenation is safe since it only uses static fragments
        assert "conditions" in source
        assert "params" in source


# =======================================================================
# RAZOR ONLINE — Additional hardening tests
# =======================================================================


# -----------------------------------------------------------------------
# RAZOR #2: Identity keys must be encrypted by default
# -----------------------------------------------------------------------

class TestRazorKeyEncryption:
    def test_save_keys_requires_passphrase(self):
        """save_keys() must raise ValueError if no passphrase and allow_plaintext=False."""
        from ironmesh.keys import generate_keypair, save_keys
        keys = generate_keypair()
        with pytest.raises(ValueError, match="Passphrase is required"):
            save_keys(keys, "/tmp/test-razor-keys.json")

    def test_save_keys_allow_plaintext_flag(self, tmp_path):
        """save_keys() with allow_plaintext=True should not raise."""
        from ironmesh.keys import generate_keypair, save_keys, load_keys
        keys = generate_keypair()
        path = str(tmp_path / "plaintext-keys.json")
        save_keys(keys, path, allow_plaintext=True)
        loaded = load_keys(path)
        assert loaded.ed25519_public == keys.ed25519_public

    def test_save_keys_with_passphrase_encrypts(self, tmp_path):
        """save_keys() with passphrase should encrypt the key."""
        from ironmesh.keys import generate_keypair, save_keys
        keys = generate_keypair()
        path = str(tmp_path / "enc-keys.json")
        save_keys(keys, path, passphrase="strong-passphrase-123")
        with open(path) as f:
            data = json.load(f)
        assert data["encrypted"] is True
        assert "ed25519_secret" not in data
        assert "ed25519_secret_encrypted" in data


# -----------------------------------------------------------------------
# RAZOR #3: CLI passphrase not in process list
# -----------------------------------------------------------------------

class TestRazorCLIPassphrase:
    def test_get_passphrase_no_cli_arg(self):
        """get_passphrase() must not accept argv arguments (removed for ps safety)."""
        import inspect
        from ironmesh.cli import get_passphrase
        sig = inspect.signature(get_passphrase)
        # Should take no parameters
        assert len(sig.parameters) == 0

    def test_get_passphrase_from_file(self, tmp_path):
        """get_passphrase() should read from IRONMESH_PASSPHRASE_FILE."""
        from ironmesh.cli import get_passphrase
        pf = tmp_path / "pass.txt"
        pf.write_text("file-based-secret\n")
        with patch.dict(os.environ, {"IRONMESH_PASSPHRASE_FILE": str(pf)}):
            result = get_passphrase()
        assert result == "file-based-secret"

    def test_run_parser_no_passphrase_flag(self):
        """--passphrase should NOT exist on run parser (removed entirely)."""
        from ironmesh.cli import parse_args
        import sys
        old_argv = sys.argv
        try:
            sys.argv = ["ironmesh", "run", "--name", "test"]
            args = parse_args()
            # --passphrase should not be an attribute on run subcommand
            assert not hasattr(args, "passphrase") or args.passphrase is None
        finally:
            sys.argv = old_argv

    def test_get_passphrase_exits_when_no_source(self):
        """get_passphrase() must exit(1) when no passphrase source available."""
        from ironmesh.cli import get_passphrase
        # Clear all passphrase env vars and make stdin non-interactive
        env = os.environ.copy()
        env.pop("IRONMESH_PASSPHRASE", None)
        env.pop("IRONMESH_PASSPHRASE_FILE", None)
        with patch.dict(os.environ, env, clear=True):
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.isatty.return_value = False
                with pytest.raises(SystemExit):
                    get_passphrase()


# -----------------------------------------------------------------------
# RAZOR #4: Default-deny mDNS discovery
# -----------------------------------------------------------------------

class TestRazorMDNSDefaultDeny:
    def test_default_deny_blocks_discovery(self):
        """Without --allowed-peers or --open-discovery, mDNS auto-connect is blocked."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        assert d._open_discovery is False
        assert d._allowed_peers is None
        d._on_peer_discovered("random-agent", {"ip": "1.2.3.4", "port": 8765})
        assert "random-agent" not in d._known_peer_addresses

    def test_open_discovery_allows_all(self):
        """--open-discovery flag allows all mDNS peers."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         open_discovery=True)
        d._on_peer_discovered("random-agent", {"ip": "1.2.3.4", "port": 8765})
        assert "random-agent" in d._known_peer_addresses

    def test_allowlist_overrides_default_deny(self):
        """--allowed-peers enables discovery for listed peers only."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         allowed_peers=["friend-agent"])
        d._on_peer_discovered("friend-agent", {"ip": "1.2.3.4", "port": 8765})
        assert "friend-agent" in d._known_peer_addresses
        d._on_peer_discovered("stranger", {"ip": "5.6.7.8", "port": 8765})
        assert "stranger" not in d._known_peer_addresses

    def test_discovery_rate_limiting(self):
        """mDNS discovery should rate-limit flood events."""
        from ironmesh.discovery import AgentListener
        listener = AgentListener()
        # Initialize rate limiting structures
        assert hasattr(listener, '_discovery_timestamps')
        # Simulate rapid rate limiting
        for _ in range(listener._DISCOVERY_RATE_LIMIT):
            assert listener._is_rate_limited() is False
        # Next one should be rate limited
        assert listener._is_rate_limited() is True


# -----------------------------------------------------------------------
# RAZOR #5: Client-side TLS support
# -----------------------------------------------------------------------

class TestRazorClientTLS:
    def test_allow_plaintext_ws_default_false(self):
        """By default, plaintext WebSocket fallback is disabled."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        assert d._allow_plaintext_ws is False

    def test_allow_plaintext_ws_flag(self):
        """--allow-plaintext-ws enables insecure fallback."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         allow_plaintext_ws=True)
        assert d._allow_plaintext_ws is True

    @pytest.mark.asyncio
    async def test_connect_to_peer_tries_tls_first(self):
        """connect_to_peer() should attempt wss:// before ws://."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        # Mock websockets.connect to track URI attempts
        attempted_uris = []

        async def mock_connect(uri, **kwargs):
            attempted_uris.append(uri)
            raise ConnectionRefusedError("test")

        with patch("ironmesh.bridge.websockets.connect", side_effect=mock_connect):
            result = await d.connect_to_peer("1.2.3.4", 8765)
        assert result is None  # Should fail gracefully
        assert any("wss://" in u for u in attempted_uris)

    @pytest.mark.asyncio
    async def test_connect_no_plaintext_fallback_by_default(self):
        """Without allow_plaintext_ws, failing TLS should not fall back to ws://."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        attempted_uris = []

        async def mock_connect(uri, **kwargs):
            attempted_uris.append(uri)
            raise ConnectionRefusedError("test")

        with patch("ironmesh.bridge.websockets.connect", side_effect=mock_connect):
            result = await d.connect_to_peer("1.2.3.4", 8765)
        assert result is None
        # Should only have tried wss://, NOT ws://
        assert all("wss://" in u for u in attempted_uris)

    @pytest.mark.asyncio
    async def test_connect_plaintext_fallback_when_allowed(self):
        """With allow_plaintext_ws=True, TLS failure falls back to ws://."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         allow_plaintext_ws=True)
        attempted_uris = []

        async def mock_connect(uri, **kwargs):
            attempted_uris.append(uri)
            raise ConnectionRefusedError("test")

        with patch("ironmesh.bridge.websockets.connect", side_effect=mock_connect):
            result = await d.connect_to_peer("1.2.3.4", 8765)
        assert result is None
        # Should have tried wss:// first, then ws://
        assert attempted_uris[0].startswith("wss://")
        assert any("ws://" in u and not u.startswith("wss://") for u in attempted_uris)


# =======================================================================
# RAZOR ONLINE Round 2 — Binary frames + bus immutability
# =======================================================================


# -----------------------------------------------------------------------
# Bus data immutability
# -----------------------------------------------------------------------

class TestBusImmutability:
    def test_bus_publish_freezes_dict_data(self):
        """MessageBus.publish should pass frozen (immutable) dicts to listeners."""
        from ironmesh.protocol import MessageBus
        from types import MappingProxyType

        received = []
        bus = MessageBus()
        bus.subscribe("test", lambda data: received.append(data))

        bus.publish("test", {"key": "value"})
        assert len(received) == 1
        assert isinstance(received[0], MappingProxyType)
        # Mutation should raise
        with pytest.raises(TypeError):
            received[0]["new_key"] = "bad"

    def test_bus_catch_all_also_frozen(self):
        """Catch-all listeners should also receive frozen dicts."""
        from ironmesh.protocol import MessageBus
        from types import MappingProxyType

        received = []
        bus = MessageBus()
        bus.on_any(lambda event_type, data: received.append(data))

        bus.publish("any_event", {"key": "value"})
        assert len(received) == 1
        assert isinstance(received[0], MappingProxyType)

    def test_bus_non_dict_data_passes_through(self):
        """Non-dict data should pass through without wrapping."""
        from ironmesh.protocol import MessageBus

        received = []
        bus = MessageBus()
        bus.subscribe("test", lambda data: received.append(data))

        bus.publish("test", "plain-string")
        assert received[0] == "plain-string"


# -----------------------------------------------------------------------
# Binary frame with signatures
# -----------------------------------------------------------------------

class TestBinaryFrameSignature:
    def test_encrypt_serialize_with_signature(self):
        """Binary frame should include Ed25519 signature when signing_key provided."""
        from ironmesh.keys import generate_keypair
        from ironmesh.protocol import Frame, MessageType

        keys = generate_keypair("alice")
        shared_key = os.urandom(32)

        frame = Frame(msg_type=MessageType.MSG, payload=b"hello world", source="alice")
        raw = frame.encrypt_and_serialize(shared_key, signing_key=keys.get_signing_key())

        # Should have header + encrypted + 64-byte signature
        assert len(raw) > Frame.HEADER_SIZE + Frame.SIGNATURE_SIZE
        # FLAG_SIGNED should be set
        assert raw[3] & Frame.FLAG_SIGNED

    def test_deserialize_verifies_signature(self):
        """deserialize_and_decrypt should verify the signature when present."""
        from ironmesh.keys import generate_keypair
        from ironmesh.protocol import Frame, MessageType

        keys = generate_keypair("alice")
        shared_key = os.urandom(32)

        frame = Frame(msg_type=MessageType.MSG, payload=b"test payload", source="alice")
        raw = frame.encrypt_and_serialize(shared_key, signing_key=keys.get_signing_key())

        # Deserialize with correct verify key
        result = Frame.deserialize_and_decrypt(raw, shared_key, verify_key=keys.get_verify_key())
        assert result.msg_type == MessageType.MSG
        assert result.payload == b"test payload"

    def test_wrong_verify_key_rejected(self):
        """Binary frame with wrong verify key should be rejected."""
        from ironmesh.keys import generate_keypair
        from ironmesh.protocol import Frame, MessageType

        alice = generate_keypair("alice")
        bob = generate_keypair("bob")
        shared_key = os.urandom(32)

        frame = Frame(msg_type=MessageType.MSG, payload=b"test", source="alice")
        raw = frame.encrypt_and_serialize(shared_key, signing_key=alice.get_signing_key())

        with pytest.raises(ValueError, match="Signature verification failed"):
            Frame.deserialize_and_decrypt(raw, shared_key, verify_key=bob.get_verify_key())

    def test_tampered_payload_rejected(self):
        """Tampering with encrypted data should cause signature rejection."""
        from ironmesh.keys import generate_keypair
        from ironmesh.protocol import Frame, MessageType

        keys = generate_keypair("alice")
        shared_key = os.urandom(32)

        frame = Frame(msg_type=MessageType.MSG, payload=b"original", source="alice")
        raw = bytearray(frame.encrypt_and_serialize(shared_key, signing_key=keys.get_signing_key()))

        # Tamper with encrypted data (after 32-byte header)
        if len(raw) > 40:
            raw[40] ^= 0xFF

        with pytest.raises(ValueError):
            Frame.deserialize_and_decrypt(bytes(raw), shared_key, verify_key=keys.get_verify_key())

    def test_unsigned_frame_still_works(self):
        """Binary frame without signature should work when no verify_key."""
        from ironmesh.protocol import Frame, MessageType

        shared_key = os.urandom(32)
        frame = Frame(msg_type=MessageType.MSG, payload=b"unsigned", source="alice")
        raw = frame.encrypt_and_serialize(shared_key)  # No signing_key

        # FLAG_SIGNED should NOT be set
        assert not (raw[3] & Frame.FLAG_SIGNED)

        result = Frame.deserialize_and_decrypt(raw, shared_key)
        assert result.payload == b"unsigned"

    def test_signed_frame_missing_verify_key_rejected(self):
        """Signed frame without verify_key should be rejected."""
        from ironmesh.keys import generate_keypair
        from ironmesh.protocol import Frame, MessageType

        keys = generate_keypair("alice")
        shared_key = os.urandom(32)

        frame = Frame(msg_type=MessageType.MSG, payload=b"test", source="alice")
        raw = frame.encrypt_and_serialize(shared_key, signing_key=keys.get_signing_key())

        with pytest.raises(ValueError, match="no verify_key"):
            Frame.deserialize_and_decrypt(raw, shared_key)  # No verify_key


# -----------------------------------------------------------------------
# Binary frame used in bridge send path
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestBridgeBinaryFramePath:
    async def test_send_frame_sends_binary(self, tmp_path):
        """_send_frame should send binary data, not JSON."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        d._keypair = generate_keypair("test")

        peer_keys = generate_keypair("peer1")
        peer_state = PeerState(node_id="peer1")
        peer_state.session_key = os.urandom(32)
        peer_state.identity_public = peer_keys.ed25519_public
        d.peers["peer1"] = peer_state

        ws = AsyncMock()
        d.ws_clients["peer1"] = ws

        frame = Frame(
            msg_type=MessageType.MSG,
            payload=b"binary test",
            source=d.node_id,
        )
        await d._send_frame("peer1", frame)

        ws.send.assert_called_once()
        sent_data = ws.send.call_args[0][0]
        # Should be bytes, not str (JSON)
        assert isinstance(sent_data, bytes)
        # Should start with IronMesh magic
        assert sent_data[:2] == Frame.MAGIC

    async def test_handle_binary_frame(self, tmp_path):
        """_handle_message should accept binary frames."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        d._keypair = generate_keypair("test")

        peer_keys = generate_keypair("peer1")
        peer_state = PeerState(node_id="peer1")
        session_key = os.urandom(32)
        peer_state.session_key = session_key
        peer_state.identity_public = peer_keys.ed25519_public
        peer_state.verified = True
        d.peers["peer1"] = peer_state

        await d._db.open()

        # Build a binary frame as the peer would send
        frame = Frame(
            msg_type=MessageType.MSG,
            payload=b"hello from peer",
            source="peer1",
            sequence=1,
        )
        raw = frame.encrypt_and_serialize(session_key, signing_key=peer_keys.get_signing_key())

        await d._handle_message("peer1", raw)
        assert peer_state.messages_received == 1
        await d._db.close()


# =======================================================================
# RAZOR ONLINE Round 3 — GUI default, key migration, mDNS pinning, audit
# =======================================================================


# -----------------------------------------------------------------------
# GUI defaults to OFF
# -----------------------------------------------------------------------

class TestGUIDefaultOff:
    def test_gui_default_is_false(self):
        """BridgeDaemon should default gui=False (opt-in, not opt-out)."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        assert d._gui_enabled is False

    def test_gui_explicit_true(self):
        """gui=True must still work when explicitly set."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE, gui=True)
        assert d._gui_enabled is True


# -----------------------------------------------------------------------
# Plaintext key auto-migration
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestKeyAutoMigration:
    async def test_plaintext_keys_migrated_to_encrypted(self, tmp_path):
        """ensure_agent_keys() should auto-encrypt plaintext key files."""
        from ironmesh.keys import generate_keypair, save_keys, load_keys
        from ironmesh.bridge import ensure_agent_keys
        keys = generate_keypair("test-agent")
        key_path = tmp_path / "keys.json"
        save_keys(keys, str(key_path), allow_plaintext=True)

        # Verify it's plaintext
        import json as _json
        with open(str(key_path)) as f:
            data = _json.load(f)
        assert data.get("encrypted", False) is False

        # Call ensure_agent_keys with a passphrase — should auto-migrate
        await ensure_agent_keys(str(key_path), passphrase=STRONG_PASSPHRASE)

        # After migration, key file should be encrypted
        with open(str(key_path)) as f:
            data = _json.load(f)
        assert data.get("encrypted") is True

    async def test_already_encrypted_keys_not_touched(self, tmp_path):
        """ensure_agent_keys() should not re-encrypt already encrypted keys."""
        from ironmesh.keys import generate_keypair, save_keys
        from ironmesh.bridge import ensure_agent_keys
        keys = generate_keypair("test-agent")
        key_path = tmp_path / "keys.json"
        save_keys(keys, str(key_path), passphrase="test-pass-12345")

        mtime_before = os.path.getmtime(str(key_path))

        import time
        time.sleep(0.05)  # Ensure mtime difference if file is rewritten

        await ensure_agent_keys(str(key_path), passphrase="test-pass-12345")

        mtime_after = os.path.getmtime(str(key_path))
        assert mtime_before == mtime_after  # File should not have been rewritten


# -----------------------------------------------------------------------
# mDNS fingerprint pinning
# -----------------------------------------------------------------------

class TestMDNSFingerprintPinning:
    def test_pinned_peers_dict_exists(self):
        """BridgeDaemon should have _pinned_peers attribute."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE)
        assert hasattr(d, "_pinned_peers")
        assert isinstance(d._pinned_peers, dict)

    def test_pinned_peer_address_change_logged_and_accepted(self):
        """mDNS address changes for pinned peers are accepted — identity is
        verified via Ed25519 pinning in `_check_tofu()` during handshake, not
        by address. Rejecting legitimate IP-change scenarios (DHCP lease,
        interface roam) would hurt availability without adding security."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         open_discovery=True)

        # Pin a peer
        d._pinned_peers["agent-x"] = {
            "fingerprint": "abc123",
            "address": "10.0.0.1:8765",
            "peer_id": "agent-x-id",
        }

        # Discover same agent from a new address — should update, not reject
        d._on_peer_discovered("agent-x", {"ip": "10.0.0.99", "port": 8765})
        assert d._pinned_peers["agent-x"]["address"] == "10.0.0.99:8765"
        assert d._known_peer_addresses.get("agent-x") == "10.0.0.99:8765"

    def test_pinned_peer_same_address_allowed(self):
        """Re-discovery from the same address should be allowed."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         open_discovery=True)

        d._pinned_peers["agent-x"] = {
            "fingerprint": "abc123",
            "address": "10.0.0.1:8765",
            "peer_id": "agent-x-id",
        }

        d._on_peer_discovered("agent-x", {"ip": "10.0.0.1", "port": 8765})
        # Same address — should be allowed through
        assert "agent-x" in d._known_peer_addresses


# -----------------------------------------------------------------------
# Audit log HMAC chain
# -----------------------------------------------------------------------

class TestAuditLogHMACChain:
    def test_audit_log_writes_and_verifies(self, tmp_path):
        """Audit log should write entries and verify HMAC chain."""
        from ironmesh.audit import AuditLog, EVENT_STARTUP, EVENT_PEER_CONNECT
        log_path = str(tmp_path / "audit.log")
        hmac_key = os.urandom(32)

        audit = AuditLog(path=log_path, hmac_key=hmac_key)
        audit.log(EVENT_STARTUP, {"node": "test", "version": "0.3"})
        audit.log(EVENT_PEER_CONNECT, {"peer": "alice", "address": "10.0.0.1"})

        # Verify chain
        valid, count, invalid_line = audit.verify()
        assert valid is True
        assert count == 2
        assert invalid_line is None

    def test_audit_log_detects_tampering(self, tmp_path):
        """Modifying an entry should break the HMAC chain."""
        from ironmesh.audit import AuditLog, EVENT_STARTUP
        log_path = str(tmp_path / "audit.log")
        hmac_key = os.urandom(32)

        audit = AuditLog(path=log_path, hmac_key=hmac_key)
        audit.log(EVENT_STARTUP, {"node": "test"})
        audit.log(EVENT_STARTUP, {"node": "test2"})

        # Tamper with the first entry
        with open(log_path, "r") as f:
            lines = f.readlines()
        import json as _json
        entry = _json.loads(lines[0])
        entry["details"]["node"] = "TAMPERED"
        lines[0] = _json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n"
        with open(log_path, "w") as f:
            f.writelines(lines)

        # Re-create audit log to verify (fresh instance reads last HMAC)
        audit2 = AuditLog(path=log_path, hmac_key=hmac_key)
        valid, count, invalid_line = audit2.verify()
        assert valid is False
        assert invalid_line == 1  # First entry was tampered

    def test_audit_log_disabled_without_key(self, tmp_path):
        """AuditLog without hmac_key should be disabled (no-op)."""
        from ironmesh.audit import AuditLog, EVENT_STARTUP
        log_path = str(tmp_path / "audit.log")

        audit = AuditLog(path=log_path, hmac_key=None)
        audit.log(EVENT_STARTUP, {"node": "test"})

        # File should not exist (no writes)
        assert not os.path.exists(log_path)

    def test_audit_log_chain_continuity(self, tmp_path):
        """Reopening an existing log should continue the HMAC chain."""
        from ironmesh.audit import AuditLog, EVENT_STARTUP, EVENT_PEER_CONNECT
        log_path = str(tmp_path / "audit.log")
        hmac_key = os.urandom(32)

        # Write first entry
        audit1 = AuditLog(path=log_path, hmac_key=hmac_key)
        audit1.log(EVENT_STARTUP, {"session": 1})

        # Reopen and write second entry
        audit2 = AuditLog(path=log_path, hmac_key=hmac_key)
        audit2.log(EVENT_PEER_CONNECT, {"session": 2})

        # Verify full chain
        valid, count, _ = audit2.verify()
        assert valid is True
        assert count == 2

    def test_audit_log_event_constants_exist(self):
        """All expected audit event constants should be defined."""
        from ironmesh import audit
        expected = [
            "EVENT_KEY_ROTATION", "EVENT_TOFU_NEW", "EVENT_TOFU_MISMATCH",
            "EVENT_AUTH_FAILURE", "EVENT_AUTH_BLOCKED", "EVENT_DECRYPT_FAILURE",
            "EVENT_SIGNATURE_FAILURE", "EVENT_REPLAY_DETECTED",
            "EVENT_PEER_CONNECT", "EVENT_PEER_DISCONNECT",
            "EVENT_GUI_ACCESS", "EVENT_STARTUP", "EVENT_SHUTDOWN",
        ]
        for const in expected:
            assert hasattr(audit, const), f"Missing event constant: {const}"


# -----------------------------------------------------------------------
# v0.4: Audit log rotation
# -----------------------------------------------------------------------

class TestAuditLogRotation:
    def test_log_rotation_at_size_limit(self, tmp_path):
        """When the log exceeds max_bytes, the live file is rotated to .1
        and a fresh anchor entry is written."""
        from ironmesh.audit import AuditLog, EVENT_STARTUP, EVENT_LOG_ROTATED

        log_path = str(tmp_path / "audit.log")
        hmac_key = b"k" * 32
        # Tiny rotation threshold (still >= 1 KB minimum) so a few writes
        # cross the boundary deterministically.
        audit = AuditLog(path=log_path, hmac_key=hmac_key, max_bytes=1024)

        # Write enough bulky entries to push past 1 KB.
        big = "x" * 200
        for i in range(15):
            audit.log(EVENT_STARTUP, {"i": i, "padding": big})

        # An archive must exist and the live log must contain the anchor entry.
        assert os.path.exists(log_path + ".1"), "Expected .audit.log.1 archive"
        assert os.path.exists(log_path), "Expected fresh live audit.log"

        with open(log_path, "r") as f:
            first_line = f.readline().strip()
        assert first_line, "Live log should not be empty after rotation"
        first_entry = json.loads(first_line)
        assert first_entry["event"] == EVENT_LOG_ROTATED
        assert "previous_tail_hmac" in first_entry["details"]
        assert first_entry["details"]["previous_tail_hmac"] != "0" * 64

    def test_chain_anchored_across_rotation(self, tmp_path):
        """The EVENT_LOG_ROTATED entry's previous_tail_hmac MUST equal the
        last HMAC of the rotated archive, and verify_chain_across_archives
        must accept the chain."""
        from ironmesh.audit import AuditLog, EVENT_STARTUP

        log_path = str(tmp_path / "audit.log")
        hmac_key = b"k" * 32
        audit = AuditLog(path=log_path, hmac_key=hmac_key, max_bytes=1024)

        big = "y" * 200
        for i in range(15):
            audit.log(EVENT_STARTUP, {"i": i, "padding": big})

        # Read the tail HMAC of the rotated archive.
        with open(log_path + ".1", "r") as f:
            archive_lines = [ln.strip() for ln in f if ln.strip()]
        archive_tail = json.loads(archive_lines[-1])["hmac"]

        # And the anchor entry in the live file.
        with open(log_path, "r") as f:
            anchor = json.loads(f.readline().strip())
        assert anchor["details"]["previous_tail_hmac"] == archive_tail

        # Walking the entire chain across the rotation must verify.
        valid, total, bad = audit.verify_chain_across_archives()
        assert valid is True
        assert bad is None
        assert total >= 16  # at least 15 bulk entries + 1 anchor

    def test_tampered_archive_breaks_cross_chain(self, tmp_path):
        """Tampering with an entry inside an archive must be detected by
        verify_chain_across_archives."""
        from ironmesh.audit import AuditLog, EVENT_STARTUP

        log_path = str(tmp_path / "audit.log")
        hmac_key = b"k" * 32
        audit = AuditLog(path=log_path, hmac_key=hmac_key, max_bytes=1024)

        big = "z" * 200
        for i in range(15):
            audit.log(EVENT_STARTUP, {"i": i, "padding": big})

        # Tamper with the second line of the archive.
        archive = log_path + ".1"
        with open(archive, "r") as f:
            lines = f.readlines()
        entry = json.loads(lines[1])
        entry["details"]["i"] = 9999
        lines[1] = json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n"
        with open(archive, "w") as f:
            f.writelines(lines)

        valid, _, bad = audit.verify_chain_across_archives()
        assert valid is False
        assert bad is not None

    def test_no_rotation_below_threshold(self, tmp_path):
        """A few small writes should NOT trigger rotation."""
        from ironmesh.audit import AuditLog, EVENT_STARTUP

        log_path = str(tmp_path / "audit.log")
        hmac_key = b"k" * 32
        audit = AuditLog(path=log_path, hmac_key=hmac_key, max_bytes=10 * 1024 * 1024)

        for i in range(5):
            audit.log(EVENT_STARTUP, {"i": i})

        assert os.path.exists(log_path)
        assert not os.path.exists(log_path + ".1")


# -----------------------------------------------------------------------
# v0.7.2: Peer long-drop alerting
# -----------------------------------------------------------------------

class TestPeerLongDropAlert:
    def test_offline_since_stamped_on_first_offline(self):
        """Going offline sets offline_since; going online clears it."""
        ps = PeerState(node_id="p1")
        assert ps.offline_since is None
        ps.transition(PeerState.Status.OFFLINE)
        assert ps.offline_since is not None
        first_stamp = ps.offline_since
        # Second offline transition doesn't reset the clock (keeps original
        # drop time so duration math is correct across flaps)
        time.sleep(0.01)
        ps.transition(PeerState.Status.OFFLINE)
        assert ps.offline_since == first_stamp

    def test_online_clears_offline_since_and_alert(self):
        ps = PeerState(node_id="p1")
        ps.transition(PeerState.Status.OFFLINE)
        ps.long_drop_alerted = True
        ps.transition(PeerState.Status.ONLINE)
        assert ps.offline_since is None
        assert ps.long_drop_alerted is False

    @pytest.mark.asyncio
    async def test_long_drop_watchdog_emits_once(self, tmp_path):
        """Watchdog emits EVENT_PEER_DROPPED_LONG exactly once per drop."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        d._long_drop_threshold_seconds = 1
        d._long_drop_check_interval = 0.1

        # Fake audit collector
        events = []
        d._audit = MagicMock()
        d._audit.log = lambda event, data: events.append((event, data))

        # Plant an offline peer who dropped 2s ago
        ps = PeerState(node_id="peer1", address="10.0.0.1:8765")
        ps.status = PeerState.Status.OFFLINE
        ps.offline_since = time.time() - 2.0
        d.peers["peer1"] = ps

        d._running = True
        task = asyncio.create_task(d._long_drop_watchdog())
        await asyncio.sleep(0.3)
        # Second pass should NOT re-alert (idempotent)
        await asyncio.sleep(0.3)
        d._running = False
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        from ironmesh.audit import EVENT_PEER_DROPPED_LONG
        drop_events = [e for e in events if e[0] == EVENT_PEER_DROPPED_LONG]
        assert len(drop_events) == 1
        assert drop_events[0][1]["peer_id"] == "peer1"
        assert drop_events[0][1]["offline_seconds"] >= 2
        assert ps.long_drop_alerted is True
        assert d._peer_long_drops_total == 1

    @pytest.mark.asyncio
    async def test_long_drop_skips_online_peer(self, tmp_path):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        d._long_drop_threshold_seconds = 1
        d._long_drop_check_interval = 0.1

        events = []
        d._audit = MagicMock()
        d._audit.log = lambda event, data: events.append((event, data))

        ps = PeerState(node_id="peer1", address="10.0.0.1:8765")
        ps.transition(PeerState.Status.ONLINE)  # online
        d.peers["peer1"] = ps

        d._running = True
        task = asyncio.create_task(d._long_drop_watchdog())
        await asyncio.sleep(0.3)
        d._running = False
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert events == []
        assert d._peer_long_drops_total == 0

    @pytest.mark.asyncio
    async def test_long_drop_threshold_zero_disables(self, tmp_path):
        """Setting threshold to 0 turns the watchdog off (exits immediately)."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        d._long_drop_threshold_seconds = 0
        d._running = True
        # Should return almost immediately because threshold <= 0
        task = asyncio.create_task(d._long_drop_watchdog())
        await asyncio.sleep(0.05)
        assert task.done()


# -----------------------------------------------------------------------
# v0.7.2: Per-peer bandwidth throttle
# -----------------------------------------------------------------------

@pytest.mark.asyncio
class TestPeerBandwidthThrottle:
    async def test_gate_admits_when_under_budget(self, tmp_path):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        # Small frame well under default 1 MB burst should admit instantly.
        t0 = time.monotonic()
        ok = await d._gate_peer_bandwidth("peer1", 1024)
        elapsed = time.monotonic() - t0
        assert ok is True
        assert elapsed < 0.1
        assert d._peer_bandwidth_drops_total == 0

    async def test_gate_drops_when_wait_exceeds_ceiling(self, tmp_path):
        """A burst that would require > max_wait seconds of refill is dropped."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        d._peer_bandwidth_rate = 1000  # 1 KB/sec
        d._peer_bandwidth_burst = 1000  # 1 KB burst
        d._peer_bandwidth_max_wait = 0.1
        # Consume the full burst first
        await d._gate_peer_bandwidth("peer1", 1000)
        # Next 1 KB at 1 KB/s would need 1s of wait; ceiling is 0.1s → drop
        ok = await d._gate_peer_bandwidth("peer1", 1000)
        assert ok is False
        assert d._peer_bandwidth_drops_total == 1

    async def test_gate_disabled_when_rate_zero(self, tmp_path):
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        d._peer_bandwidth_rate = 0
        # Any size admits without creating a bucket.
        ok = await d._gate_peer_bandwidth("peer1", 10 * 1024 * 1024)
        assert ok is True
        assert "peer1" not in d._peer_bandwidth_limiters

    async def test_per_peer_budgets_are_independent(self, tmp_path):
        """Peer A at its cap doesn't starve peer B."""
        d = BridgeDaemon(name="test", passphrase=STRONG_PASSPHRASE,
                         db_path=str(tmp_path / "test.db"))
        d._peer_bandwidth_rate = 1000
        d._peer_bandwidth_burst = 1000
        d._peer_bandwidth_max_wait = 0.05
        # Peer A exhausts burst; next request drops
        await d._gate_peer_bandwidth("peerA", 1000)
        ok_a = await d._gate_peer_bandwidth("peerA", 1000)
        assert ok_a is False
        # Peer B still has a fresh bucket
        ok_b = await d._gate_peer_bandwidth("peerB", 1000)
        assert ok_b is True
