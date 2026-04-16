"""Tests for ironmesh.protocol — Frame, replay guard, rate limiter, handshake, schemas."""

import json
import time
import pytest

from ironmesh.protocol import (
    ErrorCode,
    Frame,
    Handshake,
    MessageBus,
    MessagePriority,
    MessageType,
    PeerState,
    ReplayGuard,
    TokenBucket,
    validate_message_schema,
)


class TestFrame:
    def test_create_frame(self):
        f = Frame(msg_type=MessageType.MSG, payload=b"hello", source="alice", destination="bob")
        assert f.msg_type == MessageType.MSG
        assert f.payload == b"hello"
        assert f.source == "alice"
        assert f.destination == "bob"
        assert len(f.msg_id) in (32, 36)  # Audit M-01: hex or UUID format

    def test_to_dict_and_from_dict(self):
        f = Frame(msg_type=MessageType.MSG, payload=b"test", source="a", destination="b")
        d = f.to_dict()
        f2 = Frame.from_dict(d)
        assert f2.msg_type == f.msg_type
        assert f2.payload == f.payload
        assert f2.source == f.source
        assert f2.destination == f.destination

    def test_encrypt_and_deserialize(self, shared_secret):
        f = Frame(msg_type=MessageType.MSG, payload=b"secret data", source="alice")
        binary = f.encrypt_and_serialize(shared_secret)
        assert binary[:2] == Frame.MAGIC
        assert binary[2] == Frame.VERSION

        f2 = Frame.deserialize_and_decrypt(binary, shared_secret)
        assert f2.msg_type == f.msg_type
        assert f2.payload == f.payload
        assert f2.source == f.source

    def test_deserialize_wrong_key_fails(self, shared_secret):
        f = Frame(msg_type=MessageType.MSG, payload=b"secret")
        binary = f.encrypt_and_serialize(shared_secret)
        wrong_key = bytes(32)
        with pytest.raises(ValueError, match="Decryption failed"):
            Frame.deserialize_and_decrypt(binary, wrong_key)

    def test_deserialize_truncated_fails(self, shared_secret):
        f = Frame(msg_type=MessageType.MSG, payload=b"data")
        binary = f.encrypt_and_serialize(shared_secret)
        with pytest.raises(ValueError, match="Frame too short"):
            Frame.deserialize_and_decrypt(binary[:10], shared_secret)

    def test_deserialize_bad_magic_fails(self, shared_secret):
        f = Frame(msg_type=MessageType.MSG, payload=b"data")
        binary = f.encrypt_and_serialize(shared_secret)
        bad = b"\x00\x00" + binary[2:]
        with pytest.raises(ValueError, match="Invalid magic"):
            Frame.deserialize_and_decrypt(bad, shared_secret)

    def test_is_expired(self):
        f = Frame(msg_type=MessageType.MSG)
        assert not f.is_expired(max_age=300)
        f.timestamp = time.time() - 400
        assert f.is_expired(max_age=300)

    def test_priority_flags(self):
        f_high = Frame(msg_type=MessageType.MSG, priority=MessagePriority.HIGH)
        assert f_high.flags & Frame.FLAG_HIGH_PRIORITY

        f_crit = Frame(msg_type=MessageType.MSG, priority=MessagePriority.CRITICAL)
        assert f_crit.flags & Frame.FLAG_CRITICAL_PRIORITY

    def test_serialize_plaintext(self):
        f = Frame(msg_type=MessageType.HELLO, payload=b"hi", source="test")
        binary = f.serialize_plaintext()
        assert binary[:2] == Frame.MAGIC
        # Plaintext should not have encrypted flag
        flags = binary[3]
        assert not (flags & Frame.FLAG_ENCRYPTED)


class TestReplayGuard:
    def test_accept_new_sequence(self):
        guard = ReplayGuard()
        assert guard.check("peer1", 1, time.time()) is None
        assert guard.check("peer1", 2, time.time()) is None

    def test_reject_old_sequence(self):
        guard = ReplayGuard()
        assert guard.check("peer1", 5, time.time()) is None
        rejection = guard.check("peer1", 3, time.time())
        assert rejection is not None
        assert "Sequence" in rejection

    def test_reject_duplicate_sequence(self):
        guard = ReplayGuard()
        assert guard.check("peer1", 1, time.time()) is None
        rejection = guard.check("peer1", 1, time.time())
        assert rejection is not None

    def test_reject_old_timestamp(self):
        guard = ReplayGuard(max_age=30.0)
        old_ts = time.time() - 60
        rejection = guard.check("peer1", 1, old_ts)
        assert rejection is not None
        assert "too old" in rejection

    def test_reject_future_timestamp(self):
        guard = ReplayGuard()
        future_ts = time.time() + 60
        rejection = guard.check("peer1", 1, future_ts)
        assert rejection is not None
        assert "future" in rejection

    def test_sequence_zero_rejected(self):
        guard = ReplayGuard()
        # Sequence 0 is no longer accepted — all post-handshake messages need seq > 0
        result = guard.check("peer1", 0, time.time())
        assert result is not None
        assert "seq > 0" in result

    def test_reset_peer(self):
        guard = ReplayGuard()
        guard.check("peer1", 10, time.time())
        guard.reset_peer("peer1")
        # After reset, lower sequences should be accepted
        assert guard.check("peer1", 1, time.time()) is None

    def test_independent_peers(self):
        guard = ReplayGuard()
        assert guard.check("peer1", 1, time.time()) is None
        assert guard.check("peer2", 1, time.time()) is None


class TestTokenBucket:
    def test_allows_burst(self):
        bucket = TokenBucket(rate=10, burst=5)
        for _ in range(5):
            assert bucket.consume()

    def test_rejects_after_burst(self):
        bucket = TokenBucket(rate=10, burst=3)
        for _ in range(3):
            bucket.consume()
        assert not bucket.consume()

    def test_refills_over_time(self):
        """After sleeping, the bucket must refill. Sleep a margin above the
        worst Windows scheduler granularity (~15.6 ms) so this test is not
        flaky — at 1000 tokens/sec, 100 ms should refill ~100 tokens even
        in the slowest plausible wakeup scenario.
        """
        bucket = TokenBucket(rate=1000, burst=1)
        bucket.consume()
        assert not bucket.consume()
        import time as _time
        _time.sleep(0.1)  # 100 ms — robust to Windows 15.6 ms ticks
        assert bucket.consume()

    def test_wait_time_zero_when_available(self):
        """v0.7.2: wait_time returns 0 when tokens already available."""
        bucket = TokenBucket(rate=100, burst=10)
        assert bucket.wait_time(5) == 0.0

    def test_wait_time_proportional_to_deficit(self):
        """v0.7.2: wait_time returns deficit / rate when tokens short."""
        bucket = TokenBucket(rate=100, burst=10)
        bucket.consume(10)  # drain
        # Need 5 more tokens at 100/s = 0.05s
        wt = bucket.wait_time(5)
        assert 0.04 < wt < 0.06

    def test_wait_time_does_not_consume(self):
        """Calling wait_time must not advance bucket state."""
        bucket = TokenBucket(rate=100, burst=10)
        bucket.wait_time(5)
        bucket.wait_time(5)
        # All 10 should still be available
        assert bucket.consume(10) is True


class TestMessageBus:
    def test_subscribe_and_publish(self):
        bus = MessageBus()
        received = []
        bus.subscribe("test", lambda data: received.append(data))
        bus.publish("test", {"msg": "hello"})
        assert len(received) == 1
        assert received[0]["msg"] == "hello"

    def test_catch_all(self):
        bus = MessageBus()
        received = []
        bus.on_any(lambda t, d: received.append((t, d)))
        bus.publish("event1", "data1")
        bus.publish("event2", "data2")
        assert len(received) == 2

    def test_history(self):
        bus = MessageBus()
        for i in range(5):
            bus.publish("test", i)
        hist = bus.history(3)
        assert len(hist) == 3

    def test_unsubscribe(self):
        bus = MessageBus()
        received = []
        unsub = bus.subscribe("test", lambda d: received.append(d))
        bus.publish("test", 1)
        unsub()
        bus.publish("test", 2)
        assert len(received) == 1


class TestPeerState:
    def test_initial_state(self):
        ps = PeerState(node_id="test", address="1.2.3.4:8765")
        assert ps.status == PeerState.Status.OFFLINE
        assert ps.session_key is None
        assert ps.verified is False
        assert not ps.is_online

    def test_transition(self):
        ps = PeerState(node_id="test")
        ps.transition(PeerState.Status.ONLINE)
        assert ps.is_online
        assert ps.connected_at is not None

    def test_next_sequence(self):
        ps = PeerState(node_id="test")
        assert ps.next_sequence() == 1
        assert ps.next_sequence() == 2
        assert ps.next_sequence() == 3

    def test_to_dict(self):
        ps = PeerState(node_id="test", address="1.2.3.4:8765")
        d = ps.to_dict()
        assert d["node_id"] == "test"
        assert d["status"] == "offline"
        assert d["verified"] is False


class TestHandshake:
    def test_passphrase_proof(self):
        nonce = Handshake.generate_server_nonce()
        proof = Handshake.compute_passphrase_proof("secret", nonce)
        assert Handshake.verify_passphrase_proof(proof, "secret", nonce)

    def test_wrong_passphrase_rejected(self):
        nonce = Handshake.generate_server_nonce()
        proof = Handshake.compute_passphrase_proof("correct", nonce)
        assert not Handshake.verify_passphrase_proof(proof, "wrong", nonce)

    def test_server_nonce_is_random(self):
        n1 = Handshake.generate_server_nonce()
        n2 = Handshake.generate_server_nonce()
        assert n1 != n2
        assert len(n1) == 32

    def test_create_hello_frame(self):
        f = Handshake.create_hello_frame(
            ephemeral_public_b64="AAAA",
            identity_public_b64="BBBB",
            agent_name="test",
            source="node1",
        )
        assert f.msg_type == MessageType.HELLO
        payload = json.loads(f.payload)
        assert payload["ephemeral_public"] == "AAAA"
        assert payload["identity_public"] == "BBBB"
        assert payload["name"] == "test"


class TestSchemaValidation:
    def test_valid_hello(self):
        result = validate_message_schema(
            MessageType.HELLO,
            {"ephemeral_public": "abc", "name": "test"}
        )
        assert result is None

    def test_missing_required_field(self):
        result = validate_message_schema(
            MessageType.HELLO,
            {"name": "test"}  # missing ephemeral_public
        )
        assert result is not None
        assert "ephemeral_public" in result

    def test_unknown_type_accepted(self):
        result = validate_message_schema("CUSTOM", {"anything": True})
        assert result is None


class TestProtocolV4:
    """v0.4 wire format additions: VERSION=4, source signature, e2e payload."""

    def test_frame_version_4_serialization(self, shared_secret):
        f = Frame(msg_type=MessageType.MSG, payload=b"data", source="alice")
        binary = f.encrypt_and_serialize(shared_secret)
        assert binary[2] == 4  # version byte

    def test_inner_source_sig_field_roundtrip(self, shared_secret):
        from ironmesh.keys import generate_keypair
        src = generate_keypair("alice")
        f = Frame(
            msg_type=MessageType.MSG, payload=b"hello", source="alice"
        )
        binary = f.encrypt_and_serialize(
            shared_secret,
            source_signing_key=src.get_signing_key(),
        )

        # Verify source signature was added
        assert f.source_signature is not None
        assert len(f.source_signature) == 64  # Ed25519 signature size

        # Decrypt with source verification callback
        def lookup(node_id):
            assert node_id == "alice"
            return src.get_verify_key()

        f2 = Frame.deserialize_and_decrypt(
            binary, shared_secret, verify_source_key=lookup
        )
        assert f2.source_signature == f.source_signature
        assert f2.payload == b"hello"

    def test_e2e_payload_field_roundtrip(self, shared_secret):
        f = Frame(msg_type=MessageType.MSG, payload=b"opaque", source="a")
        f.e2e_payload = b"\x00" * 96
        binary = f.encrypt_and_serialize(shared_secret)
        f2 = Frame.deserialize_and_decrypt(binary, shared_secret)
        assert f2.e2e_payload == b"\x00" * 96

    def test_forged_inner_signature_rejected(self, shared_secret):
        """A forged source signature must fail verification on the receiver."""
        from ironmesh.keys import generate_keypair
        legit = generate_keypair("legit")
        attacker = generate_keypair("attacker")
        f = Frame(
            msg_type=MessageType.MSG, payload=b"important", source="legit"
        )
        # Attacker signs as themselves but claims source=legit
        f.source_signature = bytes(
            attacker.get_signing_key().sign(b"important").signature
        )
        binary = f.encrypt_and_serialize(shared_secret)

        def lookup(node_id):
            assert node_id == "legit"
            return legit.get_verify_key()  # Real legit's key — won't verify forged sig

        with pytest.raises(ValueError, match="Inner source signature"):
            Frame.deserialize_and_decrypt(
                binary, shared_secret, verify_source_key=lookup
            )

    def test_v3_frame_still_deserializes(self, shared_secret):
        """Backward compat: v3 frames must still decrypt under v0.4 deserializer."""
        f = Frame(msg_type=MessageType.MSG, payload=b"old", source="a")
        binary = bytearray(f.encrypt_and_serialize(shared_secret))
        binary[2] = 3  # forge version byte to simulate v0.3 sender
        # Should still parse (v3 is in the accepted set)
        f2 = Frame.deserialize_and_decrypt(bytes(binary), shared_secret)
        assert f2.payload == b"old"

    def test_protocol_version_negotiation_in_hello(self):
        from ironmesh.bridge import _peer_supports_mesh, _parse_protocol_version
        assert _parse_protocol_version("ironmesh/0.4") == (0, 4)
        assert _parse_protocol_version("ironmesh/0.3") == (0, 3)
        assert _peer_supports_mesh("ironmesh/0.4") is True
        assert _peer_supports_mesh("ironmesh/0.5") is True
        assert _peer_supports_mesh("ironmesh/0.3") is False
        assert _peer_supports_mesh("") is False


class TestPeerStateV4:
    def test_default_protocol_version(self):
        ps = PeerState(node_id="x")
        assert ps.protocol_version == "ironmesh/0.3"
        assert ps.supports_mesh is False
        assert ps.is_relay_capable is False
        assert ps.last_route_announce is None
        assert ps.capabilities == []
