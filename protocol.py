"""IronMesh Protocol — Message framing, routing, bus, handshake, peer state, and replay protection.

Wire format: binary header + encrypted payload via NaCl SecretBox.
Replay protection via per-peer monotonic sequence numbers + timestamp validation.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time

import nacl.utils

# Audit L-03: known-good protocol version strings. An implementation
# MAY warn on unknown versions but SHOULD still attempt negotiation via
# the MAJOR.MINOR comparison in bridge._parse_protocol_version.
VALID_PROTOCOL_VERSIONS = frozenset({
    "ironmesh/0.3",
    "ironmesh/0.4",
    "ironmesh/0.5",
    "ironmesh/0.5.1",
    "ironmesh/0.5.2",
    "ironmesh/0.6",
    "ironmesh/0.7",
})


def is_known_protocol_version(v: str) -> bool:
    """Return True if v is an explicitly recognized IronMesh version."""
    return v in VALID_PROTOCOL_VERSIONS
from collections import OrderedDict
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("ironmesh.protocol")


# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------

class MessageType(str, Enum):
    """All IronMesh application-level message types."""
    HELLO = "HELLO"
    GOODBYE = "GOODBYE"
    MSG = "MSG"
    ACK = "ACK"
    PING = "PING"
    PONG = "PONG"
    ERROR = "ERROR"

    # Auth
    PASSPHRASE_CHALLENGE = "PASSPHRASE_CHALLENGE"
    PASSPHRASE_VERIFIED = "PASSPHRASE_VERIFIED"
    PASSPHRASE_REJECTED = "PASSPHRASE_REJECTED"
    KEY_ROTATE = "KEY_ROTATE"
    REKEY_REQUEST = "REKEY_REQUEST"
    REKEY_RESPONSE = "REKEY_RESPONSE"
    REVOCATION = "REVOCATION"

    # Request/response
    REQ = "REQ"
    RESP = "RESP"

    # Health
    HEARTBEAT = "HEARTBEAT"
    HEALTH = "HEALTH"

    # Discovery
    DISCOVER = "DISCOVER"
    DISCOVER_RESP = "DISCOVER_RESP"

    # System
    SYS = "SYS"

    # Rate limiting
    RATE_LIMITED = "RATE_LIMITED"

    # Peer info (sent after authenticated handshake)
    PEER_INFO = "PEER_INFO"

    # v0.4: Mesh routing
    ROUTE_ANNOUNCE = "ROUTE_ANNOUNCE"
    ROUTE_UNREACHABLE = "ROUTE_UNREACHABLE"

    # v0.4: Capability discovery
    CAPABILITY_ANNOUNCE = "CAPABILITY_ANNOUNCE"
    CAPABILITY_QUERY = "CAPABILITY_QUERY"


class MessagePriority(str, Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ErrorCode(str, Enum):
    """Standard error codes for ERROR messages."""
    UNKNOWN = "UNKNOWN"
    AUTH_FAILED = "AUTH_FAILED"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    INVALID_FRAME = "INVALID_FRAME"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    RATE_LIMITED = "RATE_LIMITED"
    DECRYPTION_FAILED = "DECRYPTION_FAILED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    PEER_NOT_FOUND = "PEER_NOT_FOUND"
    INTERNAL = "INTERNAL"


# ---------------------------------------------------------------------------
# Message schemas (for validation)
# ---------------------------------------------------------------------------

MESSAGE_SCHEMAS = {
    MessageType.HELLO: {
        "required": ["ephemeral_public", "name"],
        "optional": ["identity_public", "protocol_version"],
    },
    MessageType.GOODBYE: {
        "required": [],
        "optional": ["reason"],
    },
    MessageType.MSG: {
        "required": [],
        "optional": ["content_type"],
    },
    MessageType.ACK: {
        "required": ["ack_msg_id"],
        "optional": [],
    },
    MessageType.PASSPHRASE_CHALLENGE: {
        "required": ["proof"],
        "optional": [],
    },
    MessageType.PASSPHRASE_VERIFIED: {
        "required": ["status"],
        "optional": [],
    },
    MessageType.PASSPHRASE_REJECTED: {
        "required": ["error"],
        "optional": ["code"],
    },
    MessageType.KEY_ROTATE: {
        "required": ["new_public_key"],
        "optional": ["rotated_at"],
    },
    MessageType.ERROR: {
        "required": ["error", "code"],
        "optional": ["details"],
    },
    MessageType.PEER_INFO: {
        "required": ["protocol_version"],
        "optional": ["agent_version", "capabilities"],
    },
    MessageType.ROUTE_ANNOUNCE: {
        "required": ["origin", "routes", "sequence_number"],
        "optional": [],
    },
    MessageType.ROUTE_UNREACHABLE: {
        "required": ["destination", "original_msg_id"],
        "optional": ["reason"],
    },
    MessageType.CAPABILITY_ANNOUNCE: {
        "required": ["origin", "capabilities"],
        "optional": ["sequence_number"],
    },
    MessageType.CAPABILITY_QUERY: {
        "required": ["pattern"],
        "optional": [],
    },
}


def validate_message_schema(msg_type: str, payload_dict: dict) -> Optional[str]:
    """Validate a message payload against its schema.

    Returns None if valid, or an error string describing the violation.
    """
    schema = MESSAGE_SCHEMAS.get(msg_type)
    if schema is None:
        return None  # No schema defined, accept anything

    for field in schema["required"]:
        if field not in payload_dict:
            return f"Missing required field '{field}' for {msg_type}"

    return None


# ---------------------------------------------------------------------------
# Frame — wire format
# ---------------------------------------------------------------------------

class Frame:
    """
    Wire format for IronMesh:
    [magic:2][version:1][flags:1][seq:8][timestamp:8][msg_id:8][payload_len:4][payload:var]

    Flags:
      bit 0: HIGH priority
      bit 1: CRITICAL priority
      bit 2: encrypted (payload is SecretBox ciphertext)
      bit 3: signed (payload is Ed25519 signature + message)
    """
    MAGIC: bytes = b"\xe7\xf6"
    VERSION: int = 4  # v0.4: mesh routing + inner source sig + e2e payload

    FLAG_HIGH_PRIORITY = 0x01
    FLAG_CRITICAL_PRIORITY = 0x02
    FLAG_ENCRYPTED = 0x04
    FLAG_SIGNED = 0x08

    HEADER_SIZE = 2 + 1 + 1 + 8 + 8 + 8 + 4  # 32 bytes

    def __init__(
        self,
        msg_type: str,
        payload: bytes = b"",
        msg_id: Optional[str] = None,
        source: str = "system",
        destination: str = "*",
        priority: str = MessagePriority.NORMAL,
        sequence: int = 0,
    ):
        self.msg_type = msg_type
        self.payload = payload
        # Audit M-01: use a cryptographically strong RNG rather than
        # uuid4 (which is also CSPRNG but msg_id is security-adjacent —
        # explicit intent is clearer).
        self.msg_id = msg_id or nacl.utils.random(16).hex()
        self.source = source
        self.source_display = source
        self.destination = destination
        self.timestamp = time.time()
        self.priority = priority
        self.sequence = sequence
        self.flags = 0x00
        self.retries = 0

        if priority == MessagePriority.HIGH:
            self.flags |= self.FLAG_HIGH_PRIORITY
        elif priority == MessagePriority.CRITICAL:
            self.flags |= self.FLAG_CRITICAL_PRIORITY

        self.routing: dict = {}
        self.ttl: int = 3
        self.hops: list = []

        # v0.4: end-to-end fields
        # source_signature: Ed25519 signature over the *plaintext* payload bytes
        # by the original source. Survives per-hop re-encryption by relays.
        self.source_signature: Optional[bytes] = None
        # e2e_payload: NaCl SealedBox ciphertext readable only by the destination.
        # When present, plaintext `payload` is opaque to relays; the dest unseals
        # this field to recover the true plaintext.
        self.e2e_payload: Optional[bytes] = None

    def is_expired(self, max_age: float = 300.0) -> bool:
        return (time.time() - self.timestamp) > max_age

    def to_dict(self) -> dict:
        """Serialize frame metadata + payload to a dict for JSON encoding."""
        d = {
            "type": self.msg_type,
            "payload": base64.b64encode(self.payload).decode() if self.payload else "",
            "msg_id": self.msg_id,
            "source": self.source,
            "source_display": self.source_display,
            "destination": self.destination,
            "timestamp": self.timestamp,
            "priority": self.priority,
            "sequence": self.sequence,
            "retries": self.retries,
            "routing": self.routing,
            "ttl": self.ttl,
            "hops": self.hops,
        }
        if self.source_signature is not None:
            d["source_signature"] = base64.b64encode(self.source_signature).decode()
        if self.e2e_payload is not None:
            d["e2e_payload"] = base64.b64encode(self.e2e_payload).decode()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Frame":
        """Deserialize a frame from a dict."""
        obj = cls(
            msg_type=data["type"],
            payload=base64.b64decode(data["payload"]) if data.get("payload") else b"",
            msg_id=data.get("msg_id"),
            source=data.get("source", "unknown"),
            destination=data.get("destination", "*"),
            priority=data.get("priority", MessagePriority.NORMAL),
            sequence=data.get("sequence", 0),
        )
        obj.source_display = data.get("source_display", obj.source)
        obj.timestamp = float(data.get("timestamp", time.time()))
        obj.routing = data.get("routing", {})
        # Audit L-01: validate TTL and hops strictly.
        ttl = data.get("ttl", 3)
        if not isinstance(ttl, int) or ttl < 0 or ttl > 255:
            raise ValueError(f"Invalid TTL: {ttl!r}")
        obj.ttl = ttl
        hops = data.get("hops", [])
        if not isinstance(hops, list) or not all(isinstance(h, str) for h in hops):
            raise ValueError(f"Invalid hops: {hops!r}")
        obj.hops = hops
        obj.retries = data.get("retries", 0)
        if data.get("source_signature"):
            obj.source_signature = base64.b64decode(data["source_signature"])
        if data.get("e2e_payload"):
            obj.e2e_payload = base64.b64decode(data["e2e_payload"])
        return obj

    @classmethod
    def from_json_message(cls, msg_dict: dict, payload_bytes: bytes) -> "Frame":
        """Synthesize a Frame from the legacy JSON-message dispatch path.

        The JSON path decrypts the payload separately, so the resulting Frame
        has metadata extracted from the JSON envelope plus the supplied
        already-decrypted payload bytes.
        """
        obj = cls(
            msg_type=msg_dict.get("type", ""),
            payload=payload_bytes,
            msg_id=msg_dict.get("msg_id"),
            source=msg_dict.get("from", msg_dict.get("source", "unknown")),
            destination=msg_dict.get("to", msg_dict.get("destination", "*")),
            priority=msg_dict.get("priority", MessagePriority.NORMAL),
            sequence=msg_dict.get("sequence", 0),
        )
        obj.timestamp = float(msg_dict.get("timestamp", time.time()))
        obj.ttl = msg_dict.get("ttl", 3)
        obj.hops = msg_dict.get("hops", [])
        if msg_dict.get("source_signature"):
            obj.source_signature = base64.b64decode(msg_dict["source_signature"])
        if msg_dict.get("e2e_payload"):
            obj.e2e_payload = base64.b64decode(msg_dict["e2e_payload"])
        return obj

    SIGNATURE_SIZE = 64  # Ed25519 detached signature

    def encrypt_and_serialize(self, shared_key: bytes,
                              signing_key=None,
                              source_signing_key=None) -> bytes:
        """Encrypt payload with SecretBox and serialize to binary wire format.

        Args:
            shared_key: 32-byte session key for SecretBox encryption.
            signing_key: Optional nacl.signing.SigningKey to produce a
                         detached Ed25519 signature over the encrypted data.
                         When provided, FLAG_SIGNED is set and 64-byte sig
                         is appended after the encrypted payload.
                         (This is the *outer* hop-authentication signature.)
            source_signing_key: Optional nacl.signing.SigningKey for the
                         original source. When provided, an *inner* Ed25519
                         signature is computed over the plaintext payload bytes
                         and stored in the encrypted dict as `source_signature`.
                         This survives per-hop re-encryption by relays.
        """
        from ironmesh.crypto import encrypt_message

        # v0.4: compute inner source signature over plaintext payload
        if source_signing_key is not None and self.source_signature is None:
            try:
                self.source_signature = bytes(
                    source_signing_key.sign(self.payload).signature
                )
            except Exception:
                # If signing fails, leave source_signature as None
                pass

        payload_json = json.dumps(self.to_dict(), separators=(",", ":")).encode()
        encrypted = encrypt_message(shared_key, payload_json)

        self.flags |= self.FLAG_ENCRYPTED
        if signing_key is not None:
            self.flags |= self.FLAG_SIGNED

        header = self.MAGIC + self.VERSION.to_bytes(1, "big")
        header += self.flags.to_bytes(1, "big")
        header += self.sequence.to_bytes(8, "big")
        header += int(self.timestamp * 1000).to_bytes(8, "big")  # ms precision
        header += hashlib.sha256(self.msg_id.encode()).digest()[:8]
        header += len(encrypted).to_bytes(4, "big")

        wire = header + encrypted
        if signing_key is not None:
            from ironmesh.crypto import sign_detached
            sig = sign_detached(signing_key, encrypted)
            wire += sig
        return wire

    @classmethod
    def deserialize_and_decrypt(cls, data: bytes, shared_key: bytes,
                                verify_key=None,
                                verify_source_key: Optional[Callable] = None) -> "Frame":
        """Deserialize binary wire format and decrypt with SecretBox.

        Args:
            data: Raw binary frame bytes.
            shared_key: 32-byte session key for SecretBox decryption.
            verify_key: Optional nacl.signing.VerifyKey to verify the
                        outer detached Ed25519 signature. Required if
                        FLAG_SIGNED is set.
            verify_source_key: Optional callback ``(node_id) -> VerifyKey``
                        used to look up the original source's identity key
                        for inner source-signature verification. When
                        provided AND the decrypted frame contains
                        ``source_signature``, the inner signature is
                        verified against the source's plaintext payload.
        """
        from ironmesh.crypto import decrypt_message

        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Frame too short: {len(data)} bytes (need {cls.HEADER_SIZE})")

        magic = data[:2]
        if magic != cls.MAGIC:
            raise ValueError(f"Invalid magic: {magic.hex()}")

        version = data[2]
        # v0.4 accepts v3 frames for backward compatibility with v0.3 peers
        # (v0.3 peers don't send mesh fields, but their direct messages must
        # still deserialize). New mesh-only fields are absent on v3 frames,
        # which is fine — they default to None.
        if version not in (3, 4):
            raise ValueError(
                f"Unsupported version: {version} (expected 3 or 4)"
            )

        flags = data[3]
        sequence = int.from_bytes(data[4:12], "big")
        # timestamp_ms and msg_id_hash are decoded inside encrypted payload;
        # here we just skip those header bytes. Underscore-prefixed so ruff
        # knows the read is intentional.
        _timestamp_ms = int.from_bytes(data[12:20], "big")
        _msg_id_hash = data[20:28]
        encrypted_length = int.from_bytes(data[28:32], "big")
        encrypted_data = data[32:32 + encrypted_length]

        if len(encrypted_data) < encrypted_length:
            raise ValueError(f"Truncated frame: expected {encrypted_length} bytes, got {len(encrypted_data)}")

        if not (flags & cls.FLAG_ENCRYPTED):
            raise ValueError("Received unencrypted binary frame — encryption is mandatory")

        # Verify signature if FLAG_SIGNED is set
        if flags & cls.FLAG_SIGNED:
            sig_offset = 32 + encrypted_length
            if len(data) < sig_offset + cls.SIGNATURE_SIZE:
                raise ValueError("Frame has FLAG_SIGNED but signature is missing/truncated")
            signature = data[sig_offset:sig_offset + cls.SIGNATURE_SIZE]
            if verify_key is None:
                raise ValueError("Frame is signed but no verify_key provided")
            from ironmesh.crypto import verify_detached
            try:
                verify_detached(verify_key, encrypted_data, signature)
            except Exception as e:
                raise ValueError(f"Signature verification failed: {e}")

        try:
            payload_json = decrypt_message(shared_key, encrypted_data)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

        payload_data = json.loads(payload_json)
        obj = cls.from_dict(payload_data)
        obj.sequence = sequence

        # v0.4: verify inner source signature (survives per-hop re-encryption)
        if obj.source_signature is not None and verify_source_key is not None:
            try:
                src_vk = verify_source_key(obj.source)
            except Exception as e:  # audit M-05
                logger.debug("verify_source_key lookup failed for %s: %s",
                             obj.source, e)
                src_vk = None
            if src_vk is not None:
                try:
                    src_vk.verify(obj.payload, obj.source_signature)
                except Exception as e:
                    raise ValueError(f"Inner source signature verification failed: {e}")

        return obj

    def serialize_plaintext(self) -> bytes:
        """Serialize to binary wire format WITHOUT encryption.

        Audit L-13: ONLY for use during the initial handshake, before
        the session key is established. All post-handshake frames MUST
        go through :meth:`encrypt_and_serialize` — the message loop
        enforces ``FLAG_ENCRYPTED`` on inbound frames.
        """
        payload_json = json.dumps(self.to_dict(), separators=(",", ":")).encode()

        header = self.MAGIC + self.VERSION.to_bytes(1, "big")
        header += self.flags.to_bytes(1, "big")
        header += self.sequence.to_bytes(8, "big")
        header += int(self.timestamp * 1000).to_bytes(8, "big")
        header += hashlib.sha256(self.msg_id.encode()).digest()[:8]
        header += len(payload_json).to_bytes(4, "big")
        return header + payload_json


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------

class ReplayGuard:
    """Per-peer replay protection using monotonic sequence numbers and timestamps.

    Thread safety: This class is designed for use within a single asyncio event loop.
    Cooperative scheduling in asyncio ensures that check() and reset_peer() calls
    are not interleaved, preventing data races without explicit locking.
    Do NOT call from multiple OS threads without external synchronization.

    Rejects:
    - Any frame with seq <= last_seen_seq for that peer
    - Any frame with timestamp more than max_age seconds old
    - Duplicate sequence numbers within sliding window
    """

    def __init__(self, max_age: float = 30.0, window_size: int = 1024):
        self.max_age = max_age
        self.window_size = window_size
        self._peers: Dict[str, dict] = {}

    def _ensure_peer(self, peer_id: str):
        if peer_id not in self._peers:
            self._peers[peer_id] = {
                "last_seq": 0,
                "window": OrderedDict(),
            }

    def check(self, peer_id: str, sequence: int, timestamp: float) -> Optional[str]:
        """Check if a frame should be accepted.

        Returns None if OK, or a rejection reason string.
        """
        self._ensure_peer(peer_id)
        state = self._peers[peer_id]

        # Timestamp check
        age = time.time() - timestamp
        if age > self.max_age:
            return f"Frame too old: {age:.1f}s (max {self.max_age}s)"
        if age < -5.0:  # Allow small clock skew
            return f"Frame from future: {-age:.1f}s ahead"

        # Sequence check — all post-handshake messages MUST have sequence > 0.
        # seq=0 is only valid during handshake (before replay guard is active).
        if sequence <= 0:
            return f"Invalid sequence {sequence} — post-handshake messages require seq > 0"

        # Strict monotonic floor (audit C-04): rejects any sequence
        # below the high-water mark, preventing replay of old seqs that
        # have fallen out of the sliding window.
        if sequence <= state["last_seq"]:
            return f"Sequence {sequence} <= last seen {state['last_seq']}"
        if sequence in state["window"]:
            return f"Duplicate sequence {sequence}"

        state["last_seq"] = sequence
        state["window"][sequence] = timestamp

        # Trim window
        while len(state["window"]) > self.window_size:
            state["window"].popitem(last=False)

        return None

    def reset_peer(self, peer_id: str):
        """Reset replay state for a peer (e.g., on reconnect with new session)."""
        self._peers.pop(peer_id, None)


# ---------------------------------------------------------------------------
# MessageBus
# ---------------------------------------------------------------------------

class MessageBus:
    """In-process pub/sub message bus."""

    def __init__(self):
        self._listeners: Dict[str, list] = {}
        self._catch_all: list = []
        self._queue: list = []
        self._max_history: int = 100

    def subscribe(self, event_type: str, callback: Callable) -> Callable:
        if event_type not in self._listeners:
            self._listeners[event_type] = []
        self._listeners[event_type].append(callback)
        return lambda: self._listeners[event_type].remove(callback)

    def publish(self, event_type: str, data: Any):
        # Freeze dict data to prevent listeners from mutating shared state
        frozen = MappingProxyType(data) if isinstance(data, dict) else data
        for cb in self._listeners.get(event_type, []):
            try:
                cb(frozen)
            except Exception as e:
                logger.error("Bus listener error: %s", e)
        for cb in self._catch_all:
            try:
                cb(event_type, frozen)
            except Exception as e:
                logger.error("Catch-all listener error: %s", e)
        self._queue.append({"type": event_type, "data": data, "timestamp": time.time()})
        if len(self._queue) > self._max_history:
            self._queue = self._queue[-self._max_history:]

    def on_any(self, callback: Callable):
        self._catch_all.append(callback)

    def history(self, limit: int = 10) -> list:
        return self._queue[-limit:]


# ---------------------------------------------------------------------------
# PeerState
# ---------------------------------------------------------------------------

class PeerState:
    """Tracks state of a single connected peer."""

    class Status(str, Enum):
        OFFLINE = "offline"
        CONNECTING = "connecting"
        HANDSHAKING = "handshaking"
        AUTHENTICATING = "authenticating"
        ONLINE = "online"
        DEGRADED = "degraded"

    def __init__(self, node_id: str, address: str = ""):
        self.node_id = node_id
        self.address = address
        self.status = self.Status.OFFLINE
        self.connected_at: Optional[float] = None
        self.last_seen: Optional[float] = None
        self.messages_sent: int = 0
        self.messages_received: int = 0
        self.last_error: Optional[str] = None
        self.latency_ms: Optional[float] = None
        self.pending_messages: list = []

        # Crypto state
        self.identity_public: Optional[bytes] = None  # Ed25519 verify key bytes
        self.session_key: Optional[bytes] = None  # Derived ECDH shared secret
        self.ephemeral_public: Optional[bytes] = None  # Peer's X25519 public key
        self.verified: bool = False  # True after successful handshake

        # Replay protection
        self.next_send_seq: int = 1
        self.last_recv_seq: int = 0

        # v0.4: mesh capabilities and version negotiation
        self.protocol_version: str = "ironmesh/0.3"
        self.supports_mesh: bool = False
        self.is_relay_capable: bool = False
        self.last_route_announce: Optional[float] = None
        self.capabilities: list = []

        # v0.5: transport resilience
        self.transport_type: str = "websocket"  # "websocket" or "rns"
        self.rns_dest_hash: Optional[str] = None  # RNS destination hash if known
        self.ws_address: Optional[str] = None  # WebSocket host:port for reconnection

        # v0.5.2: session key rotation
        self.session_rekey_count: int = 0
        self.last_rekey_at: Optional[float] = None
        self._pending_rekey_private = None  # ephemeral X25519 private key
        self._pending_rekey_id: Optional[str] = None

        # v0.7.2: per-peer retry + goodput accounting
        self.retries_total: int = 0          # total retry attempts
        self.retries_by_reason: dict = {}    # reason -> count
        self.bytes_sent_total: int = 0       # application bytes sent to this peer
        self.bytes_received_total: int = 0   # application bytes received from peer
        # v0.7.2: peer-drop alerting
        self.offline_since: Optional[float] = None  # wall-clock when status went OFFLINE
        self.long_drop_alerted: bool = False         # set after we emit PEER_DROPPED_LONG

    def record_retry(self, reason: str = "unknown") -> None:
        """v0.7.2: increment retry counters for observability."""
        self.retries_total += 1
        self.retries_by_reason[reason] = self.retries_by_reason.get(reason, 0) + 1

    def mark_authenticating(self):
        self.status = self.Status.AUTHENTICATING
        self.last_seen = time.time()

    def mark_handshaking(self):
        self.status = self.Status.HANDSHAKING
        self.last_seen = time.time()

    def transition(self, new_status: "PeerState.Status"):
        was = self.status
        self.status = new_status
        self.last_seen = time.time()
        if new_status == self.Status.ONLINE:
            self.connected_at = time.time()
            # v0.7.2: clear long-drop state when peer comes back
            self.offline_since = None
            self.long_drop_alerted = False
        elif new_status == self.Status.OFFLINE:
            # v0.7.2: stamp when the peer went offline (don't overwrite if
            # already offline — keep the original drop time for duration math)
            if self.offline_since is None:
                self.offline_since = time.time()
        logger.info("Peer %s: %s -> %s", self.node_id, was.value, new_status.value)

    def next_sequence(self) -> int:
        """Get next monotonic sequence number for sending.

        Audit L-02: detect imminent 63-bit overflow. In practice a
        session would have to exchange 9 quintillion messages — but
        guard against the pathological case anyway.
        """
        seq = self.next_send_seq
        if seq > (2 ** 63 - 1):
            raise RuntimeError(
                "Sequence number overflow — rekey this session immediately"
            )
        self.next_send_seq += 1
        return seq

    @property
    def uptime(self) -> Optional[float]:
        return time.time() - self.connected_at if self.connected_at else None

    @property
    def is_online(self) -> bool:
        return self.status == self.Status.ONLINE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "address": self.address,
            "status": self.status.value,
            "uptime": self.uptime,
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "verified": self.verified,
            "pending_queue_size": len(self.pending_messages),
            "latency_ms": self.latency_ms,
            "last_seen": self.last_seen,
            "fingerprint": hashlib.sha256(self.identity_public).hexdigest()[:32] if self.identity_public else None,
            "transport_type": self.transport_type,
            "rns_dest_hash": self.rns_dest_hash,
            "ws_address": self.ws_address,
            # v0.7.2: per-peer observability surfaced to GUI
            "bytes_sent_total": self.bytes_sent_total,
            "bytes_received_total": self.bytes_received_total,
            "retries_total": self.retries_total,
            "retries_by_reason": dict(self.retries_by_reason),
            "session_rekey_count": self.session_rekey_count,
            "offline_since": self.offline_since,
        }


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------

class Handshake:
    """Two-stage handshake: passphrase auth -> ephemeral ECDH key exchange.

    Flow:
    1. Server sends PASSPHRASE_CHALLENGE with nonce
    2. Client computes SHA-256(passphrase + nonce) and sends proof
    3. Server verifies -> PASSPHRASE_VERIFIED or PASSPHRASE_REJECTED
    4. Both exchange HELLO with ephemeral X25519 public keys + identity Ed25519 public keys
    5. Both derive shared secret via ECDH on ephemeral keys
    6. Session established with forward secrecy
    """

    SERVER_NONCE_LENGTH = 32  # Increased from 16 to 32 bytes

    @staticmethod
    def compute_passphrase_proof(passphrase: str, nonce: bytes) -> str:
        """Compute HMAC-SHA256(passphrase, nonce) as hex string.

        Uses HMAC instead of bare SHA-256 to prevent length-extension attacks
        and provide proper key-based authentication.
        """
        return hmac.new(
            passphrase.encode("utf-8"), nonce, hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify_passphrase_proof(proof: str, passphrase: str, nonce: bytes) -> bool:
        expected = Handshake.compute_passphrase_proof(passphrase, nonce)
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(proof, expected)

    @staticmethod
    def generate_server_nonce() -> bytes:
        return os.urandom(Handshake.SERVER_NONCE_LENGTH)

    @staticmethod
    def create_challenge_frame(passphrase: str, server_nonce: bytes, source: str = "client") -> Frame:
        proof = Handshake.compute_passphrase_proof(passphrase, server_nonce)
        return Frame(
            msg_type=MessageType.PASSPHRASE_CHALLENGE,
            payload=json.dumps({"proof": proof}).encode(),
            source=source,
        )

    @staticmethod
    def create_verified_frame(source: str = "server") -> Frame:
        return Frame(
            msg_type=MessageType.PASSPHRASE_VERIFIED,
            payload=json.dumps({"status": "verified"}).encode(),
            source=source,
        )

    @staticmethod
    def create_rejected_frame(source: str = "server") -> Frame:
        return Frame(
            msg_type=MessageType.PASSPHRASE_REJECTED,
            payload=json.dumps({"error": "passphrase rejected", "code": ErrorCode.AUTH_FAILED}).encode(),
            source=source,
        )

    @staticmethod
    def create_hello_frame(
        ephemeral_public_b64: str,
        identity_public_b64: str,
        agent_name: str,
        source: str,
        protocol_version: str = "ironmesh/0.3",
    ) -> Frame:
        """Create HELLO frame with ephemeral ECDH key + identity key."""
        return Frame(
            msg_type=MessageType.HELLO,
            payload=json.dumps({
                "ephemeral_public": ephemeral_public_b64,
                "identity_public": identity_public_b64,
                "name": agent_name,
                "protocol_version": protocol_version,
            }).encode(),
            source=source,
        )

    @staticmethod
    def create_key_rotate_frame(new_pubkey_b64: str, source: str) -> Frame:
        return Frame(
            msg_type=MessageType.KEY_ROTATE,
            payload=json.dumps({
                "new_public_key": new_pubkey_b64,
                "rotated_at": time.time(),
                "action": "re-handshake required",
            }).encode(),
            source=source,
        )


# ---------------------------------------------------------------------------
# Rate limiter (token bucket)
# ---------------------------------------------------------------------------

class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, rate: float = 20.0, burst: int = 100):
        """
        Args:
            rate: Sustained tokens per second.
            burst: Maximum burst size.
        """
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if allowed, False if rate limited."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_refill = now

        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    def wait_time(self, tokens: int = 1) -> float:
        """Seconds until ``tokens`` can be consumed, without modifying state.

        Returns 0.0 if the request would succeed immediately. Does not
        update the last_refill timestamp — call ``consume()`` when ready.
        """
        now = time.monotonic()
        elapsed = now - self._last_refill
        available = min(self.burst, self._tokens + elapsed * self.rate)
        if available >= tokens:
            return 0.0
        deficit = tokens - available
        if self.rate <= 0:
            return float("inf")
        return deficit / self.rate
