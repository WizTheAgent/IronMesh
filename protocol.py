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
from collections import OrderedDict
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Dict, Optional

import nacl.exceptions as nacl_exceptions
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
    "ironmesh/0.8",
    "ironmesh/0.9",
})


def is_known_protocol_version(v: str) -> bool:
    """Return True if v is an explicitly recognized IronMesh version."""
    return v in VALID_PROTOCOL_VERSIONS


# Ceiling on the attacker-declared encrypted_length in Frame.deserialize.
# The wire field is u32 (4 GiB max); legitimate IronMesh frames are KB-scale
# (largest known surface = capability/route gossip, a few KB). Anything beyond
# this ceiling is rejected before the buffer slice, defeating
# memory-exhaustion via an absurd declared length. Tuned generously enough
# to cover RNS.Resource chunk envelopes without re-fragmentation.
MAX_FRAME_BYTES = 1 * 1024 * 1024  # 1 MiB

# Maximum nesting depth on JSON parsed from the wire. The 1 MiB MAX_FRAME_BYTES
# ceiling already bounds the wallclock cost of `json.loads`, but a deeply-
# nested object (`[[[[...[[1]...]]]]`) inside that budget can still drive
# downstream consumers (validators, routers, persistence layers) into
# pathological recursion. 64 is well above any legitimate IronMesh shape —
# the deepest known payload nests 6 levels (route announce → routes → entry
# → metadata → cap-set → cap-tag). Sender-side JSON shapes are bounded by
# our own canonicalization; this guard is for malicious / malformed inputs.
MAX_JSON_DEPTH = 64


def _validate_json_depth(obj, max_depth: int = MAX_JSON_DEPTH, _depth: int = 0) -> None:
    """Recursively verify that ``obj`` does not nest deeper than ``max_depth``.

    Raises ``ValueError`` if the depth is exceeded. The recursion this helper
    itself uses is bounded by ``max_depth`` — Python's default recursion
    limit of 1000 is comfortably above the configured 64.
    """
    if _depth > max_depth:
        raise ValueError(
            f"JSON nesting exceeds max depth {max_depth}"
        )
    if isinstance(obj, dict):
        for value in obj.values():
            _validate_json_depth(value, max_depth, _depth + 1)
    elif isinstance(obj, list):
        for value in obj:
            _validate_json_depth(value, max_depth, _depth + 1)


def safe_json_loads(raw, max_depth: int = MAX_JSON_DEPTH):
    """Wire-safe ``json.loads`` for attacker-controlled bytes.

    Wraps the standard library decoder with the configured depth guard.
    Use this on any JSON parsed from a frame body or a peer-sent message;
    file-local config / on-disk artifacts are exempt.
    """
    obj = json.loads(raw)
    _validate_json_depth(obj, max_depth)
    return obj


# ---------------------------------------------------------------------------
# CAPABILITY_ANNOUNCE — signed-envelope canonicalization
# ---------------------------------------------------------------------------
#
# Wire shape (signed, v1):
#   {
#     "origin":         "<node-id>",
#     "capabilities":   ["chat", "embed", ...],
#     "announced_at":   1736812800.0,
#     "version":        1,
#     "signature":      "<b64 Ed25519 over canonical_capability_announce_bytes>"
#   }
#
# The canonical bytes are the JSON serialization of
# ``{origin, capabilities, announced_at, version}`` with
# ``sort_keys=True, separators=(",", ":")`` — same convention used elsewhere
# in the protocol so cross-language clients (Go, TS) reproduce the byte
# sequence exactly. Signature uses the Ed25519 domain-separation context
# ``crypto.SIG_CTX_CAPABILITY_ANNOUNCE``.
#
# Wire compat: pre-signing senders emit ``{"origin", "capabilities"}`` only.
# Receivers MUST accept those bodies UNLESS ``origin != peer_id`` (i.e.
# a relayed announce about a third party). Direct-from-peer announces
# stay backwards compatible because the outer hop signature already
# authenticates them. Cross-host announces require the inner sig.

CAPABILITY_ANNOUNCE_SIGNED_VERSION: int = 1
CAPABILITY_ANNOUNCE_MAX_AGE_DEFAULT: float = 300.0


def canonical_capability_announce_bytes(
    origin: str,
    capabilities: list,
    announced_at: float,
    version: int = CAPABILITY_ANNOUNCE_SIGNED_VERSION,
) -> bytes:
    """Build the canonical byte sequence that the inner Ed25519 signature
    binds to. Both senders and verifiers MUST use this exact function so
    the produced bytes match byte-for-byte across languages.
    """
    if not isinstance(origin, str) or not origin:
        raise ValueError("origin must be non-empty string")
    if not isinstance(capabilities, list):
        raise ValueError("capabilities must be list")
    if not all(isinstance(c, str) and c for c in capabilities):
        raise ValueError("capabilities entries must be non-empty strings")
    if not isinstance(announced_at, (int, float)):
        raise ValueError("announced_at must be a numeric timestamp")
    if not isinstance(version, int) or version < 1:
        raise ValueError("version must be a positive int")
    body = {
        "origin": origin,
        "capabilities": list(capabilities),
        "announced_at": float(announced_at),
        "version": version,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Inner end-to-end source signature (v2 bound scheme) — canonicalization
# ---------------------------------------------------------------------------
#
# The v2 inner source signature binds the originator identity, the delivery
# target, the message id, and the body. A relay can re-encrypt per hop (it
# holds the per-hop session key), so it *could* alter destination / msg_id /
# source on a frame it forwards — but it cannot forge this signature without
# the originator's Ed25519 secret. The destination recomputes the canonical
# bytes from the received fields and rejects any frame whose signature does
# not match, defeating relay redirection (destination), replay-relabel
# (msg_id), and re-attribution (source). ttl/hops are deliberately NOT bound
# — they legitimately change per hop, and binding them would break relaying.
#
# Encoding is length-prefixed (u32 big-endian per field) so concatenation is
# unambiguous and trivially reproducible by the Go / TypeScript clients.

def _lp(b: bytes) -> bytes:
    """Length-prefix (u32 big-endian) a byte field for canonical concatenation."""
    return len(b).to_bytes(4, "big") + b


def canonical_inner_source_bytes(source: str, destination: str,
                                 msg_id: str, payload: bytes) -> bytes:
    """Canonical bytes the v2 inner source signature binds to.

    Both signer (originator) and verifier (destination) MUST build these
    bytes identically. The Ed25519 domain-separation context
    ``crypto.SIG_CTX_FRAME_INNER_SOURCE`` is prepended at sign/verify time.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("payload must be bytes")
    return b"".join((
        _lp((source or "").encode("utf-8")),
        _lp((destination or "").encode("utf-8")),
        _lp((msg_id or "").encode("utf-8")),
        _lp(bytes(payload)),
    ))


# ---------------------------------------------------------------------------
# HELLO signature canonicalization
# ---------------------------------------------------------------------------
#
# The HELLO carries an Ed25519 signature proving the sender controls the
# advertised identity key, channel-bound to the server nonce. The canonical
# bytes are the JSON serialization of
# ``{channel_binding, ephemeral_public, identity_public, name,
# protocol_version}`` with ``sort_keys=True, separators=(",", ":")`` — the
# same convention as ``canonical_capability_announce_bytes`` so
# cross-language clients (Go, TS) reproduce the byte sequence exactly.
#
# Signature scheme is negotiated by protocol version:
#
# - Both peers advertise ironmesh/0.9+ → 64-byte detached Ed25519 signature
#   over ``SIG_CTX_HELLO || canonical_hello_bytes`` (domain-separated, see
#   ``crypto.sign_detached_with_context``).
# - Either peer is older → legacy attached signature (``crypto.sign_message``)
#   over the same canonical bytes.
#
# The ``protocol_version`` field sits INSIDE the canonical body, so a peer's
# advertised version cannot be rewritten in transit without invalidating
# the signature under either scheme. See docs/PROTOCOL_SPEC.md
# ("HELLO signature domain separation") for the negotiation and downgrade
# analysis.
#
# RNS link binding (protocol ironmesh/0.9, Reticulum transport only):
# on RNS Links, 0.9+ peers additionally include ``rns_link_id`` — the hex
# link id of the RNS Link the HELLO travels on — as a sixth key in the
# canonical body. The receiver independently reads the link id off the
# link the HELLO actually arrived on and rejects any mismatch, which
# cryptographically couples the IronMesh Ed25519 identity to the RNS-layer
# link session. When ``rns_link_id`` is None the body is byte-identical
# to the five-key form, so the WebSocket path (which never carries the
# field) and pre-0.9 RNS peers are unaffected.


def canonical_hello_bytes(
    channel_binding: str,
    ephemeral_public: str,
    identity_public: str,
    name: str,
    protocol_version: str,
    rns_link_id: "Optional[str]" = None,
) -> bytes:
    """Build the canonical byte sequence that the HELLO Ed25519 signature
    binds to. Both senders and verifiers MUST use this exact function so
    the produced bytes match byte-for-byte across languages.

    ``channel_binding`` (the hex server nonce) is part of the canonical
    body — this is what prevents cross-connection replay of a captured
    HELLO signature.

    ``rns_link_id`` is the Reticulum-transport link binding (hex link id
    of the RNS Link the HELLO is sent over). ``None`` — the default, and
    the only valid value on the WebSocket path — omits the key entirely,
    keeping the canonical bytes identical to the original five-key form.
    """
    if not isinstance(ephemeral_public, str) or not ephemeral_public:
        raise ValueError("ephemeral_public must be non-empty string")
    if not isinstance(identity_public, str) or not identity_public:
        raise ValueError("identity_public must be non-empty string")
    # channel_binding / name / protocol_version may legitimately be empty
    # strings on ancient or minimal peers; verification then simply fails
    # to match a properly signed body. Type-check only.
    for field_name, value in (
        ("channel_binding", channel_binding),
        ("name", name),
        ("protocol_version", protocol_version),
    ):
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string")
    body = {
        "channel_binding": channel_binding,
        "ephemeral_public": ephemeral_public,
        "identity_public": identity_public,
        "name": name,
        "protocol_version": protocol_version,
    }
    if rns_link_id is not None:
        if not isinstance(rns_link_id, str) or not rns_link_id:
            raise ValueError("rns_link_id must be a non-empty string when provided")
        body["rns_link_id"] = rns_link_id
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# INVITE token — signed-envelope canonicalization
# ---------------------------------------------------------------------------
#
# An invite is an ephemeral, single-use bootstrap token. It carries the
# inviter's CURRENT Ed25519 identity public key (to pin), the inviter's
# bootstrap endpoint (host:port or RNS destination), a single-use nonce,
# an issued_at / expires_at window, and two hints (a suggested peer
# allowlist and the deployment profile). It NEVER carries the mesh
# passphrase or any root secret.
#
# Wire shape (signed, v1):
#   {
#     "version":       1,
#     "nonce":         "<hex single-use id>",
#     "inviter_id":    "<inviter node id / fingerprint>",
#     "inviter_key":   "<b64 Ed25519 identity public>",
#     "endpoint":      "host:port"   (or "rns:<dest-hash>"),
#     "issued_at":     1736812800.0,
#     "expires_at":    1736813700.0,
#     "allowed_peers": "alice,bob"   (suggested --allowed-peers, may be ""),
#     "profile":       "lan"         (deployment profile hint, may be ""),
#     "signature":     "<b64 Ed25519 over canonical_invite_bytes,
#                        under crypto.SIG_CTX_INVITE>"
#   }
#
# The canonical bytes are the JSON serialization of the body WITHOUT the
# signature, with ``sort_keys=True, separators=(",", ":")`` — the same
# convention as ``canonical_capability_announce_bytes`` so cross-language
# clients reproduce the byte sequence exactly. The signature is a
# domain-separated detached Ed25519 signature under
# ``crypto.SIG_CTX_INVITE`` (see ``crypto.sign_detached_with_context``),
# so a signature captured from another surface cannot be replayed here.
#
# Freshness is enforced with the same clock arithmetic as everywhere else
# in the protocol: ``issued_at`` + a per-profile max-age gives
# ``expires_at``; a joiner rejects a token past its ``expires_at`` and the
# inviter re-checks it at pin time. Single-use is enforced INVITER-SIDE
# via a persisted spent-nonce ledger (see ``ironmesh.invite``), not here —
# this module only defines the signed byte format.

INVITE_SIGNED_VERSION: int = 1

# Per-profile default lifetime (seconds) for a freshly created invite.
# lan / homelab: 15 min. lora / offline: 30 min (physically walking a
# token between off-grid nodes). tactical: 5 min (shortest, pre-pinned
# only). Every value is overridable at ``invite create`` time.
INVITE_MAX_AGE_BY_PROFILE: "Dict[str, float]" = MappingProxyType({
    "lan": 900.0,
    "homelab": 900.0,
    "lora": 1800.0,
    "offline": 1800.0,
    "tactical": 300.0,
})
# Fallback when no profile (or an unknown profile) is supplied.
INVITE_MAX_AGE_DEFAULT: float = 900.0


def invite_max_age_for_profile(profile: "Optional[str]") -> float:
    """Return the default invite lifetime (seconds) for ``profile``.

    Unknown / None profiles fall back to ``INVITE_MAX_AGE_DEFAULT``.
    """
    if not profile:
        return INVITE_MAX_AGE_DEFAULT
    return INVITE_MAX_AGE_BY_PROFILE.get(profile, INVITE_MAX_AGE_DEFAULT)


def canonical_invite_bytes(
    nonce: str,
    inviter_id: str,
    inviter_key: str,
    endpoint: str,
    issued_at: float,
    expires_at: float,
    allowed_peers: str = "",
    profile: str = "",
    version: int = INVITE_SIGNED_VERSION,
) -> bytes:
    """Build the canonical byte sequence the invite signature binds to.

    Both the inviter (at sign time) and the joiner (at verify time) MUST
    use this exact function so the produced bytes match byte-for-byte.
    The ``signature`` field is deliberately NOT part of the body.
    """
    if not isinstance(nonce, str) or not nonce:
        raise ValueError("nonce must be non-empty string")
    if not isinstance(inviter_id, str) or not inviter_id:
        raise ValueError("inviter_id must be non-empty string")
    if not isinstance(inviter_key, str) or not inviter_key:
        raise ValueError("inviter_key must be non-empty string")
    if not isinstance(endpoint, str) or not endpoint:
        raise ValueError("endpoint must be non-empty string")
    if not isinstance(issued_at, (int, float)):
        raise ValueError("issued_at must be a numeric timestamp")
    if not isinstance(expires_at, (int, float)):
        raise ValueError("expires_at must be a numeric timestamp")
    if not isinstance(allowed_peers, str):
        raise ValueError("allowed_peers must be a string")
    if not isinstance(profile, str):
        raise ValueError("profile must be a string")
    if not isinstance(version, int) or version < 1:
        raise ValueError("version must be a positive int")
    body = {
        "version": version,
        "nonce": nonce,
        "inviter_id": inviter_id,
        "inviter_key": inviter_key,
        "endpoint": endpoint,
        "issued_at": float(issued_at),
        "expires_at": float(expires_at),
        "allowed_peers": allowed_peers,
        "profile": profile,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


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
    # v0.9.2 chunk A — server-driven Stage-1 skip offer. The server
    # emits this in place of PASSPHRASE_CHALLENGE when both sides are
    # eligible to skip (RNS Link + both advertise hskip). The client
    # type-dispatches on the first server message: SKIP_OFFER → use
    # the channel binding sentinel + go straight to HELLO; the
    # legacy PASSPHRASE_CHALLENGE → full challenge / verify flow.
    # This server-driven design fixes the v0.9.2-pre-r1 unilateral-
    # decision bug where client and server could disagree, sending
    # crossed messages and breaking the handshake.
    SKIP_OFFER = "SKIP_OFFER"
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

    # v0.8.2: Structured multi-turn conversations (LLM-to-LLM dialogue).
    # Payload is a JSON envelope: see docs/PROTOCOL_SPEC.md §4.
    CONV = "CONV"

    # v0.9.2 chunk B (cross-host broadcast). The complement to the
    # RNS GROUP destination: when peers are NOT on the same RNS
    # Transport (e.g., separate LANs without rnsd shared instance),
    # the sender fans out a per-peer GROUP_BROADCAST frame over each
    # established IronMesh connection. Receivers route this to the
    # `on_group_broadcast` hook (NOT the normal MSG pipeline) and
    # dedup on payload SHA-256 so a peer that hears the same broadcast
    # via both the local-segment GROUP packet AND the fan-out path
    # processes it exactly once. The payload here is the same opaque
    # bytes a caller passed to `broadcast_via_rns_group`; no envelope.
    GROUP_BROADCAST = "GROUP_BROADCAST"


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
    MessageType.SKIP_OFFER: {
        # The channel binding is the deterministic 32-byte sentinel
        # from Handshake.skip_channel_binding(); the client uses it as
        # the server_nonce in HELLO signature canonicalization.
        "required": ["channel_binding"],
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
        # Use a cryptographically strong RNG rather than uuid4 (which
        # is also CSPRNG, but msg_id is security-adjacent —
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

        # Which inner-source-signature scheme produced ``source_signature``.
        # None on receive means "tag absent" → treated as the legacy v1
        # (payload-only) scheme for backward compatibility.
        self.source_sig_scheme: Optional[str] = None
        # Set by the receive-side chokepoint once the originator's inner
        # signature has been verified (or for a wire-authenticated direct
        # sender). Downstream storage / bus / UI must never present a frame
        # as authentically-sourced unless this is True.
        self.source_authenticated: bool = False

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
            # Self-describing scheme tag so the verifier picks the right
            # canonical form without negotiating with a far source.
            d["source_sig_scheme"] = (
                self.source_sig_scheme or self.SOURCE_SIG_SCHEME_V1
            )
        if self.e2e_payload is not None:
            d["e2e_payload"] = base64.b64encode(self.e2e_payload).decode()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Frame":
        """Deserialize a frame from a dict.

        v0.8.5.2: strict type checks on the required fields. Previously a
        malformed payload with e.g. ``{"type": 123}`` (integer) would be
        accepted here and then crash a downstream string operation; now
        it rejects at the boundary with a clear error.
        """
        if not isinstance(data, dict):
            raise ValueError(f"Frame.from_dict requires a dict, got {type(data).__name__}")
        msg_type = data.get("type")
        if not isinstance(msg_type, str) or not msg_type:
            raise ValueError(f"Invalid or missing 'type' field: {msg_type!r}")
        msg_id = data.get("msg_id")
        if msg_id is not None and not isinstance(msg_id, str):
            raise ValueError(f"msg_id must be a string, got {type(msg_id).__name__}")
        source = data.get("source", "unknown")
        if not isinstance(source, str):
            raise ValueError(f"source must be a string, got {type(source).__name__}")
        destination = data.get("destination", "*")
        if not isinstance(destination, str):
            raise ValueError(f"destination must be a string, got {type(destination).__name__}")
        sequence = data.get("sequence", 0)
        if not isinstance(sequence, int) or sequence < 0:
            raise ValueError(f"sequence must be a non-negative integer, got {sequence!r}")
        obj = cls(
            msg_type=msg_type,
            payload=base64.b64decode(data["payload"]) if data.get("payload") else b"",
            msg_id=msg_id,
            source=source,
            destination=destination,
            priority=data.get("priority", MessagePriority.NORMAL),
            sequence=sequence,
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
        # Scheme tag is optional on the wire; absence => legacy v1.
        scheme = data.get("source_sig_scheme")
        if scheme is not None and not isinstance(scheme, str):
            raise ValueError(f"source_sig_scheme must be a string, got {type(scheme).__name__}")
        obj.source_sig_scheme = scheme
        if data.get("e2e_payload"):
            obj.e2e_payload = base64.b64decode(data["e2e_payload"])
        return obj

    @classmethod
    def from_json_message(cls, msg_dict: dict, payload_bytes: bytes) -> "Frame":
        """Synthesize a Frame from the legacy JSON-message dispatch path.

        The JSON path decrypts the payload separately, so the resulting Frame
        has metadata extracted from the JSON envelope plus the supplied
        already-decrypted payload bytes.

        v0.8.5.6: mirror the strict type validation that
        ``from_dict`` got in v0.8.5.2. The legacy JSON path was the
        last decode entry point that still trusted whatever the wire
        sent — a peer could ship ``{"msg_id": [1,2,3]}`` and crash
        downstream code that assumed string. Reject at the boundary.
        """
        if not isinstance(msg_dict, dict):
            raise ValueError(
                f"from_json_message requires a dict, "
                f"got {type(msg_dict).__name__}"
            )
        msg_type = msg_dict.get("type", "")
        if not isinstance(msg_type, str):
            raise ValueError(
                f"'type' must be a string, got {type(msg_type).__name__}"
            )
        msg_id = msg_dict.get("msg_id")
        if msg_id is not None and not isinstance(msg_id, str):
            raise ValueError(
                f"msg_id must be a string, got {type(msg_id).__name__}"
            )
        source = msg_dict.get("from", msg_dict.get("source", "unknown"))
        if not isinstance(source, str):
            raise ValueError(
                f"source/from must be a string, got {type(source).__name__}"
            )
        destination = msg_dict.get("to", msg_dict.get("destination", "*"))
        if not isinstance(destination, str):
            raise ValueError(
                f"destination/to must be a string, "
                f"got {type(destination).__name__}"
            )
        sequence = msg_dict.get("sequence", 0)
        if not isinstance(sequence, int) or sequence < 0:
            raise ValueError(
                f"sequence must be non-negative integer, got {sequence!r}"
            )
        ttl = msg_dict.get("ttl", 3)
        if not isinstance(ttl, int) or ttl < 0 or ttl > 255:
            raise ValueError(f"Invalid TTL: {ttl!r}")
        hops = msg_dict.get("hops", [])
        if not isinstance(hops, list) or not all(
            isinstance(h, str) for h in hops
        ):
            raise ValueError(f"Invalid hops: {hops!r}")
        obj = cls(
            msg_type=msg_type,
            payload=payload_bytes,
            msg_id=msg_id,
            source=source,
            destination=destination,
            priority=msg_dict.get("priority", MessagePriority.NORMAL),
            sequence=sequence,
        )
        obj.timestamp = float(msg_dict.get("timestamp", time.time()))
        obj.ttl = ttl
        obj.hops = hops
        if msg_dict.get("source_signature"):
            obj.source_signature = base64.b64decode(msg_dict["source_signature"])
        # Scheme tag is optional on the wire; absence => legacy v1.
        scheme = msg_dict.get("source_sig_scheme")
        if scheme is not None and not isinstance(scheme, str):
            raise ValueError(f"source_sig_scheme must be a string, got {type(scheme).__name__}")
        obj.source_sig_scheme = scheme
        if msg_dict.get("e2e_payload"):
            obj.e2e_payload = base64.b64decode(msg_dict["e2e_payload"])
        return obj

    SIGNATURE_SIZE = 64  # Ed25519 detached signature

    # Inner end-to-end source-signature schemes.
    # v1 (legacy): Ed25519 over the plaintext payload bytes only.
    # v2 (bound):  Ed25519 over SIG_CTX_FRAME_INNER_SOURCE ||
    #              canonical_inner_source_bytes(source, destination, msg_id,
    #              payload). v2 additionally defeats relay redirection
    #              (destination), replay-relabel (msg_id), and re-attribution
    #              (source). See ``verify_source_signature`` and
    #              ``docs/PROTOCOL_SPEC.md``.
    SOURCE_SIG_SCHEME_V1 = "v1"
    SOURCE_SIG_SCHEME_V2 = "v2"

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

        # Compute the inner source signature. This is the bound v2 scheme —
        # Ed25519 over SIG_CTX_FRAME_INNER_SOURCE || canonical(source,
        # destination, msg_id, payload) — which additionally defeats relay
        # redirection, replay-relabel, and re-attribution. The receiver
        # self-describes via the ``source_sig_scheme`` tag, so no protocol
        # negotiation with a far destination is required.
        if source_signing_key is not None and self.source_signature is None:
            try:
                from ironmesh.crypto import (
                    SIG_CTX_FRAME_INNER_SOURCE,
                    sign_detached_with_context,
                )
                canon = canonical_inner_source_bytes(
                    self.source, self.destination, self.msg_id, self.payload,
                )
                self.source_signature = sign_detached_with_context(
                    source_signing_key, SIG_CTX_FRAME_INNER_SOURCE, canon,
                )
                self.source_sig_scheme = self.SOURCE_SIG_SCHEME_V2
            except (nacl_exceptions.CryptoError, TypeError, ValueError) as e:
                # Inner-sig generation failed for a *crypto-input* reason
                # (bad key type, payload not bytes, nacl-level signing error).
                # Drop the inner signature and let the outer wire path proceed
                # — relays without the source key still pass the frame.
                # KeyboardInterrupt, MemoryError, AttributeError, and other
                # programmer errors are intentionally NOT caught here; they
                # propagate so real bugs surface instead of silently dropping
                # inner signatures forever.
                logger.warning(
                    "Inner source signature generation failed for msg %s: %s: %s",
                    self.msg_id, type(e).__name__, e,
                )

        payload_json = json.dumps(self.to_dict(), separators=(",", ":")).encode()
        encrypted = encrypt_message(shared_key, payload_json)

        if len(encrypted) > MAX_FRAME_BYTES:
            raise ValueError(
                f"Encrypted frame payload {len(encrypted)} bytes "
                f"exceeds MAX_FRAME_BYTES ceiling {MAX_FRAME_BYTES}"
            )

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
        # here the code just skip those header bytes. Underscore-prefixed so ruff
        # knows the read is intentional.
        _timestamp_ms = int.from_bytes(data[12:20], "big")
        _msg_id_hash = data[20:28]
        encrypted_length = int.from_bytes(data[28:32], "big")

        # Reject attacker-declared lengths before slicing/allocating the
        # encrypted_data buffer. The wire field is u32 — without this guard
        # a single malicious frame can force allocation of up to 4 GiB.
        if encrypted_length > MAX_FRAME_BYTES:
            raise ValueError(
                f"Declared frame length {encrypted_length} bytes "
                f"exceeds MAX_FRAME_BYTES ceiling {MAX_FRAME_BYTES}"
            )

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
            except nacl_exceptions.BadSignatureError as e:
                raise ValueError(f"Signature verification failed: {e}")

        try:
            payload_json = decrypt_message(shared_key, encrypted_data)
        except nacl_exceptions.CryptoError as e:
            raise ValueError(f"Decryption failed: {e}")

        payload_data = safe_json_loads(payload_json)
        obj = cls.from_dict(payload_data)
        obj.sequence = sequence

        # v0.4: verify inner source signature (survives per-hop re-encryption)
        if obj.source_signature is not None and verify_source_key is not None:
            try:
                src_vk = verify_source_key(obj.source)
            except Exception as e:  # verify_source_key safety wrap
                logger.debug("verify_source_key lookup failed for %s: %s",
                             obj.source, e)
                src_vk = None
            if src_vk is not None:
                # Scheme-aware verification (v1 payload-only or v2 bound).
                # allow_v1=True here — this protocol-level path verifies
                # cryptographic validity; the floor-based v1 refusal is
                # policy enforced at the receive-side chokepoint.
                if not obj.verify_source_signature(src_vk, allow_v1=True):
                    raise ValueError("Inner source signature verification failed")

        return obj

    def verify_source_signature(self, verify_key, *, allow_v1: bool = True) -> bool:
        """Verify the inner end-to-end source signature against ``verify_key``.

        Returns True iff a signature is present and valid. The inner
        signature is produced by the ORIGINAL source over its plaintext and
        survives per-hop re-encryption by relays, so a successful verify
        authenticates the originator of a relayed frame — not merely the
        immediate hop.

        ``allow_v1`` gates the legacy payload-only scheme. A caller that
        knows the negotiated protocol floor is >= 0.9 passes
        ``allow_v1=False`` to refuse the unbound legacy form. The v2 (bound)
        scheme is always accepted because it is strictly stronger.

        This method performs the cryptographic check only. Policy (whether a
        missing signature is tolerated, e.g. for a wire-authenticated direct
        sender) is decided by the caller — see
        ``RoutingMixin._verify_inner_source``.
        """
        if self.source_signature is None:
            return False
        scheme = self.source_sig_scheme or self.SOURCE_SIG_SCHEME_V1
        try:
            if scheme == self.SOURCE_SIG_SCHEME_V1:
                if not allow_v1:
                    return False
                verify_key.verify(self.payload, self.source_signature)
                return True
            if scheme == self.SOURCE_SIG_SCHEME_V2:
                from ironmesh.crypto import (
                    SIG_CTX_FRAME_INNER_SOURCE,
                    verify_detached_with_context,
                )
                canon = canonical_inner_source_bytes(
                    self.source, self.destination, self.msg_id, self.payload,
                )
                return verify_detached_with_context(
                    verify_key, SIG_CTX_FRAME_INNER_SOURCE, canon,
                    self.source_signature,
                )
            return False  # unknown scheme — fail closed
        except nacl_exceptions.BadSignatureError:
            return False

    def serialize_plaintext(self) -> bytes:
        """Serialize to binary wire format WITHOUT encryption.

        Audit L-13: ONLY for use during the initial handshake, before
        the session key is established. All post-handshake frames MUST
        go through :meth:`encrypt_and_serialize` — the message loop
        enforces ``FLAG_ENCRYPTED`` on inbound frames.
        """
        payload_json = json.dumps(self.to_dict(), separators=(",", ":")).encode()

        if len(payload_json) > MAX_FRAME_BYTES:
            raise ValueError(
                f"Plaintext frame payload {len(payload_json)} bytes "
                f"exceeds MAX_FRAME_BYTES ceiling {MAX_FRAME_BYTES}"
            )

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
    - Any frame with seq > MAX_SEQUENCE (sane upper bound — defeats a
      peer that ratchets its own high-water mark with an absurd value
      and then can never receive again)
    - Any frame with timestamp more than max_age seconds old
    - Duplicate sequence numbers within sliding window
    """

    # Wire field is u64. Legitimate sessions stay well under 2**48: at
    # 10_000 msg/s that's still ~890 years of traffic. Anything above is
    # either a peer bug or malicious — reject before ratcheting last_seq.
    # Without this guard, one frame with seq=2**63 permanently disables
    # replay-window acceptance for the peer (self-DoS, but it's still
    # easier to bound it here than to recover later).
    MAX_SEQUENCE = 1 << 48

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

        # Upper bound — reject before ratcheting last_seq. See MAX_SEQUENCE
        # docstring for the self-DoS scenario this defeats.
        if sequence > self.MAX_SEQUENCE:
            return f"Sequence {sequence} exceeds MAX_SEQUENCE {self.MAX_SEQUENCE}"

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

        # v0.9.4 Phase 2: peer's advertised X25519 identity public key.
        # Populated from the HELLO ``x25519_public_b64`` advertisement
        # AFTER the binding signature has verified against the peer's
        # pinned Ed25519 identity. None when the peer is pre-v0.9.4
        # (no advertisement) or the binding failed verification — in
        # which case E2E sealing falls back to the legacy
        # ``ed25519_to_curve25519`` derivation.
        self.x25519_identity_public: Optional[bytes] = None

        # Replay protection
        self.next_send_seq: int = 1
        self.last_recv_seq: int = 0

        # ironmesh/0.9: which Ed25519 scheme signed the peer's HELLO —
        # "context-v1" (domain-separated detached signature under
        # crypto.SIG_CTX_HELLO, both peers 0.9+), "legacy" (attached
        # signature, pre-0.9 peer on either end), or "unsigned" (peer
        # presented no identity key; TOFU/allowlist policy applies).
        self.hello_sig_scheme: str = "unsigned"

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

        # v0.9.1: RNS announce-driven discovery state
        self.rns_announced_at: Optional[float] = None
        self.rns_capabilities: list = []
        self.rns_features: list = []
        self.rns_announced_version: Optional[str] = None
        self.rns_hops: Optional[int] = None
        # Live link stats from RNS — only populated while a Link is active
        self.rns_estimated_rtt_ms: Optional[float] = None
        self.rns_estimated_bps: Optional[float] = None
        self.rns_link_mtu: Optional[int] = None
        self.rns_link_mdu: Optional[int] = None
        # Physical layer stats — only meaningful on radio interfaces
        self.rns_rssi: Optional[float] = None
        self.rns_snr: Optional[float] = None
        self.rns_q: Optional[float] = None

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
        self.long_drop_alerted: bool = False         # set after the code emit PEER_DROPPED_LONG

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
            # v0.8.3: surface the human-readable agent name so the dashboard
            # can render "alice" instead of a 32-hex node id. Populated by
            # the handshake. Null if the peer hasn't completed HELLO yet.
            "name": getattr(self, "agent_name", None),
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
            # v0.9.1: RNS-derived discovery + link metrics for the dashboard
            "rns_announced_at": self.rns_announced_at,
            "rns_capabilities": list(self.rns_capabilities),
            "rns_features": list(self.rns_features),
            "rns_announced_version": self.rns_announced_version,
            "rns_hops": self.rns_hops,
            "rns_estimated_rtt_ms": self.rns_estimated_rtt_ms,
            "rns_estimated_bps": self.rns_estimated_bps,
            "rns_link_mtu": self.rns_link_mtu,
            "rns_link_mdu": self.rns_link_mdu,
            "rns_rssi": self.rns_rssi,
            "rns_snr": self.rns_snr,
            "rns_q": self.rns_q,
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

    # v0.9.2: Fixed channel-binding sentinel used in lieu of a random
    # server_nonce when both peers agree to skip stage 1 of the
    # handshake on an identified RNS Link. The sentinel is signed into
    # the HELLO the same way a real nonce would be, so signature
    # verification logic downstream remains unchanged. The trade-off:
    # the IronMesh-layer channel binding no longer binds per-session
    # (since the sentinel is constant), but the underlying RNS Link
    # provides per-session integrity via its own ephemeral key
    # exchange. Operators opt in by enabling rns_skip_handshake on
    # both ends + advertising the `hskip` feature in announces.
    _SKIP_BINDING_SENTINEL = hashlib.sha256(
        b"ironmesh-handshake-skip-channel-binding-v1"
    ).digest()

    @staticmethod
    def skip_channel_binding() -> bytes:
        """Return the fixed channel-binding sentinel used when stage 1 is skipped."""
        return Handshake._SKIP_BINDING_SENTINEL

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
