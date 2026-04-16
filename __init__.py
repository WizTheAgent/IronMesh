"""IronMesh — Local-first agent-to-agent mesh protocol.

v0.4 adds multi-hop mesh routing, end-to-end NaCl SealedBox encryption,
capability discovery, Prometheus metrics, and audit log rotation on top of
the v0.3 WebSocket + mDNS + per-hop NaCl SecretBox foundation.
"""

__version__ = "0.8.0-dev"

from ironmesh.agent import Agent
from ironmesh.capabilities import CapabilityRegistry
from ironmesh.crypto import (
    decrypt_message,
    ecdh_exchange,
    encrypt_message,
    generate_ephemeral_keypair,
    sign_message,
    verify_signature,
)
from ironmesh.keys import AgentKeys, generate_ephemeral, generate_keypair
from ironmesh.mesh import (
    CircuitBreaker,
    DedupCache,
    MeshRouter,
    RoutingTable,
)
from ironmesh.mesh_crypto import seal_to_destination, unseal_from_source
from ironmesh.protocol import Frame, MessageBus, MessagePriority, MessageType, PeerState

__all__ = [
    "__version__",
    # v0.8: high-level SDK
    "Agent",
    "MessageType",
    "MessagePriority",
    "Frame",
    "PeerState",
    "MessageBus",
    "AgentKeys",
    "generate_keypair",
    "generate_ephemeral",
    "encrypt_message",
    "decrypt_message",
    "ecdh_exchange",
    "generate_ephemeral_keypair",
    "sign_message",
    "verify_signature",
    # v0.4 mesh
    "MeshRouter",
    "RoutingTable",
    "DedupCache",
    "CircuitBreaker",
    "seal_to_destination",
    "unseal_from_source",
    "CapabilityRegistry",
]
