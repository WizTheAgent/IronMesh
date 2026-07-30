"""IronMesh configuration — centralized defaults and config loading."""

import json
import os
from dataclasses import dataclass, field
from typing import Optional

DEFAULT_CONFIG_PATH = "~/.ironmesh/config.json"


@dataclass
class IronMeshConfig:
    """Centralized configuration for IronMesh."""
    # Identity
    agent_name: str = "agent"
    keys_path: str = "~/.ironmesh/keys.json"
    keys_passphrase: Optional[str] = None

    # Networking
    port: int = 8765
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None
    max_message_size: int = 1_048_576  # 1 MB

    # Auth
    passphrase: Optional[str] = None
    passphrase_file: Optional[str] = None

    # Storage
    db_path: str = "~/.ironmesh/data.db"
    trust_path: str = "~/.ironmesh/known_peers.json"

    # Rate limiting
    msg_rate_sustained: float = 20.0
    msg_rate_burst: int = 100
    conn_rate_per_minute: int = 10

    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None

    # Replay protection
    replay_max_age: float = 30.0
    replay_window_size: int = 1024

    # Maintenance
    heartbeat_interval: int = 30
    cleanup_interval: int = 3600
    reconnect_interval: int = 15
    queue_flush_interval: int = 5
    prune_days: int = 30

    # v0.4: mesh routing
    mesh_routing: str = "relay"  # "off" | "passive" | "relay"
    max_hops: int = 5
    route_announce_interval: float = 30.0
    route_ttl: float = 90.0
    routes_path: str = "~/.ironmesh/routes.json"

    # v0.4: dedup cache (per-source sharded)
    dedup_sources_max: int = 128
    dedup_per_source_max: int = 1024
    dedup_cache_ttl: float = 300.0

    # v0.4: capabilities (declared by this node)
    capabilities: list = field(default_factory=list)
    capabilities_path: str = "~/.ironmesh/capabilities.json"
    capability_announce_interval: float = 60.0

    # v0.4: audit log rotation
    audit_log_max_bytes: int = 10_485_760  # 10 MB

    # v0.4: observability
    metrics_format: str = "prometheus"  # "prometheus" | "json"
    log_format: str = "text"  # "text" | "json"

    # v0.5: Reticulum (LoRa) transport
    rns_enabled: bool = False
    rns_configdir: Optional[str] = None
    rns_announce_interval: float = 300.0

    # Reticulum ratchets — per-packet forward secrecy on Packets sent
    # to this destination outside an established Link. The ratchet key
    # is rotated on a timer and signalled via subsequent announces;
    # peers automatically pick up the new key on next announce.
    # Disable only if interoperating with very old RNS peers.
    rns_ratchets_enabled: bool = True
    rns_ratchet_interval: float = 1800.0
    rns_retained_ratchets: int = 8

    # v0.9.2: optional handshake compression on RNS Links. When both
    # peers advertise the `hskip` feature in their announces AND the
    # transport is an established RNS Link, skip stage-1 (passphrase
    # challenge / verify) and go directly to the HELLO + ephemeral
    # ECDH exchange. Saves three round-trips on LoRa, where each is
    # painful (~250 ms at 3.12 kbps for the smallest message). The
    # RNS Link itself already provides mutual authentication via
    # Identity, so the IronMesh-layer passphrase is redundant on
    # identified Links. The passphrase remains the gate on every
    # other transport. Default off so v0.9.2 installs fall back to
    # the full handshake until operators opt in.
    rns_skip_handshake: bool = False

    # ironmesh/0.9: require the RNS HELLO link binding from every RNS
    # peer. 0.9+ peers always bind their HELLO to the id of the RNS
    # Link it travels on; pre-0.9 peers cannot produce the binding.
    # Default off = pre-0.9 RNS peers keep the legacy (unbound)
    # behavior; on = their handshakes are rejected, closing the
    # RNS/IronMesh identity-binding residual completely on meshes
    # where every node has upgraded. No effect on WebSocket peers.
    rns_require_link_binding: bool = False

    # Relay-confidentiality: when True, an end-to-end sealed frame carries the
    # body SOLELY in e2e_payload (frame.payload is stripped) so a forwarding
    # relay cannot read it. OPT-IN and OFF by default because it is a
    # wire-behavior change: a node that verifies the inner source signature
    # but predates the receive-side post-unseal exemption would drop a
    # stripped frame. Enable ONLY on a mesh where every node runs this build
    # (or newer). With it off, the sealed copy is still attached but the
    # plaintext also rides in the per-hop layer (relay-readable) — fully
    # wire-compatible with all older nodes.
    e2e_strict_confidentiality: bool = False

    # v0.9.2: optional RNS Destination.GROUP for mesh-wide broadcast.
    # Every peer in the mesh derives the same symmetric group key
    # from the passphrase via HKDF, so a single packet sent to the
    # group destination reaches every member — O(1) instead of O(N)
    # for mesh-wide notifications. Useful when N grows and per-peer
    # unicast HELLO/PING becomes a real bandwidth cost on LoRa.
    # Peers advertise `group` in their announce features; both sides
    # must advertise before any broadcast is used. Default off.
    rns_group_broadcast: bool = False

    # v0.8.5: pending-trust message gate. When True, MSG/REQ/RESP frames
    # from peers that haven't been promoted to "trusted" are queued
    # instead of delivered to clients. Operator promotes via the
    # /ws promote_peer action or the ironmesh_trust_peer MCP tool.
    # Default False = no behavior change on upgrade. v0.9.0 may flip
    # this default after one release of opt-in feedback.
    require_message_promotion: bool = False
    # Per-peer cap on the queue of messages held while a peer is pending.
    # Oldest message is evicted on overflow.
    pending_trust_queue_cap: int = 100

    # RESERVED — group crypto suite selector. Keyed to the pending keying
    # RFC (rfcs/RFC-key-hierarchy-group-messaging-v0.1-skeleton.md). Left
    # UNSET on purpose: naming a group-keying suite before the RFC picks
    # one would read as a decision that hasn't been made. Reserved here so
    # a future strict posture (e.g. `--profile=tactical`) can pin a suite
    # WITHOUT a schema migration. No validator rejects None, and it is
    # excluded from save() so it stays invisible on disk until the RFC
    # lands. Do NOT default this to any real suite.
    group_crypto_suite: Optional[str] = None

    def __post_init__(self):
        # Clamp announce interval to a sane minimum to prevent flooding
        if self.route_announce_interval < 1.0:
            self.route_announce_interval = 1.0
        if self.mesh_routing not in ("off", "passive", "relay"):
            self.mesh_routing = "relay"

    @classmethod
    def from_file(cls, path: str = DEFAULT_CONFIG_PATH) -> "IronMeshConfig":
        """Load config from JSON file, falling back to defaults.

        Audit L-07: malformed JSON must not crash the caller — log and
        return defaults so the daemon can still boot.
        """
        path = os.path.expanduser(path)
        config = cls()
        if not os.path.exists(path):
            return config
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            import logging
            logging.getLogger("ironmesh.config").warning(
                "Config file %s malformed or unreadable (%s); using defaults",
                path, e,
            )
            return config
        if not isinstance(data, dict):
            return config
        for key, value in data.items():
            if hasattr(config, key):
                setattr(config, key, value)
        return config

    @classmethod
    def from_env(cls) -> "IronMeshConfig":
        """Load config from environment variables."""
        config = cls()
        env_map = {
            "IRONMESH_NAME": "agent_name",
            "IRONMESH_PORT": ("port", int),
            "IRONMESH_PASSPHRASE": "passphrase",
            "IRONMESH_KEYS_PATH": "keys_path",
            "IRONMESH_DB_PATH": "db_path",
            "IRONMESH_LOG_LEVEL": "log_level",
            "IRONMESH_LOG_FILE": "log_file",
            "IRONMESH_TLS_CERT": "tls_cert",
            "IRONMESH_TLS_KEY": "tls_key",
            "IRONMESH_PASSPHRASE_FILE": "passphrase_file",
            "IRONMESH_RNS_ENABLED": ("rns_enabled", lambda v: v.lower() in ("1", "true", "yes")),
            "IRONMESH_RNS_CONFIGDIR": "rns_configdir",
            "IRONMESH_RNS_RATCHETS": ("rns_ratchets_enabled", lambda v: v.lower() in ("1", "true", "yes")),
            "IRONMESH_RNS_RATCHET_INTERVAL": ("rns_ratchet_interval", float),
            "IRONMESH_RNS_RETAINED_RATCHETS": ("rns_retained_ratchets", int),
            "IRONMESH_REQUIRE_MSG_PROMOTION": ("require_message_promotion",
                                                lambda v: v.lower() in ("1", "true", "yes")),
            "IRONMESH_PENDING_QUEUE_CAP": ("pending_trust_queue_cap", int),
        }
        for env_var, target in env_map.items():
            val = os.environ.get(env_var)
            if val is not None:
                if isinstance(target, tuple):
                    attr, conv = target
                    setattr(config, attr, conv(val))
                else:
                    setattr(config, target, val)
        return config

    def save(self, path: str = DEFAULT_CONFIG_PATH):
        """Save current config to JSON file."""
        path = os.path.expanduser(path)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        # Don't save sensitive fields. Also omit the reserved
        # group_crypto_suite stub so it stays invisible on disk until the
        # keying RFC lands (see the field comment above).
        data = {k: v for k, v in self.__dict__.items()
                if k not in ("passphrase", "keys_passphrase",
                             "group_crypto_suite")}
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
