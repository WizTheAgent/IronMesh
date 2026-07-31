"""IronMesh Bridge — Main daemon for agent-to-agent communication.

Manages WebSocket server, mDNS discovery, peer connections, passphrase auth,
ephemeral ECDH key exchange (forward secrecy), encrypted message routing,
and offline message queue.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import signal
import ssl
import sys
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import nacl.exceptions as nacl_exceptions
import websockets

# v0.5: Optional Reticulum transport (only loaded when --reticulum flag is passed)
try:
    from ironmesh.reticulum_transport import _HAS_RNS, ReticulumTransport, RNSLinkAdapter
except ImportError:
    _HAS_RNS = False
    ReticulumTransport = None  # type: ignore[assignment,misc]
    RNSLinkAdapter = None  # type: ignore[assignment,misc]

from ironmesh import (
    crypto as ew_crypto,
    discovery as ew_discovery,
    keys as ew_keys,
    protocol as ew_protocol,
)
from ironmesh.audit import (
    EVENT_AUTH_BLOCKED,  # noqa: F401  (re-exported; used by RateLimitMixin)
    EVENT_AUTH_FAILURE,  # noqa: F401  (re-exported; used by RateLimitMixin)
    EVENT_CAPABILITY_ANNOUNCE_BAD_SIG,  # noqa: F401  (re-exported; used by RoutingMixin)
    EVENT_CAPABILITY_LEARNED,  # noqa: F401  (re-exported; used by RoutingMixin)
    EVENT_MSG_GATED_DROP,  # noqa: F401  (re-exported; used by TrustOpsMixin)
    EVENT_MSG_GATED_QUEUE,  # noqa: F401  (re-exported; used by TrustOpsMixin)
    EVENT_PEER_BLOCKED,  # noqa: F401  (re-exported; used by TrustOpsMixin)
    EVENT_PEER_CAP_ACCEPTED,  # noqa: F401  (re-exported; used by TrustOpsMixin)
    EVENT_PEER_CAP_BASELINE,  # noqa: F401  (re-exported; used by TrustOpsMixin)
    EVENT_PEER_CAP_BINDING_PARTIAL,  # noqa: F401  (re-exported; used by TrustOpsMixin)
    EVENT_PEER_CAP_SET_CHANGED,  # noqa: F401  (re-exported; used by TrustOpsMixin)
    EVENT_PEER_CONNECT,
    EVENT_PEER_DROPPED_LONG,
    EVENT_PEER_PROMOTED,  # noqa: F401  (re-exported; used by TrustOpsMixin)
    EVENT_STARTUP,
    EVENT_TOFU_MISMATCH,  # noqa: F401  (re-exported; used by TrustOpsMixin)
    EVENT_TOFU_NEW,  # noqa: F401  (re-exported; used by TrustOpsMixin)
    AuditLog,
)
from ironmesh.capabilities import CapabilityRegistry
from ironmesh.dashboard import GuiMixin
from ironmesh.dashboard_html import GUI_HTML  # noqa: F401  (re-exported; served by GuiMixin)
from ironmesh.handshake import (
    HELLO_CTX_MIN_VERSION,  # noqa: F401  (re-exported for downstream importers)
    MIN_MESH_VERSION,  # noqa: F401  (re-exported for downstream importers)
    PROTOCOL_VERSION,
    HandshakeMixin,
    _parse_protocol_version,
    _peer_supports_hello_ctx,
    _peer_supports_mesh,
    _peer_supports_rekey,  # noqa: F401  (re-exported; used by mixins)
)
from ironmesh.mesh import MeshRouter
from ironmesh.metrics import Metrics, MetricsMixin
from ironmesh.ratelimit import RateLimitMixin
from ironmesh.routing import RoutingMixin
from ironmesh.store import MessageStore
from ironmesh.telemetry import (
    emit_event as _otel_span_event,
    span as _otel_span,  # noqa: F401  (re-exported; used by RoutingMixin)
)
from ironmesh.trust_ops import TrustOpsMixin

logger = logging.getLogger("ironmesh.bridge")

MAX_MESSAGE_SIZE = 1_048_576  # 1 MB default

# CVE-2020-10735 / PEP 686 — large int string conversion DoS. Python 3.11+
# defaults `int(s)` parsing to a 4300-digit string ceiling. Python 3.10 has
# no default cap until 3.10.7, and even then a library that touches large
# int parsing via untrusted JSON input is at risk on older patch releases.
# Apply the cap at daemon bootstrap so behaviour is uniform across 3.10/3.11/
# 3.12/3.13. `set_int_max_str_digits` is a no-op on interpreters that already
# enforce the cap; the getattr guard handles the (rare) sub-3.10.7 case where
# the function is absent entirely.
def _enforce_int_str_digits_cap(limit: int = 4300) -> None:
    """Apply the CPython int-string-conversion cap at daemon bootstrap."""
    fn = getattr(sys, "set_int_max_str_digits", None)
    if fn is None:
        # Interpreter predates PEP 686 backport — there is nothing the
        # daemon can do beyond logging the gap. Callers should upgrade.
        logger.warning(
            "sys.set_int_max_str_digits unavailable (Python %s); large-int "
            "JSON parsing DoS not mitigated. Upgrade to 3.10.7+ / 3.11+.",
            sys.version.split()[0],
        )
        return
    try:
        fn(limit)
    except ValueError:
        # Already set lower than `limit` (e.g. operator env). Leave it.
        pass


_enforce_int_str_digits_cap()


def _ipv4_to_int(ip: str) -> Optional[int]:
    """Parse a dotted-quad IPv4 string to its 32-bit int form. Returns None on parse error."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        n = 0
        for p in parts:
            v = int(p)
            if v < 0 or v > 255:
                return None
            n = (n << 8) | v
        return n
    except (ValueError, AttributeError):
        return None


def _select_closest_subnet_address(candidates: List[str],
                                    local_prefixes: List[int]) -> str:
    """Pick the candidate address whose /24 matches one of ours.

    Multi-homed peers (e.g. a VPN interface plus the LAN interface)
    advertise multiple addresses via mDNS. Choosing the first one
    deterministically can cross-route to the VPN side when a LAN
    address would be cheaper and more reliable. This picks the first
    candidate whose top 24 bits match one of the supplied local
    /24 prefixes, falling back to the first candidate when no match
    exists (same as the legacy single-address path).

    ``candidates`` is a non-empty list of dotted-quad IPv4 strings.
    ``local_prefixes`` is a list of /24 prefixes (top 24 bits as int).
    """
    if not candidates:
        return ""  # unreachable per call sites — defensive only
    if len(candidates) == 1 or not local_prefixes:
        return candidates[0]
    for ip in candidates:
        ip_int = _ipv4_to_int(ip)
        if ip_int is None:
            continue
        ip_prefix = ip_int & 0xFFFFFF00
        if ip_prefix in local_prefixes:
            return ip
    return candidates[0]


# ---------------------------------------------------------------------------
# v0.4: Structured JSON log formatter
# ---------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    """Render log records as one JSON object per line.

    Includes timestamp, level, logger name, message, and any ``extra`` fields
    set on the record. Useful for log aggregators (Loki, ELK, etc.).
    """

    _RESERVED = {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "message", "asctime",
    }

    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S",
                                time.gmtime(record.created)) + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k in self._RESERVED:
                continue
            try:
                json.dumps(v)  # serialization probe
                out[k] = v
            except (TypeError, ValueError):
                out[k] = repr(v)
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, separators=(",", ":"))


# ---------------------------------------------------------------------------
# v0.4: Lightweight daemon config holder for mesh / capabilities / observability
# ---------------------------------------------------------------------------

@dataclass
class _DaemonConfig:
    """Lightweight config holder for v0.4 mesh, capability, and observability fields.

    BridgeDaemon stores these centrally so MeshRouter and CapabilityRegistry can
    receive a single config object instead of many constructor parameters. This
    is intentionally separate from IronMeshConfig (config.py) — that class is
    the user-facing JSON/env loader, while this is an internal runtime container
    populated from BridgeDaemon's __init__ args.
    """
    mesh_routing: str = "relay"
    max_hops: int = 5
    route_announce_interval: float = 30.0
    route_ttl: float = 90.0
    routes_path: str = "~/.ironmesh/routes.json"
    capabilities: List[str] = field(default_factory=list)
    capabilities_path: str = "~/.ironmesh/capabilities.json"
    capability_announce_interval: float = 60.0
    # v0.9.4 (signed capability announcement): max age (seconds) of a signed CAPABILITY_ANNOUNCE
    # the receiver will accept. Bounds the replay window for a stolen
    # origin signature; tolerant of NTP-grade clock skew + slow multi-hop
    # relays. 300 s is the established replay-window upper bound.
    capability_announce_max_age: float = 300.0
    metrics_format: str = "prometheus"
    log_format: str = "text"
    audit_log_max_bytes: int = 10_485_760
    dedup_sources_max: int = 128
    dedup_per_source_max: int = 1024
    dedup_cache_ttl: float = 300.0
    # v0.8.5: pending-trust message gate
    require_message_promotion: bool = False
    pending_trust_queue_cap: int = 100
    # v0.9.5: opt-in relay-confidentiality. When True, the send path strips
    # the plaintext body from an e2e-sealed frame so a relay carries only the
    # SealedBox. OFF by default — see IronMeshConfig.e2e_strict_confidentiality
    # for the wire-compatibility rationale.
    e2e_strict_confidentiality: bool = False


# ---------------------------------------------------------------------------
# Key management helpers
# ---------------------------------------------------------------------------

def _keys_decrypt_error(path, cause: str) -> ValueError:
    """Build an actionable error for a key file that could not be
    decrypted, listing every supported passphrase source."""
    return ValueError(
        f"Could not decrypt key file {path}: {cause}.\n"
        + ew_keys.KEYS_PASSPHRASE_SOURCES_HELP
    )


async def ensure_agent_keys(keys_path: str, passphrase: Optional[str] = None,
                            fallback_passphrase: Optional[str] = None,
                            allow_plaintext: bool = False) -> ew_keys.AgentKeys:
    """Load or generate Ed25519 identity keypair.

    ``passphrase`` is the explicit key-file passphrase. When it is not
    supplied and the on-disk key file is encrypted, ``fallback_passphrase``
    (the mesh passphrase — ``ironmesh setup`` encrypts the key file with
    the same passphrase it writes to the passphrase file) is tried
    before failing, so the wizard's printed ``ironmesh run`` command
    works with no extra flags.

    Key files are encrypted by default: an auto-generated key file is
    encrypted with ``passphrase`` or ``fallback_passphrase``, and a
    plaintext key file found on disk is re-encrypted forward when any
    passphrase is available (migration). A plaintext key file is only
    ever written with the explicit ``allow_plaintext=True`` opt-in
    (``--plaintext-keys`` on the CLI); with no passphrase and no
    opt-in, generation fails with an actionable error.
    """
    path = Path(os.path.expanduser(keys_path))
    os.makedirs(path.parent, exist_ok=True)

    if path.exists():
        try:
            effective = passphrase
            try:
                keys = ew_keys.load_keys(str(path), passphrase=effective)
            except ValueError as e:
                if effective is None and "no passphrase provided" in str(e):
                    if not fallback_passphrase:
                        raise _keys_decrypt_error(
                            path, "the file is encrypted but no passphrase "
                                  "was provided") from None
                    try:
                        keys = ew_keys.load_keys(
                            str(path), passphrase=fallback_passphrase)
                    except ValueError:
                        raise _keys_decrypt_error(
                            path, "the file is encrypted with a passphrase "
                                  "different from the mesh passphrase") from None
                    effective = fallback_passphrase
                    logger.info(
                        "Key file %s decrypted with the mesh passphrase "
                        "(no separate key-file passphrase was supplied)",
                        path,
                    )
                elif "Wrong passphrase" in str(e):
                    raise _keys_decrypt_error(
                        path, "wrong passphrase or corrupted key file") from None
                else:
                    raise
            logger.info("Keys loaded from %s (fingerprint: %s)", path, keys.get_fingerprint())

            # Auto-migrate: if the key file is plaintext and any
            # passphrase is available (explicit key-file passphrase or
            # the mesh passphrase), re-encrypt — unless the caller
            # explicitly opted into plaintext keys.
            encryption_pp = effective or fallback_passphrase
            if encryption_pp and not allow_plaintext:
                import json as _json
                with open(str(path)) as _f:
                    _data = _json.load(_f)
                if not _data.get("encrypted", False):
                    logger.warning("Migrating plaintext key file to encrypted: %s", path)
                    ew_keys.save_keys(keys, str(path), passphrase=encryption_pp)
                    logger.info("Key file migration complete — now encrypted with Argon2id")
                    effective = encryption_pp

            # v0.9.4 Phase 2 auto-migration: a daemon running v0.9.4 that
            # loads a legacy v1/v2 keystore (no master-seed envelope)
            # silently migrates it forward on first start. The Ed25519
            # seed is preserved byte-for-byte — every TOFU pin in the
            # mesh remains valid. A .legacy.bak is written next to the
            # original so an operator can roll back to a pre-v0.9.4
            # daemon within one release cycle if needed.
            #
            # The migration is best-effort: if it fails (permissions,
            # disk-full, etc.) the daemon still starts on the legacy
            # keys, just without the new HELLO advertisement.
            if not keys.is_master_seed_format():
                try:
                    keys = ew_keys.migrate_keys_to_master_seed(
                        str(path),
                        passphrase=effective,
                        allow_plaintext=not effective,
                    )
                    logger.warning(
                        "v0.9.4 Phase 2 auto-migration: legacy keys "
                        "rewritten to master-seed envelope (%s). Legacy "
                        "backup at %s.legacy.bak. Ed25519 identity "
                        "unchanged — every TOFU pin remains valid.",
                        path, path,
                    )
                except (OSError, ValueError, RuntimeError) as e:
                    logger.warning(
                        "v0.9.4 Phase 2 auto-migration FAILED for %s "
                        "(%s) — continuing on legacy keys without "
                        "HELLO X25519 advertisement",
                        path, e,
                    )

            return keys
        except Exception as e:
            logger.error("Failed to load keys from %s: %s", path, e)
            raise

    keypair = ew_keys.generate_keypair()
    effective = passphrase or fallback_passphrase
    if effective:
        ew_keys.save_keys(keypair, str(path), passphrase=effective)
        if not passphrase:
            logger.info(
                "Auto-generated key file encrypted with the mesh "
                "passphrase (no separate key-file passphrase was "
                "supplied): %s", path,
            )
    elif allow_plaintext:
        logger.warning(
            "Storing the new identity key UNENCRYPTED — plaintext keys "
            "were explicitly enabled. INSECURE for production use."
        )
        ew_keys.save_keys(keypair, str(path), passphrase=None,
                          allow_plaintext=True)
    else:
        raise ValueError(
            f"Refusing to auto-generate a PLAINTEXT identity key file at "
            f"{path}: no passphrase is available to encrypt it. Provide a "
            "key-file passphrase or the mesh passphrase, or explicitly "
            "opt in to an unencrypted key file with --plaintext-keys "
            "(allow_plaintext=True from the library)."
        )
    logger.info("New keypair generated -> %s (fingerprint: %s)", path, keypair.get_fingerprint())
    return keypair


async def rotate_keys(keys_path: str, passphrase: Optional[str] = None,
                      fallback_passphrase: Optional[str] = None,
                      allow_plaintext: bool = False) -> ew_keys.AgentKeys:
    """Generate a new keypair and save to disk.

    Same encryption contract as :func:`ensure_agent_keys`: the new key
    file is encrypted with ``passphrase`` (or ``fallback_passphrase`` —
    the mesh passphrase — when no key-file passphrase was supplied);
    a plaintext key file requires the explicit ``allow_plaintext``
    opt-in.
    """
    path = Path(os.path.expanduser(keys_path))
    os.makedirs(path.parent, exist_ok=True)

    keypair = ew_keys.generate_keypair()
    effective = passphrase or fallback_passphrase
    if effective:
        ew_keys.save_keys(keypair, str(path), passphrase=effective)
    elif allow_plaintext:
        logger.warning(
            "Storing the rotated identity key UNENCRYPTED — plaintext "
            "keys were explicitly enabled. INSECURE for production use."
        )
        ew_keys.save_keys(keypair, str(path), passphrase=None,
                          allow_plaintext=True)
    else:
        raise ValueError(
            f"Refusing to rotate to a PLAINTEXT identity key file at "
            f"{path}: no passphrase is available to encrypt it. Provide a "
            "key-file passphrase or the mesh passphrase, or explicitly "
            "opt in to an unencrypted key file with --plaintext-keys "
            "(allow_plaintext=True from the library)."
        )
    logger.info("Key rotation complete -> %s", path)
    return keypair


# ---------------------------------------------------------------------------
# BridgeDaemon
# ---------------------------------------------------------------------------

class BridgeDaemon(MetricsMixin, RateLimitMixin, TrustOpsMixin, HandshakeMixin,
                   RoutingMixin, GuiMixin):
    """WebSocket server + mDNS discovery + encrypted P2P messaging daemon."""

    def __init__(self, name: str = "agent", port: int = 8765,
                 passphrase: Optional[str] = None,
                 keys_path: str = "~/.ironmesh/keys.json",
                 db_path: str = "~/.ironmesh/data.db",
                 keys_passphrase: Optional[str] = None,
                 tls_cert: Optional[str] = None,
                 tls_key: Optional[str] = None,
                 max_message_size: int = MAX_MESSAGE_SIZE,
                 bind_address: str = "0.0.0.0",
                 log_level: str = "INFO",
                 gui: bool = False,
                 allowed_peers: Optional[list] = None,
                 open_discovery: bool = False,
                 allow_plaintext_ws: bool = False,
                 strict_tls: bool = False,
                 pinned_ca_path: Optional[str] = None,
                 max_msgs_per_sec: Optional[float] = None,
                 mesh_routing: str = "relay",
                 max_hops: int = 5,
                 route_announce_interval: float = 30.0,
                 route_ttl: float = 90.0,
                 routes_path: str = "~/.ironmesh/routes.json",
                 capabilities: Optional[list] = None,
                 capabilities_path: str = "~/.ironmesh/capabilities.json",
                 capability_announce_interval: float = 60.0,
                 metrics_format: str = "prometheus",
                 log_format: str = "text",
                 audit_log_max_bytes: int = 10_485_760,
                 # v0.5: Reticulum transport
                 rns_enabled: bool = False,
                 rns_configdir: Optional[str] = None,
                 rns_announce_interval: float = 300.0,
                 rns_connect: Optional[str] = None,
                 rns_ratchets_enabled: bool = True,
                 rns_ratchet_interval: float = 1800.0,
                 rns_retained_ratchets: int = 8,
                 rns_admin_identities: Optional[list] = None,
                 rns_skip_handshake: bool = False,
                 rns_group_broadcast: bool = False,
                 rns_require_link_binding: bool = False,
                 # v0.9.1: optional LXMF interop (Sideband / Nomadnet)
                 lxmf_enabled: bool = False,
                 lxmf_storage: str = "~/.ironmesh/lxmf",
                 lxmf_display_name: str = "IronMesh",
                 lxmf_default_peer: Optional[str] = None,
                 lxmf_propagation_node: bool = False,
                 lxmf_propagation_storage: str = "~/.ironmesh/lxmf/propagation",
                 lxmf_telemetry_target: Optional[str] = None,
                 lxmf_telemetry_interval: float = 300.0,
                 # v0.5.2: QoS + rekey
                 lora_max_payload: int = 128,
                 rekey_interval: float = 1800.0,
                 # v0.6.0: protocol hardening
                 min_protocol_version: str = "ironmesh/0.3",
                 # v0.8.5: pending-trust message gate
                 require_message_promotion: bool = False,
                 pending_trust_queue_cap: int = 100,
                 # v0.9.5: opt-in relay-confidentiality (strip plaintext from
                 # e2e-sealed frames). OFF by default = wire-compatible.
                 e2e_strict_confidentiality: bool = False,
                 # v0.8.5: explicit trust store path. Defaults to
                 # DEFAULT_TRUST_PATH (~/.ironmesh/known_peers.json) for
                 # backwards compatibility, but can be overridden so
                 # integration tests + multi-daemon hosts don't clobber
                 # each other's known_peers.json.
                 trust_path: Optional[str] = None,
                 # v0.8.5.5: GUI bind address. Defaults to 127.0.0.1
                 # (loopback only); set to 0.0.0.0 to expose to a LAN
                 # or behind a reverse proxy that's not on the same
                 # host. The startup banner emits a loud warning when
                 # this is non-loopback so it cannot quietly make it
                 # into a production config.
                 gui_bind: str = "127.0.0.1",
                 # Explicit opt-in to an UNENCRYPTED auto-generated key
                 # file. Without it, auto-generated keys are encrypted
                 # with keys_passphrase (or the mesh passphrase).
                 plaintext_keys: bool = False):
        self.name = name
        self.port = port
        self.bind_address = bind_address
        self.gui_bind = gui_bind
        # Joiner-side bootstrap invite. When this node connects OUT to an
        # inviter's endpoint to bootstrap from a token, the parsed
        # InviteToken is stashed here so the client handshake can (a) send
        # the token string in its HELLO and (b) do verified-first-use:
        # reject the connection unless the server's presented identity key
        # equals the token's pinned inviter key. None on the ordinary path.
        self._pending_invite = None  # type: ignore[assignment]
        if not passphrase:
            raise ValueError(
                "Passphrase is required. Set --passphrase or IRONMESH_PASSPHRASE env var. "
                "IronMesh refuses to start with no passphrase for security."
            )
        if len(passphrase) < 12:
            raise ValueError(
                f"Passphrase too short ({len(passphrase)} chars). "
                "Minimum 12 characters required for security."
            )
        self.passphrase = passphrase
        # v0.9.4: when keys_path is non-default and the sibling on-disk
        # paths (db_path / routes_path / capabilities_path / trust_path)
        # are still at their default ~/.ironmesh/* values, auto-derive
        # them next to the keys file. Removes the silent-collision foot-
        # gun where two daemons on one host share the same trust store
        # because the caller only redirected keys_path. The 3-way live-
        # mesh test on 2026-05-17 tripped this — a live daemon + dialogue
        # orchestrator both wrote ~/.ironmesh/known_peers.json and the
        # second one got locked read-only via MAC mismatch.
        _DEFAULT_KEYS = "~/.ironmesh/keys.json"
        _DEFAULT_DB = "~/.ironmesh/data.db"
        _DEFAULT_ROUTES = "~/.ironmesh/routes.json"
        _DEFAULT_CAPS = "~/.ironmesh/capabilities.json"
        if keys_path and keys_path != _DEFAULT_KEYS:
            _key_dir = os.path.dirname(os.path.expanduser(keys_path))
            if _key_dir:
                if db_path == _DEFAULT_DB:
                    db_path = os.path.join(_key_dir, "data.db")
                if routes_path == _DEFAULT_ROUTES:
                    routes_path = os.path.join(_key_dir, "routes.json")
                if capabilities_path == _DEFAULT_CAPS:
                    capabilities_path = os.path.join(_key_dir, "capabilities.json")
                if trust_path is None:
                    trust_path = os.path.join(_key_dir, "known_peers.json")
        self.keys_path = keys_path
        self.keys_passphrase = keys_passphrase
        self.plaintext_keys = plaintext_keys
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.max_message_size = max_message_size

        self.peers: Dict[str, ew_protocol.PeerState] = {}
        self.bus = ew_protocol.MessageBus()
        self.ws_clients: Dict[str, websockets.WebSocketServerProtocol] = {}
        self._server = None
        self._running = False
        # Handles for the long-lived background loops spawned in _start, so
        # shutdown() can cancel them before closing the DB / event loop
        # (otherwise they can resume mid-sleep into a closed connection and
        # leave "Task was destroyed but it is pending" noise at loop close).
        self._background_tasks: list = []
        self._mdns_service = None
        self._mdns_listener = None
        # The key for encrypting SQLite payloads at rest is derived inside
        # MessageStore.open(): Argon2id over the daemon passphrase with a
        # per-database persisted salt, then an HKDF-SHA256 storage subkey
        # (see store.py). The slow KDF means a leaked disk image no longer
        # allows a fast offline dictionary attack on the passphrase.
        # Databases written by earlier releases with the legacy unsalted
        # SHA-256 key are re-encrypted forward transparently on open.
        self._db = MessageStore(db_path, storage_passphrase=passphrase)
        self._keypair: Optional[ew_keys.AgentKeys] = None
        self._known_peer_addresses: Dict[str, str] = {}
        # v0.8.5: per-instance trust store path. None ⇒ legacy default
        # (~/.ironmesh/known_peers.json). Set explicitly so multi-daemon
        # hosts don't collide.
        from ironmesh.trust import DEFAULT_TRUST_PATH as _DEFAULT_TRUST_PATH
        self.trust_path: str = trust_path or _DEFAULT_TRUST_PATH

        # Single-use invite ledger — the inviting node is authoritative for
        # bootstrap-token consumption. Co-located with the trust store so a
        # custom --trust-path (multi-daemon hosts, tests) keeps the ledger
        # in the same directory. Lazily constructed on first use so the
        # common no-invite path costs nothing.
        import os as _os
        self._invite_ledger_path: str = _os.path.join(
            _os.path.dirname(_os.path.expanduser(self.trust_path)) or ".",
            "invite_ledger.json",
        )
        self._invite_ledger = None  # type: ignore[assignment]

        # Rate limiting — per-peer and per-IP
        self._peer_rate_limiters: Dict[str, ew_protocol.TokenBucket] = {}
        self._ip_rate_limiters: Dict[str, ew_protocol.TokenBucket] = {}
        self._connection_rate_limiter = ew_protocol.TokenBucket(rate=0.167, burst=10)  # 10/min

        # Global daemon-wide message rate cap (defense-in-depth on top
        # of the per-peer caps). Off by default — per-peer limits are
        # sufficient when peers are mutually trusted. Operators that
        # expose the mesh to potentially-hostile peers should pass
        # ``--max-msgs-per-sec`` to enable a daemon-level token bucket
        # that bounds total inbound message throughput across all peers.
        # Burst defaults to one second of sustained rate so short
        # legitimate spikes don't trip the limiter.
        self._max_msgs_per_sec: Optional[float] = max_msgs_per_sec
        if max_msgs_per_sec is not None and max_msgs_per_sec > 0:
            burst = max(1, int(max_msgs_per_sec))
            self._global_msg_rate_limiter: Optional[ew_protocol.TokenBucket] = (
                ew_protocol.TokenBucket(rate=float(max_msgs_per_sec), burst=burst)
            )
        else:
            self._global_msg_rate_limiter = None

        # v0.7.2: per-peer bandwidth throttle (bytes/sec). Prevents a single
        # noisy peer from starving bandwidth for the rest of the mesh.
        # 0 disables the throttle; default ~1 MB/s with 1 MB burst allows
        # normal traffic but naturally back-pressures a flood. Value tuned
        # so a 1 KB frame costs 0.001s of refill, a 1 MB frame costs 1s.
        self._peer_bandwidth_limiters: Dict[str, ew_protocol.TokenBucket] = {}
        self._peer_bandwidth_rate = 1_048_576  # bytes/sec sustained
        self._peer_bandwidth_burst = 1_048_576  # 1 MB burst allowed
        self._peer_bandwidth_max_wait = 5.0  # seconds; longer → drop with audit
        self._peer_bandwidth_drops_total = 0

        # Replay protection
        self._replay_guard = ew_protocol.ReplayGuard(max_age=30.0)

        # Metrics
        self.metrics = Metrics()
        # v0.7.2: rolling sample of end-to-end message lifetimes (seconds)
        # for the Prometheus summary. Kept bounded to avoid unbounded growth.
        from collections import deque
        self._lifetime_samples: "deque[float]" = deque(maxlen=512)

        # Hooks
        self._hooks = None  # Will be set if hooks module is available

        # GUI dashboard
        self._gui_enabled = gui
        self._gui_clients: set = set()
        self._gui_server = None

        # mDNS peer allowlist (#5) — if set, only connect to listed peers
        self._allowed_peers: Optional[list] = allowed_peers
        # Default-deny mDNS — require explicit opt-in for open discovery
        self._open_discovery: bool = open_discovery
        # TLS preference for outbound connections
        self._allow_plaintext_ws: bool = allow_plaintext_ws
        # Outbound TLS validation. Default mirrors historical mesh behavior:
        # WSS is line-level confidentiality only; peer authentication runs at
        # the application layer (passphrase HMAC + Ed25519 + TOFU). Set
        # strict_tls=True to require CA-validated certs (pinned_ca_path
        # supplies a private CA bundle when present).
        self._strict_tls: bool = strict_tls
        self._pinned_ca_path: Optional[str] = pinned_ca_path

        # Audit log — initialized after keys are loaded
        self._audit: Optional[AuditLog] = None

        # v0.8.5.7: audit-log counter sync state.
        # _audit_counter_offset — where the next scan picks up.
        # _audit_counter_inode — tracks file identity. If the live
        #   audit log has a different inode than the code last saw, rotation
        #   happened (even if the live file is now LARGER than the
        #   offset the code stored from the old file). The
        #   `current_size < offset` heuristic missed the case where
        #   post-rotation writes re-grew the live file past the
        #   pre-rotation offset before the next scan.
        # _in_proc_counter_bumps — events this daemon already bumped
        #   in-process; decremented by the scanner so this code does not
        #   double-count.
        # _counter_lock — protects both fields. The bump path can be
        #   called from mesh.py's worker thread (cross-transport replay
        #   dedup); the scanner runs on the asyncio thread. Without
        #   the lock, a concurrent bump + scan could lose an increment
        #   or corrupt the reservation dict.
        self._audit_counter_offset: int = 0
        self._audit_counter_inode: Optional[int] = None
        self._in_proc_counter_bumps: Dict[str, int] = {}
        import threading as _threading
        self._counter_lock = _threading.Lock()

        # Fingerprint pinning for mDNS — maps agent_name -> {fingerprint, address}
        # Populated after first successful handshake. mDNS announcements rejected if
        # cached fingerprint doesn't match a new address claim.
        self._pinned_peers: Dict[str, dict] = {}

        # Auth failure rate limiting (#6) — per-IP tracking
        self._auth_failures: Dict[str, list] = {}
        self._auth_block_duration = 300  # 5 minutes
        self._auth_max_failures = 3
        self._auth_failure_window = 300  # 5 minutes

        # v0.8.5.2: per-peer gate-audit write rate-limit. Prevents a
        # blocked peer from flooding the audit log with MSG_GATED_DROP
        # events faster than rotation retention, which could push
        # earlier forensic evidence out of the retained archives.
        # Keyed by originator node_id -> last audit write timestamp.
        self._gate_audit_last_write: Dict[str, float] = {}

        # GUI token (#9) — required for /metrics, /api/state, /ws
        import secrets
        self._gui_token: str = secrets.token_urlsafe(32)

        # Background task timing
        self._heartbeat_interval = 30
        # v0.7.2: peer drop alerting — emit EVENT_PEER_DROPPED_LONG when a
        # peer has been offline longer than this threshold. 0 disables.
        self._long_drop_threshold_seconds = 300
        self._long_drop_check_interval = 30
        # Count of long-drop alerts emitted (for /metrics)
        self._peer_long_drops_total = 0
        self._cleanup_interval = 3600
        self._reconnect_interval = 15
        self._queue_flush_interval = 5

        # v0.4: mesh + capability + observability config
        self.config = _DaemonConfig(
            mesh_routing=mesh_routing,
            max_hops=max_hops,
            route_announce_interval=route_announce_interval,
            route_ttl=route_ttl,
            routes_path=routes_path,
            capabilities=list(capabilities) if capabilities else [],
            capabilities_path=capabilities_path,
            capability_announce_interval=capability_announce_interval,
            metrics_format=metrics_format,
            log_format=log_format,
            audit_log_max_bytes=audit_log_max_bytes,
            require_message_promotion=require_message_promotion,
            pending_trust_queue_cap=pending_trust_queue_cap,
            e2e_strict_confidentiality=e2e_strict_confidentiality,
        )
        self._mesh = None  # MeshRouter, instantiated in _start() after keypair load
        self._capabilities = None  # CapabilityRegistry, instantiated in _start()

        # v0.9.4 (signed capability announcement): cached signed CAPABILITY_ANNOUNCE envelope bytes,
        # keyed by remote origin. Populated when a signed announce for
        # ``origin`` arrives and verifies; replayed verbatim by the
        # announce loop when re-gossiping that origin's caps to neighbors.
        # Without the cache, a relay cannot meaningfully re-broadcast a
        # third-party origin's caps under the signed-announce contract (the relay has no access
        # to the origin's signing key). With the cache, gossip continues
        # to converge across multi-hop meshes — the cached envelope is
        # fresh as long as the freshness window permits.
        # ``OrderedDict`` for LRU eviction semantics; sized generously
        # because cached entries are bounded by known-origin count.
        self._signed_announce_cache: "OrderedDict[str, dict]" = OrderedDict()
        # Per-origin replay-dedup LRU for ``(origin, announced_at)`` —
        # second copy of the same signed envelope is a no-op (does not
        # crash, does not double-emit audit / metric / observe). Bounded
        # at 4096 entries — plenty for a mesh of thousands of peers
        # cycling at 60s announce intervals.
        self._announce_dedup: "OrderedDict[str, float]" = OrderedDict()
        self._SIGNED_ANNOUNCE_CACHE_MAX = 4096
        self._ANNOUNCE_DEDUP_MAX = 4096

        # v0.5: Reticulum transport
        self._rns_enabled = rns_enabled
        self._rns_configdir = rns_configdir
        self._rns_announce_interval = rns_announce_interval
        self._rns_connect = rns_connect  # comma-separated dest hashes
        self._rns_ratchets_enabled = rns_ratchets_enabled
        self._rns_ratchet_interval = rns_ratchet_interval
        self._rns_retained_ratchets = rns_retained_ratchets
        # v0.9.1: Admin RPC allow-list — explicit RNS identity hashes
        # permitted to call /im/admin/* paths. Empty = admin RPC disabled.
        self._rns_admin_identities = list(rns_admin_identities or [])
        # v0.9.2: opt in to handshake compression on identified RNS Links.
        # Advertised in announce as the `hskip` feature. Both peers must
        # advertise + transport must be RNS Link before the skip kicks in.
        self._rns_skip_handshake = rns_skip_handshake
        # ironmesh/0.9: when True, RNS HELLOs from peers that cannot
        # produce the rns_link_id binding (pre-0.9 peers) are rejected
        # instead of falling back to the legacy unbound behavior. 0.9+
        # peers must produce the binding regardless of this flag; it
        # exists to let operators close the legacy-peer residual
        # entirely on meshes where every node has upgraded.
        self._rns_require_link_binding = rns_require_link_binding
        # v0.9.2: opt in to GROUP-destination broadcast on RNS. Advertised
        # as the `group` feature. All peers in the mesh that enable this
        # derive the same symmetric group key from the passphrase via
        # HKDF and listen on a deterministic group destination — a single
        # broadcast packet reaches every member.
        self._rns_group_broadcast = rns_group_broadcast
        # v0.9.1: LXMF listener config — when _lxmf_enabled is True
        # the announce app_data also advertises the `lxmf` feature so
        # peers know this node speaks Sideband / Nomadnet messages.
        self._lxmf_enabled = lxmf_enabled
        self._lxmf_storage = lxmf_storage
        self._lxmf_display_name = lxmf_display_name
        self._lxmf_default_peer = lxmf_default_peer
        self._lxmf_propagation_node = lxmf_propagation_node
        self._lxmf_propagation_storage = lxmf_propagation_storage
        self._lxmf_telemetry_target = lxmf_telemetry_target
        self._lxmf_telemetry_interval = lxmf_telemetry_interval
        self._lxmf: Optional[object] = None  # LXMFListener instance once started
        self._reticulum: Optional[object] = None  # ReticulumTransport instance
        self._known_rns_hashes: dict = {}  # peer_id -> rns_dest_hash_hex
        # v0.9.1: peers heard via RNS announces but not (yet) connected.
        # dest_hash_hex -> {name, version, node_id, capabilities, features,
        #                   identity_hash, hops, first_seen, last_seen}
        # Auto-Link to these peers is a Phase 2/11 concern; Phase 1 just
        # records what is heard so the dashboard and capability registry
        # see the same view as the WebSocket peers.
        #
        # THREADING MODEL: writes happen on the asyncio event loop only —
        # the RNS announce handler runs on the RNS Transport thread but
        # bridges via `loop.call_soon_threadsafe(...)` (see
        # ReticulumTransport._on_announce_received), so the actual mutation
        # in `_on_rns_peer_announced` executes on the loop. Reads from
        # async methods on the loop are therefore race-free.
        #
        # However, SYNC methods callable from worker threads (e.g.
        # `broadcast_via_rns_group`, used by Agent SDK fire-and-forget
        # broadcasts) MUST snapshot before iterating — `list(self._rns_discovered.values())`
        # — because the loop can mutate the dict concurrently with their
        # iteration. Failing to snapshot causes intermittent
        # `RuntimeError: dictionary changed size during iteration` under
        # busy-mesh load. Future maintainers: keep the `list(...)` even
        # when adding new sync iteration sites.
        self._rns_discovered: dict = {}
        self._pending_pings: dict = {}  # peer_id -> monotonic send time (for RTT)
        # v0.5.2: LoRa QoS + session key rotation
        self._lora_max_payload = lora_max_payload
        self._rekey_interval = rekey_interval
        # v0.6.0: protocol hardening
        self._min_protocol_version = min_protocol_version
        # v0.9.5: strict relay-confidentiality only delivers its guarantee if
        # NO pre-0.9 node can receive a stripped frame. A stripped frame
        # reaching a v0.9.4 destination is delivered UNAUTHENTICATED (that node
        # never verifies the inner source signature). A per-peer check cannot
        # cover multi-hop relay destinations we never handshook, so the only
        # sound enforcement is the protocol floor: when strict is enabled,
        # raise the effective floor to ironmesh/0.9 so every peer — direct or
        # relay-destination — is a 0.9+ node that verifies post-unseal. This
        # matches the operator's asserted "fully-upgraded mesh" intent; any
        # genuinely pre-0.9 peer is refused at handshake rather than silently
        # handed an unauthenticated body.
        if e2e_strict_confidentiality and \
                _parse_protocol_version(self._min_protocol_version) < (0, 9):
            logger.warning(
                "--e2e-strict-confidentiality raises the protocol floor from "
                "%s to ironmesh/0.9: pre-0.9 peers cannot verify a stripped "
                "e2e frame's source and would receive it unauthenticated, so "
                "they are refused at handshake while strict mode is on.",
                self._min_protocol_version,
            )
            self._min_protocol_version = "ironmesh/0.9"
        self._backoff_state: dict = {}  # peer_id -> {"attempts": int, "next_at": float}
        # v0.6.1: gate to prevent overlapping reconnect attempts from multiple
        # paths (_reconnect_loop / _try_transport_failover / _discover_loop /
        # _on_peer_discovered). Entries aged out after 60s to prevent stick.
        self._reconnecting: dict = {}  # peer_id_or_name -> started_at (monotonic)
        # Protect duplicate-connection check + peer-state assignment +
        # cleanup atomically. Prevents identity hijacking when two
        # connections race to the same peer_id.
        self._peer_lock = asyncio.Lock()
        # Serialize auth-failure tracking to prevent rate-
        # limit bypass via concurrent handshake attempts.
        self._auth_failures_lock = asyncio.Lock()

    @property
    def node_id(self) -> str:
        if self._keypair:
            return self._keypair.get_fingerprint()
        return "uninitialized"

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    async def _start(self):
        """Launch the bridge and all background tasks."""
        self._loop = asyncio.get_event_loop()
        # Load or generate identity keys
        # The mesh passphrase doubles as the key-file fallback: `ironmesh
        # setup` encrypts the key file with the same passphrase it writes
        # to the passphrase file, so the wizard's printed run command
        # works without a separate --keys-passphrase.
        self._keypair = await ensure_agent_keys(
            self.keys_path, self.keys_passphrase,
            fallback_passphrase=self.passphrase,
            allow_plaintext=self.plaintext_keys,
        )

        # Key rotation via env var
        if os.environ.get("IRONMESH_ROTATE_KEYS") == "1":
            logger.info("Key rotation triggered")
            self._keypair = await rotate_keys(
                self.keys_path, self.keys_passphrase,
                fallback_passphrase=self.passphrase,
                allow_plaintext=self.plaintext_keys,
            )

        # v0.8.5.6: silence the websockets-server "did not receive a valid
        # HTTP request" ERROR that fires every time a peer dials wss://
        # against the plaintext-ws server (TLS-first fallback). The
        # peer's second connection succeeds with ws:// and the IronMesh
        # handshake completes — these errors are cosmetic noise, paired
        # 1:1 with successful HELLOs in the log. Real WS handshake
        # failures still reach DEBUG and any unexpected error type still
        # reaches ERROR, so this code does not lose actionable signal.
        class _SuppressTLSFallbackNoise(logging.Filter):
            def filter(self, record):
                if record.levelno != logging.ERROR:
                    return True
                msg = record.getMessage()
                exc = getattr(record, "exc_info", None)
                exc_text = repr(exc[1]) if exc else ""
                noise = (
                    "did not receive a valid HTTP request" in msg
                    or "did not receive a valid HTTP request" in exc_text
                    or "InvalidMessage" in exc_text
                )
                if noise:
                    # Re-emit at DEBUG so operators can still inspect them
                    # under --log-level DEBUG without polluting INFO logs.
                    logger.debug("websockets WS-upgrade reject (likely "
                                 "TLS-first fallback): %s", msg)
                    return False
                return True
        logging.getLogger("websockets.server").addFilter(
            _SuppressTLSFallbackNoise()
        )

        # Initialize audit log with HMAC key derived from identity key
        audit_key = hashlib.sha256(
            self._keypair.ed25519_secret + b"ironmesh-audit-v1"
        ).digest()
        self._audit = AuditLog(
            path=os.path.join(os.path.dirname(self._db.db_path), "audit.log"),
            hmac_key=audit_key,
            max_bytes=getattr(self.config, "audit_log_max_bytes", 10 * 1024 * 1024),
        )
        # Verify chain integrity once on startup. Surfaces pre-existing
        # TAMPER without blocking — a corrupted chain is an operator
        # problem, not a reason to refuse to start. Without this check,
        # corruption from a prior run (multi-writer race pre-v0.8.5.6,
        # or filesystem damage) only surfaced when someone ran
        # `ironmesh audit verify` by hand.
        try:
            valid, entries, first_bad = self._audit.verify()
            if not valid:
                logger.warning(
                    "Audit chain TAMPER detected at entry %s (of %d scanned). "
                    "Prior entries remain valid; new writes from this start "
                    "forward will chain cleanly. See OPERATOR_RUNBOOK for "
                    "recovery guidance.",
                    first_bad, entries,
                )
            else:
                logger.info(
                    "Audit chain verified clean (%d entries).", entries,
                )
        except Exception as e:
            logger.warning("Audit chain verification skipped: %s", e)
        # Reconcile Prometheus counters with the tail of the audit log
        # so restart doesn't zero out every mirrored counter. Bounded
        # at 10k entries to keep startup fast on hosts with huge logs.
        self._reconcile_counters_from_audit_tail(limit=10_000)
        self._audit.log(EVENT_STARTUP, {
            "node_id": self.node_id, "name": self.name, "port": self.port,
        })
        # v0.9.3: prime the posture gauges so a fresh `/metrics` scrape
        # reflects strict_tls + trust-store-envelope state without
        # waiting for first-message activity.
        self.metrics.strict_tls_enabled = 1 if self._strict_tls else 0
        try:
            ts_path = os.path.expanduser(
                getattr(self, "trust_path", None) or "~/.ironmesh/known_peers.json"
            )
            if os.path.exists(ts_path):
                import json as _json
                with open(ts_path) as _f:
                    _envelope = _json.load(_f)
                if isinstance(_envelope, dict):
                    if _envelope.get("version") == 2:
                        self.metrics.trust_store_version = 2
                    elif "_mac" in _envelope or "peers" in _envelope:
                        self.metrics.trust_store_version = 1
        except (OSError, ValueError):
            pass
        # v0.9.3: surface posture-changing flags as their own audit events
        # so forensic review can pinpoint when a daemon was started in a
        # stricter mode without grepping for free-form startup args.
        if self._strict_tls:
            try:
                from ironmesh.audit import EVENT_STRICT_TLS_ENABLED
                self._audit.log(EVENT_STRICT_TLS_ENABLED, {
                    "node_id": self.node_id,
                    "trust_anchor": (
                        self._pinned_ca_path or "system_trust_store"
                    ),
                })
            except ImportError:
                pass
        if self._global_msg_rate_limiter is not None:
            try:
                from ironmesh.audit import EVENT_STARTUP as _e
                self._audit.log("GLOBAL_RATE_CAP_CONFIGURED", {
                    "node_id": self.node_id,
                    "max_msgs_per_sec": self._max_msgs_per_sec,
                })
                _ = _e  # quiet linters that flag the import-as-binding
            except ImportError:
                pass

        # Open database
        await self._db.open()

        # Try to load hooks
        try:
            from ironmesh.hooks import HookManager
            self._hooks = HookManager()
        except ImportError:
            pass

        # TLS setup with hardened configuration
        ssl_context = None
        if self.tls_cert and self.tls_key:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(self.tls_cert, self.tls_key)
            # Enforce TLS 1.2+ only
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            # Disable compression (CRIME attack mitigation)
            ssl_context.options |= ssl.OP_NO_COMPRESSION
            # Prefer server cipher order
            ssl_context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
            logger.info("TLS enabled with cert: %s (TLS 1.2+ enforced)", self.tls_cert)

        # Start WebSocket server
        self._running = True
        self._server = await websockets.serve(
            self._handle_connection,
            self.bind_address,
            self.port,
            ssl=ssl_context,
            max_size=self.max_message_size,
            # v0.6.1: native WebSocket pings detect dead connections
            # much faster than app-level heartbeat alone.
            ping_interval=20,
            ping_timeout=10,
            # v0.9.4: SO_REUSEADDR so daemon restart on Windows doesn't
            # trip Errno 10048 ("only one usage of each socket address
            # ... is normally permitted") while the previous bind sits
            # in TIME_WAIT. POSIX already allows this in most kernels;
            # Windows requires the explicit flag. Live-mesh test on
            # 2026-05-17 hit this three times during orchestrator
            # restarts.
            reuse_address=True,
        )
        scheme = "wss" if ssl_context else "ws"
        logger.info("WebSocket server started on %s://%s:%d", scheme, self.bind_address, self.port)

        # Register mDNS (in thread to avoid blocking event loop)
        try:
            loop = asyncio.get_event_loop()
            self._mdns_service = await loop.run_in_executor(
                None, lambda: ew_discovery.register_service(
                    self.name, self.port,
                    # full public_key NOT broadcast; only a 16-hex idhash
                    bind_address=self.bind_address,
                    identity_pubkey_bytes=self._keypair.ed25519_public,
                )
            )
            logger.info("mDNS registered: %s on port %d", self.name, self.port)

            # Start mDNS browsing to discover other agents on the LAN
            self._mdns_listener = ew_discovery.AgentListener(
                on_discovered=self._on_peer_discovered,
            )
            self._mdns_listener.start(self._mdns_service._zc)
        except Exception as e:
            logger.warning("mDNS registration failed (%s: %s); peers must be added manually",
                         type(e).__name__, e)

        # Start GUI dashboard (or fallback to metrics-only)
        if self._gui_enabled:
            await self._start_gui_server()
            self._wire_gui_hooks()
            self._spawn_bg(self._gui_state_loop())
        else:
            self._spawn_bg(self._metrics_server())

        # Background tasks (tracked so shutdown can cancel them)
        self._spawn_bg(self._heartbeat_loop())
        self._spawn_bg(self._cleanup_loop())
        self._spawn_bg(self._audit_counter_sync_loop())
        self._spawn_bg(self._reconnect_loop())
        self._spawn_bg(self._queue_flush_loop())
        self._spawn_bg(self._discover_loop())
        self._spawn_bg(self._rekey_loop())
        self._spawn_bg(self._long_drop_watchdog())

        # v0.4: Mesh routing — instantiate after keypair so node_id is real
        if self.config.mesh_routing != "off":
            self._mesh = MeshRouter(self, self.config)
            try:
                self._mesh.load_persisted_routes()
            except Exception as e:
                logger.warning("Failed to load persisted routes: %s", e)
            self._spawn_bg(self._mesh.announce_loop())
            self._spawn_bg(self._mesh.cleanup_loop())
            logger.info("Mesh routing enabled (mode=%s, max_hops=%d)",
                        self.config.mesh_routing, self.config.max_hops)
        else:
            logger.info("Mesh routing disabled (mesh_routing=off)")

        # v0.4: Capability registry — keyed off identity for persistence HMAC
        cap_hmac_key = hashlib.sha256(
            self._keypair.ed25519_secret + b"ironmesh-capabilities-v1"
        ).digest()
        self._capabilities = CapabilityRegistry(
            my_node_id=self.node_id,
            persist_path=self.config.capabilities_path,
            hmac_key=cap_hmac_key,
        )
        try:
            self._capabilities.load()
        except Exception as e:
            logger.debug("Capability load failed: %s", e)
        # v0.8.5.6: when the operator (CLI / SDK / config)
        # provides an explicit capability list, treat it as
        # authoritative. The previous additive pattern
        # (load + advertise_local-per-cap) merged old persisted caps
        # into the new set, producing "ghost capabilities" that kept
        # being announced after a role / model change. set_local
        # replaces the entire local set so the announce reflects the
        # current config exactly.
        if self.config.capabilities:
            self._capabilities.set_local(self.config.capabilities)
            try:
                self._capabilities.save()
            except OSError as e:
                # Disk write failed (permissions, full FS, network mount
                # gone). The in-memory registry is still valid for the
                # session; the announce loop also calls save() each
                # cycle so a transient FS error self-heals. Logged for
                # operator visibility.
                logger.warning(
                    "Capability registry initial save failed: %s — "
                    "will retry on next announce loop", e,
                )
            logger.info("Advertising %d local capability/ies: %s",
                        len(self.config.capabilities),
                        ", ".join(self.config.capabilities))
        self._spawn_bg(self._capability_announce_loop())

        # v0.5: Reticulum transport
        if self._rns_enabled and _HAS_RNS and ReticulumTransport is not None:
            try:
                self._reticulum = ReticulumTransport(
                    daemon=self,
                    announce_interval=self._rns_announce_interval,
                    configdir=self._rns_configdir,
                    ratchets_enabled=self._rns_ratchets_enabled,
                    ratchet_interval=self._rns_ratchet_interval,
                    retained_ratchets=self._rns_retained_ratchets,
                    admin_identities=self._rns_admin_identities,
                    group_broadcast=self._rns_group_broadcast,
                    group_secret=(self.passphrase.encode("utf-8")
                                  if self._rns_group_broadcast and self.passphrase
                                  else None),
                )
                self._reticulum.start(asyncio.get_event_loop())
                # Connect to any startup destinations
                if self._rns_connect:
                    hashes = [h.strip() for h in self._rns_connect.split(",") if h.strip()]
                    for dest_hash in hashes:
                        asyncio.ensure_future(self._connect_and_track_rns(dest_hash))
            except Exception as e:
                logger.error("Reticulum transport failed to start: %s", e)
                self._reticulum = None
        elif self._rns_enabled and not _HAS_RNS:
            logger.warning("--reticulum flag set but rns package not installed. "
                           "Install with: pip install ironmesh[rns]")

        # v0.9.1: optional LXMF listener for Sideband / Nomadnet interop.
        # Requires the `lxmf` extra. Reuses the Reticulum singleton the
        # peer transport just started (or starts its own if --reticulum
        # was not also passed).
        if self._lxmf_enabled:
            try:
                from .lxmf_listener import _HAS_LXMF, LXMFListener
                if not _HAS_LXMF:
                    logger.warning(
                        "--lxmf flag set but lxmf package not installed. "
                        "Install with: pip install ironmesh[lxmf]"
                    )
                else:
                    self._lxmf = LXMFListener(
                        daemon=self,
                        storage_path=self._lxmf_storage,
                        display_name=self._lxmf_display_name,
                        default_inbound_peer=self._lxmf_default_peer,
                        propagation_node=self._lxmf_propagation_node,
                        propagation_storage_path=self._lxmf_propagation_storage,
                        telemetry_target=self._lxmf_telemetry_target,
                        telemetry_interval=self._lxmf_telemetry_interval,
                    )
                    self._lxmf.start(asyncio.get_event_loop())
            except Exception as e:
                logger.error("LXMF listener failed to start: %s", e)
                self._lxmf = None

        logger.info("IronMesh Bridge running as '%s' (node_id=%s)", self.name, self.node_id)
        logger.info("GUI token: %s", self._gui_token)

    # ------------------------------------------------------------------
    # Connection handling with ephemeral ECDH handshake
    # ------------------------------------------------------------------

    async def _handle_connection(self, websocket, path=None):
        """Handle incoming WebSocket connection: passphrase auth -> ephemeral ECDH -> message loop."""
        peer_id = None
        self.metrics.connections_total += 1

        # Connection rate limiting (global)
        if not self._connection_rate_limiter.consume():
            self.metrics.rate_limits_triggered += 1
            logger.warning("Connection rate limited (global)")
            try:
                await websocket.send(json.dumps({
                    "type": ew_protocol.MessageType.RATE_LIMITED,
                    "error": "Too many connections",
                }))
            except (websockets.exceptions.ConnectionClosed, OSError, RuntimeError):
                # Best-effort error notification to a misbehaving peer:
                # ConnectionClosed = peer already gave up; OSError =
                # socket-level failure mid-send; RuntimeError = event
                # loop shutting down. None of these block the local
                # control-flow goal (refuse the connection); silently
                # drop and let the outer `return` close it out.
                pass
            return

        # Per-IP rate limiting
        remote_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
        if remote_ip not in self._ip_rate_limiters:
            self._ip_rate_limiters[remote_ip] = ew_protocol.TokenBucket(rate=0.5, burst=5)  # 5 conn/10s per IP
        if not self._ip_rate_limiters[remote_ip].consume():
            self.metrics.rate_limits_triggered += 1
            logger.warning("Connection rate limited for IP %s", remote_ip)
            try:
                await websocket.send(json.dumps({
                    "type": ew_protocol.MessageType.RATE_LIMITED,
                    "error": "Too many connections from your IP",
                }))
            except (websockets.exceptions.ConnectionClosed, OSError, RuntimeError):
                # Same pattern as the connection-cap notify above.
                pass
            return

        try:
            # Check if IP is blocked due to auth failures.
            if await self._is_ip_blocked(remote_ip):
                logger.warning("Auth-blocked IP %s attempted connection", remote_ip)
                try:
                    await websocket.send(json.dumps({
                        "type": ew_protocol.MessageType.PASSPHRASE_REJECTED,
                        "error": "Too many authentication failures. Try again later.",
                    }))
                except (websockets.exceptions.ConnectionClosed, OSError, RuntimeError):
                    # Best-effort auth-blocked notification — see
                    # rate-limit comments above for rationale.
                    pass
                return

            # --- STAGE 1: Passphrase Auth ---
            #
            # v0.9.2 (chunk A): on RNS Links where both peers advertised
            # the `hskip` feature in their announces, the entire stage-1
            # round trip is replaced by a fixed channel-binding sentinel.
            # The RNS Link itself authenticates both ends via Identity,
            # so the IronMesh-layer passphrase is redundant on identified
            # Links. The fixed sentinel is signed into the HELLO payload
            # the same way a random server_nonce would be, so signature-
            # verification logic downstream is unchanged.
            # v0.9.2 chunk A — server-driven Stage-1 skip (corrected
            # design after the v0.9.2-pre-r1 unilateral-decision bug).
            # The server is the active party and SPEAKS FIRST. If both
            # sides are eligible to skip (RNS Link + peer's hskip
            # advertised), the server emits SKIP_OFFER carrying the
            # channel-binding sentinel; otherwise it emits the normal
            # PASSPHRASE_CHALLENGE. The client type-dispatches on the
            # first server message — never decides skip unilaterally.
            # This guarantees both sides agree before HELLO is sent,
            # eliminating the crossed-message handshake failure.
            #
            # On RNS Links, briefly poll for the remote's identify
            # proof to land before checking eligibility. The outbound
            # side's `link.identify()` call races our eligibility check
            # otherwise, and we'd silently fall back to the legacy
            # flow despite the peer having advertised hskip.
            if (RNSLinkAdapter is not None
                    and isinstance(websocket, RNSLinkAdapter)
                    and getattr(self, "_rns_skip_handshake", False)):
                await self._await_remote_identity(websocket, timeout=1.5)
            skip_stage1 = self._handshake_skip_eligible_server(websocket)
            if skip_stage1:
                server_nonce = ew_protocol.Handshake.skip_channel_binding()
                # Tell the client: skip is on, here's the channel binding.
                await websocket.send(json.dumps({
                    "type": ew_protocol.MessageType.SKIP_OFFER,
                    "from": self.node_id,
                    "channel_binding": server_nonce.hex(),
                    "protocol_version": PROTOCOL_VERSION,
                }))
                # Counter + telemetry only after the SKIP_OFFER is on the
                # wire — a client disconnect mid-send shouldn't inflate
                # the offered count. The matching `activated` counter is
                # incremented client-side only when the offer is accepted,
                # so divergence between fleet-wide sums of offered vs
                # activated reveals send failures or downgrade-rejects.
                self._inc_metric("handshake_skips_offered")
                logger.debug(
                    "Handshake skip offered — peer is RNS-identified and advertises hskip"
                )
                _otel_span_event(
                    "handshake.skip.offered",
                    getattr(websocket, "remote_identity_hash", "unknown"),
                    {"ironmesh.skip.side": "server", "ironmesh.transport": "rns"},
                )
            else:
                server_nonce = ew_protocol.Handshake.generate_server_nonce()

                await websocket.send(json.dumps({
                    "type": ew_protocol.MessageType.PASSPHRASE_CHALLENGE,
                    "from": self.node_id,
                    "nonce": server_nonce.hex(),
                    "protocol_version": PROTOCOL_VERSION,
                }))

                raw = await asyncio.wait_for(websocket.recv(), timeout=30)
                msg = json.loads(raw)

                if msg.get("type") != ew_protocol.MessageType.PASSPHRASE_CHALLENGE:
                    await websocket.send(json.dumps({
                        "type": ew_protocol.MessageType.PASSPHRASE_REJECTED,
                        "from": self.node_id,
                        "error": f"Expected PASSPHRASE_CHALLENGE, got {msg.get('type')}",
                    }))
                    self.metrics.handshake_failures += 1
                    return

                proof = msg.get("proof")
                if not proof or not ew_protocol.Handshake.verify_passphrase_proof(
                    proof, self.passphrase, server_nonce
                ):
                    await self._record_auth_failure(remote_ip)
                    await websocket.send(json.dumps({
                        "type": ew_protocol.MessageType.PASSPHRASE_REJECTED,
                        "from": self.node_id,
                        "error": "Wrong passphrase",
                    }))
                    self.metrics.handshake_failures += 1
                    logger.warning("Auth failed for incoming connection from %s — wrong passphrase", remote_ip)
                    return

                # Auth passed — mutual auth: server also proves it knows the passphrase
                # Server computes proof over reversed nonce so it's different from client's proof
                server_proof = ew_protocol.Handshake.compute_passphrase_proof(
                    self.passphrase, server_nonce[::-1]  # reversed nonce for separation
                )
                await websocket.send(json.dumps({
                    "type": ew_protocol.MessageType.PASSPHRASE_VERIFIED,
                    "from": self.node_id,
                    "status": "verified",
                    "server_proof": server_proof,
                }))

            # --- STAGE 2: Ephemeral ECDH Key Exchange ---
            # Generate the ephemeral X25519 keypair for this session
            my_ephemeral_private, my_ephemeral_public = ew_keys.generate_ephemeral()

            raw = await asyncio.wait_for(websocket.recv(), timeout=30)
            msg = json.loads(raw)

            if msg.get("type") != ew_protocol.MessageType.HELLO:
                logger.warning("Expected HELLO, got %s", msg.get("type"))
                self.metrics.handshake_failures += 1
                return

            claimed_peer_id = msg.get("from")
            peer_name = msg.get("name", claimed_peer_id)
            peer_ephemeral_b64 = msg.get("ephemeral_public")
            peer_identity_b64 = msg.get("identity_public")

            if not claimed_peer_id or not peer_ephemeral_b64:
                await websocket.send(json.dumps({
                    "type": ew_protocol.MessageType.ERROR,
                    "error": "Invalid HELLO: missing ephemeral_public",
                    "code": ew_protocol.ErrorCode.INVALID_FRAME,
                }))
                self.metrics.handshake_failures += 1
                return

            # Verify Ed25519 signature on HELLO (proves identity owns the keys).
            # ironmesh/0.9 — the client's advertised version (inside the
            # signed canonical body) selects the scheme: 0.9+ REQUIRES the
            # detached domain-separated signature under SIG_CTX_HELLO;
            # older versions use the legacy attached form. The version
            # cannot be rewritten in transit without breaking the signature
            # under either scheme, so a stripped/rewritten version fails
            # closed instead of silently selecting the legacy path.
            peer_signature_b64 = msg.get("signature")
            client_hello_version = msg.get("protocol_version", "")

            # ironmesh/0.9: enforce the RNS link-binding policy BEFORE the
            # signature check. On RNS Links, 0.9+ clients (and every client
            # after a stage-1 skip) must bind their HELLO to the id of the
            # link it arrived on; on the WebSocket path the field must be
            # absent. The returned claimed binding feeds the canonical-body
            # reconstruction below, so the HELLO signature covers it — a
            # matching-but-forged claim still fails at the signature step.
            bind_ok, claimed_link_binding, bind_reason = (
                self._evaluate_rns_hello_binding(
                    websocket, msg, client_hello_version, skip_stage1,
                )
            )
            if not bind_ok:
                logger.warning(
                    "HELLO link-binding check FAILED for %s: %s",
                    claimed_peer_id, bind_reason,
                )
                await websocket.send(json.dumps({
                    "type": ew_protocol.MessageType.ERROR,
                    "error": f"HELLO link binding rejected: {bind_reason}",
                    "code": ew_protocol.ErrorCode.AUTH_FAILED,
                }))
                self.metrics.handshake_failures += 1
                return

            hello_sig_scheme = "unsigned"
            if peer_identity_b64 and peer_signature_b64:
                try:
                    from nacl.signing import VerifyKey
                    verify_key = VerifyKey(base64.b64decode(peer_identity_b64))
                    # Reconstruct the canonical signed payload (with channel binding)
                    canonical = ew_protocol.canonical_hello_bytes(
                        channel_binding=server_nonce.hex(),
                        ephemeral_public=peer_ephemeral_b64,
                        identity_public=peer_identity_b64,
                        name=peer_name,
                        protocol_version=client_hello_version,
                        rns_link_id=claimed_link_binding,
                    )
                    if _peer_supports_hello_ctx(client_hello_version):
                        ew_crypto.verify_detached_with_context(
                            verify_key,
                            ew_crypto.SIG_CTX_HELLO,
                            canonical,
                            base64.b64decode(peer_signature_b64),
                        )
                        hello_sig_scheme = "context-v1"
                    else:
                        extracted = ew_crypto.verify_signature(
                            verify_key, base64.b64decode(peer_signature_b64)
                        )
                        # Verify extracted payload matches reconstructed canonical
                        if extracted != canonical:
                            raise ValueError("HELLO signature payload does not match canonical form")
                        hello_sig_scheme = "legacy"
                    logger.debug("HELLO signature verified for peer %s (%s)",
                                 claimed_peer_id, hello_sig_scheme)
                except Exception as e:
                    logger.warning("HELLO signature verification FAILED for %s: %s", claimed_peer_id, e)
                    await websocket.send(json.dumps({
                        "type": ew_protocol.MessageType.ERROR,
                        "error": "HELLO signature verification failed",
                        "code": ew_protocol.ErrorCode.AUTH_FAILED,
                    }))
                    self.metrics.handshake_failures += 1
                    return
            elif peer_identity_b64 and not peer_signature_b64:
                logger.warning("Peer %s sent identity key but no signature — rejecting", claimed_peer_id)
                await websocket.send(json.dumps({
                    "type": ew_protocol.MessageType.ERROR,
                    "error": "HELLO signature required when identity_public is provided",
                    "code": ew_protocol.ErrorCode.AUTH_FAILED,
                }))
                self.metrics.handshake_failures += 1
                return

            # ironmesh/0.9: the skip path must end in a SIGNED client
            # HELLO — an unsigned HELLO would leave the link binding
            # (and the constant skip sentinel) unauthenticated. "Present
            # and verified" means covered by the HELLO signature.
            if skip_stage1 and hello_sig_scheme == "unsigned":
                logger.warning(
                    "Unsigned HELLO from %s after handshake skip — "
                    "rejecting (skip requires a signed, link-bound HELLO)",
                    claimed_peer_id,
                )
                await websocket.send(json.dumps({
                    "type": ew_protocol.MessageType.ERROR,
                    "error": "handshake skip requires a signed, link-bound HELLO",
                    "code": ew_protocol.ErrorCode.AUTH_FAILED,
                }))
                self.metrics.handshake_failures += 1
                return

            # Derive peer_id from identity key (don't trust claimed ID)
            if peer_identity_b64:
                peer_id = ew_keys.get_fingerprint(base64.b64decode(peer_identity_b64))
            else:
                peer_id = claimed_peer_id

            # Decode peer's ephemeral public key
            from nacl.public import PublicKey as X25519PublicKey
            peer_ephemeral_public = X25519PublicKey(base64.b64decode(peer_ephemeral_b64))

            # Derive shared secret via ECDH
            session_key = ew_crypto.ecdh_exchange(my_ephemeral_private, peer_ephemeral_public)

            # Destroy the ephemeral private key (forward secrecy)
            ew_crypto.secure_wipe(my_ephemeral_private)
            del my_ephemeral_private

            # Send the HELLO, signed with Ed25519 + channel binding via server_nonce.
            # v0.9.4 Phase 2: HELLO MAY carry x25519_public_b64 +
            # x25519_binding_signature_b64 advertising the master-seed X25519
            # subkey for E2E sealing. The fields are OUTSIDE the signed
            # canonical body (which stays at the v0.9.4 shape so pre-v0.9.4
            # receivers verify the sig identically); the binding signature
            # is itself an Ed25519 signature over the X25519 public under
            # SIG_CTX_X25519_BINDING, so receivers that DO understand the
            # advertisement get cryptographic binding without breaking the
            # mixed-mesh sig-verify path.
            #
            # ironmesh/0.9 — signature scheme is gated on the version the
            # client advertised inside ITS signed HELLO (already verified
            # above): 0.9+ clients get the detached domain-separated
            # signature under SIG_CTX_HELLO; older clients get the legacy
            # attached signature so mixed-version meshes keep working.
            # ironmesh/0.9: on RNS Links toward 0.9+ clients, bind the
            # server HELLO to this specific RNS link (None on WebSocket
            # or toward pre-0.9 clients — the field is then omitted and
            # the canonical body keeps its five-key form).
            my_link_binding = self._rns_hello_link_binding(
                websocket, client_hello_version,
            )
            hello_canonical = ew_protocol.canonical_hello_bytes(
                channel_binding=server_nonce.hex(),
                ephemeral_public=base64.b64encode(bytes(my_ephemeral_public)).decode(),
                identity_public=self._keypair.get_public_key_base64(),
                name=self.name,
                protocol_version=PROTOCOL_VERSION,
                rns_link_id=my_link_binding,
            )
            if _peer_supports_hello_ctx(client_hello_version):
                signature = ew_crypto.sign_detached_with_context(
                    self._keypair.get_signing_key(),
                    ew_crypto.SIG_CTX_HELLO,
                    hello_canonical,
                )
            else:
                signature = ew_crypto.sign_message(
                    self._keypair.get_signing_key(), hello_canonical
                )
            outgoing_hello = {
                "type": ew_protocol.MessageType.HELLO,
                "from": self.node_id,
                "name": self.name,
                "ephemeral_public": base64.b64encode(bytes(my_ephemeral_public)).decode(),
                "identity_public": self._keypair.get_public_key_base64(),
                "protocol_version": PROTOCOL_VERSION,
                "channel_binding": server_nonce.hex(),
                "signature": base64.b64encode(signature).decode(),
            }
            if my_link_binding is not None:
                outgoing_hello["rns_link_id"] = my_link_binding
            outgoing_hello.update(self._hello_x25519_advertisement())
            await websocket.send(json.dumps(outgoing_hello))

            # TOFU check BEFORE adding peer to dicts. A joiner bootstrapping
            # from an invite presents the full token here; this node (the
            # inviter) is authoritative for single-use consumption and pins
            # the joiner "pending" — see TrustOpsMixin._check_tofu.
            invite_token_str = msg.get("invite_token")
            await self._check_tofu(peer_id, peer_identity_b64, invite_token_str)

            # Peer presented a valid TOFU-pinned (or fresh-pin) identity —
            # clear any auth-failure block for this source IP. The block
            # exists to defeat brute-force on the passphrase, not to gate
            # known-identity peers; without this, a peer that briefly
            # mismatched passphrases stays blocked from the same IP even
            # after correcting itself.
            try:
                remote_ip_for_clear = (
                    websocket.remote_address[0]
                    if websocket.remote_address else None
                )
                if remote_ip_for_clear:
                    await self._clear_ip_auth_history(remote_ip_for_clear)
            except (AttributeError, IndexError, RuntimeError) as _e:
                logger.debug("IP-block clear after TOFU failed: %s", _e)

            # Set up peer state (only after TOFU passes)
            peer_state = ew_protocol.PeerState(
                node_id=peer_id,
                address=f"{websocket.remote_address[0]}:{websocket.remote_address[1]}",
            )
            peer_state.session_key = session_key
            peer_state.ephemeral_public = base64.b64decode(peer_ephemeral_b64)
            peer_state.identity_public = base64.b64decode(peer_identity_b64) if peer_identity_b64 else None
            peer_state.verified = True
            # ironmesh/0.9: record which HELLO signature scheme the peer
            # used ("context-v1", "legacy", or "unsigned") for
            # observability + tests.
            peer_state.hello_sig_scheme = hello_sig_scheme
            # v0.9.4 Phase 2: capture the peer's advertised X25519 identity
            # public ONLY if the binding signature verifies under their
            # pinned Ed25519. Receiver-prefer / legacy-fallback semantics
            # live at the E2E sealing call sites in mesh_crypto.py.
            peer_state.x25519_identity_public = self._verify_peer_x25519_binding(
                peer_identity_b64,
                msg.get("x25519_public_b64"),
                msg.get("x25519_binding_signature_b64"),
            )

            # v0.4: protocol version negotiation
            peer_protocol = msg.get("protocol_version", "ironmesh/0.3")

            # v0.6: reject peers below configured minimum
            if _parse_protocol_version(peer_protocol) < _parse_protocol_version(self._min_protocol_version):
                logger.warning(
                    "Rejecting peer %s on %s (below min %s)",
                    peer_id, peer_protocol, self._min_protocol_version,
                )
                self.metrics.handshake_failures += 1
                return

            peer_state.protocol_version = peer_protocol
            peer_state.supports_mesh = _peer_supports_mesh(peer_protocol)
            peer_state.is_relay_capable = peer_state.supports_mesh
            # Expose the HELLO-advertised agent name so SDK helpers like
            # Agent.peer_by_name() and the dashboard peer list can resolve
            # a peer by its friendly name.
            peer_state.agent_name = peer_name
            if not peer_state.supports_mesh:
                logger.info("Peer %s on %s — mesh forwarding disabled (direct only)",
                            peer_id, peer_protocol)

            # Duplicate-check + peer-state assignment must be atomic
            # to prevent identity hijacking when two
            # connections race to the same peer_id.
            async with self._peer_lock:
                # Guard against duplicate connections (both sides connect simultaneously).
                # v0.5: allow WebSocket to upgrade an existing RNS connection.
                existing_state = self.peers.get(peer_id)
                if existing_state and existing_state.is_online and peer_id in self.ws_clients:
                    new_is_rns = RNSLinkAdapter is not None and isinstance(websocket, RNSLinkAdapter)
                    old_is_rns = existing_state.transport_type == "rns"
                    if not new_is_rns and old_is_rns:
                        # Upgrade: replace RNS with faster WebSocket
                        logger.info("Upgrading %s from RNS to WebSocket", peer_id)
                        old_ws = self.ws_clients.pop(peer_id, None)
                        if old_ws:
                            try:
                                await old_ws.close()
                            except (websockets.exceptions.ConnectionClosed, OSError, RuntimeError):
                                # Closing a held-but-replaced connection.
                                # If the underlying socket is already gone
                                # (peer dropped, OS reaped), close() raises
                                # and we proceed to the upgrade either way.
                                pass
                        # Fall through to establish WebSocket connection
                    else:
                        logger.debug("Already connected to %s via %s, dropping inbound duplicate",
                                     peer_id, existing_state.transport_type)
                        return

                peer_state.transition(ew_protocol.PeerState.Status.ONLINE)
                self.peers[peer_id] = peer_state
                self.ws_clients[peer_id] = websocket
                self._peer_rate_limiters[peer_id] = ew_protocol.TokenBucket(rate=20.0, burst=100)
                self._replay_guard.reset_peer(peer_id)

            # v0.5: track transport type for failover
            if RNSLinkAdapter is not None and isinstance(websocket, RNSLinkAdapter):
                peer_state.transport_type = "rns"
                # Bind peer_id onto the adapter so the RNS stats poller
                # knows which PeerState to update for this Link.
                websocket.peer_id = peer_id
                # v0.9.1: tell the adapter what the peer's announce
                # said it supports, so large payloads can be routed
                # via Resource only for peers that will accept them.
                node_id_for_caps = getattr(peer_state, "node_id", None) or peer_id
                discovered = None
                # Snapshot — RNS announce handler mutates this dict on
                # the RNS Transport thread.
                for entry in list(self._rns_discovered.values()):
                    if entry.get("node_id") == node_id_for_caps:
                        discovered = entry
                        break
                if discovered:
                    websocket.peer_supports_resource = (
                        "resource" in discovered.get("features", [])
                    )
                rns_hash = getattr(websocket, '_dest_hash_hex', None)
                if rns_hash and rns_hash != "unknown":
                    peer_state.rns_dest_hash = rns_hash
                    self._known_rns_hashes[peer_id] = rns_hash
            else:
                peer_state.transport_type = "websocket"
                peer_state.ws_address = self._known_peer_addresses.get(
                    peer_name, peer_state.address)

            # Update peer in DB
            fingerprint = ew_keys.get_fingerprint(
                base64.b64decode(peer_identity_b64)
            ) if peer_identity_b64 else None
            await self._db.upsert_peer(
                peer_id,
                identity_public_b64=peer_identity_b64,
                address=peer_state.address,
                fingerprint=fingerprint,
            )

            self.metrics.handshake_successes += 1
            self._reset_backoff(peer_id)  # v0.6
            logger.info("Peer %s (%s) online via %s — ephemeral ECDH complete",
                        peer_name, peer_id, peer_state.transport_type)

            # Pin peer fingerprint + address for mDNS verification
            # Use the mDNS-known address (listening port) if available,
            # not the ephemeral source port from the inbound WebSocket.
            pin_address = self._known_peer_addresses.get(peer_name, peer_state.address)
            if peer_name and fingerprint:
                self._pinned_peers[peer_name] = {
                    "fingerprint": fingerprint,
                    "address": pin_address,
                    "peer_id": peer_id,
                }

            # Audit: peer connected
            if self._audit:
                self._audit.log(EVENT_PEER_CONNECT, {
                    "peer_id": peer_id, "peer_name": peer_name,
                    "address": peer_state.address,
                })

            # Fire hook
            if self._hooks:
                await self._hooks.fire("on_peer_connect", {
                    "peer_id": peer_id, "peer_name": peer_name,
                })

            # Flush pending messages
            asyncio.ensure_future(self._flush_pending(peer_id))

            # --- STAGE 3: Encrypted Message Loop ---
            # v0.8.5.6: tag inbound transport so dedup can detect cross-
            # transport replay attempts.
            _transport_name = (
                "rns" if RNSLinkAdapter is not None
                and isinstance(websocket, RNSLinkAdapter)
                else "ws"
            )
            async for raw in websocket:
                try:
                    self.metrics.bytes_received += len(raw)
                    await self._handle_message(
                        peer_id, raw, transport=_transport_name,
                    )
                except (json.JSONDecodeError, ValueError) as e:
                    # Expected parse/validation errors get a narrow
                    # warning. Unexpected exceptions fall through
                    # to the broader handler below so the code see tracebacks.
                    logger.warning("Malformed message from %s: %s", peer_id, e)
                except nacl_exceptions.CryptoError as e:
                    logger.warning("Crypto error from %s: %s", peer_id, e)
                except Exception:
                    logger.exception("Unexpected error from %s", peer_id)

        except websockets.ConnectionClosed:
            logger.info("Peer %s disconnected", peer_id or "unknown")
        except (TimeoutError, asyncio.TimeoutError, json.JSONDecodeError) as e:
            # asyncio.TimeoutError is a distinct class from builtins.TimeoutError
            # on Python 3.10 (unified in 3.11 via PEP 616). Spelling both keeps
            # the 3.10 matrix green.
            logger.warning("Handshake failed: %s", e)
            self.metrics.handshake_failures += 1
        except (ConnectionResetError, ConnectionError, OSError) as e:
            logger.warning("Peer %s connection error: %s", peer_id or "unknown", e)
        finally:
            # Always close the websocket, even if peer_id
            # was never established (early handshake failure).
            try:
                await websocket.close()
            except (websockets.exceptions.ConnectionClosed, OSError, RuntimeError):
                # Already-closed / socket-dead / loop-shutting-down
                # are all valid outcomes of `close()` in the finally
                # path. We've already decided to drop the connection;
                # the close attempt is purely cleanup.
                pass
            if peer_id:
                # v0.8.1: scope the teardown to the owning connection.
                # When two handshakes race for the same peer (both sides
                # dial simultaneously), the duplicate-handler `return`
                # path would otherwise tear down a *live* connection
                # that belongs to the winning handshake. Only clear the
                # ws_clients entry + session_key if this specific
                # websocket is the one registered.
                owned_session = False
                async with self._peer_lock:
                    if self.ws_clients.get(peer_id) is websocket:
                        self.ws_clients.pop(peer_id, None)
                        self._peer_rate_limiters.pop(peer_id, None)
                        if peer_id in self.peers:
                            self.peers[peer_id].transition(
                                ew_protocol.PeerState.Status.OFFLINE,
                            )
                            self.peers[peer_id].session_key = None
                        owned_session = True
                if owned_session:
                    if self._hooks:
                        try:
                            await self._hooks.fire(
                                "on_peer_disconnect", {"peer_id": peer_id},
                            )
                        except Exception as e:  # noqa: BLE001
                            # User-supplied hook callbacks can raise
                            # any exception class — pinning to a
                            # narrow set would silently drop a hook
                            # that raised a custom exception type.
                            # Best-effort dispatch with a logged note
                            # is the documented contract.
                            logger.warning(
                                "on_peer_disconnect hook raised: %s: %s",
                                type(e).__name__, e,
                            )
                    # No failover attempts for connections that drop
                    # because this daemon is the one shutting down.
                    if self._running:
                        asyncio.ensure_future(
                            self._try_transport_failover(peer_id)
                        )

    async def _try_transport_failover(self, peer_id: str):
        """Attempt immediate reconnection on an alternative transport after disconnect."""
        await asyncio.sleep(2)  # Brief cooldown

        state = self.peers.get(peer_id)
        if not state or state.is_online:
            return  # Already reconnected or unknown peer

        # v0.6.1: don't race with other reconnect paths
        if not self._try_claim_reconnect(peer_id):
            return
        try:
            old_transport = state.transport_type
            if old_transport == "websocket":
                rns_hash = self._known_rns_hashes.get(peer_id) or getattr(state, 'rns_dest_hash', None)
                if rns_hash and self._reticulum:
                    logger.info("Transport failover for %s: WebSocket -> RNS", peer_id)
                    await self._connect_and_track_rns(rns_hash)
            elif old_transport == "rns":
                ws_addr = getattr(state, 'ws_address', None)
                if ws_addr and not ws_addr.startswith("rns:"):
                    try:
                        host, port_str = ws_addr.rsplit(":", 1)
                        port = int(port_str)
                        logger.info("Transport failover for %s: RNS -> WebSocket", peer_id)
                        await self.connect_to_peer(host, port)
                    except Exception as e:
                        logger.debug("WS failover for %s failed: %s", peer_id, e)
        finally:
            # _reset_backoff clears the reconnect claim on success,
            # but if the code get here without success, clear explicitly.
            state_now = self.peers.get(peer_id)
            if not state_now or not state_now.is_online:
                self._release_reconnect(peer_id)

    def _on_rns_link_stats(self, peer_id: str, stats: dict) -> None:
        """Update PeerState with the latest RNS Link metrics.

        Called from ReticulumTransport's stats poller (running on the
        asyncio loop). Best-effort: this code never raises — a missing peer or
        stale state just means the next sample wins.
        """
        state = self.peers.get(peer_id)
        if state is None:
            return
        if "mtu" in stats:
            state.rns_link_mtu = stats["mtu"]
        if "mdu" in stats:
            state.rns_link_mdu = stats["mdu"]
        if "expected_bps" in stats:
            state.rns_estimated_bps = stats["expected_bps"]
        if "rssi" in stats:
            state.rns_rssi = stats["rssi"]
        if "snr" in stats:
            state.rns_snr = stats["snr"]
        if "q" in stats:
            state.rns_q = stats["q"]
        # Derive an RTT estimate from age + no_data_for as a coarse fallback
        # when RNS doesn't expose RTT directly. PacketReceipts (Phase 2)
        # provide the authoritative value.

    async def _on_rns_peer_announced(self, dest_hash_hex: str,
                                     identity_hash_hex: Optional[str],
                                     app_data: dict,
                                     hops: Optional[int]) -> None:
        """Record a peer heard via the RNS announce handler.

        Called from ReticulumTransport when an ironmesh/bridge announce
        arrives. The current scope just tracks the peer so the dashboard
        and capability registry see them. A later release auto-establishes
        a Link when an Agent SDK call tries to reach them by name, so that
        ``agent.send_to("alice")`` resolves transparently whether alice is
        reachable via WebSocket, RNS, or LXMF.
        """
        try:
            now = time.time()
            entry = self._rns_discovered.get(dest_hash_hex)
            new_peer = entry is None
            if entry is None:
                entry = {
                    "dest_hash": dest_hash_hex,
                    "first_seen": now,
                }
                self._rns_discovered[dest_hash_hex] = entry
            entry["last_seen"] = now
            entry["identity_hash"] = identity_hash_hex
            entry["hops"] = hops
            entry["name"] = app_data.get("n")
            entry["version"] = app_data.get("v")
            entry["node_id"] = app_data.get("i")
            entry["capabilities"] = list(app_data.get("c") or [])
            entry["features"] = list(app_data.get("f") or [])

            # If this peer is also currently connected, mirror the
            # announce-derived metadata onto its PeerState so the
            # dashboard sees a single unified view.
            node_id = entry["node_id"]
            if node_id and node_id in self.peers:
                state = self.peers[node_id]
                state.rns_announced_at = now
                state.rns_capabilities = entry["capabilities"]
                state.rns_features = entry["features"]
                state.rns_announced_version = entry["version"]
                state.rns_hops = hops
                if not state.rns_dest_hash:
                    state.rns_dest_hash = dest_hash_hex
                self._known_rns_hashes.setdefault(node_id, dest_hash_hex)

            if new_peer:
                logger.info(
                    "RNS announce: discovered %s (name=%s ver=%s hops=%s caps=%d)",
                    dest_hash_hex[:12], entry["name"], entry["version"],
                    hops, len(entry["capabilities"]),
                )
            else:
                logger.debug(
                    "RNS announce refresh: %s (hops=%s)",
                    dest_hash_hex[:12], hops,
                )
        except Exception:
            logger.exception("_on_rns_peer_announced failed")

    def broadcast_via_rns_group(self, payload: bytes) -> dict:
        """Two-phase mesh-wide broadcast.

        v0.9.2 corrected design after the chunk B cross-host gap was
        identified. RNS GROUP destinations are architecturally same-
        segment-only (they cannot be `announce()`d, so cross-host RNS
        Transport has no path to them). To get true cross-host
        broadcast we layer a fan-out at the IronMesh frame layer on
        top of the same-segment GROUP packet:

          Phase 1 — RNS GROUP packet (O(1) on the local segment).
                    Reaches every listener that shares the same RNS
                    Transport (e.g., all daemons connected to one
                    rnsd, or all nodes on one LoRa medium).
          Phase 2 — IronMesh GROUP_BROADCAST fan-out (O(N) across
                    established IronMesh connections). For every
                    online peer that we know advertises the `group`
                    feature in its RNS announce, send a GROUP_BROADCAST
                    frame over the existing WS/RNS Link.

        Receivers dedup on payload SHA-256 (60-second window, 10k cap)
        so a peer that hears the same payload via BOTH phases handles
        it exactly once. The dedup runs in `_on_rns_group_message`.

        Returns a small dict describing what happened — useful for
        callers / logs / tests:

            {
              "local_segment": True | False,  # phase 1 succeeded?
              "fanout_sent": int,             # phase 2 peer count
              "fanout_skipped": int,          # peers without `group`
            }
        """
        result = {"local_segment": False,
                  "fanout_sent": 0, "fanout_skipped": 0}
        if not payload:
            return result
        if not isinstance(payload, (bytes, bytearray)):
            payload = str(payload).encode("utf-8")
        else:
            payload = bytes(payload)

        # Phase 1: same-segment RNS GROUP packet (cheap, local-only).
        t = getattr(self, "_reticulum", None)
        if t is not None:
            try:
                result["local_segment"] = bool(t.broadcast_via_group(payload))
            except Exception as e:
                # WARNING (not exception) — per-call failures shouldn't
                # spam the log with full tracebacks; operators get the
                # cause via %s and can re-run with --log-level DEBUG.
                logger.warning("Phase-1 GROUP packet failed (continuing): %s", e)

        # Phase 2: cross-host fan-out via IronMesh GROUP_BROADCAST.
        # For every ONLINE peer we know about that ALSO advertised the
        # `group` feature in its RNS announce, send a per-peer
        # GROUP_BROADCAST frame. The receiver routes it to
        # `_on_rns_group_message` (NOT the regular MSG path) which
        # dedups on payload SHA-256 — a peer that received the same
        # bytes via Phase 1 will silently discard the Phase-2 copy.
        #
        # Only send to peers that DECLARED the `group` feature so we
        # don't surprise non-participants with traffic they won't
        # know what to do with.
        # Snapshot _rns_discovered before iterating — the RNS announce
        # handler runs on the RNS Transport thread and mutates this
        # dict concurrently. Iterating without a snapshot risks
        # `RuntimeError: dictionary changed size during iteration`.
        rns_group_peers = set()
        for entry in list(self._rns_discovered.values()):
            if "group" in (entry.get("features") or []):
                node_id = entry.get("node_id")
                if node_id:
                    rns_group_peers.add(node_id)

        for peer_id, state in list(self.peers.items()):
            if not getattr(state, "is_online", False):
                continue
            if peer_id == self.node_id:
                continue
            if rns_group_peers and peer_id not in rns_group_peers:
                result["fanout_skipped"] += 1
                continue
            try:
                # Schedule the send on the daemon's event loop.
                # send_message is async — fire-and-forget so this
                # method stays sync-safe for callers (the local-segment
                # GROUP packet is also fire-and-forget at the RNS layer).
                #
                # Use get_running_loop() — get_event_loop() is deprecated
                # in Python 3.10+ when no loop is running and will
                # eventually raise RuntimeError.
                try:
                    asyncio.get_running_loop()
                    on_event_loop = True
                except RuntimeError:
                    on_event_loop = False
                if on_event_loop:
                    asyncio.ensure_future(
                        self.send_message(peer_id, "GROUP_BROADCAST",
                                            payload, "NORMAL"),
                    )
                else:
                    # Fallback for callers not on the daemon loop.
                    try:
                        loop = self._loop if hasattr(self, "_loop") else None
                        if loop is not None and loop.is_running():
                            asyncio.run_coroutine_threadsafe(
                                self.send_message(peer_id, "GROUP_BROADCAST",
                                                    payload, "NORMAL"),
                                loop,
                            )
                    except Exception:
                        pass
                result["fanout_sent"] += 1
            except Exception as e:
                # WARNING (not exception) — fan-out is per-peer; one
                # failure shouldn't dump a traceback for every other
                # peer in the broadcast set.
                logger.warning(
                    "Phase-2 GROUP_BROADCAST fan-out to %s failed: %s",
                    peer_id, e,
                )

        # Metric: count this as one logical send if EITHER phase reached
        # at least one peer. Detailed counts live in the result dict.
        if result["local_segment"] or result["fanout_sent"] > 0:
            self._inc_metric("group_broadcasts_sent")
        return result

    # v0.9.2 hardening: bound the dedup cache size so a flood of
    # unique-payload group broadcasts can't drive unbounded memory
    # growth. 10k entries × ~80 bytes/entry ≈ 800 KB cap, plenty of
    # headroom for legitimate operator traffic. OrderedDict gives
    # O(1) eviction of the oldest entry.
    _GROUP_DEDUP_MAX = 10_000
    _GROUP_DEDUP_TTL = 60.0

    async def _on_rns_group_message(self, payload: bytes) -> None:
        """Inbound broadcast packet on the shared GROUP destination.

        Dedup is keyed on SHA-256 of the payload so self-sent broadcasts
        that echo back (on some RNS versions) don't re-enter processing.
        Beyond that, group traffic rides the existing gossip/message
        pipeline — the daemon just hands the payload to the generic
        frame handler with a synthetic `group:` source marker, so any
        pipeline that inspects the sender can distinguish group traffic
        from unicast without adding a new MessageType.
        """
        if not payload:
            return
        digest = hashlib.sha256(payload).digest()
        from collections import OrderedDict
        seen = self.__dict__.get("_group_seen")
        if seen is None or not isinstance(seen, OrderedDict):
            seen = OrderedDict()
            self._group_seen = seen
        now = time.time()
        # Per-call O(1) hot path: pop the oldest entry IF it's stale.
        # The full sweep happens lazily in the size-cap branch below,
        # which is rare for a healthy mesh but bounds worst-case memory.
        while seen:
            oldest_key = next(iter(seen))
            if now - seen[oldest_key] > self._GROUP_DEDUP_TTL:
                seen.popitem(last=False)
            else:
                break
        if digest in seen:
            self._inc_metric("group_broadcasts_deduped")
            # Move-to-end so a hot duplicate doesn't get evicted by
            # a later size-cap trim before it's actually stale.
            seen.move_to_end(digest)
            return
        seen[digest] = now
        # Hard cap on size — even before TTL expires, never let the
        # dict grow past _GROUP_DEDUP_MAX entries.
        while len(seen) > self._GROUP_DEDUP_MAX:
            seen.popitem(last=False)
        self._inc_metric("group_broadcasts_received")
        try:
            logger.debug("RNS group broadcast received (%d bytes)", len(payload))
        except Exception:
            pass
        # Surface via a daemon hook that operator code can override.
        handler = getattr(self, "on_group_broadcast", None)
        if callable(handler):
            try:
                result = handler(payload)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("on_group_broadcast handler raised")

    # ------------------------------------------------------------------
    # Background loops
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self):
        # RNS Links carry their own keepalive (~0.45 bps) plus a closed-
        # callback that fires immediately on disconnect. Sending a full
        # IronMesh PING/PONG every heartbeat_interval over LoRa wastes
        # scarce bandwidth and provides no information the Link itself
        # doesn't already expose. For RNS peers the code uses a longer cadence
        # (5x default) and short-circuit on no_data_for() exceeding the
        # silence threshold so dead Links surface in seconds, not minutes.
        rns_interval_multiplier = 5
        rns_silence_threshold = self._heartbeat_interval * 3
        while self._running:
            await asyncio.sleep(self._heartbeat_interval)
            for peer_id, state in list(self.peers.items()):
                if not state.is_online:
                    continue
                is_rns = (state.transport_type == "rns")
                # Native liveness check for RNS peers — read from the
                # latest stats sample. If the Link has been silent past
                # the threshold, mark offline immediately rather than
                # waiting for the IronMesh PING timeout chain.
                if is_rns:
                    silence = None
                    adapter = self.ws_clients.get(peer_id)
                    if adapter is not None and hasattr(adapter, "_link"):
                        try:
                            silence = adapter._link.no_data_for()
                        except Exception:
                            silence = None
                    if silence is not None and silence > rns_silence_threshold:
                        logger.info(
                            "RNS peer %s silent for %.1fs (>%.0fs threshold) — marking offline",
                            peer_id, silence, rns_silence_threshold,
                        )
                        state.transition(ew_protocol.PeerState.Status.OFFLINE)
                        state.session_key = None
                        self.ws_clients.pop(peer_id, None)
                        self._pending_pings.pop(peer_id, None)
                        continue
                    # Skip PING this tick on a longer cadence
                    last_ping = self._pending_pings.get(peer_id, 0)
                    if (time.monotonic() - last_ping
                            < self._heartbeat_interval * rns_interval_multiplier):
                        continue
                try:
                    self._pending_pings[peer_id] = time.monotonic()
                    await self._send_encrypted_control(
                        peer_id, ew_protocol.MessageType.PING
                    )
                    state.last_seen = time.time()
                except Exception:
                        logger.warning("Heartbeat failed for %s", peer_id)
                        state.transition(ew_protocol.PeerState.Status.OFFLINE)
                        state.session_key = None
                        self.ws_clients.pop(peer_id, None)
                        self._pending_pings.pop(peer_id, None)

    async def _cleanup_loop(self):
        while self._running:
            await asyncio.sleep(self._cleanup_interval)
            try:
                await self._db.cleanup_old_pending()
                await self._db.prune_old(days=30)
            except Exception as e:
                logger.warning("Cleanup loop error: %s", e)

    async def _long_drop_watchdog(self):
        """v0.7.2: alert on peers offline beyond the configured threshold.

        Emits EVENT_PEER_DROPPED_LONG exactly once per drop (the code clear the
        ``long_drop_alerted`` flag when the peer comes back online). Useful
        for ops dashboards / pagers — a peer silently dropping for hours is
        the most common mesh-reliability signal to escalate on.
        """
        if self._long_drop_threshold_seconds <= 0:
            return
        while self._running:
            await asyncio.sleep(self._long_drop_check_interval)
            now = time.time()
            for peer_id, state in list(self.peers.items()):
                offline_since = getattr(state, "offline_since", None)
                if offline_since is None or state.is_online:
                    continue
                if state.long_drop_alerted:
                    continue
                duration = now - offline_since
                if duration < self._long_drop_threshold_seconds:
                    continue
                state.long_drop_alerted = True
                self._peer_long_drops_total += 1
                logger.warning(
                    "Peer %s (%s) offline for %.0fs — crossed %ds threshold",
                    peer_id, getattr(state, "agent_name", "") or "?",
                    duration, self._long_drop_threshold_seconds,
                )
                if self._audit:
                    try:
                        self._audit.log(EVENT_PEER_DROPPED_LONG, {
                            "peer_id": peer_id,
                            "name": getattr(state, "agent_name", None),
                            "offline_seconds": int(duration),
                            "threshold_seconds": self._long_drop_threshold_seconds,
                        })
                    except Exception:
                        pass

    async def _queue_flush_loop(self):
        while self._running:
            await asyncio.sleep(self._queue_flush_interval)
            try:
                for peer_id, state in list(self.peers.items()):
                    if state.is_online and peer_id in self.ws_clients:
                        pending = await self._db.get_pending_for_peer(peer_id)
                        if pending:
                            await self._flush_pending(peer_id)
            except Exception as e:
                logger.warning("Queue flush loop error: %s", e)

    def _on_peer_discovered(self, agent_name: str, info: dict):
        """Called by mDNS listener when a peer is found on the LAN."""
        if agent_name == self.name:
            return  # Skip self
        # If allowlist is set, skip peers not on it.
        if self._allowed_peers is not None and agent_name not in self._allowed_peers:
            logger.info("mDNS: ignoring unlisted peer %s (not in allowed_peers)", agent_name)
            return
        # Default-deny — if no allowlist and no open_discovery, reject all
        if self._allowed_peers is None and not self._open_discovery:
            logger.info("mDNS: blocking auto-connect to %s (default-deny, use --allowed-peers or --open-discovery)", agent_name)
            return
        # Multi-homed peer: if the announcement carries multiple
        # addresses, prefer the one whose /24 matches one of our own
        # local interfaces. Falls through to the first announced
        # address when no subnet match is found (same as the legacy
        # single-address path).
        candidate_ips = info.get("addresses") or [info["ip"]]
        chosen_ip = _select_closest_subnet_address(candidate_ips, self._local_subnet_prefixes()) \
            if len(candidate_ips) > 1 else candidate_ips[0]
        addr = f"{chosen_ip}:{info['port']}"
        # If this code has seen this peer before, log address changes.
        # Identity is verified via Ed25519 key pinning in _check_tofu()
        # during the handshake — mDNS address changes are safe to accept.
        pinned = self._pinned_peers.get(agent_name)
        if pinned and pinned["address"] != addr:
            # v0.9.4: same-IP port-shift (ephemeral source port giving
            # way to the announced listen port) is benign and was
            # producing repeat "address changed" log noise during the
            # 3-way live-mesh test. Downgrade to DEBUG; only a real
            # IP change (different host) warrants the operator-visible
            # log.
            _old_host = pinned["address"].rsplit(":", 1)[0] if ":" in pinned["address"] else pinned["address"]
            _new_host = addr.rsplit(":", 1)[0] if ":" in addr else addr
            if _old_host == _new_host:
                logger.debug(
                    "mDNS: port shift for pinned peer %s (was %s, now %s)",
                    agent_name, pinned["address"], addr,
                )
            else:
                logger.info(
                    "mDNS: address changed for pinned peer %s "
                    "(was %s, now %s). Identity will be verified during handshake.",
                    agent_name, pinned["address"], addr,
                )
            pinned["address"] = addr
        # Skip if THIS specific peer is already online (avoid duplicate connections)
        # Match by agent_name OR by node_id (peers dict is keyed by node_id but
        # agent_name may not match until after handshake).
        existing = self.peers.get(agent_name)
        if existing is not None and existing.is_online:
            return
        # Also check by display name (best-effort pre-handshake)
        for s in self.peers.values():
            if s.is_online and getattr(s, "agent_name", None) == agent_name:
                return
        # Simultaneous-dial tie-breaker: prevents the online->offline flap
        # that occurs when both ends dial each other at the same tick.
        #
        # v0.7.2: the code uses a SINGLE stable criterion (agent_name) — not a mix
        # of name-before-handshake and node_id-after — because flipping
        # criteria mid-session caused the winner to swap once the peer_id
        # became known, reintroducing the flap. Names are symmetric (both
        # sides see the same pair) and available from first mDNS hit.
        #
        # Rule: the lexicographically smaller name dials; larger waits.
        if self.name and agent_name and self.name > agent_name:
            logger.debug(
                "mDNS tie-breaker: self=%s > peer=%s — waiting for peer to dial",
                self.name, agent_name,
            )
            self._known_peer_addresses[agent_name] = addr
            return
        self._known_peer_addresses[agent_name] = addr
        # v0.6.1: gate against other reconnect paths
        if not self._try_claim_reconnect(agent_name):
            logger.debug("mDNS skip %s — another reconnect in progress", agent_name)
            return
        logger.info("mDNS discovered peer: %s @ %s", agent_name, addr)
        # Schedule connection attempt on the event loop (mDNS callback runs in Zeroconf thread)
        try:
            loop = self._loop
            host = chosen_ip
            port = info["port"]
            logger.info("mDNS scheduling connect_to_peer(%s, %s) for %s", host, port, agent_name)
            def _schedule():
                try:
                    asyncio.ensure_future(self.connect_to_peer(host, port))
                except Exception as ex:
                    logger.warning("mDNS ensure_future failed for %s: %s", agent_name, ex)
            loop.call_soon_threadsafe(_schedule)
        except Exception as e:
            logger.warning("Auto-connect schedule to %s failed: %s", agent_name, e)
            self._release_reconnect(agent_name)

    def _local_subnet_prefixes(self) -> List[int]:
        """Return the /24 prefixes of this host's IPv4 interfaces.

        Used by the mDNS discovery callback to prefer same-LAN
        candidate addresses on multi-homed peers. Cached after the
        first call — interface set is treated as stable for the
        process lifetime, which matches every real deployment we've
        seen (a flapping NIC during runtime would simply revert to
        the legacy first-announced behaviour on the affected calls).
        """
        cached = getattr(self, "_subnet_prefix_cache", None)
        if cached is not None:
            return cached
        prefixes: List[int] = []
        try:
            import socket as _socket
            # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist).
            # On Windows the ipaddrlist usually contains every bound
            # IPv4, so subnet matching works. On many Linux distros
            # (Debian/Ubuntu) the hostname maps to 127.0.1.1 via
            # /etc/hosts, so this can return only loopback and miss the
            # real LAN /24 — subnet matching then finds no match and we
            # fall back to the first announced address (legacy
            # behaviour). A getsockname()-based probe would be more
            # reliable; tracked as a follow-up.
            _, _, ips = _socket.gethostbyname_ex(_socket.gethostname())
            for ip in ips:
                n = _ipv4_to_int(ip)
                if n is not None:
                    prefixes.append(n & 0xFFFFFF00)
        except (OSError, _socket.gaierror):
            # Best-effort: if we can't enumerate interfaces, fall back
            # to legacy first-announced behaviour by returning an
            # empty prefix list.
            pass
        self._subnet_prefix_cache = prefixes
        return prefixes

    def _has_online_peer(self) -> bool:
        """Check if any peer is currently online."""
        return any(s.is_online for s in self.peers.values())

    async def _discover_loop(self):
        while self._running:
            await asyncio.sleep(30)
            for name_or_id, addr in list(self._known_peer_addresses.items()):
                # v0.7.2: per-peer online check (not global) — matches the
                # mDNS fix. Multi-peer mesh needs to dial each peer
                # independently of the others' state.
                peer_online = False
                for s in self.peers.values():
                    if s.is_online and getattr(s, "agent_name", None) == name_or_id:
                        peer_online = True
                        break
                if peer_online:
                    continue
                # v0.7.2: apply the same tie-breaker as the mDNS path so
                # only one side initiates. The larger-named side waits for
                # the incoming connection from the smaller-named side.
                if self.name and name_or_id and self.name > name_or_id:
                    continue
                try:
                    host, port_str = addr.rsplit(":", 1)
                    port = int(port_str)
                    asyncio.ensure_future(self.connect_to_peer(host, port))
                except Exception as e:
                    logger.debug("Discovery failed for %s at %s: %s",
                                 name_or_id, addr, e)

    async def _reconnect_loop(self):
        """Periodically reconnect to offline peers with jittered exponential backoff.

        Per-peer schedule uses: delay = min(5 * 2**attempts, 300) + jitter(0-2s).
        Backoff resets on successful handshake (see _reset_backoff).
        """
        import random
        while self._running:
            await asyncio.sleep(5)  # tick interval — actual reconnects gated by backoff
            now = time.monotonic()
            for peer_id, state in list(self.peers.items()):
                if state.status != ew_protocol.PeerState.Status.OFFLINE:
                    continue

                # v0.7.2: tie-breaker — if this peer has a smaller name
                # than the local node, the call waits for them to dial instead. Mirrors the
                # mDNS + discover loop rule so reconnects don't create
                # simultaneous-dial races.
                peer_name = getattr(state, "agent_name", None)
                if self.name and peer_name and self.name > peer_name:
                    continue

                # v0.6.1: skip if another reconnect path is already working
                if not self._try_claim_reconnect(peer_id):
                    continue

                # Check backoff
                bs = self._backoff_state.get(peer_id, {"attempts": 0, "next_at": 0})
                if now < bs["next_at"]:
                    self._release_reconnect(peer_id)
                    continue  # not time yet

                # Schedule next attempt
                attempts = bs["attempts"]
                delay = min(5.0 * (2 ** attempts), 300.0) + random.uniform(0, 2)
                self._backoff_state[peer_id] = {
                    "attempts": attempts + 1,
                    "next_at": now + delay,
                }
                logger.debug("Reconnect attempt %d for %s (next delay=%.1fs)",
                             attempts + 1, peer_id, delay)

                # Try WebSocket first (faster)
                ws_addr = getattr(state, 'ws_address', None) or state.address
                if ws_addr and not ws_addr.startswith("rns:"):
                    try:
                        host, port_str = ws_addr.rsplit(":", 1)
                        port = int(port_str)
                        asyncio.ensure_future(self.connect_to_peer(host, port))
                        continue
                    except Exception as e:
                        logger.debug("WS reconnect to %s failed: %s", peer_id, e)

                # Fall through to RNS if no WS address or parse failed
                rns_hash = self._known_rns_hashes.get(peer_id) or getattr(state, 'rns_dest_hash', None)
                if rns_hash and self._reticulum:
                    try:
                        asyncio.ensure_future(self._connect_and_track_rns(rns_hash))
                    except Exception as e:
                        logger.debug("RNS reconnect to %s failed: %s", peer_id, e)

    def _reset_backoff(self, peer_id: str) -> None:
        """Reset backoff state for a peer after a successful handshake."""
        self._backoff_state.pop(peer_id, None)
        self._reconnecting.pop(peer_id, None)  # v0.6.1

    def _try_claim_reconnect(self, key: str) -> bool:
        """v0.6.1: return True if this reconnect is allowed to proceed.

        Claims the reconnect slot for ``key`` (peer_id or agent_name).
        Other reconnect paths calling this within 60s will get False and
        should skip. Stale claims older than 60s are cleared.
        """
        now = time.monotonic()
        started = self._reconnecting.get(key)
        if started is not None and (now - started) < 60.0:
            return False
        self._reconnecting[key] = now
        return True

    def _release_reconnect(self, key: str) -> None:
        """Release a reconnect claim (on success or unrecoverable failure)."""
        self._reconnecting.pop(key, None)

    # ------------------------------------------------------------------
    # v0.4: Capability discovery
    # ------------------------------------------------------------------

    def _build_signed_announce_payload(self, origin: str, caps: list) -> bytes:
        """Build the wire body for a signed CAPABILITY_ANNOUNCE.

        Only valid for ``origin == self.node_id`` — the node has no
        signing key for any other origin. Callers are expected to gate
        on that condition (the announce loop does so explicitly).
        """
        announced_at = time.time()
        canonical = ew_protocol.canonical_capability_announce_bytes(
            origin=origin,
            capabilities=caps,
            announced_at=announced_at,
            version=ew_protocol.CAPABILITY_ANNOUNCE_SIGNED_VERSION,
        )
        sig = ew_crypto.sign_detached_with_context(
            self._keypair.signing_key,
            ew_crypto.SIG_CTX_CAPABILITY_ANNOUNCE,
            canonical,
        )
        body = {
            "origin": origin,
            "capabilities": list(caps),
            "announced_at": announced_at,
            "version": ew_protocol.CAPABILITY_ANNOUNCE_SIGNED_VERSION,
            "signature": base64.b64encode(sig).decode("ascii"),
        }
        return json.dumps(body, separators=(",", ":")).encode("utf-8")

    async def _capability_announce_loop(self):
        """Periodically gossip capabilities to direct neighbors.

        v0.9.4 (signed capability announcement): each iteration emits ONE signed announce for the
        local node's own capabilities (signed with the daemon's identity
        Ed25519 key + ``SIG_CTX_CAPABILITY_ANNOUNCE``), then re-broadcasts
        cached signed envelopes for remote origins this node has already
        verified. Remote-origin re-broadcast is a verbatim replay of the
        cached envelope bytes — the receiver re-verifies the origin's
        signature, so a relay cannot tamper en-route. Cached envelopes
        outside the freshness window are skipped; convergence resumes on
        origin's next direct announce.
        """
        # Stagger initial announce so peers handshake first
        await asyncio.sleep(10)
        max_age = float(getattr(
            self.config, "capability_announce_max_age", 300.0,
        ))
        while self._running:
            try:
                if self._capabilities is not None:
                    all_caps = self._capabilities.all()
                    announcements: list = []
                    now = time.time()

                    # 1) Own caps — sign fresh every loop.
                    own_caps = all_caps.get(self.node_id) or []
                    if own_caps:
                        own_payload = self._build_signed_announce_payload(
                            self.node_id, list(own_caps),
                        )
                        announcements.append((self.node_id, own_payload))
                        # Cache our own announce too so the dedup/freshness
                        # semantics are uniform across origin types if we
                        # later add self-loopback checks.
                        self._signed_announce_cache[self.node_id] = {
                            "payload": own_payload,
                            "announced_at": now,
                        }
                        self._signed_announce_cache.move_to_end(self.node_id)

                    # 2) Remote origins — replay cached signed envelope verbatim
                    #    if it's within the freshness window. Without signed envelopes we
                    #    re-generated the body each loop; that path is now
                    #    invalid because we cannot sign on behalf of a remote
                    #    origin. Cached entries older than max_age are evicted
                    #    so receivers never see a stale envelope from us.
                    stale_keys = []
                    for origin, entry in list(self._signed_announce_cache.items()):
                        if origin == self.node_id:
                            continue
                        announced_at = entry.get("announced_at", 0.0)
                        if (now - announced_at) > max_age:
                            stale_keys.append(origin)
                            continue
                        if not all_caps.get(origin):
                            continue
                        announcements.append((origin, entry["payload"]))
                    for k in stale_keys:
                        self._signed_announce_cache.pop(k, None)

                    for origin, payload_bytes in announcements:
                        for pid, state in list(self.peers.items()):
                            if not state.is_online:
                                continue
                            if pid not in self.ws_clients:
                                continue
                            # Don't send a node's own announcement back to it
                            if pid == origin:
                                continue
                            frame = ew_protocol.Frame(
                                msg_type=ew_protocol.MessageType.CAPABILITY_ANNOUNCE,
                                payload=payload_bytes,
                                source=self.node_id,
                                destination=pid,
                            )
                            try:
                                await self._send_frame(pid, frame)
                            except Exception as e:
                                logger.debug("Capability announce to %s failed: %s",
                                             pid, e)
            except Exception as e:
                logger.debug("Capability announce loop error: %s", e)
            # Defensive periodic persist: belt-and-braces alongside the
            # save inside the inbound handler. Catches the case where
            # learn_remote happened but save() raised silently.
            try:
                if self._capabilities is not None:
                    self._capabilities.save()
            except Exception:
                pass
            await asyncio.sleep(
                max(1.0, getattr(self.config, "capability_announce_interval", 60.0))
            )

    def advertise_capability(self, capability: str) -> None:
        """Public API: declare a capability this node provides."""
        if self._capabilities is None:
            return
        self._capabilities.advertise_local(capability)
        try:
            self._capabilities.save()
        except Exception:
            pass

    def find_capability(self, pattern: str) -> list:
        """Public API: return [(node_id, capability), ...] matching glob pattern."""
        if self._capabilities is None:
            return []
        return self._capabilities.find(pattern)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _spawn_bg(self, coro):
        """Schedule a long-lived background loop and track its Task handle so
        shutdown() can cancel it. Returns the Task."""
        task = asyncio.ensure_future(coro)
        self._background_tasks.append(task)
        return task

    async def shutdown(self):
        """Graceful shutdown. Idempotent — a second concurrent call (e.g.
        SIGINT then SIGTERM, or a double SIGTERM from systemd) returns
        immediately so the first shutdown is not raced to completion. Without
        this guard a second invocation's ``loop.stop()`` (in
        ``_shutdown_and_stop``) can fire while the first is still awaiting
        ``self._db.close()``, leaving the non-daemon aiosqlite worker thread
        un-joined and the process hanging on exit."""
        if getattr(self, "_shutting_down", False):
            return
        self._shutting_down = True
        self._running = False

        # Cancel the long-lived background loops BEFORE tearing down the DB /
        # transports they touch, so none resumes mid-sleep into a closed
        # resource. Setting _running above lets well-behaved loops exit on
        # their own; cancel() covers those parked in an await.
        tasks = [t for t in getattr(self, "_background_tasks", []) if not t.done()]
        for t in tasks:
            t.cancel()
        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                pass
        self._background_tasks = []

        # Close GUI server and clients
        for client in list(self._gui_clients):
            try:
                await client.close()
            except Exception:
                pass
        self._gui_clients.clear()
        if self._gui_server:
            self._gui_server.close()
            try:
                await asyncio.wait_for(self._gui_server.wait_closed(), timeout=3.0)
            except (asyncio.TimeoutError, TimeoutError):
                logger.debug("GUI server close wait timed out; continuing shutdown")

        # Send encrypted GOODBYE to all peers
        for peer_id in list(self.ws_clients.keys()):
            try:
                await self._send_encrypted_control(
                    peer_id, ew_protocol.MessageType.GOODBYE
                )
                await self.ws_clients[peer_id].close()
            except Exception:
                pass

        self.ws_clients.clear()

        # Clear all session keys
        for state in self.peers.values():
            state.session_key = None

        # v0.9.1: stop the LXMF listener BEFORE the Reticulum transport
        # so its announce + telemetry loops cancel cleanly before the
        # underlying RNS instance disappears. Without this the loops
        # raise on the next iteration with confusing "loop closed"
        # tracebacks during shutdown (discovery during testing).
        if self._lxmf:
            try:
                self._lxmf.shutdown()
            except Exception:
                pass

        # v0.5: Reticulum transport shutdown
        if self._reticulum:
            try:
                self._reticulum.shutdown()
            except Exception:
                pass

        # Close mDNS off-loop. The zeroconf instance was created while
        # this event loop was running, so zeroconf schedules its own
        # coroutines here — its *blocking* close()/unregister calls,
        # made from this loop's thread, would wait on work that can
        # only run once this coroutine yields: a permanent
        # self-deadlock that parked shutdown forever (and with it the
        # store close below). A helper thread lets those coroutines
        # run during the bounded wait; the thread is a daemon so a
        # truly stuck close can never pin the interpreter open.
        if self._mdns_listener or self._mdns_service:
            mdns_listener, mdns_service = self._mdns_listener, self._mdns_service
            self._mdns_listener = None
            self._mdns_service = None

            def _close_mdns_blocking():
                if mdns_listener:
                    try:
                        mdns_listener.stop()
                    except Exception:
                        pass
                if mdns_service:
                    try:
                        mdns_service.close()
                    except Exception:
                        pass

            import threading
            closer = threading.Thread(
                target=_close_mdns_blocking,
                name="ironmesh-mdns-close",
                daemon=True,
            )
            closer.start()
            deadline = time.monotonic() + 3.0
            while closer.is_alive() and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            if closer.is_alive():
                logger.debug("mDNS close still running after 3s; continuing shutdown")

        if self._server:
            self._server.close()
            # wait_closed() waits for every connection handler to finish.
            # A handler stuck mid close-handshake (e.g. the peer at the
            # other end is itself shutting down) can park this await for
            # tens of seconds — or indefinitely — and everything below,
            # including the store close that releases the non-daemon
            # sqlite worker threads, never runs. Bound the wait: the
            # daemon is exiting either way at this point.
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=3.0)
            except (asyncio.TimeoutError, TimeoutError):
                logger.debug("WebSocket server close wait timed out; continuing shutdown")

        await self._db.close()
        logger.info("Bridge daemon shut down")

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self, background: bool = False):
        loop = asyncio.new_event_loop()
        # Windows proactor has a known race (CPython issue #109538 family)
        # where an accept() completes between server.close() and the
        # actual socket shutdown, and the fresh transport asserts because
        # the server's _sockets is already None. Install a scoped handler
        # that swallows *only* that specific pattern — every other
        # exception still surfaces through the default handler.
        def _handle_loop_exception(the_loop, context):
            exc = context.get("exception")
            if isinstance(exc, AssertionError):
                msg = context.get("message", "") or ""
                tb_str = "".join(
                    str(f) for f in (context.get("source_traceback") or [])
                )
                if (
                    "_start_serving" in msg
                    or "_start_serving" in tb_str
                    or "proactor_events" in tb_str
                ):
                    return
            the_loop.default_exception_handler(context)

        loop.set_exception_handler(_handle_loop_exception)
        loop.run_until_complete(self._start())

        if background:
            return loop

        async def _shutdown_and_stop():
            # Run the graceful shutdown, then stop run_forever(). Without the
            # loop.stop() the daemon would hang after handling SIGTERM
            # (systemd `stop` would time out and escalate to SIGKILL).
            try:
                await self.shutdown()
            finally:
                loop.stop()

        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(
                    sig, lambda: asyncio.ensure_future(_shutdown_and_stop()))
        except NotImplementedError:
            pass  # Windows — SIGINT surfaces as KeyboardInterrupt below

        try:
            loop.run_forever()
        except KeyboardInterrupt:
            loop.run_until_complete(self.shutdown())
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# Programmatic entry points
# ---------------------------------------------------------------------------

async def run_bridge(name: str, port: int, keys_path: str,
                     passphrase: Optional[str] = None) -> BridgeDaemon:
    """Programmatic entry point."""
    daemon = BridgeDaemon(name=name, port=port, keys_path=keys_path, passphrase=passphrase)
    daemon.run(background=True)
    return daemon
