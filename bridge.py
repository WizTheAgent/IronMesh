"""IronMesh Bridge — Main daemon for agent-to-agent communication.

Manages WebSocket server, mDNS discovery, peer connections, passphrase auth,
ephemeral ECDH key exchange (forward secrecy), encrypted message routing,
and offline message queue.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import signal
import ssl
import time
import uuid
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
    EVENT_AUTH_BLOCKED,
    EVENT_AUTH_FAILURE,
    EVENT_CAPABILITY_LEARNED,
    EVENT_MSG_GATED_DROP,
    EVENT_MSG_GATED_QUEUE,
    EVENT_PEER_BLOCKED,
    EVENT_PEER_CAP_ACCEPTED,
    EVENT_PEER_CAP_BASELINE,
    EVENT_PEER_CAP_BINDING_PARTIAL,
    EVENT_PEER_CAP_SET_CHANGED,
    EVENT_PEER_CONNECT,
    EVENT_PEER_DROPPED_LONG,
    EVENT_PEER_PROMOTED,
    EVENT_STARTUP,
    EVENT_TOFU_MISMATCH,
    EVENT_TOFU_NEW,
    AuditLog,
)
from ironmesh.capabilities import CapabilityRegistry
from ironmesh.mesh import MeshRouter
from ironmesh.store import MessageStore
from ironmesh.telemetry import (
    emit_event as _otel_span_event,
    span as _otel_span,
)

logger = logging.getLogger("ironmesh.bridge")

PROTOCOL_VERSION = "ironmesh/0.6"
MIN_MESH_VERSION = "ironmesh/0.4"  # Peers below this version cannot relay
MAX_MESSAGE_SIZE = 1_048_576  # 1 MB default


def _parse_protocol_version(v: str) -> tuple:
    """Parse 'ironmesh/X.Y' into a (major, minor) tuple. Returns (0, 0) on parse failure."""
    if not v:
        return (0, 0)
    try:
        prefix, ver = v.split("/", 1)
        major_s, minor_s = ver.split(".", 1)
        return (int(major_s), int(minor_s.split(".")[0]))
    except (ValueError, IndexError):
        return (0, 0)


def _peer_supports_mesh(peer_version: str) -> bool:
    """Return True if the peer is at least ironmesh/0.4 (mesh-capable)."""
    return _parse_protocol_version(peer_version) >= _parse_protocol_version(MIN_MESH_VERSION)


def _peer_supports_rekey(peer_version: str) -> bool:
    """Return True if the peer supports in-session rekeying (v0.5+)."""
    return _parse_protocol_version(peer_version) >= (0, 5)


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
    metrics_format: str = "prometheus"
    log_format: str = "text"
    audit_log_max_bytes: int = 10_485_760
    dedup_sources_max: int = 128
    dedup_per_source_max: int = 1024
    dedup_cache_ttl: float = 300.0
    # v0.8.5: pending-trust message gate
    require_message_promotion: bool = False
    pending_trust_queue_cap: int = 100


# ---------------------------------------------------------------------------
# Key management helpers
# ---------------------------------------------------------------------------

async def ensure_agent_keys(keys_path: str, passphrase: Optional[str] = None) -> ew_keys.AgentKeys:
    """Load or generate Ed25519 identity keypair.

    If a plaintext key file is found and a passphrase is available,
    automatically re-encrypts the key file (migration).
    """
    path = Path(os.path.expanduser(keys_path))
    os.makedirs(path.parent, exist_ok=True)

    if path.exists():
        try:
            keys = ew_keys.load_keys(str(path), passphrase=passphrase)
            logger.info("Keys loaded from %s (fingerprint: %s)", path, keys.get_fingerprint())

            # Auto-migrate: if key file is plaintext and we have a passphrase, re-encrypt
            if passphrase:
                import json as _json
                with open(str(path)) as _f:
                    _data = _json.load(_f)
                if not _data.get("encrypted", False):
                    logger.warning("Migrating plaintext key file to encrypted: %s", path)
                    ew_keys.save_keys(keys, str(path), passphrase=passphrase)
                    logger.info("Key file migration complete — now encrypted with Argon2id")

            return keys
        except Exception as e:
            logger.error("Failed to load keys from %s: %s", path, e)
            raise

    keypair = ew_keys.generate_keypair()
    if not passphrase:
        logger.warning("No passphrase provided for key file — storing unencrypted (INSECURE)")
    ew_keys.save_keys(keypair, str(path), passphrase=passphrase,
                      allow_plaintext=not passphrase)
    logger.info("New keypair generated -> %s (fingerprint: %s)", path, keypair.get_fingerprint())
    return keypair


async def rotate_keys(keys_path: str, passphrase: Optional[str] = None) -> ew_keys.AgentKeys:
    """Generate a new keypair and save to disk."""
    path = Path(os.path.expanduser(keys_path))
    os.makedirs(path.parent, exist_ok=True)

    keypair = ew_keys.generate_keypair()
    if not passphrase:
        logger.warning("No passphrase provided for key file — storing unencrypted (INSECURE)")
    ew_keys.save_keys(keypair, str(path), passphrase=passphrase,
                      allow_plaintext=not passphrase)
    logger.info("Key rotation complete -> %s", path)
    return keypair


# ---------------------------------------------------------------------------
# Metrics collector
# ---------------------------------------------------------------------------

class Metrics:
    """Simple metrics collector for bridge health monitoring."""

    def __init__(self):
        self.started_at = time.time()
        self.messages_sent = 0
        self.messages_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.handshake_successes = 0
        self.handshake_failures = 0
        self.connections_total = 0
        self.rate_limits_triggered = 0
        # v0.4: mesh + capability metrics
        self.messages_relayed = 0
        self.route_lookup_failures = 0
        self.e2e_decrypt_failures = 0
        # v0.5.2: delivery + QoS + rekey metrics
        self.messages_delivered = 0
        self.messages_failed = 0
        self.session_rekeys = 0
        self.lora_oversized_messages = 0
        # v0.8.5.7: cap-binding + cross-transport replay observability.
        # One counter per audit event type introduced by v0.8.5.6 so
        # operators can alert on them via Prometheus (e.g. fire a
        # PagerDuty page when peer_cap_set_changed_total increases
        # outside of a maintenance window).
        self.peer_cap_set_changed = 0
        self.peer_cap_baseline = 0
        self.peer_cap_accepted = 0
        self.peer_cap_binding_partial = 0
        self.msg_replay_cross_transport = 0
        self.peer_revoked_local = 0
        self.peer_state_changed = 0
        # v0.8.5.7: trust-state operator transitions.
        # Pre-existing PEER_PROMOTED and PEER_BLOCKED audit event types
        # didn't have counters in any prior release. The audit-log
        # scanner landed in v0.8.5.7 B21; now's the time to mirror
        # them into Prometheus so operators can distinguish "operator
        # accepted this peer" from "operator flipped state to
        # something else" in Grafana.
        self.peer_promoted = 0
        self.peer_blocked = 0

    def to_dict(self) -> dict:
        return {
            "uptime_seconds": time.time() - self.started_at,
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "handshake_successes": self.handshake_successes,
            "handshake_failures": self.handshake_failures,
            "connections_total": self.connections_total,
            "rate_limits_triggered": self.rate_limits_triggered,
            "messages_relayed": self.messages_relayed,
            "route_lookup_failures": self.route_lookup_failures,
            "e2e_decrypt_failures": self.e2e_decrypt_failures,
            "messages_delivered": self.messages_delivered,
            "messages_failed": self.messages_failed,
            "session_rekeys": self.session_rekeys,
            "lora_oversized_messages": self.lora_oversized_messages,
            "peer_cap_set_changed": self.peer_cap_set_changed,
            "peer_cap_baseline": self.peer_cap_baseline,
            "peer_cap_accepted": self.peer_cap_accepted,
            "peer_cap_binding_partial": self.peer_cap_binding_partial,
            "msg_replay_cross_transport": self.msg_replay_cross_transport,
            "peer_revoked_local": self.peer_revoked_local,
            "peer_state_changed": self.peer_state_changed,
            "peer_promoted": self.peer_promoted,
            "peer_blocked": self.peer_blocked,
        }


# ---------------------------------------------------------------------------
# GUI Dashboard HTML
# ---------------------------------------------------------------------------

GUI_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<!-- CSP: lock the rendered dashboard to same-origin only. Pull the plug on your router — this keeps working.
     'unsafe-inline' for style/script is scoped to the bytes baked into bridge.py; peer payloads are HTML-escaped. -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'">
<title>IRONMESH · Operator Console</title>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#050505">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
 --bg:#050505; --surface:#0c0c0c; --surface-2:#121212;
 --border:#1a1a1a; --border-2:#222;
 --text:#e8e8e8; --text-dim:#888; --text-faint:#555;
 --signal:#5aff6e; --signal-dim:#3bcc4d;
 --warn:#ffb340; --alarm:#f85149;
 --metallic:#9aa0a6;
 --mono:ui-monospace,SFMono-Regular,"Cascadia Code",Consolas,"Liberation Mono",monospace;
 --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
}
html,body{height:100%}
body{font-family:var(--sans);background:var(--bg);color:var(--text);font-size:13px;line-height:1.5;overflow-x:hidden}
.mono{font-family:var(--mono)}
button{font-family:inherit}

/* Background grid, subtle — matches site identity. */
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
 background-image:linear-gradient(rgba(90,255,110,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(90,255,110,.02) 1px,transparent 1px);
 background-size:48px 48px}

/* === HEADER === */
.chrome{position:sticky;top:0;z-index:50;background:rgba(5,5,5,.92);backdrop-filter:blur(10px);
 border-bottom:1px solid var(--border);padding:10px 20px;
 display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.wordmark{font-family:var(--mono);font-weight:700;font-size:16px;letter-spacing:2px;color:var(--signal);
 text-shadow:0 0 18px rgba(90,255,110,.28)}
.version-pill{font-family:var(--mono);font-size:10px;color:var(--warn);background:rgba(255,179,64,.08);
 border:1px solid rgba(255,179,64,.3);padding:2px 8px;border-radius:3px;letter-spacing:1px}
.node-fp{font-family:var(--mono);font-size:11px;color:var(--text-dim);cursor:pointer;user-select:none;
 padding:2px 6px;border-radius:3px}
.node-fp:hover{color:var(--signal);background:rgba(90,255,110,.05)}
.mesh-state{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:11px;
 letter-spacing:1.5px;padding:4px 10px;border-radius:3px;border:1px solid}
.mesh-state[data-state="OPERATIONAL"]{color:var(--signal);border-color:rgba(90,255,110,.3);background:rgba(90,255,110,.05)}
.mesh-state[data-state="DEGRADED"]   {color:var(--warn);  border-color:rgba(255,179,64,.3);background:rgba(255,179,64,.05)}
.mesh-state[data-state="ISOLATED"]   {color:var(--alarm); border-color:rgba(248,81,73,.3); background:rgba(248,81,73,.05)}
.mesh-state .dot{width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}
.uptime{font-family:var(--mono);font-size:11px;color:var(--text-dim)}
.offline-badge{font-family:var(--mono);font-size:10px;color:var(--signal);
 border:1px solid var(--signal-dim);padding:3px 8px;border-radius:3px;letter-spacing:1.5px}
.token-box{display:flex;align-items:center;gap:4px;background:var(--surface);border:1px solid var(--border);
 padding:2px 6px;border-radius:3px;font-family:var(--mono);font-size:11px;color:var(--text-dim);margin-left:auto}
.token-box > span:first-child{letter-spacing:1.5px;padding-right:4px;border-right:1px solid var(--border-2);font-size:10px}
.token-box input{background:transparent;border:0;color:var(--text-dim);font-family:var(--mono);font-size:11px;
 width:130px;outline:none;padding:2px 4px}
.icon-btn{background:transparent;border:0;color:var(--text-dim);cursor:pointer;padding:3px;display:inline-flex;align-items:center;border-radius:3px}
.icon-btn:hover{color:var(--signal);background:rgba(90,255,110,.08)}
.icon{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

/* === STAT STRIP === */
.stat-strip{display:grid;grid-template-columns:repeat(6,1fr);gap:1px;background:var(--border);
 border-bottom:1px solid var(--border);position:relative;z-index:1}
@media(max-width:1200px){.stat-strip{grid-template-columns:repeat(3,1fr)}}
@media(max-width:600px){.stat-strip{grid-template-columns:repeat(2,1fr)}}
.stat{background:var(--bg);padding:14px 16px;display:flex;flex-direction:column;gap:4px;position:relative;min-height:78px}
.stat .label{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text-faint)}
.stat .value{font-family:var(--mono);font-size:22px;font-weight:700;color:var(--text);line-height:1.15}
.stat .value.signal{color:var(--signal)} .stat .value.warn{color:var(--warn)} .stat .value.alarm{color:var(--alarm)}
.stat .sub{font-family:var(--mono);font-size:10px;color:var(--text-faint)}
.stat .spark{position:absolute;right:12px;bottom:10px;width:64px;height:20px;opacity:.75}

/* === MAIN === */
main{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:1px;background:var(--border);
 position:relative;z-index:1}
@media(max-width:1100px){main{grid-template-columns:1fr}}
.panel{background:var(--bg);display:flex;flex-direction:column;min-width:0}
.panel-hdr{display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--border);
 font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--text-dim)}
.panel-hdr .title{color:var(--text)}
.panel-hdr .count{color:var(--signal);background:rgba(90,255,110,.08);padding:1px 6px;border-radius:2px;font-size:10px;letter-spacing:1px}
.panel-hdr .tools{margin-left:auto;display:flex;gap:4px}
.panel-hdr input.filter{background:var(--surface);border:1px solid var(--border);color:var(--text);
 font-family:var(--mono);font-size:11px;padding:4px 8px;border-radius:3px;outline:none;width:140px}
.panel-hdr input.filter:focus{border-color:var(--signal-dim)}

/* === PEER TABLE === */
.peer-wrap{overflow-x:auto}
table.peers{width:100%;border-collapse:collapse}
table.peers th{text-align:left;padding:8px 12px;font-family:var(--mono);font-size:9px;
 text-transform:uppercase;letter-spacing:1.5px;color:var(--text-faint);
 border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg);z-index:1}
table.peers td{padding:8px 12px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px;
 color:var(--text);white-space:nowrap}
table.peers tr{cursor:pointer}
table.peers tr:hover td{background:rgba(90,255,110,.03)}
table.peers tr.selected td{background:rgba(90,255,110,.08);border-left:2px solid var(--signal);padding-left:10px}
table.peers tr.mismatch td{background:rgba(248,81,73,.08)}
table.peers tr.mismatch:hover td{background:rgba(248,81,73,.14)}
.peer-name{color:var(--signal)}
.trust-state{display:inline-block;padding:1px 6px;font-size:10px;border-radius:2px;letter-spacing:1px}
.trust-verified{color:var(--signal);background:rgba(90,255,110,.1)}
.trust-tofu    {color:var(--metallic);background:rgba(154,160,166,.1)}
.trust-pending {color:var(--warn);background:rgba(255,179,64,.1)}
.trust-mismatch{color:var(--alarm);background:rgba(248,81,73,.15);font-weight:700}
.transport-badge{display:inline-block;font-size:10px;padding:1px 6px;border-radius:2px;
 border:1px solid var(--border-2);color:var(--text-dim);letter-spacing:1px}
.transport-ws  {color:var(--signal);border-color:rgba(90,255,110,.3)}
.transport-rns {color:var(--warn);  border-color:rgba(255,179,64,.3)}
.transport-both{color:var(--signal);border-color:rgba(90,255,110,.3);background:rgba(90,255,110,.04)}
.cap-pill{display:inline-block;font-size:10px;color:var(--text-dim);background:var(--surface);
 padding:1px 5px;border-radius:2px;margin-right:3px}

/* === HANDSHAKE === */
.hs-box{padding:14px 18px;font-family:var(--mono);font-size:11px;color:var(--text-dim);
 white-space:pre;overflow-x:auto;line-height:1.5}
.hs-stage{color:var(--text-faint);display:block}
.hs-stage.ok    {color:var(--signal)}
.hs-stage.active{color:var(--warn)}
.hs-stage.fail  {color:var(--alarm)}

/* === TRANSPORT === */
.transport-panel{display:grid;grid-template-columns:1fr 1fr;border-top:1px solid var(--border)}
@media(max-width:900px){.transport-panel{grid-template-columns:1fr}}
.tp-cell{padding:10px 16px;border-right:1px solid var(--border);font-family:var(--mono);font-size:11px;color:var(--text)}
.tp-cell:last-child{border-right:0}
.tp-cell.disabled{opacity:.45}
.tp-cell .tp-title{font-size:10px;letter-spacing:1.5px;color:var(--text-faint);text-transform:uppercase;margin-bottom:6px}
.tp-cell .tp-row{display:flex;justify-content:space-between;padding:2px 0}
.tp-cell .tp-row .k{color:var(--text-dim)}
.tp-cell .tp-row .v{color:var(--text)}

/* === FEED === */
.feed-tools{display:flex;gap:8px;padding:8px 12px;border-bottom:1px solid var(--border);align-items:center}
.feed-tools input[type=text]{flex:1;background:var(--surface);border:1px solid var(--border);
 color:var(--text);font-family:var(--mono);font-size:11px;padding:5px 8px;border-radius:3px;outline:none}
.feed-tools input[type=text]:focus{border-color:var(--signal-dim)}
.feed-tools label{font-family:var(--mono);font-size:10px;color:var(--text-dim);display:inline-flex;align-items:center;gap:4px;cursor:pointer;user-select:none}
.feed-body{overflow-y:auto;font-family:var(--mono);font-size:11px;max-height:420px;min-height:260px}
.feed-row{display:grid;grid-template-columns:4px 70px 12px 68px 96px 1fr;gap:8px;padding:3px 12px;
 border-bottom:1px solid rgba(26,26,26,.55);line-height:1.5}
.feed-row:hover{background:rgba(90,255,110,.02)}
.feed-row .gutter{border-left:2px solid transparent;height:100%}
.feed-row.sev-info  .gutter{border-color:var(--text-faint)}
.feed-row.sev-ok    .gutter{border-color:var(--signal-dim)}
.feed-row.sev-warn  .gutter{border-color:var(--warn)}
.feed-row.sev-alarm .gutter{border-color:var(--alarm)}
.feed-row .time{color:var(--text-faint);font-size:10px}
.feed-row .dir {color:var(--text-dim);text-align:center}
.feed-row .dir.in {color:var(--signal)}
.feed-row .dir.out{color:var(--warn)}
.feed-row .type{color:var(--metallic);font-size:10px;text-transform:uppercase;letter-spacing:1px}
.feed-row .peer{color:var(--text-dim);overflow:hidden;text-overflow:ellipsis}
.feed-row .payload{color:var(--text);word-break:break-all;white-space:pre-wrap;font-size:11px}

/* === SEND === */
.send-wrap{border-top:1px solid var(--border);padding:10px 12px;background:var(--surface)}
.send-row{display:flex;gap:6px;margin-bottom:6px;align-items:center;flex-wrap:wrap}
.send-row:last-child{margin-bottom:0}
.send-row select,.send-row input,.send-row textarea{background:var(--bg);border:1px solid var(--border);
 color:var(--text);font-family:var(--mono);font-size:12px;padding:6px 8px;border-radius:3px;outline:none;min-width:0}
.send-row select,.send-row input[type=text],.send-row textarea{flex:1}
.send-row select:focus,.send-row input:focus,.send-row textarea:focus{border-color:var(--signal-dim)}
.send-row input[type=number]{max-width:70px;flex:0 0 auto}
.send-row textarea{resize:vertical;font-family:var(--mono)}
.btn-signal{background:transparent;color:var(--signal);border:1px solid var(--signal-dim);
 cursor:pointer;font-weight:700;letter-spacing:2px;text-transform:uppercase;padding:6px 14px;font-size:11px;
 font-family:var(--mono);border-radius:3px}
.btn-signal:hover{background:rgba(90,255,110,.08)}
.btn-alarm{background:transparent;color:var(--alarm);border:1px solid rgba(248,81,73,.4);cursor:pointer;
 font-size:11px;font-family:var(--mono);text-transform:uppercase;letter-spacing:1.5px;padding:6px 12px;border-radius:3px}
.btn-alarm:hover{background:rgba(248,81,73,.1)}

/* === FOOTER === */
footer.ops{border-top:1px solid var(--border);background:var(--bg);padding:10px 20px;
 display:flex;gap:8px;flex-wrap:wrap;align-items:center;font-family:var(--mono);font-size:11px;position:relative;z-index:1}
footer.ops .ops-label{color:var(--text-faint);letter-spacing:1.5px;text-transform:uppercase;font-size:10px;margin-right:6px}
footer.ops button{background:transparent;border:1px solid var(--border);color:var(--text-dim);
 padding:5px 10px;border-radius:3px;cursor:pointer;font-family:var(--mono);font-size:11px;
 display:inline-flex;align-items:center;gap:6px;letter-spacing:1px}
footer.ops button:hover{color:var(--signal);border-color:var(--signal-dim)}
footer.ops button.btn-alarm:hover{color:var(--alarm);border-color:var(--alarm)}
footer.ops .spacer{flex:1}
footer.ops .legal{color:var(--text-faint);font-size:10px;letter-spacing:.5px}

/* === STATUSLINE === */
.statusline{position:fixed;bottom:0;left:0;right:0;background:var(--surface);
 border-top:1px solid var(--signal-dim);color:var(--signal);padding:6px 16px;
 font-family:var(--mono);font-size:11px;transform:translateY(100%);
 transition:transform .18s ease;z-index:100;letter-spacing:.5px}
.statusline.show{transform:translateY(0)}
.statusline.warn {color:var(--warn); border-top-color:var(--warn)}
.statusline.alarm{color:var(--alarm);border-top-color:var(--alarm)}

/* === SCROLLBARS === */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border-2)}
::-webkit-scrollbar-thumb:hover{background:var(--text-faint)}

.empty{padding:28px 16px;text-align:center;color:var(--text-faint);font-family:var(--mono);font-size:11px;letter-spacing:1px}

/* === MOBILE === */
@media(max-width:600px){
 .chrome{padding:8px 10px;gap:8px}
 .wordmark{font-size:14px;letter-spacing:1.5px}
 .token-box{display:none}
 .stat{padding:10px 12px;min-height:64px}
 .stat .value{font-size:18px}
 .stat .spark{display:none}
 .feed-body{max-height:320px}
 .send-row select,.send-row input,.send-row textarea,.send-row button{min-height:36px;font-size:13px}
}
</style></head><body>

<!-- Inline SVG sprite — no CDN, no outbound requests. -->
<svg style="display:none" aria-hidden="true">
 <symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></symbol>
 <symbol id="i-eye" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></symbol>
 <symbol id="i-eye-off" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></symbol>
 <symbol id="i-refresh" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></symbol>
 <symbol id="i-pause" viewBox="0 0 24 24"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></symbol>
 <symbol id="i-play" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></symbol>
 <symbol id="i-download" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></symbol>
 <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></symbol>
 <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></symbol>
 <symbol id="i-alert" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></symbol>
 <symbol id="i-link" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></symbol>
 <symbol id="i-trash" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></symbol>
 <symbol id="i-key" viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></symbol>
</svg>

<!-- HEADER -->
<header class="chrome">
 <div class="wordmark">IRONMESH</div>
 <span class="version-pill">{{IRONMESH_VERSION}} · PRE-1.0</span>
 <div class="node-fp" id="node-fp" title="click to copy full fingerprint">— · —</div>
 <div class="mesh-state" id="mesh-state" data-state="ISOLATED">
  <span class="dot"></span>
  <span id="mesh-state-label">INITIALIZING</span>
 </div>
 <div class="uptime" id="uptime">uptime 0s</div>
 <div class="offline-badge" title="Content-Security-Policy locks this page to same-origin. No Google Fonts, no CDNs, no analytics. Yank your router — this keeps working.">OFFLINE-FIRST</div>
 <div class="token-box" title="Bearer token for this dashboard session (printed at startup)">
  <span>TOKEN</span>
  <input type="password" id="token-input" readonly autocomplete="off" spellcheck="false" value="">
  <button class="icon-btn" id="token-reveal" title="reveal / hide token"><svg class="icon"><use href="#i-eye"/></svg></button>
  <button class="icon-btn" id="token-copy" title="copy dashboard URL"><svg class="icon"><use href="#i-link"/></svg></button>
  <button class="icon-btn" id="token-rotate" title="rotate session token"><svg class="icon"><use href="#i-refresh"/></svg></button>
 </div>
</header>

<!-- STAT STRIP -->
<section class="stat-strip">
 <div class="stat"><div class="label">Active Peers</div><div class="value signal" id="s-peers">0</div><div class="sub" id="s-peers-sub">0 total · 0 routes</div><svg class="spark" id="sp-peers" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
 <div class="stat"><div class="label">Messages · 15m</div><div class="value" id="s-msgs">0 / 0</div><div class="sub">in / out</div><svg class="spark" id="sp-msgs" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
 <div class="stat"><div class="label">Handshakes</div><div class="value signal" id="s-hs">0 / 0</div><div class="sub">✓ success · ✗ fail</div><svg class="spark" id="sp-hs" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
 <div class="stat"><div class="label">Queue Depth</div><div class="value" id="s-q">0</div><div class="sub" id="s-q-sub">pending · evicted 0</div><svg class="spark" id="sp-q" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
 <div class="stat"><div class="label">Bytes · Encrypted</div><div class="value" id="s-bytes">0B</div><div class="sub">↓ in  ·  ↑ out</div><svg class="spark" id="sp-bytes" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
 <div class="stat"><div class="label">Auth-Fail Blocks</div><div class="value" id="s-auth">0</div><div class="sub" id="s-auth-sub">IP-level · rate-limited 0</div><svg class="spark" id="sp-auth" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
</section>

<!-- MAIN GRID -->
<main>
 <section class="panel">
  <div class="panel-hdr">
   <span class="title">PEERS</span>
   <span class="count" id="peer-count">0</span>
   <span class="tools"><input type="text" class="filter" id="peer-filter" placeholder="filter peers…"></span>
  </div>
  <div class="peer-wrap">
   <table class="peers">
    <thead><tr>
     <th>Name</th><th>Fingerprint</th><th>Transport</th><th>Latency</th><th>Trust</th><th>Last</th><th>Capabilities</th>
    </tr></thead>
    <tbody id="peer-body"><tr><td colspan="7" class="empty">no peers yet · mDNS default-deny · --allowed-peers to gate</td></tr></tbody>
   </table>
  </div>

  <div class="panel-hdr" style="border-top:1px solid var(--border)">
   <span class="title">HANDSHAKE</span>
   <span class="count" id="hs-peer-label">no peer selected</span>
  </div>
  <pre class="hs-box" id="hs-diagram">Client                                    Server
  |                                        |
<span class="hs-stage" data-stage="1">  |&lt;── PASSPHRASE_CHALLENGE ──────────────|</span> (32-byte server nonce)
<span class="hs-stage" data-stage="1">  |─── HMAC-SHA256(pass, nonce) ─────────&gt;|</span>
<span class="hs-stage" data-stage="1">  |&lt;── PASSPHRASE_VERIFIED + server_proof─|</span> (mutual auth)
  |                                        |
<span class="hs-stage" data-stage="2">  |─── HELLO (eph_pub_A, id_pub_A) ──────&gt;|</span> signed Ed25519 + channel_binding
<span class="hs-stage" data-stage="2">  |&lt;── HELLO (eph_pub_B, id_pub_B) ───────|</span> signed Ed25519 + channel_binding
<span class="hs-stage" data-stage="2">  |    TOFU check on id_pub_B              |</span> TOFU check on id_pub_A
  |                                        |
<span class="hs-stage" data-stage="3">  | ECDH(eph_priv_A, eph_pub_B)            |</span> ECDH(eph_priv_B, eph_pub_A)
<span class="hs-stage" data-stage="3">  |    = shared_secret                     |</span>    = shared_secret
<span class="hs-stage" data-stage="3">  |  (ephemeral privkeys destroyed)        |</span> (ephemeral privkeys destroyed)
  |                                        |
<span class="hs-stage" data-stage="4">  |&lt;═══ Encrypted + Signed Messages ═════&gt;|</span> XSalsa20-Poly1305 + Ed25519
</pre>

  <div class="transport-panel">
   <div class="tp-cell" id="tp-ws">
    <div class="tp-title">WebSocket · LAN</div>
    <div class="tp-row"><span class="k">peers</span><span class="v" id="tp-ws-peers">0</span></div>
    <div class="tp-row"><span class="k">throughput</span><span class="v" id="tp-ws-tput">0 B/s</span></div>
    <div class="tp-row"><span class="k">latency p50</span><span class="v" id="tp-ws-lat">—</span></div>
   </div>
   <div class="tp-cell" id="tp-rns">
    <div class="tp-title">Reticulum · LoRa</div>
    <div class="tp-row"><span class="k">status</span><span class="v" id="tp-rns-status">install ironmesh[rns] to enable</span></div>
    <div class="tp-row"><span class="k">dest hash</span><span class="v" id="tp-rns-dest">—</span></div>
    <div class="tp-row"><span class="k">profile</span><span class="v" id="tp-rns-prof">—</span></div>
   </div>
  </div>

  <!-- v0.8.5: pending-trust message gate -->
  <div class="panel-hdr" style="border-top:1px solid var(--border)">
   <span class="title">PENDING TRUST</span>
   <span class="count" id="pending-trust-count">0</span>
   <span class="tools">
    <span id="pending-trust-status" style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em">gate off</span>
   </span>
  </div>
  <div class="pending-trust-wrap" id="pending-trust-wrap" style="padding:6px 10px 12px">
   <div class="empty" id="pending-trust-empty" style="font-size:11px;color:var(--text-dim);padding:6px 0">no peers awaiting promotion</div>
   <table class="peers" id="pending-trust-table" style="display:none">
    <thead><tr>
     <th>Node</th><th>Fingerprint</th><th>Queued</th><th>First seen</th><th>Action</th>
    </tr></thead>
    <tbody id="pending-trust-body"></tbody>
   </table>
  </div>

  <!-- v0.8.5.7: pending capability-set change (cap-binding operator surface) -->
  <div class="panel-hdr" style="border-top:1px solid var(--border)">
   <span class="title">PENDING CAP CHANGE</span>
   <span class="count" id="pending-cap-count">0</span>
   <span class="tools">
    <span id="pending-cap-hint" style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em">capability-set binding</span>
   </span>
  </div>
  <div class="pending-cap-wrap" id="pending-cap-wrap" style="padding:6px 10px 12px">
   <div class="empty" id="pending-cap-empty" style="font-size:11px;color:var(--text-dim);padding:6px 0">no peers awaiting cap review</div>
   <table class="peers" id="pending-cap-table" style="display:none">
    <thead><tr>
     <th>Node</th><th>Added</th><th>Removed</th><th>Action</th>
    </tr></thead>
    <tbody id="pending-cap-body"></tbody>
   </table>
  </div>
 </section>

 <section class="panel">
  <div class="panel-hdr">
   <span class="title">MESSAGE FEED</span>
   <span class="count" id="feed-count">0</span>
   <span class="tools">
    <button class="icon-btn" id="feed-pause" title="pause tail"><svg class="icon"><use href="#i-pause"/></svg></button>
    <button class="icon-btn" id="feed-export" title="export CSV"><svg class="icon"><use href="#i-download"/></svg></button>
    <button class="icon-btn" id="feed-clear" title="clear feed"><svg class="icon"><use href="#i-trash"/></svg></button>
   </span>
  </div>
  <div class="feed-tools">
   <svg class="icon" style="color:var(--text-dim);flex:0 0 auto"><use href="#i-search"/></svg>
   <input type="text" id="feed-search" placeholder="filter (substring or /regex/i)…" autocomplete="off">
   <label><input type="checkbox" id="feed-show-chatter"> chatter</label>
  </div>
  <div class="feed-body" id="feed"><div class="empty">waiting for encrypted traffic…</div></div>

  <div class="send-wrap">
   <div class="send-row">
    <select id="send-peer"><option value="">— select peer —</option></select>
    <input type="text" id="send-type" value="MSG" maxlength="16" style="max-width:80px;flex:0 0 auto" title="message type">
    <select id="send-prio" style="max-width:110px;flex:0 0 auto" title="priority">
     <option value="normal">normal</option><option value="high">high</option><option value="low">low</option>
    </select>
   </div>
   <div class="send-row">
    <textarea id="send-payload" rows="2" placeholder="signed + encrypted before leaving this host…"></textarea>
    <button class="btn-signal" id="send-btn" style="flex:0 0 auto">SEND</button>
   </div>
   <div class="send-row" style="border-top:1px dashed var(--border);padding-top:8px">
    <select id="dlg-a"><option value="">— AI peer A —</option></select>
    <select id="dlg-b"><option value="">— AI peer B —</option></select>
    <input type="number" id="dlg-turns" value="4" min="1" max="20" title="max turns">
    <input type="text" id="dlg-seed" placeholder="seed prompt…">
    <button class="btn-signal" id="dlg-btn" style="flex:0 0 auto">A2A</button>
   </div>
  </div>
 </section>
</main>

<!-- FOOTER OPS -->
<footer class="ops">
 <span class="ops-label">OPS</span>
 <button id="op-audit" title="view tamper-evident audit log"><svg class="icon" style="width:12px;height:12px"><use href="#i-shield"/></svg>AUDIT LOG</button>
 <button id="op-rotate-keys" title="rotate identity keypair"><svg class="icon" style="width:12px;height:12px"><use href="#i-key"/></svg>ROTATE KEYS</button>
 <button id="op-rekey" title="force session rekey"><svg class="icon" style="width:12px;height:12px"><use href="#i-refresh"/></svg>SESSION REKEY</button>
 <button id="op-panic" class="btn-alarm" title="wipe ephemeral keys, disconnect all peers"><svg class="icon" style="width:12px;height:12px"><use href="#i-alert"/></svg>PANIC WIPE</button>
 <span class="spacer"></span>
 <span class="legal">XSalsa20-Poly1305 · X25519 · Ed25519 · Argon2id · TOFU · MIT · No cloud · No internet required</span>
</footer>

<div class="statusline" id="statusline">—</div>

<script>
(function(){
 const $ = id => document.getElementById(id);
 const token = new URLSearchParams(location.search).get('token') || '';
 const WS_URL = 'ws://' + location.host + '/ws' + (token ? '?token=' + token : '');

 let ws = null;
 let state = { peers:[], metrics:{}, capabilities:{}, history:[] };
 let selectedPeer = null;
 let feedPaused = false;
 let showChatter = false;
 let feedBuf = [];
 const FEED_CAP = 1500;
 const sparkBuf = { peers:[], msgs:[], hs:[], q:[], bytes:[], auth:[] };
 const SPARK_N = 48;
 let _seeded = false;

 const fmtBytes = b => b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':b<1073741824?(b/1048576).toFixed(1)+'MB':(b/1073741824).toFixed(2)+'GB';
 const fmtUp    = s => { const h=Math.floor(s/3600), m=Math.floor((s%3600)/60), x=Math.floor(s%60); return (h?h+'h ':'')+(m?m+'m ':'')+x+'s'; };
 const fmtRel   = t => { const d=Date.now()/1000 - t; if(d<0)return 'now'; if(d<60)return Math.floor(d)+'s'; if(d<3600)return Math.floor(d/60)+'m'; return Math.floor(d/3600)+'h'; };
 const escHtml  = s => String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
 const shortFp  = fp => fp && fp.length>=12 ? fp.slice(0,4)+'…'+fp.slice(-4) : (fp||'—');

 function statusline(msg, kind){
  const el = $('statusline');
  el.textContent = msg;
  el.className = 'statusline show' + (kind?' '+kind:'');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 2600);
 }
 async function copy(text){
  try{
   if(navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
   else { const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); }
   statusline('copied · '+(text.length>40?text.slice(0,40)+'…':text));
  }catch(e){ statusline('copy failed', 'alarm'); }
 }

 // Token box
 $('token-input').value = token || '(none — check startup log)';
 $('token-reveal').addEventListener('click', () => {
  const inp = $('token-input');
  const isPwd = inp.type === 'password';
  inp.type = isPwd ? 'text' : 'password';
  $('token-reveal').innerHTML = isPwd ? '<svg class="icon"><use href="#i-eye-off"/></svg>' : '<svg class="icon"><use href="#i-eye"/></svg>';
 });
 $('token-copy').addEventListener('click', () => copy(location.href));
 $('token-rotate').addEventListener('click', () => {
  if(!confirm('Rotate the dashboard session token? This invalidates the current URL.')) return;
  if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'rotate_gui_token'}));
  statusline('token rotation requested · backend wiring pending', 'warn');
 });
 $('node-fp').addEventListener('click', () => { if(state.node_id) copy(state.node_id); });

 // WS
 function connect(){
  ws = new WebSocket(WS_URL);
  ws.onopen    = () => {
   setMeshState('ISOLATED','control channel open');
   statusline('control channel open · ephemeral ECDH complete');
   // v0.8.5: pull initial pending-trust state for the panel.
   try{ ws.send(JSON.stringify({action:'list_pending_trust'})); }catch(e){}
   // v0.8.5.7: pull initial pending-cap-change state.
   try{ ws.send(JSON.stringify({action:'list_pending_cap'})); }catch(e){}
  };
  ws.onclose   = () => { setMeshState('ISOLATED','CONTROL CHANNEL CLOSED'); statusline('control channel closed · reconnecting…', 'warn'); setTimeout(connect, 2000); };
  ws.onerror   = () => { try{ ws.close(); }catch(e){} };
  ws.onmessage = e => { try{ handle(JSON.parse(e.data)); }catch(x){ console.error(x); } };
 }

 function handle(msg){
  if(msg.type === 'snapshot' || msg.type === 'state_update'){
   state = Object.assign(state, msg.data || msg);
   updateUI();
  } else if(msg.type === 'message_event'){
   pushFeed(toFeedRow(msg));
  } else if(msg.type === 'peer_event'){
   const ok = msg.event === 'connected';
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:ok?'ok':'warn', type:ok?'CONNECT':'DISCONNECT', peer:msg.peer_id||'', payload:msg.reason||'' });
  } else if(msg.type === 'send_ack'){
   pushFeed({ t:Date.now()/1000, dir:'out', sev:'ok', type:'ACK', peer:'self', payload:'sent · '+msg.msg_id });
  } else if(msg.type === 'send_error'){
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:'alarm', type:'ERROR', peer:'self', payload:msg.error||'' });
  } else if(msg.type === 'dialogue_event'){
   pushFeed(toDialogueRow(msg));
  } else if(msg.type === 'auth_failure'){
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:'alarm', type:'AUTHFAIL', peer:msg.ip||'', payload:msg.reason||'' });
  } else if(msg.type === 'pending_trust_list'){
   renderPendingTrust(msg.pending || [], !!msg.gate_enabled);
  } else if(msg.type === 'pending_trust'){
   // Incremental: a new MSG just got queued for a pending peer. Refresh the panel.
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:'warn', type:'PENDING',
              peer:(msg.source_node_id||'').slice(0,12), payload:'queued · count='+msg.queued_count });
   if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'list_pending_trust'}));
  } else if(msg.type === 'promote_ack'){
   statusline('promoted '+(msg.target||'').slice(0,12)+' · drained '+msg.drained, msg.ok?'ok':'alarm');
   if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'list_pending_trust'}));
  } else if(msg.type === 'block_ack'){
   statusline('blocked '+(msg.target||'').slice(0,12)+' · discarded '+msg.discarded, msg.ok?'warn':'alarm');
   if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'list_pending_trust'}));
  } else if(msg.type === 'pending_cap_list'){
   // v0.8.5.7: initial or refreshed list of peers in pending-cap-change
   renderPendingCap(msg.pending || []);
  } else if(msg.type === 'cap_change_detected'){
   // v0.8.5.7: a peer's cap-set just changed. Surface on feed + refresh panel.
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:'warn', type:'CAPCHG',
              peer:(msg.peer||'').slice(0,12),
              payload:'+'+(msg.added||[]).length+' -'+(msg.removed||[]).length+' caps · review in panel' });
   if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'list_pending_cap'}));
  } else if(msg.type === 'cap_promote_ack'){
   statusline('cap-accepted '+(msg.node_id||'').slice(0,12)+' · new baseline '+(msg.new_hash||'').slice(0,8), msg.ok?'ok':'alarm');
   if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'list_pending_cap'}));
  }
 }

 function renderPendingTrust(rows, gateEnabled){
  $('pending-trust-status').textContent = gateEnabled ? 'gate on' : 'gate off';
  $('pending-trust-status').style.color = gateEnabled ? 'var(--ok, #4ade80)' : 'var(--text-dim)';
  $('pending-trust-count').textContent = rows.length;
  const empty = $('pending-trust-empty');
  const table = $('pending-trust-table');
  if(!rows.length){
   empty.style.display = '';
   empty.textContent = gateEnabled ? 'no peers awaiting promotion' : 'gate disabled — start daemon with --require-message-promotion to gate new peers';
   table.style.display = 'none';
   return;
  }
  empty.style.display = 'none';
  table.style.display = '';
  $('pending-trust-body').innerHTML = rows.map(r => {
   const nid = r.node_id || '';
   const fp = r.fingerprint || '';
   const queued = r.queued_count != null ? r.queued_count : 0;
   const first = r.first_seen ? fmtRel(r.first_seen) + ' ago' : '—';
   return '<tr>'
    + '<td><code title="'+escHtml(nid)+'">'+escHtml(nid.slice(0,12))+'…</code></td>'
    + '<td>'+escHtml(shortFp(fp))+'</td>'
    + '<td style="text-align:right">'+queued+'</td>'
    + '<td>'+escHtml(first)+'</td>'
    + '<td>'
    +  '<button class="btn-signal pending-promote" data-node="'+escHtml(nid)+'" style="padding:2px 8px;font-size:10px">PROMOTE</button> '
    +  '<button class="btn-alarm pending-block" data-node="'+escHtml(nid)+'" style="padding:2px 8px;font-size:10px">BLOCK</button>'
    + '</td>'
    + '</tr>';
  }).join('');
  // Wire button handlers (delegated rebind on each render).
  document.querySelectorAll('#pending-trust-body .pending-promote').forEach(b => {
   b.addEventListener('click', () => {
    const node = b.getAttribute('data-node');
    if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'promote_peer', target_node_id:node}));
   });
  });
  document.querySelectorAll('#pending-trust-body .pending-block').forEach(b => {
   b.addEventListener('click', () => {
    const node = b.getAttribute('data-node');
    if(!confirm('Block peer '+node.slice(0,12)+'…? This drops queued messages and silences future MSGs from this peer.')) return;
    if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'block_peer', target_node_id:node}));
   });
  });
 }

 // v0.8.5.7: render the pending capability-set change panel. Parallels
 // renderPendingTrust for the cap-binding feature. A row per peer whose
 // currently-announced cap set differs from the accepted baseline;
 // shows the diff (added/removed tokens) so the operator can decide.
 function renderPendingCap(rows){
  rows = rows || [];
  $('pending-cap-count').textContent = rows.length;
  const empty = $('pending-cap-empty');
  const table = $('pending-cap-table');
  if(!rows.length){
   empty.style.display = '';
   empty.textContent = 'no peers awaiting cap review';
   table.style.display = 'none';
   return;
  }
  empty.style.display = 'none';
  table.style.display = '';
  $('pending-cap-body').innerHTML = rows.map(r => {
   const nid = r.node_id || '';
   const added = (r.added || []).map(escHtml).join(', ') || '—';
   const removed = (r.removed || []).map(escHtml).join(', ') || '—';
   const addedTitle = 'Baseline hash: ' + (r.baseline_hash||'').slice(0,16) +
                      '…\nPending hash:  ' + (r.pending_hash||'').slice(0,16) + '…';
   return '<tr>'
    + '<td><code title="'+escHtml(nid)+'">'+escHtml(nid.slice(0,12))+'…</code></td>'
    + '<td style="color:var(--ok,#4ade80);max-width:180px;overflow:hidden;text-overflow:ellipsis" title="'+escHtml(addedTitle)+'">+ '+added+'</td>'
    + '<td style="color:var(--warn,#f87171);max-width:180px;overflow:hidden;text-overflow:ellipsis">− '+removed+'</td>'
    + '<td>'
    +  '<button class="btn-signal cap-promote" data-node="'+escHtml(nid)+'" style="padding:2px 8px;font-size:10px" title="Accept the new capability set as the baseline and restore trust.">ACCEPT</button>'
    + '</td>'
    + '</tr>';
  }).join('');
  document.querySelectorAll('#pending-cap-body .cap-promote').forEach(b => {
   b.addEventListener('click', () => {
    const node = b.getAttribute('data-node');
    if(!confirm('Accept the new capability set for '+node.slice(0,12)+'…?\n\nThis pins the peer\'s currently-advertised capability set as the new baseline and restores the trusted state. Inbound messages that were queueing at the daemon will drain.')) return;
    if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'cap_promote_peer', target_node_id:node}));
   });
  });
 }

 function toFeedRow(msg){
  const mt = msg.msg_type || '?';
  let payload = msg.payload;
  if(payload instanceof ArrayBuffer || payload instanceof Uint8Array) payload = '[binary]';
  else if(typeof payload === 'object'){ try{ payload = JSON.stringify(payload); }catch(e){ payload = String(payload); } }
  else payload = String(payload==null?'':payload);
  if(payload.charAt(0)==='{' && payload.indexOf('"conv_id"')>0){
   try{ const e=JSON.parse(payload); payload='['+e.kind+' turn '+e.turn+'/'+e.max_turns+'] '+e.body; }catch(x){}
  }
  return { t: msg.timestamp || Date.now()/1000, dir: msg.direction||'in',
   sev: mt==='ERROR'?'alarm':(mt==='MSG'||mt==='CONV'?'ok':'info'),
   type: mt, peer: msg.peer_id||'', payload };
 }
 function toDialogueRow(msg){
  const ev = msg.event || '?';
  let line = '', sev = 'info';
  if(ev==='started')           line = 'start · '+(msg.peer_a||'').slice(0,8)+' ↔ '+(msg.peer_b||'').slice(0,8)+' · max_turns='+msg.max_turns;
  else if(ev==='turn')        { line = 'T'+msg.turn+' '+(msg.speaker||'?')+': '+(msg.body||'').slice(0,400); sev='ok'; }
  else if(ev==='end')           line = '[END] '+(msg.speaker||'?')+': '+(msg.reason||'');
  else if(ev==='error')       { line = '[ERR] '+(msg.speaker||'?')+': '+(msg.reason||''); sev='alarm'; }
  else if(ev==='timeout')     { line = '[TIMEOUT] waiting on '+(msg.waiting_on||'?')+' ('+msg.timeout+'s)'; sev='warn'; }
  else if(ev==='turn_cap_reached') line = '[CAP] '+msg.cap+' turns reached';
  else if(ev==='finished')     line = '[FINISHED]';
  else                         line = '['+ev+'] '+JSON.stringify(msg);
  return { t:Date.now()/1000, dir: ev==='turn'?'in':'sys', sev, type:'A2A', peer: msg.conv_id||'', payload: line };
 }

 const isChatter = r => r.type==='PING' || r.type==='PONG' || r.type==='HEARTBEAT' || r.type==='ROUTE_ANNOUNCE' || r.type==='CAPABILITY_ANNOUNCE';

 function pushFeed(row){
  feedBuf.push(row);
  if(feedBuf.length > FEED_CAP) feedBuf.splice(0, feedBuf.length - FEED_CAP);
  if(!feedPaused) renderFeed(true);
 }

 function renderFeed(appendHint){
  const feed = $('feed');
  const search = $('feed-search').value.trim();
  let matcher = null;
  if(search){
   const rx = /^\/(.+)\/([a-z]*)$/.exec(search);
   try{ matcher = rx ? new RegExp(rx[1], rx[2]) : { test: s => s.toLowerCase().includes(search.toLowerCase()) }; }
   catch(e){ matcher = { test: s => s.includes(search) }; }
  }
  const rows = feedBuf.filter(r => (showChatter || !isChatter(r)) && (!matcher || matcher.test(r.type+' '+r.peer+' '+r.payload)));
  $('feed-count').textContent = rows.length;
  if(!rows.length){
   // Disambiguate empty buffer vs filtered-to-zero — operators kept asking "why nothing?" after clear.
   const msg = feedBuf.length === 0 ? 'waiting for encrypted traffic…' : 'no matching events · adjust filter';
   feed.innerHTML = '<div class="empty">'+msg+'</div>';
   return;
  }
  const atBottom = feed.scrollTop + feed.clientHeight >= feed.scrollHeight - 24;
  const shown = rows.slice(-300);
  feed.innerHTML = shown.map(renderRow).join('');
  if(atBottom && !feedPaused) feed.scrollTop = feed.scrollHeight;
 }
 function renderRow(r){
  const t = new Date(r.t*1000);
  const ts = t.toLocaleTimeString([], { hour12:false });
  const arrow = r.dir==='out' ? '↑' : (r.dir==='sys' ? '·' : '↓');
  const peerLabel = peerName(r.peer);
  return '<div class="feed-row sev-'+r.sev+'">'+
   '<span class="gutter"></span>'+
   '<span class="time">'+ts+'</span>'+
   '<span class="dir '+r.dir+'">'+arrow+'</span>'+
   '<span class="type">'+escHtml(r.type)+'</span>'+
   '<span class="peer">'+escHtml(peerLabel)+'</span>'+
   '<span class="payload">'+escHtml((r.payload||'').slice(0,500))+'</span>'+
   '</div>';
 }
 function peerName(id){
  if(!id) return '';
  if(id==='self' || id==='a2a') return id;
  const p = (state.peers||[]).find(p => p.node_id===id);
  return p ? (p.name || id.slice(0,8)) : id.slice(0,8);
 }

 $('feed-pause').addEventListener('click', () => {
  feedPaused = !feedPaused;
  $('feed-pause').innerHTML = feedPaused ? '<svg class="icon"><use href="#i-play"/></svg>' : '<svg class="icon"><use href="#i-pause"/></svg>';
  $('feed-pause').title = feedPaused ? 'resume tail' : 'pause tail';
  if(!feedPaused) renderFeed();
  statusline(feedPaused ? 'tail paused' : 'tail resumed');
 });
 $('feed-export').addEventListener('click', () => {
  const header = 'timestamp_iso,direction,severity,type,peer,payload';
  const lines = [header];
  feedBuf.forEach(r => {
   const esc = (r.payload||'').replace(/"/g,'""').replace(/\r?\n/g,' ');
   lines.push([new Date(r.t*1000).toISOString(), r.dir, r.sev, r.type, r.peer, '"'+esc+'"'].join(','));
  });
  const blob = new Blob([lines.join('\n')], { type:'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download='ironmesh-feed-'+Date.now()+'.csv'; a.click();
  setTimeout(()=>URL.revokeObjectURL(url), 1000);
  statusline('feed exported');
 });
 $('feed-clear').addEventListener('click', () => { feedBuf = []; renderFeed(); statusline('feed cleared'); });
 $('feed-search').addEventListener('input', renderFeed);
 $('feed-show-chatter').addEventListener('change', e => { showChatter = e.target.checked; renderFeed(); });
 $('peer-filter').addEventListener('input', () => renderPeers(state.peers||[]));

 // Mesh state
 function setMeshState(s, label){
  const el = $('mesh-state');
  el.dataset.state = s;
  $('mesh-state-label').textContent = label || s;
 }

 function updateUI(){
  const m = state.metrics || {};
  const peers = state.peers || [];
  const online = peers.filter(p => p.status === 'online').length;

  if(state.node_id) $('node-fp').textContent = shortFp(state.node_id) + ' · ' + (state.name || '—');
  $('uptime').textContent = 'uptime ' + fmtUp(m.uptime_seconds || 0);

  if(online === 0) setMeshState('ISOLATED', 'ISOLATED · 0 PEERS');
  else if(peers.some(p => p.status==='handshaking' || !p.verified)) setMeshState('DEGRADED', 'DEGRADED · '+online+'/'+peers.length);
  else setMeshState('OPERATIONAL', online+' PEER'+(online===1?'':'S')+' ONLINE');

  $('s-peers').textContent = m.active_peers != null ? m.active_peers : online;
  $('s-peers-sub').textContent = (m.total_peers||peers.length)+' total · '+(m.routes_known||0)+' routes';
  $('s-msgs').textContent  = (m.messages_received||0) + ' / ' + (m.messages_sent||0);
  const hsF = m.handshake_failures||0;
  $('s-hs').textContent    = (m.handshake_successes||0) + ' / ' + hsF;
  $('s-hs').className = 'value ' + (hsF > 0 ? 'warn' : 'signal');
  const qDepth = peers.reduce((a,p)=>a+(p.pending_queue_size||0), 0);
  $('s-q').textContent     = qDepth;
  $('s-q-sub').textContent = 'pending · evicted '+(m.pending_evicted||0);
  $('s-bytes').textContent = fmtBytes((m.bytes_sent||0)+(m.bytes_received||0));
  const authBlocks = m.auth_fail_blocks || 0;
  $('s-auth').textContent  = authBlocks;
  $('s-auth').className    = 'value ' + (authBlocks > 0 ? 'alarm' : '');
  $('s-auth-sub').textContent = 'IP-level · rate-limited '+(m.rate_limits_triggered||0);

  pushSpark('peers', online);
  pushSpark('msgs',  (m.messages_received||0) + (m.messages_sent||0));
  pushSpark('hs',    m.handshake_successes || 0);
  pushSpark('q',     qDepth);
  pushSpark('bytes', (m.bytes_sent||0)+(m.bytes_received||0));
  pushSpark('auth',  authBlocks);

  renderPeers(peers);
  renderTransports(peers, m);
  seedFeedFromHistory();
 }

 function renderPeers(peers){
  const filter = ($('peer-filter').value || '').toLowerCase();
  const shown = peers.filter(p => !filter || (p.name||'').toLowerCase().includes(filter) || (p.node_id||'').toLowerCase().includes(filter));
  $('peer-count').textContent = shown.length;
  const body = $('peer-body');
  if(!shown.length){
   body.innerHTML = '<tr><td colspan="7" class="empty">'+(filter?'no peers match filter':'no peers yet · mDNS default-deny · --allowed-peers to gate')+'</td></tr>';
   populateSends(peers);
   renderHandshake(null);
   return;
  }
  body.innerHTML = shown.map(p => {
   const trust = trustState(p);
   const transport = transportBadge(p);
   const latency = p.latency_ms != null ? p.latency_ms.toFixed(0)+'ms' : '—';
   const last = p.last_seen ? fmtRel(p.last_seen) : '—';
   const caps = capabilitiesFor(p.node_id).slice(0,3).map(c => '<span class="cap-pill">'+escHtml(c)+'</span>').join('');
   const sel = p.node_id === selectedPeer ? ' selected' : '';
   const mm  = trust.kind === 'mismatch' ? ' mismatch' : '';
   return '<tr class="peer-row'+sel+mm+'" data-id="'+escHtml(p.node_id)+'">'+
    '<td class="peer-name">'+escHtml(p.name||'—')+'</td>'+
    '<td>'+shortFp(p.node_id)+'</td>'+
    '<td>'+transport+'</td>'+
    '<td>'+latency+'</td>'+
    '<td><span class="trust-state '+trust.cls+'">'+trust.label+'</span></td>'+
    '<td title="'+new Date((p.last_seen||0)*1000).toISOString()+'">'+last+'</td>'+
    '<td>'+(caps||'<span style="color:var(--text-faint)">—</span>')+'</td>'+
    '</tr>';
  }).join('');
  body.querySelectorAll('tr.peer-row').forEach(tr => {
   tr.addEventListener('click', () => {
    selectedPeer = tr.dataset.id;
    body.querySelectorAll('tr.peer-row').forEach(x => x.classList.toggle('selected', x.dataset.id===selectedPeer));
    renderHandshake(peers.find(p => p.node_id===selectedPeer));
   });
  });
  populateSends(peers);
  if(selectedPeer){
   const peer = peers.find(p => p.node_id===selectedPeer);
   if(peer) renderHandshake(peer); else renderHandshake(null);
  } else renderHandshake(null);
 }

 function trustState(p){
  if(p.trust_state === 'mismatch' || p.mismatch === true) return { kind:'mismatch', cls:'trust-mismatch', label:'✗ MISMATCH' };
  if(p.status === 'handshaking')                          return { kind:'pending',  cls:'trust-pending',  label:'… HANDSHAKING' };
  if(!p.verified)                                          return { kind:'pending',  cls:'trust-pending',  label:'… UNVERIFIED' };
  // v0.8.5.2: when the daemon ran with --require-message-promotion the trust
  // store carries a tri-state (pending/trusted/blocked). Surface that here so
  // operators see gate state in the main peers table, not only in PENDING TRUST.
  if(p.trust_gate_state === 'blocked')                    return { kind:'blocked',  cls:'trust-mismatch', label:'⛔ BLOCKED' };
  if(p.trust_gate_state === 'pending')                    return { kind:'pending',  cls:'trust-pending',  label:'… PENDING-PROMOTE' };
  // v0.8.3 backend pins on first sight (trust.py TOFU); fresh vs returning requires a new field.
  return { kind:'tofu', cls:'trust-verified', label:'✓ TOFU-PINNED' };
 }
 function transportBadge(p){
  const hasWs  = p.ws_address || (p.transport_type||'websocket') === 'websocket';
  const hasRns = p.rns_dest_hash || p.transport_type === 'reticulum' || p.transport_type === 'both';
  if(hasWs && hasRns) return '<span class="transport-badge transport-both">WS+RNS</span>';
  if(hasRns)          return '<span class="transport-badge transport-rns">RNS</span>';
  return '<span class="transport-badge transport-ws">WS</span>';
 }
 function capabilitiesFor(nodeId){
  const out = [];
  const caps = state.capabilities || {};
  Object.keys(caps).forEach(c => { if((caps[c]||[]).indexOf(nodeId) !== -1) out.push(c); });
  return out;
 }

 function renderHandshake(peer){
  const stages = document.querySelectorAll('#hs-diagram .hs-stage');
  stages.forEach(s => s.classList.remove('ok','active','fail'));
  if(!peer){ $('hs-peer-label').textContent = 'no peer selected'; return; }
  $('hs-peer-label').textContent = (peer.name||'—') + ' · ' + shortFp(peer.node_id);
  let maxOk = 0;
  if(peer.trust_state === 'mismatch' || peer.mismatch){ stages.forEach(s => { if(+s.dataset.stage<=2) s.classList.add('ok'); else s.classList.add('fail'); }); return; }
  if(peer.status === 'offline'){ stages.forEach(s => s.classList.add('fail')); return; }
  if(peer.status === 'online' && peer.verified) maxOk = 4;
  else if(peer.status === 'online')              maxOk = 3;
  else if(peer.status === 'handshaking')         maxOk = 1;
  stages.forEach(s => {
   const st = +s.dataset.stage;
   if(st <= maxOk) s.classList.add('ok');
   else if(st === maxOk+1) s.classList.add('active');
  });
 }

 function renderTransports(peers, m){
  const wsPeers = peers.filter(p => (p.transport_type||'websocket') !== 'reticulum');
  const rnsPeers = peers.filter(p => p.rns_dest_hash);
  $('tp-ws-peers').textContent = wsPeers.length;
  const totalBytes = (m.bytes_sent||0) + (m.bytes_received||0);
  const up = Math.max(1, m.uptime_seconds||1);
  $('tp-ws-tput').textContent = fmtBytes(totalBytes / up) + '/s';
  const lats = wsPeers.map(p => p.latency_ms).filter(x => x != null).sort((a,b)=>a-b);
  $('tp-ws-lat').textContent = lats.length ? lats[Math.floor(lats.length/2)].toFixed(0)+'ms' : '—';
  const tpRns = $('tp-rns');
  if(rnsPeers.length){
   tpRns.classList.remove('disabled');
   $('tp-rns-status').textContent = rnsPeers.length+' destination'+(rnsPeers.length===1?'':'s');
   $('tp-rns-dest').textContent   = rnsPeers[0].rns_dest_hash ? rnsPeers[0].rns_dest_hash.slice(0,10)+'…' : '—';
   $('tp-rns-prof').textContent   = 'SF8 · BW125 · ~1.1s @ 16B';
  } else {
   tpRns.classList.add('disabled');
   $('tp-rns-status').textContent = 'install ironmesh[rns] to enable';
   $('tp-rns-dest').textContent   = '—';
   $('tp-rns-prof').textContent   = '—';
  }
 }

 function populateSends(peers){
  const peerSel = $('send-peer'), a = $('dlg-a'), b = $('dlg-b');
  const prev = { p: peerSel.value, a: a.value, b: b.value };
  const opts = p => '<option value="'+escHtml(p.node_id)+'">'+escHtml(p.name||p.node_id.slice(0,8))+' · '+p.status+'</option>';
  peerSel.innerHTML = '<option value="">— select peer —</option>' + peers.map(opts).join('');
  const llm = new Set();
  Object.keys(state.capabilities||{}).forEach(c => { if(c.indexOf('llm:')===0) (state.capabilities[c]||[]).forEach(n => llm.add(n)); });
  const llmPeers = peers.filter(p => llm.has(p.node_id));
  // CAPABILITY_ANNOUNCE is periodic (~30s) and may not have arrived yet when the
  // first peer snapshot lands. Fall back to every peer so the A2A form is usable
  // immediately; the placeholder signals that the llm:* filter is inactive.
  const a2aPeers = llmPeers.length ? llmPeers : peers;
  const a2aHint  = llmPeers.length ? '' : ' · no llm:* advertised';
  a.innerHTML = '<option value="">— AI peer A'+a2aHint+' —</option>' + a2aPeers.map(opts).join('');
  b.innerHTML = '<option value="">— AI peer B'+a2aHint+' —</option>' + a2aPeers.map(opts).join('');
  if(prev.p) peerSel.value = prev.p;
  if(prev.a) a.value = prev.a;
  if(prev.b) b.value = prev.b;
 }

 $('send-btn').addEventListener('click', sendMessage);
 // Enter sends; Shift+Enter inserts a newline (standard chat-input convention).
 $('send-payload').addEventListener('keydown', e => {
  if(e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); sendMessage(); }
 });
 function sendMessage(){
  const peer = $('send-peer').value, typ = ($('send-type').value.trim()||'MSG'), payload = $('send-payload').value;
  if(!peer)    { statusline('pick a peer first', 'warn'); return; }
  if(!payload) { statusline('empty payload', 'warn'); return; }
  try{
   ws.send(JSON.stringify({ action:'send_message', to_node:peer, msg_type:typ, payload, priority:$('send-prio').value }));
   pushFeed({ t:Date.now()/1000, dir:'out', sev:'ok', type:typ, peer, payload });
   $('send-payload').value = '';
  } catch(err){
   statusline('send failed · ws closed', 'alarm');
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:'alarm', type:'ERROR', peer:'self', payload:'ws.send: '+(err && err.message || err) });
  }
 }

 $('dlg-btn').addEventListener('click', () => {
  const a = $('dlg-a').value, b = $('dlg-b').value, seed = $('dlg-seed').value, turns = parseInt($('dlg-turns').value||'4', 10);
  if(!a || !b || !seed){ statusline('pick two AI peers and a seed prompt', 'warn'); return; }
  if(a === b){ statusline('A and B must differ', 'warn'); return; }
  ws.send(JSON.stringify({ action:'start_dialogue', peer_a:a, peer_b:b, seed, max_turns:turns }));
  $('dlg-seed').value = '';
  statusline('A2A dialogue dispatched · '+turns+' turns');
 });

 // Footer ops
 $('op-audit').addEventListener('click', () => statusline('audit is HMAC-chained at ~/.ironmesh/audit.log · GUI viewer queued for v0.9'));
 $('op-rotate-keys').addEventListener('click', () => {
  if(!confirm('Rotate identity keypair? Every pinned peer must re-TOFU on next session.')) return;
  statusline('identity rotation requires offline CLI: ironmesh keys rotate', 'warn');
 });
 $('op-rekey').addEventListener('click', () => {
  if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'force_rekey'}));
  statusline('session rekey requested across active peers');
 });
 $('op-panic').addEventListener('click', () => {
  if(!confirm('PANIC WIPE: drop every ephemeral key and disconnect all peers. Continue?')) return;
  if(!confirm('Second confirmation — really wipe?')) return;
  if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'panic_wipe'}));
  statusline('panic wipe dispatched', 'alarm');
 });

 // Sparklines
 function pushSpark(key, val){
  const buf = sparkBuf[key];
  buf.push(val);
  if(buf.length > SPARK_N) buf.shift();
  drawSpark('sp-'+key, buf);
 }
 function drawSpark(id, data){
  const el = document.getElementById(id);
  if(!el || !data.length) return;
  const w = 64, h = 20;
  const max = Math.max.apply(null, data.concat([1])), min = Math.min.apply(null, data.concat([0]));
  const range = (max - min) || 1;
  const pts = data.map((v, i) => {
   const x = (i / Math.max(1, data.length-1)) * w;
   const y = h - ((v - min) / range) * (h - 2) - 1;
   return x.toFixed(1)+','+y.toFixed(1);
  }).join(' ');
  el.innerHTML = '<polyline points="'+pts+'" fill="none" stroke="#5aff6e" stroke-width="1.2" />';
 }

 function seedFeedFromHistory(){
  if(_seeded) return;
  _seeded = true;
  (state.history || []).forEach(h => {
   pushFeed(toFeedRow({ msg_type:h.type||'?', peer_id:(h.data&&h.data.peer_id)||'', direction:'in', payload:(h.data&&h.data.payload)||'', timestamp:h.timestamp }));
  });
 }

 // Relative-time tick
 setInterval(() => { if(state.peers && state.peers.length) renderPeers(state.peers); }, 5000);

 connect();
})();
</script></body></html>"""


# ---------------------------------------------------------------------------
# BridgeDaemon
# ---------------------------------------------------------------------------

class BridgeDaemon:
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
                 # v0.5.2: QoS + rekey
                 lora_max_payload: int = 128,
                 rekey_interval: float = 1800.0,
                 # v0.6.0: protocol hardening
                 min_protocol_version: str = "ironmesh/0.3",
                 # v0.8.5: pending-trust message gate
                 require_message_promotion: bool = False,
                 pending_trust_queue_cap: int = 100,
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
                 gui_bind: str = "127.0.0.1"):
        self.name = name
        self.port = port
        self.bind_address = bind_address
        self.gui_bind = gui_bind
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
        self.keys_path = keys_path
        self.keys_passphrase = keys_passphrase
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.max_message_size = max_message_size

        self.peers: Dict[str, ew_protocol.PeerState] = {}
        self.bus = ew_protocol.MessageBus()
        self.ws_clients: Dict[str, websockets.WebSocketServerProtocol] = {}
        self._server = None
        self._running = False
        self._mdns_service = None
        self._mdns_listener = None
        # Derive storage key from passphrase for encrypting SQLite payloads at rest.
        storage_key = hashlib.sha256(
            (passphrase + "ironmesh-storage-v1").encode()
        ).digest()
        self._db = MessageStore(db_path, storage_key=storage_key)
        self._keypair: Optional[ew_keys.AgentKeys] = None
        self._known_peer_addresses: Dict[str, str] = {}
        # v0.8.5: per-instance trust store path. None ⇒ legacy default
        # (~/.ironmesh/known_peers.json). Set explicitly so multi-daemon
        # hosts don't collide.
        from ironmesh.trust import DEFAULT_TRUST_PATH as _DEFAULT_TRUST_PATH
        self.trust_path: str = trust_path or _DEFAULT_TRUST_PATH

        # Rate limiting — per-peer and per-IP
        self._peer_rate_limiters: Dict[str, ew_protocol.TokenBucket] = {}
        self._ip_rate_limiters: Dict[str, ew_protocol.TokenBucket] = {}
        self._connection_rate_limiter = ew_protocol.TokenBucket(rate=0.167, burst=10)  # 10/min

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

        # Audit log — initialized after keys are loaded
        self._audit: Optional[AuditLog] = None

        # v0.8.5.7: audit-log counter sync state.
        # _audit_counter_offset — where the next scan picks up.
        # _audit_counter_inode — tracks file identity. If the live
        #   audit log has a different inode than we last saw, rotation
        #   happened (even if the live file is now LARGER than the
        #   offset we stored from the old file). The
        #   `current_size < offset` heuristic missed the case where
        #   post-rotation writes re-grew the live file past the
        #   pre-rotation offset before the next scan.
        # _in_proc_counter_bumps — events this daemon already bumped
        #   in-process; decremented by the scanner so we don't
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
        )
        self._mesh = None  # MeshRouter, instantiated in _start() after keypair load
        self._capabilities = None  # CapabilityRegistry, instantiated in _start()

        # v0.5: Reticulum transport
        self._rns_enabled = rns_enabled
        self._rns_configdir = rns_configdir
        self._rns_announce_interval = rns_announce_interval
        self._rns_connect = rns_connect  # comma-separated dest hashes
        self._rns_ratchets_enabled = rns_ratchets_enabled
        self._rns_ratchet_interval = rns_ratchet_interval
        self._rns_retained_ratchets = rns_retained_ratchets
        self._reticulum: Optional[object] = None  # ReticulumTransport instance
        self._known_rns_hashes: dict = {}  # peer_id -> rns_dest_hash_hex
        # v0.9.1: peers heard via RNS announces but not (yet) connected.
        # dest_hash_hex -> {name, version, node_id, capabilities, features,
        #                   identity_hash, hops, first_seen, last_seen}
        # Auto-Link to these peers is a Phase 2/11 concern; Phase 1 just
        # records what we hear so the dashboard and capability registry
        # see the same view as the WebSocket peers.
        self._rns_discovered: dict = {}
        self._pending_pings: dict = {}  # peer_id -> monotonic send time (for RTT)
        # v0.5.2: LoRa QoS + session key rotation
        self._lora_max_payload = lora_max_payload
        self._rekey_interval = rekey_interval
        # v0.6.0: protocol hardening
        self._min_protocol_version = min_protocol_version
        self._backoff_state: dict = {}  # peer_id -> {"attempts": int, "next_at": float}
        # v0.6.1: gate to prevent overlapping reconnect attempts from multiple
        # paths (_reconnect_loop / _try_transport_failover / _discover_loop /
        # _on_peer_discovered). Entries aged out after 60s to prevent stick.
        self._reconnecting: dict = {}  # peer_id_or_name -> started_at (monotonic)
        # Audit C-01: protect duplicate-connection check + peer-state
        # assignment + cleanup. Prevents identity hijacking when two
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
        self._keypair = await ensure_agent_keys(self.keys_path, self.keys_passphrase)

        # Key rotation via env var
        if os.environ.get("IRONMESH_ROTATE_KEYS") == "1":
            logger.info("Key rotation triggered")
            self._keypair = await rotate_keys(self.keys_path, self.keys_passphrase)

        # v0.8.5.6: silence the websockets-server "did not receive a valid
        # HTTP request" ERROR that fires every time a peer dials wss://
        # against our plaintext-ws server (TLS-first fallback). The
        # peer's second connection succeeds with ws:// and the IronMesh
        # handshake completes — these errors are cosmetic noise, paired
        # 1:1 with successful HELLOs in the log. Real WS handshake
        # failures still reach DEBUG and any unexpected error type still
        # reaches ERROR, so we don't lose actionable signal.
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
            asyncio.ensure_future(self._gui_state_loop())
        else:
            asyncio.ensure_future(self._metrics_server())

        # Background tasks
        asyncio.ensure_future(self._heartbeat_loop())
        asyncio.ensure_future(self._cleanup_loop())
        asyncio.ensure_future(self._audit_counter_sync_loop())
        asyncio.ensure_future(self._reconnect_loop())
        asyncio.ensure_future(self._queue_flush_loop())
        asyncio.ensure_future(self._discover_loop())
        asyncio.ensure_future(self._rekey_loop())
        asyncio.ensure_future(self._long_drop_watchdog())

        # v0.4: Mesh routing — instantiate after keypair so node_id is real
        if self.config.mesh_routing != "off":
            self._mesh = MeshRouter(self, self.config)
            try:
                self._mesh.load_persisted_routes()
            except Exception as e:
                logger.warning("Failed to load persisted routes: %s", e)
            asyncio.ensure_future(self._mesh.announce_loop())
            asyncio.ensure_future(self._mesh.cleanup_loop())
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
            except Exception:
                pass
            logger.info("Advertising %d local capability/ies: %s",
                        len(self.config.capabilities),
                        ", ".join(self.config.capabilities))
        asyncio.ensure_future(self._capability_announce_loop())

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
                           "Install with: pip install rns")

        logger.info("IronMesh Bridge running as '%s' (node_id=%s)", self.name, self.node_id)
        logger.info("GUI token: %s", self._gui_token)

    # ------------------------------------------------------------------
    # Connection handling with ephemeral ECDH handshake
    # ------------------------------------------------------------------

    async def _is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked due to too many auth failures.

        Serialized access to ``_auth_failures`` to prevent
        concurrent handshakes from bypassing the rate limit.
        """
        async with self._auth_failures_lock:
            failures = self._auth_failures.get(ip, [])
            now = time.time()
            # Prune old failures
            recent = [t for t in failures if now - t < self._auth_failure_window]
            self._auth_failures[ip] = recent
            if len(recent) >= self._auth_max_failures:
                # Check if still within block duration from latest failure
                if recent and now - recent[-1] < self._auth_block_duration:
                    return True
            return False

    async def _record_auth_failure(self, ip: str):
        """Record an auth failure for an IP address."""
        async with self._auth_failures_lock:
            if ip not in self._auth_failures:
                self._auth_failures[ip] = []
            self._auth_failures[ip].append(time.time())
            count = len(self._auth_failures[ip])
        # Audit log is thread-safe independently; fire outside the lock.
        if self._audit:
            self._audit.log(EVENT_AUTH_FAILURE, {"ip": ip, "failure_count": count})
            if count >= self._auth_max_failures:
                self._audit.log(EVENT_AUTH_BLOCKED, {"ip": ip, "duration_seconds": self._auth_block_duration})

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
            except Exception:
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
            except Exception:
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
                except Exception:
                    pass
                return

            # --- STAGE 1: Passphrase Auth ---
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
            # Generate our ephemeral X25519 keypair for this session
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

            # Verify Ed25519 signature on HELLO (proves identity owns the keys)
            peer_signature_b64 = msg.get("signature")
            if peer_identity_b64 and peer_signature_b64:
                try:
                    from nacl.signing import VerifyKey
                    verify_key = VerifyKey(base64.b64decode(peer_identity_b64))
                    # Reconstruct the canonical signed payload (with channel binding)
                    canonical = json.dumps({
                        "channel_binding": server_nonce.hex(),
                        "ephemeral_public": peer_ephemeral_b64,
                        "identity_public": peer_identity_b64,
                        "name": peer_name,
                        "protocol_version": msg.get("protocol_version", ""),
                    }, separators=(",", ":"), sort_keys=True)
                    extracted = ew_crypto.verify_signature(
                        verify_key, base64.b64decode(peer_signature_b64)
                    )
                    # Verify extracted payload matches reconstructed canonical
                    if extracted != canonical.encode():
                        raise ValueError("HELLO signature payload does not match canonical form")
                    logger.debug("HELLO signature verified for peer %s", claimed_peer_id)
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

            # Destroy our ephemeral private key (forward secrecy)
            ew_crypto.secure_wipe(my_ephemeral_private)
            del my_ephemeral_private

            # Send our HELLO, signed with Ed25519 + channel binding via server_nonce
            hello_payload = json.dumps({
                "channel_binding": server_nonce.hex(),
                "ephemeral_public": base64.b64encode(bytes(my_ephemeral_public)).decode(),
                "identity_public": self._keypair.get_public_key_base64(),
                "name": self.name,
                "protocol_version": PROTOCOL_VERSION,
            }, separators=(",", ":"), sort_keys=True)
            signature = ew_crypto.sign_message(
                self._keypair.get_signing_key(), hello_payload.encode()
            )
            await websocket.send(json.dumps({
                "type": ew_protocol.MessageType.HELLO,
                "from": self.node_id,
                "name": self.name,
                "ephemeral_public": base64.b64encode(bytes(my_ephemeral_public)).decode(),
                "identity_public": self._keypair.get_public_key_base64(),
                "protocol_version": PROTOCOL_VERSION,
                "channel_binding": server_nonce.hex(),
                "signature": base64.b64encode(signature).decode(),
            }))

            # TOFU check BEFORE adding peer to dicts.
            await self._check_tofu(peer_id, peer_identity_b64)

            # Set up peer state (only after TOFU passes)
            peer_state = ew_protocol.PeerState(
                node_id=peer_id,
                address=f"{websocket.remote_address[0]}:{websocket.remote_address[1]}",
            )
            peer_state.session_key = session_key
            peer_state.ephemeral_public = base64.b64decode(peer_ephemeral_b64)
            peer_state.identity_public = base64.b64decode(peer_identity_b64) if peer_identity_b64 else None
            peer_state.verified = True

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

            # Audit C-01: duplicate-check + peer-state assignment must
            # be atomic to prevent identity hijacking when two
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
                            except Exception:
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
                    # Audit M-13: expected parse/validation errors get a
                    # narrow warning. Unexpected exceptions fall through
                    # to the broader handler below so we see tracebacks.
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
            except Exception:
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
                        except Exception:
                            pass
                    asyncio.ensure_future(self._try_transport_failover(peer_id))

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
            # but if we get here without success, clear explicitly.
            state_now = self.peers.get(peer_id)
            if not state_now or not state_now.is_online:
                self._release_reconnect(peer_id)

    # ------------------------------------------------------------------
    # v0.5.2: Session key rotation (REKEY)
    # ------------------------------------------------------------------

    async def _rekey_loop(self):
        """Periodically rotate session keys with online v0.5+ peers.

        To avoid simultaneous rekey (both sides initiate at the same
        interval), only the node with the lexicographically smaller
        node_id initiates.  The other side just responds.
        """
        if self._rekey_interval <= 0:
            return
        while self._running:
            await asyncio.sleep(self._rekey_interval)
            for peer_id, state in list(self.peers.items()):
                if not state.is_online or not state.session_key:
                    continue
                if not _peer_supports_rekey(state.protocol_version):
                    continue
                # Tie-breaker: only the smaller node_id initiates
                if self.node_id >= peer_id:
                    continue
                try:
                    await self._initiate_rekey(peer_id)
                except Exception as e:
                    state.record_retry("rekey_failed")
                    logger.warning("Rekey failed for %s: %s", peer_id, e)

    async def _initiate_rekey(self, peer_id: str):
        """Send REKEY_REQUEST with a new ephemeral X25519 public key."""
        peer_state = self.peers.get(peer_id)
        if not peer_state:
            return
        new_private, new_public = ew_keys.generate_ephemeral()
        rekey_id = str(uuid.uuid4())
        peer_state._pending_rekey_private = new_private
        peer_state._pending_rekey_id = rekey_id
        await self._send_encrypted_control(
            peer_id, ew_protocol.MessageType.REKEY_REQUEST, {
                "new_ephemeral_public": base64.b64encode(bytes(new_public)).decode(),
                "rekey_id": rekey_id,
            },
        )
        logger.info("REKEY_REQUEST sent to %s (id=%s)", peer_id, rekey_id[:8])

    async def _handle_rekey_request(self, peer_id: str, payload, peer_state):
        """Respond to REKEY_REQUEST: derive new session key, send our ephemeral."""
        try:
            data = json.loads(payload) if isinstance(payload, (bytes, str)) else {}
        except (json.JSONDecodeError, TypeError):
            data = {}
        peer_pub_b64 = data.get("new_ephemeral_public")
        rekey_id = data.get("rekey_id", "")
        if not peer_pub_b64:
            logger.warning("Invalid REKEY_REQUEST from %s", peer_id)
            return
        from nacl.public import PublicKey as X25519Pub
        peer_pub = X25519Pub(base64.b64decode(peer_pub_b64))
        my_private, my_public = ew_keys.generate_ephemeral()
        new_key = ew_crypto.ecdh_exchange(my_private, peer_pub)
        ew_crypto.secure_wipe(my_private)
        # Respond with OLD key (still active), then switch
        await self._send_encrypted_control(
            peer_id, ew_protocol.MessageType.REKEY_RESPONSE, {
                "new_ephemeral_public": base64.b64encode(bytes(my_public)).decode(),
                "rekey_id": rekey_id,
            },
        )
        peer_state.session_key = new_key
        peer_state.session_rekey_count += 1
        peer_state.last_rekey_at = time.time()
        peer_state.next_send_seq = 1
        self._replay_guard.reset_peer(peer_id)
        self._pending_pings.pop(peer_id, None)
        self.metrics.session_rekeys += 1
        logger.info("Session rekeyed with %s (id=%s, count=%d)",
                    peer_id, rekey_id[:8], peer_state.session_rekey_count)

    async def _handle_rekey_response(self, peer_id: str, payload, peer_state):
        """Complete rekey: derive new session key from peer's ephemeral."""
        try:
            data = json.loads(payload) if isinstance(payload, (bytes, str)) else {}
        except (json.JSONDecodeError, TypeError):
            data = {}
        peer_pub_b64 = data.get("new_ephemeral_public")
        rekey_id = data.get("rekey_id", "")
        if peer_state._pending_rekey_id != rekey_id:
            logger.warning("Rekey ID mismatch from %s", peer_id)
            return
        if not peer_pub_b64 or not peer_state._pending_rekey_private:
            logger.warning("Invalid REKEY_RESPONSE from %s", peer_id)
            return
        from nacl.public import PublicKey as X25519Pub
        peer_pub = X25519Pub(base64.b64decode(peer_pub_b64))
        new_key = ew_crypto.ecdh_exchange(peer_state._pending_rekey_private, peer_pub)
        ew_crypto.secure_wipe(peer_state._pending_rekey_private)
        peer_state._pending_rekey_private = None
        peer_state._pending_rekey_id = None
        peer_state.session_key = new_key
        peer_state.session_rekey_count += 1
        peer_state.last_rekey_at = time.time()
        peer_state.next_send_seq = 1
        self._replay_guard.reset_peer(peer_id)
        self._pending_pings.pop(peer_id, None)
        self.metrics.session_rekeys += 1
        logger.info("Session rekeyed (initiator) with %s (id=%s, count=%d)",
                    peer_id, rekey_id[:8], peer_state.session_rekey_count)

    # ------------------------------------------------------------------
    # v0.6.0: Signed peer revocation broadcast
    # ------------------------------------------------------------------

    async def broadcast_revocation(self, target_node_id: str, reason: str = "") -> None:
        """Create a signed REVOCATION message and send to all online peers."""
        from ironmesh.trust import TrustStore
        timestamp = time.time()
        # Sign: target_node_id || revoker_node_id || str(int(timestamp))
        msg_bytes = (
            target_node_id + self.node_id + str(int(timestamp))
        ).encode()
        signature = ew_crypto.sign_detached(
            self._keypair.get_signing_key(), msg_bytes
        )
        payload = {
            "target_node_id": target_node_id,
            "revoker_node_id": self.node_id,
            "timestamp": int(timestamp),
            "reason": reason,
            "signature": base64.b64encode(signature).decode(),
        }
        # Also mark locally
        mac_key = self._keypair.ed25519_secret[:32]
        ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        ts.mark_revoked(target_node_id, self.node_id, timestamp, reason)
        # Broadcast to all online peers
        for pid, state in list(self.peers.items()):
            if not state.is_online or pid == target_node_id:
                continue
            try:
                await self._send_encrypted_control(
                    pid, ew_protocol.MessageType.REVOCATION, payload
                )
            except Exception as e:
                logger.warning("Failed to send REVOCATION to %s: %s", pid, e)
        logger.warning("Broadcast REVOCATION for %s (reason: %s)",
                       target_node_id, reason or "none")

    async def _handle_revocation(self, peer_id: str, payload, peer_state) -> None:
        """Validate and apply a signed REVOCATION message from a trusted peer."""
        try:
            data = json.loads(payload) if isinstance(payload, (bytes, str)) else {}
        except (json.JSONDecodeError, TypeError):
            return
        target = data.get("target_node_id")
        revoker = data.get("revoker_node_id")
        timestamp = data.get("timestamp")
        signature_b64 = data.get("signature")
        reason = data.get("reason", "")
        if not (target and revoker and timestamp and signature_b64):
            logger.warning("Invalid REVOCATION from %s: missing fields", peer_id)
            return

        # Revoker must match the immediate sender (simple trust model —
        # accept only revocations signed by the peer sending it).
        if revoker != peer_id:
            logger.warning("REVOCATION from %s signed by %s — rejecting",
                           peer_id, revoker)
            return

        # Verify signature using the sender's pinned Ed25519 identity key
        if not peer_state or not peer_state.identity_public:
            logger.warning("No pinned identity for revoker %s", revoker)
            return
        msg_bytes = (target + revoker + str(int(timestamp))).encode()
        try:
            from nacl.signing import VerifyKey
            vk = VerifyKey(peer_state.identity_public)
            ew_crypto.verify_detached(
                vk,
                msg_bytes,
                base64.b64decode(signature_b64),
            )
        except Exception as e:
            logger.warning("REVOCATION signature invalid from %s: %s", revoker, e)
            return

        # Apply locally
        from ironmesh.trust import TrustStore
        mac_key = self._keypair.ed25519_secret[:32]
        ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        ts.mark_revoked(target, revoker, float(timestamp), reason)
        logger.warning("Accepted REVOCATION for %s from %s (reason: %s)",
                       target, revoker, reason or "none")

        # If the target is currently connected, disconnect it
        if target in self.ws_clients:
            ws = self.ws_clients.pop(target, None)
            if ws:
                try:
                    await ws.close()
                except Exception:
                    pass
            if target in self.peers:
                self.peers[target].transition(ew_protocol.PeerState.Status.OFFLINE)
                self.peers[target].session_key = None

    # ------------------------------------------------------------------
    # v0.8.5: Pending-trust message gate
    # ------------------------------------------------------------------

    # Frame types eligible for the gate. Control frames (REKEY, HEARTBEAT,
    # ROUTE_*, CAPABILITY_*) handle themselves earlier in dispatch.
    _GATED_MSG_TYPES: frozenset = frozenset({"MSG", "REQ", "RESP"})

    async def _gate_inbound_msg(self, peer_id: str,
                                 frame: "ew_protocol.Frame") -> str:
        """Decide whether to deliver, queue, or drop an inbound user MSG.

        Returns one of:
          "deliver" — fall through to normal handling
          "queue"   — enqueued in pending_trust_messages, do not store/publish
          "drop"    — sender is blocked, silently dropped

        Gate is a no-op when ``require_message_promotion`` is False or the
        frame is not a user-payload type.

        Trust judgement keys on ``peer_id`` — the wire-authenticated peer
        whose identity key signed the frame. ``frame.source`` looks
        appealing for relayed messages but is unauthenticated metadata
        on both the JSON and binary paths (the peer's signature covers
        the encrypted payload, not the source field). A pending peer
        could otherwise forge ``source = self.node_id`` and bypass the
        gate via the self-loopback exemption below. v0.9.0 may add
        source_signature verification so relays gate on the originator.
        """
        if not self.config.require_message_promotion:
            return "deliver"
        if frame.msg_type not in self._GATED_MSG_TYPES:
            return "deliver"

        originator = peer_id
        # Don't gate ourselves (loopback / self-test).
        if originator == self.node_id:
            return "deliver"

        try:
            from ironmesh.trust import TrustStore
            mac_key = self._keypair.ed25519_secret[:32]
            ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        except Exception as e:
            # Fail closed: a broken trust store is a security event, not a
            # reason to bypass the gate. Drop pending-class traffic until
            # an operator fixes the file.
            logger.error("Trust gate: failed to open TrustStore (%s) — failing closed (drop)", e)
            return "drop"

        state = ts.get_trust_state(originator)
        if state == "trusted":
            return "deliver"
        if state == "blocked":
            self.metrics.messages_received_blocked = (
                getattr(self.metrics, "messages_received_blocked", 0) + 1
            )
            # v0.8.5.2: surface to operators via /api/mesh_stats.
            self._db.pending_trust_dropped += 1
            logger.debug("Trust gate: dropping MSG from blocked peer %s",
                         originator[:12])
            # v0.8.5.2: rate-limit audit writes for blocked peers to
            # 1 per peer per second. Without this cap, a malicious
            # blocked peer sending 1000 MSGs/sec could grow the audit
            # log at ~200 KB/sec, rotating older entries out within
            # ~4 minutes (MAX_ARCHIVES=5, max_bytes=10MB each). The
            # attacker could then use the flood to obscure earlier
            # forensic evidence. Counter-only path keeps per-peer
            # drop totals visible via /api/mesh_stats without growing
            # the audit chain.
            now = time.time()
            last_audit = self._gate_audit_last_write.get(originator, 0.0)
            if now - last_audit >= 1.0:
                self._gate_audit_last_write[originator] = now
                if self._audit:
                    try:
                        self._audit.log(EVENT_MSG_GATED_DROP, {
                            "peer_id": originator,
                            "msg_id": frame.msg_id,
                            "msg_type": frame.msg_type,
                            "reason": "blocked",
                        })
                    except Exception:
                        pass
            return "drop"

        # state == "pending" — queue the wire payload for later drain.
        try:
            queued = await self._db.queue_pending_trust(
                source_node_id=originator,
                msg_id=frame.msg_id,
                msg_type=frame.msg_type,
                payload=frame.payload,
                priority=getattr(frame, "priority", "NORMAL") or "NORMAL",
                cap=int(self.config.pending_trust_queue_cap or 100),
            )
            if queued:
                queued_count = await self._db.pending_trust_count_for(originator)
                # Surface to GUI clients so an operator can react.
                try:
                    await self._gui_broadcast({
                        "type": "pending_trust",
                        "source_node_id": originator,
                        "queued_count": queued_count,
                        "msg_id": frame.msg_id,
                    })
                except Exception:
                    pass
                if self._audit:
                    try:
                        self._audit.log(EVENT_MSG_GATED_QUEUE, {
                            "peer_id": originator,
                            "trust_state": "pending",
                            "msg_id": frame.msg_id,
                            "msg_type": frame.msg_type,
                            "queued_count": queued_count,
                        })
                    except Exception:
                        pass
        except Exception as e:
            # Storage failure is bad but should not crash dispatch — log
            # and fail-closed (drop) so a pending peer can't bypass the
            # gate by tripping a storage error.
            logger.error("Trust gate: queue_pending_trust failed for %s msg=%s: %s",
                         originator, frame.msg_id, e)
            return "drop"
        return "queue"

    async def promote_pending_peer(self, target_node_id: str) -> dict:
        """Operator action: promote a pending peer to trusted, drain its queue.

        Returns ``{"ok": bool, "drained": int, "error": str | None}``. The
        drained messages are re-stored in history and re-published to the
        bus in arrival order, exactly as if they had arrived just now —
        downstream consumers (GUI, MCP subscribers, OpenClaw) see them
        through the normal inbound path.
        """
        from ironmesh.trust import TrustStore
        try:
            mac_key = self._keypair.ed25519_secret[:32]
            ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        except Exception as e:
            return {"ok": False, "drained": 0, "error": f"trust store: {e}"}
        if not ts.set_trust_state(target_node_id, "trusted"):
            return {"ok": False, "drained": 0,
                    "error": f"peer {target_node_id} not in trust store"}
        drained = await self._db.drain_pending_trust(target_node_id)
        for m in drained:
            try:
                await self._db.store_message(
                    msg_id=m["msg_id"], source=target_node_id,
                    source_display=target_node_id,
                    destination=self.node_id, msg_type=m["msg_type"],
                    payload=m["payload"], direction="inbound",
                    priority=m["priority"],
                )
                self.bus.publish(m["msg_type"], {
                    "peer_id": target_node_id,
                    "msg_id": m["msg_id"],
                    "type": m["msg_type"],
                    "payload": m["payload"],
                })
            except Exception as e:
                logger.warning("Promote-drain re-publish failed for %s msg=%s: %s",
                               target_node_id, m["msg_id"], e)
        self._emit_audit_with_reservation(
            "peer_promoted", EVENT_PEER_PROMOTED, {
                "peer_id": target_node_id,
                "drained": len(drained),
            },
        )
        logger.info("Promoted peer %s to trusted (drained %d queued)",
                    target_node_id, len(drained))
        return {"ok": True, "drained": len(drained), "error": None}

    async def block_pending_peer(self, target_node_id: str) -> dict:
        """Operator action: mark a peer as blocked (local-only quiet block).

        Drops any currently-queued pending messages and prevents future
        MSGs from being delivered. Distinct from broadcast_revocation —
        that propagates a signed REVOCATION to the network; this is a
        unilateral local block that doesn't interact with peer keys.
        """
        from ironmesh.trust import TrustStore
        try:
            mac_key = self._keypair.ed25519_secret[:32]
            ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        except Exception as e:
            return {"ok": False, "discarded": 0, "error": f"trust store: {e}"}
        if not ts.set_trust_state(target_node_id, "blocked"):
            return {"ok": False, "discarded": 0,
                    "error": f"peer {target_node_id} not in trust store"}
        discarded = await self._db.discard_pending_trust(target_node_id)
        self._emit_audit_with_reservation(
            "peer_blocked", EVENT_PEER_BLOCKED, {
                "peer_id": target_node_id,
                "discarded": discarded,
            },
        )
        logger.info("Blocked peer %s (discarded %d queued)",
                    target_node_id, discarded)
        return {"ok": True, "discarded": discarded, "error": None}

    async def list_pending_trust(self) -> list:
        """Return one entry per peer awaiting promotion, with queued count
        and identity metadata. Used by GUI dashboard + MCP tool."""
        from ironmesh.trust import TrustStore
        try:
            mac_key = self._keypair.ed25519_secret[:32]
            ts = TrustStore(agent_key=mac_key, path=self.trust_path)
        except Exception:
            return []
        # Union: peers in trust store with state=pending + peers with
        # queued messages even if missing from store (defensive).
        store_pending = {p["node_id"]: p for p in ts.list_by_trust_state("pending")}
        queue_summary = await self._db.list_pending_trust_summary()
        out = []
        seen: set = set()
        for q in queue_summary:
            nid = q["source_node_id"]
            seen.add(nid)
            rec = store_pending.get(nid, {})
            out.append({
                "node_id": nid,
                "fingerprint": rec.get("fingerprint", ""),
                "first_seen": rec.get("first_seen"),
                "last_seen": rec.get("last_seen"),
                "queued_count": q["queued_count"],
                "oldest_queued_at": q["oldest_queued_at"],
                "newest_queued_at": q["newest_queued_at"],
            })
        # Pending peers in the store with no queued messages right now.
        for nid, rec in store_pending.items():
            if nid in seen:
                continue
            out.append({
                "node_id": nid,
                "fingerprint": rec.get("fingerprint", ""),
                "first_seen": rec.get("first_seen"),
                "last_seen": rec.get("last_seen"),
                "queued_count": 0,
                "oldest_queued_at": None,
                "newest_queued_at": None,
            })
        return out

    # ------------------------------------------------------------------
    # v0.8.5.6: capability-set binding
    # ------------------------------------------------------------------

    def _open_trust_store(self):
        """Open a fresh TrustStore bound to this daemon's identity key.

        Mirrors the pattern used by the other trust-touching methods in
        this class — TrustStore is constructed on demand rather than
        held as an instance attribute, because its on-disk state is the
        single source of truth and another daemon (or the operator CLI)
        may have mutated it since the last call. Returns ``None`` if
        the keypair isn't loaded yet (early startup).
        """
        if self._keypair is None:
            return None
        try:
            from ironmesh.trust import TrustStore
            mac_key = self._keypair.ed25519_secret[:32]
            return TrustStore(agent_key=mac_key, path=self.trust_path)
        except Exception as exc:
            logger.debug("_open_trust_store failed: %s", exc)
            return None

    def _handle_cap_observation(self, peer_id: str, result: dict,
                                trust_store=None) -> None:
        """React to a TrustStore.observe_capabilities result.

        The three non-error cases:
            - first-observation: log a baseline audit event; no state change
            - match: no action
            - changed: stash the pending set, demote the peer to
              pending-cap-change, emit PEER_CAP_SET_CHANGED

        ``trust_store`` is the same store used to compute ``result`` —
        passed in to avoid reopening + re-MAC-verifying on the hot path.
        Falls back to opening a fresh one if not supplied.
        """
        status = result.get("status")
        if status == "first-observation":
            # Observability: counter mirror for the baseline pinning
            # event (the cap-binding TOFU-for-caps moment). OTel span
            # is independent of the counter path and fires regardless
            # of audit-log health.
            _otel_span_event("peer.cap.baseline", peer_id, {
                "capability_hash": (result.get("hash") or "")[:16],
                "capability_count": len(result.get("set") or []),
            })
            self._emit_audit_with_reservation(
                "peer_cap_baseline", EVENT_PEER_CAP_BASELINE, {
                    "peer": peer_id,
                    "capability_hash": result.get("hash"),
                    "capability_count": len(result.get("set") or []),
                },
            )
            return
        if status == "match":
            return
        if status == "pending-match":
            # Peer is already demoted and just re-announced the same
            # pending set. Stay silent — the change was already recorded.
            return
        if status == "reverted":
            # Peer reverted to the accepted baseline while in
            # pending-cap-change. Trust store has already cleared the
            # pending stash. We don't auto-promote (that's an operator
            # decision — they may want to investigate the flap) but we
            # DO surface the revert in the audit log.
            if self._audit:
                try:
                    self._audit.log(EVENT_PEER_CAP_SET_CHANGED, {
                        "peer": peer_id,
                        "old_hash": result.get("cleared_pending_hash"),
                        "new_hash": result.get("hash"),
                        "added": [],
                        "removed": [],
                        "trust_state_effective":
                            "pending-cap-change (reverted to baseline)",
                        "note": "peer reverted to previously-accepted "
                                "capability set; operator action still "
                                "required to re-promote",
                    })
                except Exception:
                    pass
            logger.info(
                "Peer %s reverted to baseline capability set — "
                "pending stash cleared, trust state unchanged",
                peer_id,
            )
            return
        if status == "changed":
            # v0.8.5.6: both the stash and the demote must
            # succeed before we fire PEER_CAP_SET_CHANGED. Pre-fix,
            # stash/demote failures were silently downgraded to
            # debug logs while the audit event still fired claiming
            # "trust_state_effective: pending-cap-change" — leaving
            # an operator following the audit trail to later find
            # that cap-promote returns "no pending capability change"
            # because the stash never reached disk. Now we propagate
            # failures and fire a distinct PEER_CAP_BINDING_PARTIAL
            # event so the audit trail stays truthful.
            ts = trust_store if trust_store is not None else self._open_trust_store()
            stashed = False
            demoted = False
            demote_needed = False
            if ts is not None:
                try:
                    stashed = bool(ts.stash_pending_capability_change(
                        peer_id, result.get("new_set") or [],
                    ))
                except Exception as exc:
                    logger.warning(
                        "stash_pending_capability_change FAILED for %s: %s",
                        peer_id, exc,
                    )
                try:
                    current = ts.get_trust_state(peer_id)
                    demote_needed = (current != "pending-cap-change")
                    if demote_needed:
                        demoted = bool(ts.set_trust_state(
                            peer_id, "pending-cap-change",
                        ))
                    else:
                        # Already pending-cap-change; no demote needed.
                        demoted = True
                except Exception as exc:
                    logger.warning(
                        "trust-state demote FAILED for %s: %s",
                        peer_id, exc,
                    )
            fully_applied = stashed and demoted
            event = (EVENT_PEER_CAP_SET_CHANGED if fully_applied
                     else EVENT_PEER_CAP_BINDING_PARTIAL)
            counter_name = ("peer_cap_set_changed" if fully_applied
                            else "peer_cap_binding_partial")
            _otel_span_event(
                "peer.cap.set_changed" if fully_applied
                else "peer.cap.binding_partial",
                peer_id, {
                    "added": len(result.get("added") or []),
                    "removed": len(result.get("removed") or []),
                    "stashed": stashed,
                    "demoted": demoted,
                },
            )
            self._emit_audit_with_reservation(
                counter_name, event, {
                    "peer": peer_id,
                    "old_hash": result.get("old_hash"),
                    "new_hash": result.get("new_hash"),
                    "added": list(result.get("added") or []),
                    "removed": list(result.get("removed") or []),
                    "trust_state_effective":
                        "pending-cap-change" if fully_applied
                        else "unchanged (persistence failure)",
                    "stashed": stashed,
                    "demoted": demoted,
                },
            )
            # v0.8.5.7: push incremental notification to the dashboard
            # so the operator doesn't need to refresh the panel manually.
            if fully_applied and self._gui_clients:
                try:
                    asyncio.ensure_future(self._gui_broadcast({
                        "type": "cap_change_detected",
                        "peer": peer_id,
                        "added": list(result.get("added") or []),
                        "removed": list(result.get("removed") or []),
                        "old_hash": result.get("old_hash"),
                        "new_hash": result.get("new_hash"),
                    }))
                except Exception:
                    pass  # broadcast is best-effort
            if fully_applied:
                logger.warning(
                    "Peer %s demoted to pending-cap-change: "
                    "+%d cap(s), -%d cap(s)",
                    peer_id, len(result.get("added") or []),
                    len(result.get("removed") or []),
                )
            else:
                logger.error(
                    "Peer %s cap change detected but not fully applied "
                    "(stashed=%s, demoted=%s). Trust state unchanged. "
                    "This typically indicates a disk / lock error — "
                    "check trust store integrity and retry.",
                    peer_id, stashed, demoted,
                )

    async def accept_pending_cap_change(self, node_id: str) -> dict:
        """Operator action: accept the pending capability-set change for
        a peer that was demoted to pending-cap-change. Re-promotes the
        peer to the prior trust state (or "trusted" if none known) and
        records the new capability baseline.

        Returns a small status dict suitable for CLI / MCP / dashboard
        surface. Raises ValueError if the peer isn't actually in
        pending-cap-change.
        """
        ts = self._open_trust_store()
        if ts is None:
            return {"ok": False, "error": "trust store unavailable"}
        rec = ts.get_peer(node_id)
        if rec is None:
            return {"ok": False, "error": "unknown peer"}
        current_state = ts.get_trust_state(node_id)
        if current_state != "pending-cap-change":
            return {"ok": False, "error": f"peer is in state {current_state}"}
        if rec.get("capability_hash_pending") is None:
            return {"ok": False, "error": "no pending capability change"}
        # Accept the pending set as the new baseline
        old_hash = rec.get("capability_hash")
        new_hash = rec.get("capability_hash_pending")
        accepted = ts.accept_capability_change(node_id)
        if not accepted:
            return {"ok": False, "error": "accept_capability_change returned False"}
        ts.set_trust_state(node_id, "trusted")
        _otel_span_event("peer.cap.accepted", node_id, {
            "new_hash": (new_hash or "")[:16],
        })
        self._emit_audit_with_reservation(
            "peer_cap_accepted", EVENT_PEER_CAP_ACCEPTED, {
                "peer": node_id,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "trust_state_effective": "trusted",
            },
        )
        return {"ok": True, "old_hash": old_hash, "new_hash": new_hash}

    # ------------------------------------------------------------------
    # TOFU (Trust-On-First-Use)
    # ------------------------------------------------------------------

    async def _check_tofu(self, peer_id: str, identity_public_b64: Optional[str]):
        """Check TOFU key pinning for a peer. Raises on mismatch (possible MITM).

        #12: This is called BEFORE the peer is added to self.peers/self.ws_clients,
        so on mismatch we just raise — the caller never populates the dicts.
        """
        if not identity_public_b64:
            return

        try:
            from ironmesh.trust import TrustStore
            # Audit C-03: TrustStore requires an agent_key; assertion
            # enforces daemon bootstrap order (keys must load first).
            if not self._keypair:
                raise RuntimeError("TrustStore requires the daemon keypair to be loaded")
            mac_key = self._keypair.ed25519_secret[:32]
            trust = TrustStore(agent_key=mac_key, path=self.trust_path)
            # v0.6: refuse connection from revoked peers
            if trust.is_revoked(peer_id):
                logger.warning("REVOKED peer %s attempted to connect — refusing",
                               peer_id)
                raise ConnectionError(f"Peer {peer_id} is revoked")
            result = trust.verify_peer(peer_id, identity_public_b64)
            if result == "new":
                # v0.8.5: when require_message_promotion is on, brand-new
                # peers are pinned in "pending" state — their MSGs queue
                # until an operator promotes. Default-off preserves the
                # pre-v0.8.5 behavior (peers are immediately trusted).
                gate_on = bool(getattr(self.config, "require_message_promotion", False))
                initial_state = "pending" if gate_on else "trusted"
                trust.pin_peer(peer_id, identity_public_b64,
                               trust_state=initial_state)
                logger.info("TOFU: Pinned new peer %s (state=%s)",
                            peer_id, initial_state)
                if self._audit:
                    self._audit.log(EVENT_TOFU_NEW, {
                        "peer_id": peer_id,
                        "trust_state": initial_state,
                    })
            elif result == "mismatch":
                if self._audit:
                    self._audit.log(EVENT_TOFU_MISMATCH, {"peer_id": peer_id})
                logger.critical(
                    "TOFU VIOLATION: Peer %s identity key changed! Possible MITM attack. "
                    "Disconnecting peer. Use 'ironmesh trust revoke %s' then reconnect "
                    "if the key change is legitimate.", peer_id, peer_id
                )
                # Clean up if peer was already in dicts (legacy path)
                ws = self.ws_clients.pop(peer_id, None)
                if ws:
                    try:
                        await ws.send(json.dumps({
                            "type": ew_protocol.MessageType.ERROR,
                            "error": "Identity key mismatch — possible MITM. Connection refused.",
                            "code": ew_protocol.ErrorCode.AUTH_FAILED,
                        }))
                        await ws.close()
                    except Exception:
                        pass
                self.peers.pop(peer_id, None)
                self._peer_rate_limiters.pop(peer_id, None)
                raise ConnectionError(f"TOFU mismatch for peer {peer_id}")
        except ImportError:
            pass  # trust module not yet available
        except ConnectionError:
            raise  # Re-raise TOFU mismatch
        except Exception as e:
            logger.debug("TOFU check failed: %s", e)

    # ------------------------------------------------------------------
    # Message handling (encrypted)
    # ------------------------------------------------------------------

    async def _handle_message(self, peer_id: str, raw, transport: str = "ws"):
        """Handle an incoming message from a peer.

        Accepts both binary frames (preferred) and legacy JSON (backward compat).
        Binary frames hide all metadata inside the encrypted envelope.

        ``transport`` (v0.8.5.6) tags the inbound transport so the dedup
        cache can detect cross-transport replay attempts. The WebSocket
        path passes ``"ws"``; the Reticulum path passes ``"rns"``.
        """
        peer_state = self.peers.get(peer_id)
        if not peer_state or not peer_state.session_key:
            logger.warning("No session key for peer %s — dropping message", peer_id)
            return

        # Rate limiting
        rate_limiter = self._peer_rate_limiters.get(peer_id)
        if rate_limiter and not rate_limiter.consume():
            self.metrics.rate_limits_triggered += 1
            logger.warning("Rate limited peer %s", peer_id)
            try:
                await self._send_encrypted_control(
                    peer_id, ew_protocol.MessageType.RATE_LIMITED
                )
            except Exception:
                pass
            return

        # Detect binary vs JSON wire format
        if isinstance(raw, bytes) and len(raw) >= ew_protocol.Frame.HEADER_SIZE and raw[:2] == ew_protocol.Frame.MAGIC:
            return await self._handle_binary_frame(peer_id, raw, peer_state,
                                                    transport=transport)
        elif isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError:
                logger.warning("Unrecognized binary data from %s — dropping", peer_id)
                return
        return await self._handle_json_message(peer_id, raw, peer_state,
                                                transport=transport)

    async def _handle_binary_frame(self, peer_id: str, raw: bytes, peer_state,
                                    transport: str = "ws"):
        """Handle a binary wire-format frame (preferred path).

        ``transport`` (v0.8.5.6) propagates to the dedup cache for
        cross-transport replay detection.
        """
        if not peer_state.identity_public:
            logger.warning("Cannot verify binary frame from %s — no identity key", peer_id)
            return
        try:
            from nacl.signing import VerifyKey
            verify_key = VerifyKey(peer_state.identity_public)
            frame = ew_protocol.Frame.deserialize_and_decrypt(
                raw, peer_state.session_key, verify_key=verify_key
            )
        except Exception as e:
            logger.warning("Binary frame rejected from %s: %s", peer_id, e)
            return

        sequence = frame.sequence
        timestamp = frame.timestamp

        # Replay protection
        if sequence <= 0:
            logger.warning("Rejected binary frame from %s with seq=%d", peer_id, sequence)
            return
        rejection = self._replay_guard.check(peer_id, sequence, timestamp)
        if rejection:
            logger.warning("Replay detected from %s: %s", peer_id, rejection)
            return

        # Dispatch to common handler
        await self._dispatch_message(peer_id, peer_state, frame, transport=transport)

    async def _handle_json_message(self, peer_id: str, raw: str, peer_state,
                                    transport: str = "ws"):
        """Handle a legacy JSON message (backward compat).

        ``transport`` (v0.8.5.6) propagates to the dedup cache.
        """
        # Parse the incoming message
        msg = json.loads(raw)
        msg_id = msg.get("msg_id", str(uuid.uuid4()))

        # Decrypt payload — plaintext is NEVER accepted after handshake
        encrypted_b64 = msg.get("encrypted_payload")
        if not encrypted_b64:
            logger.warning("Rejected plaintext message from %s — encryption required after handshake", peer_id)
            return
        try:
            encrypted_bytes = base64.b64decode(encrypted_b64)
            payload = ew_crypto.decrypt_message(peer_state.session_key, encrypted_bytes)
        except Exception as e:
            logger.warning("Decryption failed from %s: %s", peer_id, e)
            return

        # Replay protection — all post-handshake messages must have sequence > 0
        sequence = msg.get("sequence", 0)
        timestamp = msg.get("timestamp", time.time())
        if sequence <= 0:
            logger.warning("Rejected message from %s with seq=%d — sequence required", peer_id, sequence)
            return
        rejection = self._replay_guard.check(peer_id, sequence, timestamp)
        if rejection:
            logger.warning("Replay detected from %s: %s", peer_id, rejection)
            return

        # Mandatory signature verification — all messages must be signed
        signed_b64 = msg.get("signature")
        if not signed_b64:
            logger.warning("Rejected unsigned message from %s — signature required", peer_id)
            return
        if not peer_state.identity_public:
            logger.warning("Cannot verify signature from %s — no identity key", peer_id)
            return
        try:
            from nacl.signing import VerifyKey
            verify_key = VerifyKey(peer_state.identity_public)
            # Detached signature verification — sig binds directly to received encrypted bytes
            ew_crypto.verify_detached(verify_key, encrypted_bytes, base64.b64decode(signed_b64))
        except Exception as e:
            logger.warning("Signature verification FAILED from %s: %s", peer_id, e)
            return

        # Synthesize Frame from JSON envelope and dispatch to common handler
        msg["msg_id"] = msg_id
        frame = ew_protocol.Frame.from_json_message(msg, payload)
        frame.sequence = sequence
        frame.timestamp = timestamp
        await self._dispatch_message(peer_id, peer_state, frame, transport=transport)

    async def _dispatch_message(self, peer_id: str, peer_state,
                                frame: "ew_protocol.Frame",
                                transport: str = "ws"):
        """Common message dispatch — shared by binary frame and JSON paths.

        Args:
            peer_id: ID of the immediate peer (NOT necessarily the original source).
            peer_state: PeerState for the immediate peer.
            frame: Decrypted Frame with full metadata (msg_type, msg_id, payload,
                   source, destination, ttl, hops, source_signature, e2e_payload).
        """
        msg_type = frame.msg_type
        msg_id = frame.msg_id
        payload = frame.payload

        # v0.5.2: decompress LoRa-compressed payloads
        if getattr(frame, 'routing', {}).get("compressed"):
            import gzip
            try:
                payload = gzip.decompress(payload)
                frame.payload = payload
            except Exception as e:
                logger.warning("Failed to decompress LoRa payload from %s: %s",
                               peer_id, e)

        # v0.4: ROUTE_ANNOUNCE is control-plane; handle and return without
        # bus-publishing or storing in history.
        if msg_type == ew_protocol.MessageType.ROUTE_ANNOUNCE:
            peer_state.last_seen = time.time()
            if self._mesh is not None:
                await self._mesh.handle_route_announce(peer_id, payload)
            return

        # v0.4: ROUTE_UNREACHABLE is also control-plane.
        if msg_type == ew_protocol.MessageType.ROUTE_UNREACHABLE:
            peer_state.last_seen = time.time()
            logger.info("ROUTE_UNREACHABLE from %s: %s", peer_id, payload[:200])
            return

        # v0.4: CAPABILITY_ANNOUNCE — learn remote capabilities and propagate
        # via mesh routing if destined for "*". Don't bus-publish: capabilities
        # are control plane.
        if msg_type == ew_protocol.MessageType.CAPABILITY_ANNOUNCE:
            peer_state.last_seen = time.time()
            if self._capabilities is not None:
                try:
                    # v0.8.5.6: validate types up front so
                    # downstream code that uses `origin` as a dict key
                    # (TrustStore.get_peer, CapabilityRegistry._remote)
                    # can't be tripped up by a malicious peer sending
                    # `{"origin": [1,2,3], "capabilities": [...]}`.
                    if not isinstance(payload, (bytes, bytearray, str)):
                        return
                    if isinstance(payload, (bytes, bytearray)) and \
                            len(payload) > 1_048_576:
                        logger.warning(
                            "CAPABILITY_ANNOUNCE from %s too large: %d bytes",
                            peer_id, len(payload),
                        )
                        return
                    data = json.loads(payload)
                    if not isinstance(data, dict):
                        return
                    origin = data.get("origin", peer_id)
                    if not isinstance(origin, str) or not origin:
                        return
                    caps = data.get("capabilities", [])
                    if not isinstance(caps, list):
                        return
                    # Drop non-string / empty cap tokens before letting
                    # them reach the registry. Cap a sanity-bound on
                    # the number of caps to limit per-announce work.
                    caps = [c for c in caps
                            if isinstance(c, str) and c]
                    if len(caps) > 1024:
                        logger.warning(
                            "CAPABILITY_ANNOUNCE from %s claims %d "
                            "caps; truncating to 1024",
                            peer_id, len(caps),
                        )
                        caps = caps[:1024]
                    if origin != self.node_id:
                        delta = self._capabilities.learn_remote(origin, caps)
                        if delta:
                            # Persist learned remote caps so a daemon
                            # restart doesn't lose them. Wrapped in
                            # try/except because announce-path latency
                            # must not be coupled to disk health.
                            try:
                                self._capabilities.save()
                            except Exception:
                                pass
                            if self._audit:
                                try:
                                    self._audit.log(EVENT_CAPABILITY_LEARNED, {
                                        "origin": origin,
                                        "capabilities": list(caps),
                                    })
                                except Exception:
                                    pass
                        # v0.8.5.6: bind the observed capability set to the
                        # origin peer's pinned trust record. If it differs
                        # from the last-accepted baseline, demote the peer
                        # to pending-cap-change and emit an audit event.
                        # Only do this for peers that are already pinned
                        # (i.e. we've completed TOFU with them) — otherwise
                        # there's no trust record to bind against.
                        if isinstance(caps, list):
                            try:
                                ts = self._open_trust_store()
                                if ts is not None and ts.get_peer(origin) is not None:
                                    result = ts.observe_capabilities(origin, caps)
                                    self._handle_cap_observation(
                                        origin, result, trust_store=ts,
                                    )
                            except Exception as e:
                                logger.debug(
                                    "cap-binding observe failed for %s: %s",
                                    origin, e,
                                )
                except Exception as e:
                    logger.debug("Bad CAPABILITY_ANNOUNCE from %s: %s", peer_id, e)
            return

        # v0.4: Relay decision — if the destination is not us (and not a
        # broadcast), forward via the mesh router. Forwarded messages are
        # NOT bus-published locally and NOT stored in inbound history.
        if (frame.destination
                and frame.destination not in (self.node_id, "*", "")
                and self._mesh is not None):
            peer_state.last_seen = time.time()
            try:
                await self._mesh.relay_message(
                    frame, from_peer=peer_id, transport=transport,
                )
            except Exception as e:
                logger.warning("Relay failed for %s -> %s: %s",
                               frame.source, frame.destination, e)
            return

        # v0.4: E2E unseal — if the destination is us and the frame carries
        # an e2e_payload, decrypt it with our identity key. Replace
        # frame.payload (and the local payload variable) with the plaintext
        # so subsequent handlers see the original message body.
        if frame.e2e_payload is not None and self._keypair is not None:
            try:
                from ironmesh import mesh_crypto
                plaintext = mesh_crypto.unseal_from_source(
                    frame.e2e_payload, self._keypair.ed25519_secret
                )
                frame.payload = plaintext
                payload = plaintext
            except Exception as e:
                logger.warning("E2E unseal failed from source %s: %s",
                               frame.source, e)
                if self._audit:
                    try:
                        from ironmesh.audit import EVENT_E2E_DECRYPT_FAILURE
                        self._audit.log(EVENT_E2E_DECRYPT_FAILURE, {
                            "source": frame.source, "msg_id": msg_id,
                        })
                    except Exception:
                        pass
                return

        # v0.8.5: pending-trust message gate. Only user-payload frames are
        # gated — control frames (REKEY/HEARTBEAT/etc.) short-circuit
        # earlier in this function. The originator we judge against is the
        # frame source if present (so relayed messages from a pending peer
        # still get gated), otherwise the immediate peer.
        gate_action = await self._gate_inbound_msg(peer_id, frame)
        if gate_action == "queue":
            peer_state.last_seen = time.time()
            return
        if gate_action == "drop":
            peer_state.last_seen = time.time()
            return
        # action == "deliver" → fall through to normal handling

        # Store in history
        await self._db.store_message(
            msg_id=msg_id, source=peer_id,
            source_display=peer_id,
            destination=self.node_id, msg_type=msg_type,
            payload=payload, direction="inbound",
            priority="NORMAL",
        )

        # Publish to bus
        self.bus.publish(msg_type, {"peer_id": peer_id, "msg_id": msg_id,
                                     "type": msg_type, "payload": payload})

        # Update peer state
        peer_state.messages_received += 1
        peer_state.last_seen = time.time()
        peer_state.bytes_received_total += len(payload) if payload else 0
        self.metrics.messages_received += 1

        # v0.7.2: sample message lifetime for the Prometheus summary.
        # Frame timestamps are wall-clock seconds — negative/outlier values
        # from clock skew are clamped at the recv side.
        try:
            ts = getattr(frame, "timestamp", None)
            if ts is not None:
                delta = time.time() - float(ts)
                if 0.0 <= delta <= 300.0:  # clamp 5 min max
                    self._lifetime_samples.append(delta)
        except Exception:
            pass

        # Fire hook
        if self._hooks:
            try:
                await self._hooks.fire("post_receive", {
                    "peer_id": peer_id, "msg_type": msg_type,
                    "msg_id": msg_id, "payload": payload,
                })
            except Exception:
                pass

        # Handle specific message types
        if msg_type == ew_protocol.MessageType.KEY_ROTATE:
            logger.info("Peer %s rotated keys — re-handshake required", peer_id)
            peer_state.transition(ew_protocol.PeerState.Status.HANDSHAKING)
            return

        if msg_type == ew_protocol.MessageType.REKEY_REQUEST:
            await self._handle_rekey_request(peer_id, payload, peer_state)
            return

        if msg_type == ew_protocol.MessageType.REKEY_RESPONSE:
            await self._handle_rekey_response(peer_id, payload, peer_state)
            return

        if msg_type == ew_protocol.MessageType.REVOCATION:
            await self._handle_revocation(peer_id, payload, peer_state)
            return

        if msg_type == ew_protocol.MessageType.ACK:
            logger.debug("ACK from %s for %s", peer_id, msg_id)
            return

        if msg_type == ew_protocol.MessageType.PING:
            await self._send_encrypted_control(
                peer_id, ew_protocol.MessageType.PONG
            )
            return

        if msg_type == ew_protocol.MessageType.PONG:
            sent_at = self._pending_pings.pop(peer_id, None)
            if sent_at is not None:
                rtt_ms = (time.monotonic() - sent_at) * 1000
                peer_state.latency_ms = rtt_ms
            return

        logger.info("From %s [%s]: %s", peer_id, msg_type, msg_id)

    # ------------------------------------------------------------------
    # Encrypted control messages (#3, #4: no plaintext after handshake)
    # ------------------------------------------------------------------

    async def _send_encrypted_control(self, peer_id: str, msg_type: str,
                                       extra_fields: dict = None):
        """Send an encrypted + signed control message via binary frame.

        All post-handshake messages use binary wire format — no plaintext
        or JSON metadata exposed on the wire.
        """
        control_payload = {"type": msg_type, "from": self.node_id}
        if extra_fields:
            control_payload.update(extra_fields)
        payload_bytes = json.dumps(control_payload, separators=(",", ":")).encode()

        frame = ew_protocol.Frame(
            msg_type=msg_type,
            payload=payload_bytes,
            source=self.node_id,
        )
        await self._send_frame(peer_id, frame)

    # ------------------------------------------------------------------
    # Sending messages
    # ------------------------------------------------------------------

    async def send_message(self, to_node: str, msg_type: str, payload: bytes,
                          priority: str = "NORMAL") -> str:
        """Send a message to a peer. Direct → routed → queued, in that order.

        Order of delivery attempts:
            1. Direct WebSocket if peer is connected with active session.
            2. v0.4 mesh route if MeshRouter has a known next hop.
            3. Offline queue (legacy fallback).
        """
        with _otel_span(
            "ironmesh.send_message",
            **{
                "ironmesh.peer.node_id": to_node[:32] if to_node else "",
                "ironmesh.message.type": msg_type,
                "ironmesh.message.priority": priority,
                "ironmesh.message.size_bytes": len(payload) if payload else 0,
            },
        ) as _sp:
            return await self._send_message_inner(
                to_node, msg_type, payload, priority, _sp,
            )

    async def _send_message_inner(self, to_node, msg_type, payload, priority,
                                  _otel_sp=None):
        msg_id = str(uuid.uuid4())

        # Store in history
        await self._db.store_message(
            msg_id=msg_id, source=self.node_id, source_display=self.name,
            destination=to_node, msg_type=msg_type, payload=payload,
            direction="outbound", priority=priority,
        )

        peer_state = self.peers.get(to_node)
        ws = self.ws_clients.get(to_node)

        # Fire pre-send hook (best effort, regardless of path)
        if self._hooks:
            try:
                await self._hooks.fire("pre_send", {
                    "peer_id": to_node, "msg_type": msg_type,
                    "msg_id": msg_id, "payload": payload,
                })
            except Exception:
                pass

        # v0.4: Build a routing-aware Frame. If we can look up the
        # destination's identity public key, e2e-seal the payload so relays
        # cannot read it.
        e2e_payload = None
        dest_pubkey = self._lookup_dest_identity(to_node)
        if dest_pubkey is not None and to_node != self.node_id:
            try:
                from ironmesh import mesh_crypto
                e2e_payload = mesh_crypto.seal_to_destination(payload, dest_pubkey)
            except Exception as e:
                logger.debug("E2E seal failed for %s: %s — falling back to per-hop only",
                             to_node, e)
                e2e_payload = None

        # v0.5.2: LoRa QoS — compress large payloads for RNS peers
        compressed = False
        if (peer_state and peer_state.transport_type == "rns"
                and self._lora_max_payload > 0
                and len(payload) > self._lora_max_payload):
            self.metrics.lora_oversized_messages += 1
            import gzip
            try:
                shrunk = gzip.compress(payload, compresslevel=9)
                if len(shrunk) <= self._lora_max_payload:
                    logger.info("LoRa QoS: compressed %d -> %d bytes for %s",
                                len(payload), len(shrunk), to_node)
                    payload = shrunk
                    compressed = True
                else:
                    logger.warning("LoRa QoS: payload %d bytes (compressed %d) "
                                   "exceeds max %d for %s",
                                   len(payload), len(shrunk),
                                   self._lora_max_payload, to_node)
            except Exception as e:
                logger.warning("LoRa QoS compression failed: %s", e)

        frame = ew_protocol.Frame(
            msg_type=msg_type,
            payload=payload,
            msg_id=msg_id,
            source=self.node_id,
            destination=to_node,
            priority=priority,
        )
        frame.e2e_payload = e2e_payload
        frame.ttl = self.config.max_hops
        frame.hops = []
        if compressed:
            frame.routing["compressed"] = True

        # 1. Direct WebSocket
        if ws and peer_state and peer_state.session_key:
            try:
                await self._send_frame(to_node, frame)
                peer_state.messages_sent += 1
                peer_state.bytes_sent_total += len(payload) if payload else 0
                self.metrics.messages_sent += 1
                self.metrics.messages_delivered += 1
                logger.info("Sent %s -> %s [%s] (direct)", msg_type, to_node, msg_id)
                return msg_id
            except Exception as e:
                peer_state.record_retry("direct_send_failed")
                logger.warning("Direct send failed to %s, trying mesh: %s", to_node, e)

        # 2. v0.4 routed delivery via MeshRouter
        if self._mesh is not None:
            next_hop = self._mesh.get_route(to_node)
            if next_hop is not None and next_hop != to_node:
                try:
                    await self._send_frame(next_hop, frame)
                    # v0.7.2: credit the NEXT-HOP peer state with bytes + counter
                    # parity with direct send path so /api/mesh_stats is accurate
                    next_peer = self.peers.get(next_hop)
                    if next_peer is not None:
                        next_peer.bytes_sent_total += len(payload) if payload else 0
                    self.metrics.messages_sent += 1
                    self.metrics.messages_delivered += 1
                    logger.info("Sent %s -> %s via %s [%s] (routed)",
                                msg_type, to_node, next_hop, msg_id)
                    return msg_id
                except Exception as e:
                    # Record retry against next-hop and ultimate destination
                    # for visibility into where the delivery broke.
                    next_peer = self.peers.get(next_hop)
                    if next_peer is not None:
                        next_peer.record_retry("routed_send_failed")
                    if peer_state is not None:
                        peer_state.record_retry("routed_send_failed")
                    logger.warning("Routed send via %s failed: %s", next_hop, e)

        # 3. Offline queue (legacy fallback)
        self.metrics.messages_failed += 1
        if peer_state is not None:
            peer_state.record_retry("queued_offline")
        admitted = await self._db.queue_for_peer(
            to_node, msg_id, self.node_id, msg_type, payload, priority,
        )
        if admitted is False:
            # v0.7.2: offline queue refused admission (cap hit + all higher
            # priority). Surface as an explicit failure so the caller can
            # re-attempt later with CRITICAL or back off.
            if peer_state is not None:
                peer_state.record_retry("queue_full_dropped")
            logger.warning(
                "Offline queue refused %s for %s (cap hit, lower priority than all queued)",
                msg_id, to_node,
            )
        return msg_id

    def _lookup_dest_identity(self, node_id: str) -> Optional[bytes]:
        """Return the destination's Ed25519 identity public key, or None.

        Checks the live peer registry first (for direct peers we've handshook
        with), then falls back to the TOFU pinned peer table. Returns None for
        unknown destinations — caller must then fall back to per-hop crypto only.
        """
        peer = self.peers.get(node_id)
        if peer is not None and getattr(peer, "identity_public", None):
            return peer.identity_public
        # TOFU pinned peers — keyed by agent name, value carries fingerprint
        # which is the same identifier as node_id when we look up by name.
        for name, info in self._pinned_peers.items():
            if info.get("fingerprint") == node_id:
                pub = info.get("identity_public")
                if pub:
                    return pub
        return None

    async def _gate_peer_bandwidth(self, peer_id: str, n_bytes: int) -> bool:
        """v0.7.2: throttle outbound bandwidth per-peer.

        Returns True if the bytes were admitted (possibly after a brief
        wait). Returns False if the wait would exceed ``_peer_bandwidth_max_wait``
        — caller should drop the frame and record the miss.

        When rate is 0, the throttle is disabled and admissions are free.
        """
        if self._peer_bandwidth_rate <= 0:
            return True
        bucket = self._peer_bandwidth_limiters.get(peer_id)
        if bucket is None:
            bucket = ew_protocol.TokenBucket(
                rate=float(self._peer_bandwidth_rate),
                burst=int(self._peer_bandwidth_burst),
            )
            self._peer_bandwidth_limiters[peer_id] = bucket
        # Large frames may exceed the bucket burst; clamp to burst so we
        # don't deadlock waiting for an impossible refill.
        cost = min(int(n_bytes), bucket.burst)
        wait = bucket.wait_time(cost)
        if wait > self._peer_bandwidth_max_wait:
            logger.warning(
                "Bandwidth throttle dropping %d bytes to %s — wait %.1fs > ceiling %.1fs",
                n_bytes, peer_id, wait, self._peer_bandwidth_max_wait,
            )
            # Counter incremented at the gate so it's accurate regardless
            # of what the caller does with the False return.
            self._peer_bandwidth_drops_total += 1
            return False
        if wait > 0:
            await asyncio.sleep(wait)
        bucket.consume(cost)
        return True

    async def _send_frame(self, peer_id: str, frame: ew_protocol.Frame):
        """Send a Frame to a connected peer using binary wire format.

        Binary format hides message metadata (type, source, msg_id) inside
        the encrypted payload — only sequence, timestamp, and msg_id hash
        are visible on the wire. Signature is appended as 64-byte Ed25519.
        """
        ws = self.ws_clients.get(peer_id)
        peer_state = self.peers.get(peer_id)
        if not ws or not peer_state:
            return

        if not peer_state.session_key:
            logger.warning("Cannot send frame to %s — no session key", peer_id)
            return

        frame.sequence = peer_state.next_sequence()

        # v0.4: Only attach an inner source signature when we are the original
        # source. Relays must not re-sign — they preserve the source signature
        # set by the originator. encrypt_and_serialize is also a no-op when
        # frame.source_signature is already set, but we make the intent
        # explicit here.
        source_signing_key = None
        if frame.source == self.node_id and frame.source_signature is None:
            source_signing_key = self._keypair.get_signing_key()

        try:
            raw = frame.encrypt_and_serialize(
                peer_state.session_key,
                signing_key=self._keypair.get_signing_key(),
                source_signing_key=source_signing_key,
            )
            # v0.7.2: per-peer bandwidth throttle. Block briefly if the peer
            # would exceed its allocated bytes/sec; drop with audit if the
            # required wait exceeds the max_wait ceiling (prevents unbounded
            # buffering under attack).
            if not await self._gate_peer_bandwidth(peer_id, len(raw)):
                # Dropped — don't increment bytes_sent. Counter already
                # incremented inside the gate so /metrics is accurate.
                peer_state.record_retry("bandwidth_throttled")
                return
            # v0.6.1: 5-second send timeout prevents blocked sockets from
            # hanging the heartbeat loop. On timeout we treat the peer as
            # disconnected and trigger cleanup.
            try:
                await asyncio.wait_for(ws.send(raw), timeout=5.0)
                self.metrics.bytes_sent += len(raw)
            except asyncio.TimeoutError:
                logger.warning("Send timeout to %s — marking offline", peer_id)
                self.ws_clients.pop(peer_id, None)
                if peer_id in self.peers:
                    self.peers[peer_id].transition(ew_protocol.PeerState.Status.OFFLINE)
                    self.peers[peer_id].session_key = None
                try:
                    await ws.close()
                except Exception:
                    pass
        except Exception as e:
            logger.warning("Failed to send frame to %s: %s", peer_id, e)
            # v0.6.1: on send error, also transition offline to avoid spamming
            # "failed to send" on a dead connection.
            if peer_id in self.peers and self.peers[peer_id].is_online:
                self.ws_clients.pop(peer_id, None)
                self.peers[peer_id].transition(ew_protocol.PeerState.Status.OFFLINE)
                self.peers[peer_id].session_key = None

    # ------------------------------------------------------------------
    # Pending message flush
    # ------------------------------------------------------------------

    async def _flush_pending(self, peer_id: str):
        """Flush all pending messages for a newly-connected peer."""
        try:
            pending = await self._db.get_pending_for_peer(peer_id)
            if not pending:
                return

            logger.info("Flushing %d pending messages to %s", len(pending), peer_id)
            peer_state = self.peers.get(peer_id)
            for msg in pending:
                frame = ew_protocol.Frame(
                    msg_type=msg["msg_type"],
                    payload=msg["payload"],
                    source=msg["source"],
                    destination=peer_id,
                    priority=msg["priority"],
                )
                await self._send_frame(peer_id, frame)
                await self._db.mark_delivered(peer_id, msg["msg_id"])
                # v0.9.0: parity with direct + routed send paths — the
                # flush path previously bypassed both per-peer and
                # daemon-level counters, so messages_sent_total
                # under-reported any traffic that went through the
                # offline-queue path. Caught during the v0.9.0
                # stress run on the live mesh.
                payload_len = len(msg.get("payload") or b"")
                if peer_state is not None:
                    peer_state.messages_sent += 1
                    peer_state.bytes_sent_total += payload_len
                self.metrics.messages_sent += 1
                self.metrics.messages_delivered += 1
            logger.info("All pending messages delivered to %s", peer_id)
        except Exception as e:
            logger.warning("Error flushing pending messages for %s: %s", peer_id, e)

    # ------------------------------------------------------------------
    # Outbound connection (client-side handshake)
    # ------------------------------------------------------------------

    async def _do_client_handshake(self, ws, label: str) -> Optional[str]:
        """Run the client-side passphrase auth + ephemeral ECDH + message loop.

        This is the transport-agnostic core of the outbound handshake.
        ``ws`` can be a real WebSocket or an ``RNSLinkAdapter`` — it only
        needs ``send()``, ``recv()``, ``remote_address``, and ``async for``.

        Returns the peer_id on success, or None on failure.
        """
        # Stage 1: Receive challenge
        raw = await asyncio.wait_for(ws.recv(), timeout=30)
        msg = json.loads(raw)

        if msg.get("type") != ew_protocol.MessageType.PASSPHRASE_CHALLENGE:
            logger.warning("Expected PASSPHRASE_CHALLENGE, got %s", msg.get("type"))
            return None

        server_nonce = bytes.fromhex(msg["nonce"])

        # Send proof
        proof = ew_protocol.Handshake.compute_passphrase_proof(
            self.passphrase, server_nonce
        )
        await ws.send(json.dumps({
            "type": ew_protocol.MessageType.PASSPHRASE_CHALLENGE,
            "from": self.node_id,
            "proof": proof,
        }))

        # Wait for verification + mutual auth
        raw = await asyncio.wait_for(ws.recv(), timeout=30)
        msg = json.loads(raw)
        if msg.get("type") != ew_protocol.MessageType.PASSPHRASE_VERIFIED:
            logger.warning("Auth rejected by %s", label)
            return None

        # Verify server also knows the passphrase (mutual auth)
        server_proof = msg.get("server_proof")
        if server_proof:
            expected_server_proof = ew_protocol.Handshake.compute_passphrase_proof(
                self.passphrase, server_nonce[::-1]
            )
            if not hmac.compare_digest(server_proof, expected_server_proof):
                logger.warning("Mutual auth failed — server proof invalid at %s", label)
                return None
            logger.debug("Mutual auth verified with %s", label)

        # Stage 2: Ephemeral ECDH
        my_ephemeral_private, my_ephemeral_public = ew_keys.generate_ephemeral()

        # Sign our HELLO with Ed25519 + channel binding via server_nonce
        my_ephemeral_b64 = base64.b64encode(bytes(my_ephemeral_public)).decode()
        my_identity_b64 = self._keypair.get_public_key_base64()
        hello_payload = json.dumps({
            "channel_binding": server_nonce.hex(),
            "ephemeral_public": my_ephemeral_b64,
            "identity_public": my_identity_b64,
            "name": self.name,
            "protocol_version": PROTOCOL_VERSION,
        }, separators=(",", ":"), sort_keys=True)
        signature = ew_crypto.sign_message(
            self._keypair.get_signing_key(), hello_payload.encode()
        )
        await ws.send(json.dumps({
            "type": ew_protocol.MessageType.HELLO,
            "from": self.node_id,
            "name": self.name,
            "ephemeral_public": my_ephemeral_b64,
            "identity_public": my_identity_b64,
            "protocol_version": PROTOCOL_VERSION,
            "channel_binding": server_nonce.hex(),
            "signature": base64.b64encode(signature).decode(),
        }))

        # Receive server's HELLO
        raw = await asyncio.wait_for(ws.recv(), timeout=30)
        msg = json.loads(raw)
        if msg.get("type") != ew_protocol.MessageType.HELLO:
            logger.warning("Expected HELLO, got %s", msg.get("type"))
            return None

        claimed_peer_id = msg.get("from")
        peer_name = msg.get("name", claimed_peer_id)
        peer_ephemeral_b64 = msg.get("ephemeral_public")
        peer_identity_b64 = msg.get("identity_public")

        if not peer_ephemeral_b64:
            logger.warning("Server HELLO missing ephemeral_public")
            return None

        # Verify server's HELLO signature
        peer_sig_b64 = msg.get("signature")
        if peer_identity_b64 and peer_sig_b64:
            try:
                from nacl.signing import VerifyKey
                verify_key = VerifyKey(base64.b64decode(peer_identity_b64))
                # Reconstruct canonical from server's HELLO fields
                server_canonical = json.dumps({
                    "channel_binding": msg.get("channel_binding", ""),
                    "ephemeral_public": peer_ephemeral_b64,
                    "identity_public": peer_identity_b64,
                    "name": peer_name,
                    "protocol_version": msg.get("protocol_version", ""),
                }, separators=(",", ":"), sort_keys=True)
                extracted = ew_crypto.verify_signature(
                    verify_key, base64.b64decode(peer_sig_b64)
                )
                if extracted != server_canonical.encode():
                    raise ValueError("Server HELLO signature payload does not match canonical form")
                logger.debug("Server HELLO signature verified")
            except Exception as e:
                logger.warning("Server HELLO signature FAILED: %s", e)
                return None
        elif peer_identity_b64 and not peer_sig_b64:
            logger.warning("Server sent identity key but no signature — rejecting")
            return None

        # Derive peer_id from identity key
        if peer_identity_b64:
            peer_id = ew_keys.get_fingerprint(base64.b64decode(peer_identity_b64))
        else:
            peer_id = claimed_peer_id

        from nacl.public import PublicKey as X25519PublicKey
        peer_ephemeral_public = X25519PublicKey(base64.b64decode(peer_ephemeral_b64))
        session_key = ew_crypto.ecdh_exchange(my_ephemeral_private, peer_ephemeral_public)
        ew_crypto.secure_wipe(my_ephemeral_private)
        del my_ephemeral_private  # Forward secrecy

        # TOFU check BEFORE adding peer to dicts.
        await self._check_tofu(peer_id, peer_identity_b64)

        # Set up peer state (only after TOFU passes)
        address = f"{ws.remote_address[0]}:{ws.remote_address[1]}"
        peer_state = ew_protocol.PeerState(
            node_id=peer_id, address=address
        )
        peer_state.session_key = session_key
        peer_state.ephemeral_public = base64.b64decode(peer_ephemeral_b64)
        peer_state.identity_public = base64.b64decode(peer_identity_b64) if peer_identity_b64 else None
        peer_state.verified = True

        # v0.4: protocol version negotiation
        peer_protocol = msg.get("protocol_version", "ironmesh/0.3")

        # v0.6: reject peers below configured minimum
        if _parse_protocol_version(peer_protocol) < _parse_protocol_version(self._min_protocol_version):
            logger.warning(
                "Rejecting peer %s on %s (below min %s)",
                peer_id, peer_protocol, self._min_protocol_version,
            )
            self.metrics.handshake_failures += 1
            return None

        peer_state.protocol_version = peer_protocol
        peer_state.supports_mesh = _peer_supports_mesh(peer_protocol)
        peer_state.is_relay_capable = peer_state.supports_mesh
        peer_state.agent_name = peer_name
        if not peer_state.supports_mesh:
            logger.info("Peer %s on %s — mesh forwarding disabled (direct only)",
                        peer_id, peer_protocol)

        # Audit C-01: atomic duplicate-check + peer-state assignment.
        async with self._peer_lock:
            # Guard against duplicate connections (both sides connect simultaneously).
            # v0.5: allow WebSocket to upgrade an existing RNS connection.
            existing_state = self.peers.get(peer_id)
            if existing_state and existing_state.is_online and peer_id in self.ws_clients:
                new_is_rns = RNSLinkAdapter is not None and isinstance(ws, RNSLinkAdapter)
                old_is_rns = existing_state.transport_type == "rns"
                if not new_is_rns and old_is_rns:
                    logger.info("Upgrading %s from RNS to WebSocket", peer_id)
                    old_ws = self.ws_clients.pop(peer_id, None)
                    if old_ws:
                        try:
                            await old_ws.close()
                        except Exception:
                            pass
                else:
                    logger.debug("Already connected to %s via %s, dropping outbound duplicate",
                                 peer_id, existing_state.transport_type)
                    return None

            peer_state.transition(ew_protocol.PeerState.Status.ONLINE)
            self.peers[peer_id] = peer_state
            self.ws_clients[peer_id] = ws
            self._peer_rate_limiters[peer_id] = ew_protocol.TokenBucket(rate=20.0, burst=100)
            self._replay_guard.reset_peer(peer_id)
            self._known_peer_addresses[peer_id] = address

        # v0.5: track transport type for failover
        if RNSLinkAdapter is not None and isinstance(ws, RNSLinkAdapter):
            peer_state.transport_type = "rns"
            rns_hash = label.replace("rns:", "") if label.startswith("rns:") else None
            if rns_hash:
                peer_state.rns_dest_hash = rns_hash
                self._known_rns_hashes[peer_id] = rns_hash
        else:
            peer_state.transport_type = "websocket"
            peer_state.ws_address = address

        await self._db.upsert_peer(
            peer_id, identity_public_b64=peer_identity_b64,
            address=address,
        )

        self.metrics.handshake_successes += 1
        self._reset_backoff(peer_id)  # v0.6
        logger.info("Connected to peer %s at %s via %s", peer_id, label,
                    peer_state.transport_type)

        # Pin peer fingerprint + address for mDNS verification
        if peer_identity_b64:
            fp = ew_keys.get_fingerprint(base64.b64decode(peer_identity_b64))
            if peer_name:
                self._pinned_peers[peer_name] = {
                    "fingerprint": fp,
                    "address": address,
                    "peer_id": peer_id,
                }

        # Flush pending
        asyncio.ensure_future(self._flush_pending(peer_id))

        # Message loop. On exit (socket closed or error), tear down the
        # peer state so reconnect paths see OFFLINE and can re-dial. v0.8.1
        # fix: previously the client side left the peer as ONLINE forever
        # once the message loop ended, which blocked the reconnect loop
        # (which skips peers not in OFFLINE state).
        try:
            # v0.8.5.6: tag inbound transport.
            _transport_name = (
                "rns" if RNSLinkAdapter is not None
                and isinstance(ws, RNSLinkAdapter)
                else "ws"
            )
            async for raw in ws:
                try:
                    self.metrics.bytes_received += len(raw)
                    await self._handle_message(
                        peer_id, raw, transport=_transport_name,
                    )
                except Exception as e:
                    logger.warning("Error from %s: %s", peer_id, e)
        finally:
            # Scope the teardown to the owning connection -- same
            # duplicate-handshake race as _handle_connection.
            owned_session = False
            async with self._peer_lock:
                if self.ws_clients.get(peer_id) is ws:
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
                    except Exception:
                        pass
                asyncio.ensure_future(self._try_transport_failover(peer_id))

        return peer_id

    async def connect_to_peer(self, host: str, port: int) -> Optional[str]:
        """Connect to a remote peer as client, performing full handshake.

        Attempts wss:// (TLS) first. Falls back to ws:// only if
        _allow_plaintext_ws is True. This protects the handshake from
        passive eavesdropping.
        """
        ws = None
        uri = None
        # Try TLS first
        try:
            uri = f"wss://{host}:{port}"
            client_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Allow self-signed certs in mesh networks (peers verify via TOFU)
            client_ssl.check_hostname = False
            client_ssl.verify_mode = ssl.CERT_NONE
            client_ssl.minimum_version = ssl.TLSVersion.TLSv1_2
            ws = await asyncio.wait_for(
                websockets.connect(uri, ssl=client_ssl, max_size=self.max_message_size, ping_interval=20, ping_timeout=10),
                timeout=10,
            )
            logger.info("TLS connection established to %s:%d", host, port)
        except Exception as tls_err:
            if not self._allow_plaintext_ws:
                logger.warning(
                    "TLS connection failed to %s:%d and plaintext is disabled: %s",
                    host, port, tls_err)
                return None
            # Fallback to plaintext
            logger.warning(
                "TLS unavailable for %s:%d, falling back to ws:// (INSECURE): %s",
                host, port, tls_err)
            try:
                uri = f"ws://{host}:{port}"
                ws = await asyncio.wait_for(
                    websockets.connect(uri, max_size=self.max_message_size, ping_interval=20, ping_timeout=10),
                    timeout=10,
                )
            except Exception as plain_err:
                logger.warning("Plaintext connection also failed to %s:%d: %s", host, port, plain_err)
                return None
        try:
            async with ws:
                return await self._do_client_handshake(ws, f"{host}:{port}")

        except Exception as e:
            logger.debug("Connect to %s:%d failed: %s", host, port, e)
            return None

    async def _connect_rns_peer(self, dest_hash: str) -> Optional[str]:
        """Connect to a peer over Reticulum (LoRa/RNS).

        Resolves the destination, creates an RNS link, wraps it in an
        ``RNSLinkAdapter``, then runs the standard IronMesh handshake.
        """
        if not self._reticulum:
            logger.warning("Cannot connect to RNS peer — Reticulum transport not active")
            return None
        try:
            adapter = await self._reticulum.connect_to_destination(dest_hash)
            if not adapter:
                return None
            return await self._do_client_handshake(adapter, f"rns:{dest_hash}")
        except Exception as e:
            logger.warning("RNS connect to %s failed: %s", dest_hash, e)
            return None

    async def _connect_and_track_rns(self, dest_hash: str):
        """Connect to an RNS peer and remember the hash for reconnection."""
        peer_id = await self._connect_rns_peer(dest_hash)
        if peer_id:
            self._known_rns_hashes[peer_id] = dest_hash
        return peer_id

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

    # ------------------------------------------------------------------
    # Background loops
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self):
        while self._running:
            await asyncio.sleep(self._heartbeat_interval)
            for peer_id, state in list(self.peers.items()):
                if state.is_online:
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

    # v0.8.5.7: single source of truth for event-driven counters.
    # The daemon in-process bumps covered events it ORIGINATED, but CLI
    # and MCP-in-a-separate-process paths fire the same audit events
    # without access to daemon.metrics. Rather than have each process
    # try to reach across to the daemon's memory, the daemon tails its
    # own audit log: every second it reads from a stored byte offset to
    # EOF, parses each new entry, and bumps the counter that matches the
    # event type. Audit-log rotation resets the offset. In-process
    # bumps are NOT duplicated — the scanner is authoritative so they
    # live on the write path only as a "record of intent" (actual
    # counter value comes from the scanner).
    def _reserve_counter_bump(self, counter_name: str) -> None:
        """Reserve an in-process counter bump. The daemon itself is
        about to fire an audit event; bump the metric NOW (so /metrics
        is fresh) and tell the scanner to skip the next matching event
        when it reads back the log (avoid double-counting).

        Thread-safe: mesh.py calls this from a worker thread; scanner
        runs on the asyncio thread. _counter_lock serializes both.
        """
        try:
            with self._counter_lock:
                cur = getattr(self.metrics, counter_name)
                setattr(self.metrics, counter_name, cur + 1)
                self._in_proc_counter_bumps[counter_name] = \
                    self._in_proc_counter_bumps.get(counter_name, 0) + 1
        except AttributeError:
            pass

    def _unreserve_counter_bump(self, counter_name: str) -> None:
        """Undo a prior _reserve_counter_bump when the paired audit
        emit failed to persist. Without this, the metric counter
        stays +1 above truth until the next durable emit of the same
        type arrives and consumes the stale reservation — at which
        point that real event is silently absorbed by the scanner
        instead of bumping the counter. Either way the counter
        misreports. Releasing the reservation here restores both
        invariants.

        Floored at zero so a double-unreserve can never drive the
        counter negative. Same lock as _reserve_counter_bump — safe
        from any thread.
        """
        try:
            with self._counter_lock:
                cur = getattr(self.metrics, counter_name)
                setattr(self.metrics, counter_name, max(0, cur - 1))
                pending = self._in_proc_counter_bumps.get(counter_name, 0)
                if pending > 0:
                    self._in_proc_counter_bumps[counter_name] = pending - 1
        except AttributeError:
            pass

    def _emit_audit_with_reservation(
        self,
        counter_name: str,
        event: str,
        payload: dict,
    ) -> bool:
        """Bundled: bump counter + reserve it against the scanner, emit
        the audit event, and release the reservation if the emit fails.

        This is the ONE correct pattern for firing an audit event whose
        type has a Prometheus counter mirror. Every call site that
        spells the reserve/emit/except block out by hand is a latent
        drift bug — prefer this helper.

        Returns True if the audit event reached disk, False otherwise
        (no audit log attached, or emit raised). The caller rarely
        needs the return value; the helper already handles the
        observability bookkeeping.
        """
        self._reserve_counter_bump(counter_name)
        if self._audit is None:
            return False
        try:
            self._audit.log(event, payload)
            return True
        except Exception as e:
            logger.warning("audit emit %s failed: %s", event, e)
            self._unreserve_counter_bump(counter_name)
            return False

    _AUDIT_EVENT_TO_COUNTER = {
        "PEER_CAP_SET_CHANGED":       "peer_cap_set_changed",
        "PEER_CAP_BASELINE":          "peer_cap_baseline",
        "PEER_CAP_ACCEPTED":          "peer_cap_accepted",
        "PEER_CAP_BINDING_PARTIAL":   "peer_cap_binding_partial",
        "MSG_REPLAY_CROSS_TRANSPORT": "msg_replay_cross_transport",
        "PEER_REVOKED_LOCAL":         "peer_revoked_local",
        "PEER_STATE_CHANGED":         "peer_state_changed",
        # v0.8.5.7: pre-existing events that now get Prometheus
        # mirrors via the same scanner path.
        "PEER_PROMOTED":              "peer_promoted",
        "PEER_BLOCKED":               "peer_blocked",
    }

    def _reconcile_counters_from_audit_tail(self, limit: int = 10_000) -> None:
        """Bump Prometheus counters for the last `limit` entries of the
        audit log so restart doesn't zero out the mirrored counters.

        Counter continuity across restart matters because Grafana's
        `rate()` / `increase()` queries assume monotonic counters. A
        zero-reset on restart creates a negative delta that Prometheus
        reports as a counter reset — noisy and misleading. Seeding
        from the log tail makes the restart invisible to downstream
        alerts.

        Bounded at `limit` entries (last N) so startup stays fast even
        when the audit log is very large (>200 MB). Entries older than
        the bound don't contribute; operators running `increase(...)`
        with long time windows already expect edge-effects at log
        rotation boundaries, so this is a reasonable compromise.
        """
        if self._audit is None:
            return
        path = self._audit._path  # noqa: SLF001
        if not os.path.exists(path):
            return
        try:
            # Read the last `limit` lines via a simple tail that
            # doesn't load the entire file. Python doesn't have a
            # built-in; this buffered-block-from-end approach is
            # O(limit * avg_line_len) memory.
            tail_lines = self._tail_lines(path, limit)
        except Exception as e:
            logger.debug("counter reconcile: tail read failed: %s", e)
            return
        bumped = 0
        for line in tail_lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue
            event = entry.get("event")
            counter_name = self._AUDIT_EVENT_TO_COUNTER.get(event)
            if counter_name is None:
                continue
            try:
                with self._counter_lock:
                    cur = getattr(self.metrics, counter_name)
                    setattr(self.metrics, counter_name, cur + 1)
                bumped += 1
            except AttributeError:
                continue
        if bumped:
            logger.info(
                "Reconciled %d audit-mirror counter bump(s) from the last "
                "%d audit entries.", bumped, limit,
            )

    @staticmethod
    def _tail_lines(path: str, limit: int, block_size: int = 8192) -> list:
        """Return up to the last `limit` lines of `path` as a list of
        strings (order preserved, oldest first). Reads backward in
        block_size chunks so a 1 GB file doesn't fully load into
        memory. Returns [] on any read error."""
        try:
            with open(path, "rb") as f:
                f.seek(0, 2)
                file_size = f.tell()
                if file_size == 0:
                    return []
                chunks: list = []
                line_count = 0
                offset = file_size
                while offset > 0 and line_count <= limit:
                    read_size = min(block_size, offset)
                    offset -= read_size
                    f.seek(offset)
                    chunk = f.read(read_size)
                    chunks.append(chunk)
                    line_count += chunk.count(b"\n")
                raw = b"".join(reversed(chunks))
                lines = raw.decode("utf-8", errors="replace").splitlines()
                return lines[-limit:]
        except OSError:
            return []

    async def _audit_counter_sync_loop(self):
        """Periodically tail the audit log and increment counters for
        events fired by CLI / MCP / other processes that can't reach
        daemon.metrics directly. Idempotent on event reads because
        the byte-offset advances monotonically within a single log file
        and resets cleanly on rotation.
        """
        if self._audit is None:
            return
        log_path = self._audit._path  # noqa: SLF001
        # Start from current EOF — we count events emitted from this
        # daemon-run forward. Historical events (pre-restart) show up
        # in the audit log but the counter starts at 0 on each restart,
        # matching every other counter in the Metrics dataclass.
        try:
            st = os.stat(log_path)
            self._audit_counter_offset = st.st_size
            self._audit_counter_inode = st.st_ino
        except OSError:
            self._audit_counter_offset = 0
            self._audit_counter_inode = None

        # Track in-process increments so the scanner can deduct them
        # rather than double-counting. _in_proc_bumps[event] = count.
        # Each time the scanner reads an event, it checks if the daemon
        # already bumped in-process for that event; if yes, it DOESN'T
        # bump again, and decrements the in-process counter.
        while self._running:
            await asyncio.sleep(1.0)
            try:
                self._scan_audit_for_counters(log_path)
            except Exception as e:
                logger.debug("audit counter sync failed: %s", e)

    def _scan_audit_for_counters(self, log_path: str) -> None:
        """Read new audit entries from ``self._audit_counter_offset`` to
        EOF, parse each one, and bump the matching metric counter.

        Rotation detection is via inode comparison: when `audit.log` is
        renamed to `.1` during rotation, the new live file has a
        different st_ino. This catches the case where post-rotation
        writes re-grow the live file past our stored offset before we
        next scan (the naive size<offset check misses this — B24).
        """
        try:
            st = os.stat(log_path)
        except OSError:
            return
        current_size = st.st_size
        current_inode = st.st_ino

        rotated_path = log_path + ".1"
        # v0.8.5.7: inode change → rotation. Rescue events the
        # scanner hadn't yet read from the file that just became `.1`,
        # then reset offset.
        if (self._audit_counter_inode is not None
                and current_inode != self._audit_counter_inode):
            if os.path.exists(rotated_path):
                try:
                    rot_st = os.stat(rotated_path)
                    # Only rescue the file whose inode matches what we
                    # were tracking — i.e. the file that just became .1.
                    # If `.1` is an older rotation (already scanned),
                    # skip to avoid double-counting.
                    if rot_st.st_ino == self._audit_counter_inode:
                        rot_size = rot_st.st_size
                        start = min(self._audit_counter_offset, rot_size)
                        with open(rotated_path, "r", encoding="utf-8") as rf:
                            rf.seek(start)
                            self._process_audit_buf(rf.read())
                except OSError:
                    pass
            self._audit_counter_offset = 0
            self._audit_counter_inode = current_inode
        elif self._audit_counter_inode is None:
            # First scan of this run — adopt the current file identity
            self._audit_counter_inode = current_inode

        if current_size < self._audit_counter_offset:
            # Sanity fallback: file shrank but inode unchanged (truncation,
            # operator manually zeroed the file). Don't try to rescue —
            # there's no known prior file with this content.
            self._audit_counter_offset = 0
        if current_size == self._audit_counter_offset:
            return  # nothing new
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                f.seek(self._audit_counter_offset)
                buf = f.read()
                new_offset = f.tell()
        except OSError:
            return
        self._process_audit_buf(buf)
        self._audit_counter_offset = new_offset

    def _process_audit_buf(self, buf: str) -> None:
        """Parse each line of an audit-log buffer and bump the matching
        metric counter. Shared by the live-file path and the rotated-
        file rescue path (v0.8.5.7 B24)."""
        for line in buf.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue  # torn or malformed line — next scan will retry
            event = entry.get("event")
            counter_name = self._AUDIT_EVENT_TO_COUNTER.get(event)
            if counter_name is None:
                continue
            # If the daemon already bumped in-process for this event,
            # consume the reservation rather than double-counting.
            # Lock the whole read-modify-write against concurrent
            # _reserve_counter_bump from other threads.
            with self._counter_lock:
                if (self._in_proc_counter_bumps.get(counter_name, 0) > 0):
                    self._in_proc_counter_bumps[counter_name] -= 1
                    continue
                try:
                    cur = getattr(self.metrics, counter_name)
                    setattr(self.metrics, counter_name, cur + 1)
                except AttributeError:
                    pass

    async def _long_drop_watchdog(self):
        """v0.7.2: alert on peers offline beyond the configured threshold.

        Emits EVENT_PEER_DROPPED_LONG exactly once per drop (we clear the
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
        addr = f"{info['ip']}:{info['port']}"
        # If we've seen this peer before, log address changes.
        # Identity is verified via Ed25519 key pinning in _check_tofu()
        # during the handshake — mDNS address changes are safe to accept.
        pinned = self._pinned_peers.get(agent_name)
        if pinned and pinned["address"] != addr:
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
        # v0.7.2: we use a SINGLE stable criterion (agent_name) — not a mix
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
            host = info["ip"]
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
                # than us, we wait for them to dial instead. Mirrors the
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

    async def _capability_announce_loop(self):
        """Periodically gossip capabilities to direct neighbors.

        Each iteration sends one CAPABILITY_ANNOUNCE per known origin node:
        the local node's own capabilities, plus a re-broadcast of every
        remote node we have learned about. Re-broadcast preserves the
        original ``origin`` field so receivers attribute capabilities to
        the correct node, and we never send a node's announcement back to
        itself. This is a simple gossip flood that converges within a few
        iterations on a multi-hop topology.
        """
        # Stagger initial announce so peers handshake first
        await asyncio.sleep(10)
        while self._running:
            try:
                if self._capabilities is not None:
                    all_caps = self._capabilities.all()
                    announcements: list = []
                    for origin, caps in all_caps.items():
                        if not caps:
                            continue
                        announcements.append({
                            "origin": origin,
                            "capabilities": list(caps),
                        })

                    for announcement in announcements:
                        payload_bytes = json.dumps(
                            announcement, separators=(",", ":")
                        ).encode()
                        origin = announcement["origin"]
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
    # GUI Dashboard
    # ------------------------------------------------------------------

    def _build_mesh_stats(self) -> dict:
        """Compact snapshot for /api/mesh_stats — stable schema.

        Used by the benchmark harness, Grafana probes, and the dashboard
        mini-health widget. Fields are additive across releases.
        """
        lifetimes = list(getattr(self, "_lifetime_samples", ()))
        lifetime_block: dict
        if lifetimes:
            s = sorted(lifetimes)
            n = len(s)
            lifetime_block = {
                "count": n,
                "sum": sum(s),
                "p50": s[n // 2],
                "p90": s[min(int(0.9 * n), n - 1)],
                "p99": s[min(int(0.99 * n), n - 1)],
            }
        else:
            lifetime_block = {"count": 0, "sum": 0.0, "p50": None, "p90": None, "p99": None}

        peers = []
        for pid, p in self.peers.items():
            peers.append({
                "node_id": pid,
                "name": getattr(p, "agent_name", None),
                "online": bool(p.is_online),
                "transport": getattr(p, "transport_type", "websocket"),
                "rtt_ms": p.latency_ms,
                "messages_sent": int(getattr(p, "messages_sent", 0)),
                "messages_received": int(getattr(p, "messages_received", 0)),
                "bytes_sent_total": int(getattr(p, "bytes_sent_total", 0)),
                "bytes_received_total": int(getattr(p, "bytes_received_total", 0)),
                "retries_total": int(getattr(p, "retries_total", 0)),
                "retries_by_reason": dict(getattr(p, "retries_by_reason", {})),
                "session_rekey_count": int(getattr(p, "session_rekey_count", 0)),
                "last_seen": p.last_seen,
            })

        return {
            "node_id": self.node_id,
            "name": self.name,
            "ts": time.time(),
            "uptime_seconds": self.metrics.to_dict().get("uptime_seconds", 0),
            "active_peers": sum(1 for p in self.peers.values() if p.is_online),
            "total_peers": len(self.peers),
            "message_lifetime": lifetime_block,
            "peers": peers,
            # v0.8.5.2: gate counters + flag so harness/Grafana probes
            # can monitor queue pressure and blocked traffic without
            # scraping the Prometheus /metrics endpoint.
            "gate_enabled": bool(getattr(self.config, "require_message_promotion", False)),
            "pending_trust_evicted": int(getattr(self._db, "pending_trust_evicted", 0)),
            "pending_trust_dropped": int(getattr(self._db, "pending_trust_dropped", 0)),
            "messages_received_blocked": int(getattr(self.metrics, "messages_received_blocked", 0)),
        }

    def _build_metrics_dict(self) -> dict:
        """Build the metrics dict (shared by GUI and /metrics endpoint)."""
        d = self.metrics.to_dict()
        d["active_peers"] = sum(1 for p in self.peers.values() if p.is_online)
        d["total_peers"] = len(self.peers)
        # v0.4: mesh + capability metrics derived from live state
        if self._mesh is not None:
            d["routes_known"] = len(self._mesh.table)
            d["dedup_cache_size"] = self._mesh.dedup.size()
            d["dedup_sources"] = self._mesh.dedup.source_count()
            d["circuit_breakers_open"] = sum(
                1 for pid in self._mesh.circuit_breaker.all_peers()
                if self._mesh.circuit_breaker.is_open(pid)
            )
        else:
            d["routes_known"] = 0
            d["dedup_cache_size"] = 0
            d["dedup_sources"] = 0
            d["circuit_breakers_open"] = 0
        if self._capabilities is not None:
            d["capabilities_known"] = len(self._capabilities)
            d["capability_remote_nodes"] = len(self._capabilities.remote_nodes())
        else:
            d["capabilities_known"] = 0
            d["capability_remote_nodes"] = 0
        # v0.5.2: average RTT across online peers
        rtt_values = [p.latency_ms for p in self.peers.values()
                      if p.is_online and p.latency_ms is not None]
        d["avg_rtt_ms"] = sum(rtt_values) / len(rtt_values) if rtt_values else 0
        # v0.7.2: offline-queue backpressure counters
        d["pending_dropped"] = int(getattr(self._db, "pending_dropped", 0))
        d["pending_evicted"] = int(getattr(self._db, "pending_evicted", 0))
        # v0.7.2: peer-drop alerting counter
        d["peer_long_drops"] = int(getattr(self, "_peer_long_drops_total", 0))
        # v0.7.2: bandwidth-throttle drops
        d["peer_bandwidth_drops"] = int(getattr(self, "_peer_bandwidth_drops_total", 0))
        # v0.8.5.2: pending-trust gate counters (separate from offline queue
        # so operators can tell which queue is under pressure).
        d["pending_trust_evicted"] = int(getattr(self._db, "pending_trust_evicted", 0))
        d["pending_trust_dropped"] = int(getattr(self._db, "pending_trust_dropped", 0))
        d["messages_received_blocked"] = int(getattr(self.metrics, "messages_received_blocked", 0))
        d["gate_enabled"] = bool(getattr(self.config, "require_message_promotion", False))
        return d

    def _format_metrics_prometheus(self, m: dict) -> str:
        """Render the metrics dict as Prometheus exposition text format.

        Naming follows the ``ironmesh_<subsystem>_<name>`` convention. Type
        annotations declare counters vs gauges so scrapers compute rates
        correctly.
        """
        # (key_in_dict, prometheus_name, type, help)
        spec = [
            ("uptime_seconds", "ironmesh_uptime_seconds", "gauge",
             "Daemon uptime in seconds"),
            ("messages_sent", "ironmesh_messages_sent_total", "counter",
             "Total application messages sent (originated by this node)"),
            ("messages_received", "ironmesh_messages_received_total", "counter",
             "Total application messages received and dispatched locally"),
            ("messages_relayed", "ironmesh_messages_relayed_total", "counter",
             "Total messages relayed by this node on behalf of others"),
            ("route_lookup_failures", "ironmesh_route_lookup_failures_total",
             "counter", "Number of times a route lookup returned no next hop"),
            ("e2e_decrypt_failures", "ironmesh_e2e_decrypt_failures_total",
             "counter", "Number of times E2E SealedBox decryption failed"),
            ("bytes_sent", "ironmesh_bytes_sent_total", "counter",
             "Total bytes sent over WebSocket frames"),
            ("bytes_received", "ironmesh_bytes_received_total", "counter",
             "Total bytes received over WebSocket frames"),
            ("handshake_successes", "ironmesh_handshake_successes_total",
             "counter", "Successful peer handshakes"),
            ("handshake_failures", "ironmesh_handshake_failures_total",
             "counter", "Failed peer handshakes"),
            ("connections_total", "ironmesh_connections_total", "counter",
             "Total inbound connections accepted"),
            ("rate_limits_triggered", "ironmesh_rate_limits_triggered_total",
             "counter", "Total rate-limit denials"),
            ("active_peers", "ironmesh_active_peers", "gauge",
             "Currently online peers"),
            ("total_peers", "ironmesh_total_peers", "gauge",
             "Total peers known (online + offline)"),
            ("routes_known", "ironmesh_routes_known", "gauge",
             "Number of distinct destinations in the routing table"),
            ("dedup_cache_size", "ironmesh_dedup_cache_size", "gauge",
             "Total entries across all source dedup buckets"),
            ("dedup_sources", "ironmesh_dedup_sources", "gauge",
             "Number of distinct sources tracked in the dedup cache"),
            ("circuit_breakers_open", "ironmesh_circuit_breakers_open", "gauge",
             "Number of peers whose circuit breakers are currently open"),
            ("capabilities_known", "ironmesh_capabilities_known", "gauge",
             "Total local + remote capabilities tracked"),
            ("capability_remote_nodes", "ironmesh_capability_remote_nodes",
             "gauge", "Number of remote nodes whose capabilities we have learned"),
            # v0.5.2: delivery, RTT, QoS, rekey
            ("messages_delivered", "ironmesh_messages_delivered_total", "counter",
             "Messages delivered in real-time (direct or routed)"),
            ("messages_failed", "ironmesh_messages_failed_total", "counter",
             "Messages that fell back to offline queue"),
            ("avg_rtt_ms", "ironmesh_avg_rtt_ms", "gauge",
             "Average RTT to online peers in milliseconds"),
            ("session_rekeys", "ironmesh_session_rekeys_total", "counter",
             "Total in-session key rotations"),
            ("lora_oversized_messages", "ironmesh_lora_oversized_messages_total",
             "counter", "Messages exceeding LoRa max payload threshold"),
            # v0.7.2: offline queue backpressure
            ("pending_dropped", "ironmesh_pending_queue_dropped_total", "counter",
             "Messages refused admission to the offline queue (cap hit, lower priority than all queued)"),
            ("pending_evicted", "ironmesh_pending_queue_evicted_total", "counter",
             "Messages displaced from the offline queue to make room for higher-priority admits"),
            # v0.7.2: peer long-drop alerting
            ("peer_long_drops", "ironmesh_peer_long_drops_total", "counter",
             "Peers that stayed offline longer than the long-drop threshold"),
            # v0.7.2: per-peer bandwidth throttle drops
            ("peer_bandwidth_drops", "ironmesh_peer_bandwidth_drops_total", "counter",
             "Frames dropped because per-peer bandwidth budget was exceeded"),
            # v0.8.5.2: pending-trust gate counters
            ("pending_trust_evicted", "ironmesh_pending_trust_evicted_total", "counter",
             "MSGs evicted from a peer's pending-trust queue (FIFO at cap)"),
            ("pending_trust_dropped", "ironmesh_pending_trust_dropped_total", "counter",
             "MSGs silently dropped at the gate because the peer is blocked"),
            ("messages_received_blocked", "ironmesh_messages_received_blocked_total", "counter",
             "Inbound MSGs from blocked peers (subset of pending_trust_dropped from operator's view)"),
            # v0.8.5.7: cap-binding + cross-transport replay counters.
            # Each mirrors one of the audit event types introduced in
            # v0.8.5.6 so operators can alert on the underlying condition
            # via Prometheus without scraping the audit log.
            ("peer_cap_set_changed", "ironmesh_peer_cap_set_changed_total", "counter",
             "Peer auto-demoted to pending-cap-change because advertised capabilities differ from the pinned baseline"),
            ("peer_cap_baseline", "ironmesh_peer_cap_baseline_total", "counter",
             "First-time capability-set observations recorded as the baseline (TOFU-for-capabilities)"),
            ("peer_cap_accepted", "ironmesh_peer_cap_accepted_total", "counter",
             "Operator-accepted capability-set changes promoted to new baseline"),
            ("peer_cap_binding_partial", "ironmesh_peer_cap_binding_partial_total", "counter",
             "Cap-change detected but stash / demote did NOT fully persist (disk or lock error). Needs investigation"),
            ("msg_replay_cross_transport", "ironmesh_msg_replay_cross_transport_total", "counter",
             "Duplicate frame arrived on a different transport than the original (potential active replay across paths)"),
            ("peer_revoked_local", "ironmesh_peer_revoked_local_total", "counter",
             "Local operator revoked a pinned peer via CLI (no network-wide propagation)"),
            ("peer_state_changed", "ironmesh_peer_state_changed_total", "counter",
             "Trust-state transitions via operator CLI (covers states other than PROMOTED/BLOCKED)"),
            # v0.8.5.7: mirror the pre-existing PEER_PROMOTED /
            # PEER_BLOCKED audit events into Prometheus counters.
            ("peer_promoted", "ironmesh_peer_promoted_total", "counter",
             "Operator promoted a pending peer to trusted (drained any queued messages)"),
            ("peer_blocked", "ironmesh_peer_blocked_total", "counter",
             "Operator blocked a peer (local-only quiet block; distinct from signed REVOCATION)"),
        ]
        lines = []
        for key, name, kind, help_text in spec:
            if key not in m:
                continue
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {kind}")
            value = m[key]
            try:
                lines.append(f"{name} {float(value)}")
            except (TypeError, ValueError):
                lines.append(f"{name} 0")

        # v0.7.2: per-peer labelled metrics — essential for multi-hop mesh
        # observability. Wiz's hardening asks for per-hop RTT + retries +
        # message lifetime. These series use the peer node_id as a label.
        def _label(pid: str) -> str:
            # node_ids are 32-hex already safe for Prometheus label values
            return pid.replace('"', '')

        peer_rtt_lines = []
        peer_retry_lines = []
        peer_bytes_sent_lines = []
        peer_bytes_recv_lines = []
        peer_status_lines = []
        for pid, p in self.peers.items():
            label = _label(pid)
            agent = getattr(p, "agent_name", None) or ""
            status = 1 if p.is_online else 0
            peer_status_lines.append(
                f'ironmesh_peer_online{{peer="{label}",name="{agent}"}} {status}'
            )
            if p.latency_ms is not None:
                peer_rtt_lines.append(
                    f'ironmesh_peer_rtt_ms{{peer="{label}",name="{agent}"}} {float(p.latency_ms)}'
                )
            retries = getattr(p, "retries_total", 0)
            if retries:
                peer_retry_lines.append(
                    f'ironmesh_peer_retries_total{{peer="{label}",name="{agent}"}} {int(retries)}'
                )
            bs = getattr(p, "bytes_sent_total", 0)
            if bs:
                peer_bytes_sent_lines.append(
                    f'ironmesh_peer_bytes_sent_total{{peer="{label}",name="{agent}"}} {int(bs)}'
                )
            br = getattr(p, "bytes_received_total", 0)
            if br:
                peer_bytes_recv_lines.append(
                    f'ironmesh_peer_bytes_received_total{{peer="{label}",name="{agent}"}} {int(br)}'
                )

        if peer_status_lines:
            lines.append("# HELP ironmesh_peer_online Peer is currently online (1) or offline (0)")
            lines.append("# TYPE ironmesh_peer_online gauge")
            lines.extend(peer_status_lines)
        if peer_rtt_lines:
            lines.append("# HELP ironmesh_peer_rtt_ms Per-peer round-trip time in milliseconds from the last PING")
            lines.append("# TYPE ironmesh_peer_rtt_ms gauge")
            lines.extend(peer_rtt_lines)
        if peer_retry_lines:
            lines.append("# HELP ironmesh_peer_retries_total Per-peer retry attempts")
            lines.append("# TYPE ironmesh_peer_retries_total counter")
            lines.extend(peer_retry_lines)
        if peer_bytes_sent_lines:
            lines.append("# HELP ironmesh_peer_bytes_sent_total Per-peer application bytes sent")
            lines.append("# TYPE ironmesh_peer_bytes_sent_total counter")
            lines.extend(peer_bytes_sent_lines)
        if peer_bytes_recv_lines:
            lines.append("# HELP ironmesh_peer_bytes_received_total Per-peer application bytes received")
            lines.append("# TYPE ironmesh_peer_bytes_received_total counter")
            lines.extend(peer_bytes_recv_lines)

        # Message lifetime histogram — populated by a rolling sample of
        # (send_timestamp -> receive_now) deltas. Shows end-to-end latency
        # including routing + decryption + dispatch.
        lifetime_samples = list(getattr(self, "_lifetime_samples", ()))
        if lifetime_samples:
            lines.append("# HELP ironmesh_message_lifetime_seconds Observed end-to-end message latency")
            lines.append("# TYPE ironmesh_message_lifetime_seconds summary")
            sorted_lt = sorted(lifetime_samples)
            n = len(sorted_lt)
            for q, label in [(0.5, "0.5"), (0.9, "0.9"), (0.99, "0.99")]:
                idx = min(int(q * n), n - 1)
                lines.append(
                    f'ironmesh_message_lifetime_seconds{{quantile="{label}"}} {sorted_lt[idx]:.6f}'
                )
            lines.append(f"ironmesh_message_lifetime_seconds_count {n}")
            lines.append(f"ironmesh_message_lifetime_seconds_sum {sum(lifetime_samples):.6f}")

        return "\n".join(lines) + "\n"

    def _wants_prometheus(self, path: str) -> bool:
        """Decide whether the metrics request prefers Prometheus exposition.

        - Default is governed by ``self.config.metrics_format``.
        - A ``?format=json`` or ``?format=prometheus`` query string overrides.
        """
        default = getattr(self.config, "metrics_format", "prometheus") == "prometheus"
        if "format=json" in path:
            return False
        if "format=prometheus" in path:
            return True
        return default

    def _build_full_state(self) -> dict:
        """Build complete state snapshot for GUI clients."""
        # v0.8.3: surface the capability registry inverted (cap -> [node_ids])
        # so the dashboard's A2A filter and per-peer capability pills can
        # populate. Previously the GUI checked `state.capabilities` but the
        # backend never emitted it, so the filter silently matched nothing.
        caps_by_name: dict = {}
        if self._capabilities is not None:
            try:
                for node_id, caps in self._capabilities.all().items():
                    for cap in caps:
                        caps_by_name.setdefault(cap, []).append(node_id)
            except Exception:
                caps_by_name = {}
        # v0.8.5.2: enrich peers with their persisted trust_state so the
        # dashboard's PEERS table can show pending/trusted/blocked at a
        # glance instead of only in the separate PENDING TRUST subpanel.
        trust_state_by_peer: dict = {}
        try:
            from ironmesh.trust import TrustStore
            if self._keypair:
                ts = TrustStore(
                    agent_key=self._keypair.ed25519_secret[:32],
                    path=self.trust_path,
                )
                for rec in ts.list_peers():
                    trust_state_by_peer[rec["node_id"]] = rec.get(
                        "trust_state", "trusted",
                    )
        except Exception:
            pass  # GUI degrades gracefully if the trust file is unreadable
        peer_dicts = []
        for p in self.peers.values():
            d = p.to_dict()
            ts = trust_state_by_peer.get(d.get("node_id"))
            if ts is not None:
                d["trust_gate_state"] = ts
            peer_dicts.append(d)
        return {
            "node_id": self.node_id,
            "name": self.name,
            "port": self.port,
            "metrics": self._build_metrics_dict(),
            "peers": peer_dicts,
            "history": self.bus.history(50),
            "capabilities": caps_by_name,
        }

    async def _gui_broadcast(self, msg: dict):
        """Push a JSON message to all connected GUI WebSocket clients."""
        if not self._gui_clients:
            return
        raw = json.dumps(msg, default=str)
        closed = []
        for client in list(self._gui_clients):
            try:
                await client.send(raw)
            except Exception:
                closed.append(client)
        for c in closed:
            self._gui_clients.discard(c)

    async def _gui_state_loop(self):
        """Push full state to all GUI clients every 2 seconds."""
        while self._running:
            await asyncio.sleep(2)
            if self._gui_clients:
                await self._gui_broadcast({
                    "type": "state_update",
                    "data": self._build_full_state(),
                })

    def _wire_gui_hooks(self):
        """Hook into bus events and peer lifecycle to push to GUI clients."""
        def on_bus_event(event_type, data):
            # MessageBus.publish wraps dict payloads in MappingProxyType for
            # immutability, and MappingProxyType is NOT a dict subclass --
            # ``isinstance(data, dict)`` returned False and every GUI event
            # was broadcast with empty peer_id + payload. Use the Mapping ABC
            # instead so both dicts and proxies are accepted.
            from collections.abc import Mapping
            safe = {}
            if isinstance(data, Mapping):
                for k, v in data.items():
                    if isinstance(v, bytes):
                        safe[k] = v.decode("utf-8", errors="replace")
                    else:
                        safe[k] = v
            msg = {
                "type": "message_event",
                "msg_type": event_type,
                "peer_id": safe.get("peer_id", ""),
                "msg_id": safe.get("msg_id", ""),
                "payload": safe.get("payload", ""),
                "timestamp": time.time(),
            }
            if self._gui_clients:
                asyncio.ensure_future(self._gui_broadcast(msg))
        self.bus.on_any(on_bus_event)

        if self._hooks:
            async def on_peer_connect(ctx):
                await self._gui_broadcast({
                    "type": "peer_event",
                    "event": "connected",
                    "peer_id": ctx.get("peer_id", ""),
                    "timestamp": time.time(),
                })
            async def on_peer_disconnect(ctx):
                await self._gui_broadcast({
                    "type": "peer_event",
                    "event": "disconnected",
                    "peer_id": ctx.get("peer_id", ""),
                    "timestamp": time.time(),
                })
            self._hooks.register("on_peer_connect", on_peer_connect)
            self._hooks.register("on_peer_disconnect", on_peer_disconnect)

    def _check_gui_token(self, request) -> bool:
        """Check if the request has a valid GUI token via query param or Authorization header.

        v0.8.5.2: uses constant-time comparison (``hmac.compare_digest``) to
        prevent timing side-channel recovery of the token over the network.
        """
        import hmac as _hmac
        expected = self._gui_token
        # Check ?token= query parameter
        path_str = request.path if hasattr(request, "path") else str(request)
        if "?" in path_str:
            query = path_str.split("?", 1)[1]
            for part in query.split("&"):
                if part.startswith("token="):
                    if _hmac.compare_digest(part[6:], expected):
                        return True
        # Check Authorization: Bearer header
        req_headers = getattr(request, "headers", None)
        if req_headers:
            auth = None
            if hasattr(req_headers, "get"):
                auth = req_headers.get("Authorization") or req_headers.get("authorization")
            if auth and auth.startswith("Bearer "):
                if _hmac.compare_digest(auth[7:], expected):
                    return True
        return False

    async def _gui_process_request(self, connection, request):
        """Route HTTP requests: serve dashboard, metrics JSON, or allow WS upgrade."""
        import websockets.http11

        path = request.path if hasattr(request, "path") else str(request)
        # Strip query string for route matching
        clean_path = path.split("?")[0] if "?" in path else path

        if clean_path == "/ws":
            # Require token for WebSocket upgrade.
            if not self._check_gui_token(request):
                body = b"401 Unauthorized - token required"
                headers = websockets.Headers()
                headers["Content-Type"] = "text/plain"
                headers["Content-Length"] = str(len(body))
                return websockets.http11.Response(401, "Unauthorized", headers, body)
            return None  # Allow WebSocket upgrade

        headers = websockets.Headers()

        if clean_path == "/" or clean_path == "/index.html":
            # Serve HTML without auth — the HTML itself is not sensitive
            from ironmesh import __version__ as _imv
            body = GUI_HTML.replace("{{IRONMESH_VERSION}}", f"v{_imv}").encode()
            headers["Content-Type"] = "text/html; charset=utf-8"
            headers["Content-Length"] = str(len(body))
            return websockets.http11.Response(200, "OK", headers, body)

        # v0.7: PWA manifest for install-to-homescreen support
        if clean_path == "/manifest.json":
            manifest = {
                "name": f"IronMesh — {self.name}",
                "short_name": "IronMesh",
                "start_url": "/",
                "display": "standalone",
                "orientation": "any",
                "background_color": "#0d1117",
                "theme_color": "#0d1117",
                "description": "Encrypted agent-to-agent mesh dashboard",
                "icons": [
                    {
                        "src": "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 192 192'%3E%3Crect width='192' height='192' fill='%230d1117'/%3E%3Ctext x='96' y='120' font-size='100' text-anchor='middle' fill='%233fb950' font-family='monospace'%3E%E2%9F%90%3C/text%3E%3C/svg%3E",
                        "sizes": "192x192",
                        "type": "image/svg+xml",
                    }
                ],
            }
            body = json.dumps(manifest).encode()
            headers["Content-Type"] = "application/manifest+json"
            headers["Content-Length"] = str(len(body))
            return websockets.http11.Response(200, "OK", headers, body)

        # All data endpoints require token.
        if clean_path in ("/metrics", "/api/state", "/api/mesh_stats"):
            if not self._check_gui_token(request):
                body = b"401 Unauthorized - token required"
                headers["Content-Type"] = "text/plain"
                headers["Content-Length"] = str(len(body))
                return websockets.http11.Response(401, "Unauthorized", headers, body)

        if clean_path == "/metrics":
            metrics_dict = self._build_metrics_dict()
            if self._wants_prometheus(path):
                body = self._format_metrics_prometheus(metrics_dict).encode()
                headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
            else:
                body = json.dumps(metrics_dict, indent=2).encode()
                headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
            return websockets.http11.Response(200, "OK", headers, body)

        if clean_path == "/api/state":
            body = json.dumps(self._build_full_state(), indent=2, default=str).encode()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
            return websockets.http11.Response(200, "OK", headers, body)

        if clean_path == "/api/mesh_stats":
            # v0.7.2: compact, machine-friendly snapshot optimised for
            # harness/dashboard polling. Stable schema over releases.
            body = json.dumps(self._build_mesh_stats(), default=str).encode()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
            return websockets.http11.Response(200, "OK", headers, body)

        body = b"404 Not Found"
        headers["Content-Type"] = "text/plain"
        headers["Content-Length"] = str(len(body))
        return websockets.http11.Response(404, "Not Found", headers, body)

    async def _gui_ws_handler(self, websocket):
        """Handle a GUI WebSocket connection: send snapshot, then listen for commands."""
        self._gui_clients.add(websocket)
        try:
            # Send initial snapshot
            await websocket.send(json.dumps({
                "type": "snapshot",
                "data": self._build_full_state(),
            }, default=str))

            async for raw in websocket:
                try:
                    cmd = json.loads(raw)
                    await self._handle_gui_command(cmd, websocket)
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({
                        "type": "send_error", "error": "Invalid JSON",
                    }))
                except Exception as e:
                    await websocket.send(json.dumps({
                        "type": "send_error", "error": str(e),
                    }))
        except websockets.ConnectionClosed:
            pass
        finally:
            self._gui_clients.discard(websocket)

    async def _handle_gui_command(self, cmd: dict, websocket):
        """Process a command from the GUI WebSocket client."""
        action = cmd.get("action")

        if action == "send_message":
            to_node = cmd.get("to_node")
            msg_type = cmd.get("msg_type", "MSG")
            payload = cmd.get("payload", "")
            if not to_node:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "to_node required",
                }))
                return
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            try:
                msg_id = await self.send_message(to_node, msg_type, payload)
                await websocket.send(json.dumps({
                    "type": "send_ack", "msg_id": msg_id,
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": str(e),
                }))

        elif action == "get_history":
            # v0.8.5.6: clamp `limit` to a sane upper bound.
            # Pre-fix, an authenticated GUI client could request
            # `limit=10**9` and force the daemon into a multi-GB SQL
            # SELECT that drove the process to OOM. 5000 is well above
            # any UI's actual paging needs and bounds peak memory at
            # a few MB worth of message rows.
            peer_id = cmd.get("peer_id")
            if peer_id is not None and not isinstance(peer_id, str):
                await websocket.send(json.dumps({
                    "type": "send_error",
                    "error": "peer_id must be a string",
                }))
                return
            try:
                limit = int(cmd.get("limit", 50))
            except (TypeError, ValueError):
                limit = 50
            limit = max(1, min(limit, 5000))
            try:
                messages = await self._db.get_messages(peer_id=peer_id, limit=limit)
                await websocket.send(json.dumps({
                    "type": "history",
                    "messages": messages,
                }, default=str))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": str(e),
                }))

        elif action == "refresh":
            await websocket.send(json.dumps({
                "type": "snapshot",
                "data": self._build_full_state(),
            }, default=str))

        elif action == "broadcast_revocation":
            target = cmd.get("target_node_id")
            reason = cmd.get("reason", "")
            if not target:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "target_node_id required",
                }))
                return
            try:
                await self.broadcast_revocation(target, reason)
                await websocket.send(json.dumps({
                    "type": "revoke_ack", "target": target,
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"Revocation failed: {e}",
                }))

        elif action == "list_pending_trust":
            try:
                pending = await self.list_pending_trust()
                await websocket.send(json.dumps({
                    "type": "pending_trust_list",
                    "pending": pending,
                    "gate_enabled": bool(self.config.require_message_promotion),
                }, default=str))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"list_pending_trust failed: {e}",
                }))

        elif action == "promote_peer":
            target = cmd.get("target_node_id")
            if not target:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "target_node_id required",
                }))
                return
            try:
                result = await self.promote_pending_peer(target)
                await websocket.send(json.dumps({
                    "type": "promote_ack", "target": target, **result,
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"promote failed: {e}",
                }))

        elif action == "block_peer":
            target = cmd.get("target_node_id")
            if not target:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "target_node_id required",
                }))
                return
            try:
                result = await self.block_pending_peer(target)
                await websocket.send(json.dumps({
                    "type": "block_ack", "target": target, **result,
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"block failed: {e}",
                }))

        elif action == "list_pending_cap":
            # v0.8.5.7: dashboard surface for the v0.8.5.6 cap-binding
            # feature. Returns one entry per peer whose currently-
            # announced capability set differs from the baseline.
            try:
                ts = self._open_trust_store()
                if ts is None:
                    await websocket.send(json.dumps({
                        "type": "pending_cap_list", "pending": [],
                    }))
                    return
                rows = []
                for r in ts.list_by_capability_status("pending-cap-change"):
                    baseline = set(r.get("capability_set") or [])
                    pending = set(r.get("pending_set") or [])
                    rows.append({
                        "node_id": r["node_id"],
                        "baseline_hash": r.get("capability_hash"),
                        "pending_hash": r.get("pending_hash"),
                        "baseline_set": sorted(baseline),
                        "pending_set": sorted(pending),
                        "added": sorted(pending - baseline),
                        "removed": sorted(baseline - pending),
                    })
                await websocket.send(json.dumps({
                    "type": "pending_cap_list", "pending": rows,
                }, default=str))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error",
                    "error": f"list_pending_cap failed: {e}",
                }))

        elif action == "cap_promote_peer":
            target = cmd.get("target_node_id")
            if not target:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "target_node_id required",
                }))
                return
            try:
                result = await self.accept_pending_cap_change(target)
                await websocket.send(json.dumps({
                    "type": "cap_promote_ack",
                    "node_id": target,
                    **(result or {}),
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error",
                    "error": f"cap_promote_peer failed: {e}",
                }))

        elif action == "rotate_session":
            peer_id = cmd.get("peer_id")
            if not peer_id:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": "peer_id required",
                }))
                return
            state = self.peers.get(peer_id)
            if not state or not state.is_online:
                await websocket.send(json.dumps({
                    "type": "send_error",
                    "error": f"Peer {peer_id} not online",
                }))
                return
            if not _peer_supports_rekey(state.protocol_version):
                await websocket.send(json.dumps({
                    "type": "send_error",
                    "error": f"Peer protocol {state.protocol_version} does not support rekey",
                }))
                return
            try:
                await self._initiate_rekey(peer_id)
                await websocket.send(json.dumps({
                    "type": "rotate_ack", "peer_id": peer_id,
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"Rekey failed: {e}",
                }))

        elif action == "start_dialogue":
            # v0.8.2: in-process orchestrator for AI-to-AI dialogue.
            # Accepts {peer_a, peer_b, seed, max_turns?, budget_seconds?,
            # budget_bytes?} where peer_a and peer_b are node_ids. Spawns
            # a background task that shuttles CONV frames between the two
            # peers and streams transcript events back via the existing
            # gui broadcast path (type="dialogue_event").
            try:
                await self._spawn_dialogue(cmd, websocket)
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "send_error", "error": f"Dialogue failed: {e}",
                }))

        else:
            await websocket.send(json.dumps({
                "type": "send_error", "error": f"Unknown action: {action}",
            }))

    async def _spawn_dialogue(self, cmd: dict, websocket) -> None:
        """Run a bounded AI-to-AI dialogue between two mesh peers.

        Sends the seed to peer_a as turn 0 via a CONV frame, then
        shuttles each response to the other peer until we see an end
        frame, hit the turn cap, or time out.
        """
        import uuid as _uuid

        from ironmesh.conversation import (
            KIND_PROMPT as _KP,
            Budget as _Budget,
            ConvEnvelope as _CE,
        )

        peer_a = cmd.get("peer_a")
        peer_b = cmd.get("peer_b")
        seed = cmd.get("seed") or ""
        max_turns = int(cmd.get("max_turns", 4))
        turn_timeout = float(cmd.get("turn_timeout", 120.0))
        budget_seconds = cmd.get("budget_seconds")
        budget_bytes = cmd.get("budget_bytes")
        if not peer_a or not peer_b:
            raise ValueError("peer_a and peer_b required")
        if peer_a not in self.peers or peer_b not in self.peers:
            raise ValueError("one or both peers not in peer table")

        conv_id = _uuid.uuid4().hex[:12]
        budget = None
        if budget_seconds is not None or budget_bytes is not None:
            budget = _Budget(
                max_seconds=(float(budget_seconds)
                             if budget_seconds is not None else None),
                max_bytes=(int(budget_bytes)
                           if budget_bytes is not None else None),
            )

        def _name_of(pid: str) -> str:
            state = self.peers.get(pid)
            return getattr(state, "agent_name", None) or pid[:12]

        async def emit(payload: dict) -> None:
            await websocket.send(json.dumps({
                "type": "dialogue_event",
                "conv_id": conv_id,
                **payload,
            }, default=str))

        # Queue incoming CONV envelopes for THIS conversation only.
        q: asyncio.Queue = asyncio.Queue()
        from ironmesh.conversation import ConvEnvelope as _CE_cls

        def _on_conv_event(event_type, data):
            if event_type != "CONV":
                return
            pid = data.get("peer_id", "") if hasattr(data, "get") else ""
            pl = data.get("payload", b"") if hasattr(data, "get") else b""
            if isinstance(pl, str):
                pl = pl.encode("utf-8")
            try:
                env = _CE_cls.decode(pl)
            except Exception:
                return
            if env.conv_id != conv_id:
                return
            q.put_nowait((pid, env))

        self.bus.on_any(_on_conv_event)

        try:
            await emit({
                "event": "started",
                "peer_a": peer_a, "peer_b": peer_b,
                "max_turns": max_turns, "seed": seed,
            })

            # Turn 0: send seed to peer_a.
            first_env = _CE(
                conv_id=conv_id, turn=0, max_turns=max_turns,
                kind=_KP, body=seed,
                from_role="orchestrator", to_role=_name_of(peer_a),
                budget=budget,
            )
            await self.send_message(peer_a, "CONV", first_env.encode())
            await emit({"event": "turn", "turn": 0,
                        "speaker": "ORCHESTRATOR", "body": seed})

            current = peer_a
            other = peer_b
            while True:
                try:
                    pid, env = await asyncio.wait_for(q.get(), timeout=turn_timeout)
                except asyncio.TimeoutError:
                    await emit({"event": "timeout",
                                "waiting_on": _name_of(current),
                                "timeout": turn_timeout})
                    break

                if env.kind in ("end", "error"):
                    await emit({
                        "event": env.kind,
                        "speaker": _name_of(pid),
                        "reason": env.end_reason or env.body,
                    })
                    break

                await emit({
                    "event": "turn", "turn": env.turn,
                    "speaker": _name_of(pid), "body": env.body,
                })

                if env.turn >= max_turns:
                    await emit({"event": "turn_cap_reached", "cap": max_turns})
                    break

                # Relay to the other peer, carrying the same turn.
                current, other = other, current
                next_env = _CE(
                    conv_id=conv_id, turn=env.turn, max_turns=max_turns,
                    kind=_KP, body=env.body,
                    from_role=_name_of(pid), to_role=_name_of(current),
                    budget=budget,
                )
                await self.send_message(current, "CONV", next_env.encode())
        finally:
            # Detach the listener. MessageBus has no explicit off_any API
            # for catch-alls; accept the small per-conversation overhead
            # and just leave a no-op closure behind. Trim the list to
            # avoid growth on long-running processes.
            try:
                self.bus._catch_all.remove(_on_conv_event)
            except ValueError:
                pass
            await emit({"event": "finished"})

    async def _start_gui_server(self):
        """Start the GUI WebSocket+HTTP server on port+1.

        Bind address comes from `self.gui_bind` (default 127.0.0.1).
        Setting it to a non-loopback value emits a loud warning at
        startup because exposing the dashboard directly to a network
        bypasses any reverse-proxy hardening (TLS, rate limits, ACLs).
        See docs/REVERSE_PROXY.md.
        """
        gui_port = self.port + 1
        bind = self.gui_bind
        is_loopback = bind in ("127.0.0.1", "::1", "localhost")
        if not is_loopback:
            logger.warning(
                "INSECURE BIND: GUI dashboard configured to bind %s:%d "
                "(non-loopback). The dashboard's only auth is a bearer "
                "token; without TLS in front of it (reverse proxy or "
                "--tls-cert / --tls-key), the token can be sniffed on "
                "the wire. See docs/REVERSE_PROXY.md for the recommended "
                "deployment pattern.",
                bind, gui_port,
            )
        try:
            self._gui_server = await websockets.serve(
                self._gui_ws_handler,
                bind,
                gui_port,
                process_request=self._gui_process_request,
            )
            logger.info(
                "GUI dashboard at http://%s:%d/ (metrics at /metrics?token=%s)",
                bind, gui_port, self._gui_token,
            )
        except Exception as e:
            logger.warning("GUI server failed to start on port %d: %s", gui_port, e)

    # ------------------------------------------------------------------
    # Metrics HTTP endpoint (fallback when GUI disabled)
    # ------------------------------------------------------------------

    async def _metrics_server(self):
        """Simple HTTP server for metrics endpoint."""
        try:
            async def handle_metrics(reader, writer):
                raw_request = await reader.read(4096)
                # Parse first line for method + path.
                request_line = raw_request.split(b"\r\n")[0].decode("ascii", errors="replace")
                parts = request_line.split()
                path = parts[1] if len(parts) >= 2 else "/"
                clean_path = path.split("?")[0] if "?" in path else path

                if clean_path != "/metrics":
                    body = "404 Not Found"
                    response = (
                        f"HTTP/1.1 404 Not Found\r\n"
                        f"Content-Type: text/plain\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                        f"{body}"
                    )
                    writer.write(response.encode())
                    await writer.drain()
                    writer.close()
                    return

                metrics_data = self._build_metrics_dict()
                if self._wants_prometheus(path):
                    body = self._format_metrics_prometheus(metrics_data)
                    content_type = "text/plain; version=0.0.4; charset=utf-8"
                else:
                    body = json.dumps(metrics_data, indent=2)
                    content_type = "application/json"
                response = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                    f"{body}"
                )
                writer.write(response.encode())
                await writer.drain()
                writer.close()

            metrics_port = self.port + 1
            # Server is kept alive by the asyncio task that handles it; we
            # don't need to hold a reference for lifecycle purposes (shutdown
            # is handled by cancelling the enclosing loop).
            await asyncio.start_server(handle_metrics, "127.0.0.1", metrics_port)
            logger.info("Metrics endpoint at http://127.0.0.1:%d/metrics", metrics_port)
        except Exception as e:
            logger.debug("Metrics server failed to start: %s", e)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    async def shutdown(self):
        """Graceful shutdown."""
        self._running = False

        # Close GUI server and clients
        for client in list(self._gui_clients):
            try:
                await client.close()
            except Exception:
                pass
        self._gui_clients.clear()
        if self._gui_server:
            self._gui_server.close()
            await self._gui_server.wait_closed()

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

        # v0.5: Reticulum transport shutdown
        if self._reticulum:
            try:
                self._reticulum.shutdown()
            except Exception:
                pass

        if self._mdns_listener:
            try:
                self._mdns_listener.stop()
            except Exception:
                pass
        if self._mdns_service:
            try:
                self._mdns_service.close()
            except Exception:
                pass

        if self._server:
            self._server.close()
            await self._server.wait_closed()

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

        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: asyncio.ensure_future(self.shutdown()))
        except NotImplementedError:
            pass  # Windows

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
