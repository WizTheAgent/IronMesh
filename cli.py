#!/usr/bin/env python3
"""IronMesh CLI — Command-line entry point for the bridge daemon.

Supports bridge daemon, key management, trust management, and metrics.
"""

import argparse
import getpass
import hashlib
import logging
import os
import sys
import time
from typing import Optional


def _parse_admin_identities(raw):
    """Split a comma-separated identity-hash list into a normalised list.

    Empty / None input returns []. Each entry is lowercased and stripped
    of common separators (colons, spaces). Per-entry validation happens
    in ReticulumTransport — bad entries silently fail the admin check
    rather than crashing startup.
    """
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def parse_args():
    parser = argparse.ArgumentParser(
        description="IronMesh — Zero-config encrypted A2A protocol",
        epilog="Example: ironmesh --name alice --port 8765 --passphrase secret123",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # --- run (default) ---
    run_parser = sub.add_parser("run", help="Start the bridge daemon")
    run_parser.add_argument("--name", required=True, help="Agent name (e.g. alice, bob)")
    run_parser.add_argument("--port", type=int, default=8765, help="WebSocket port (default: 8765)")
    run_parser.add_argument(
        "--profile", default=None,
        choices=["secure", "dev", "offline"],
        help=(
            "Bundled flag preset. 'secure' = production hardening "
            "(pending-trust gate on, no plaintext-ws fallback, mDNS "
            "default-deny). 'dev' = same-machine localhost shortcuts "
            "(open discovery, plaintext ws — INSECURE). 'offline' = "
            "Reticulum/LoRa transport only, mDNS off. Explicit flags "
            "override the profile but emit a warning."
        ),
    )
    # --passphrase REMOVED from run parser — leaks in process list (ps aux).
    # Use --passphrase-file, IRONMESH_PASSPHRASE_FILE, or interactive getpass.
    run_parser.add_argument("--keys-path", default="~/.ironmesh/keys.json")
    run_parser.add_argument("--keys-passphrase", default=None, help="Passphrase to decrypt key file")
    run_parser.add_argument("--db-path", default="~/.ironmesh/data.db")
    run_parser.add_argument("--tls-cert", default=None, help="TLS certificate file for WSS")
    run_parser.add_argument("--tls-key", default=None, help="TLS private key file for WSS")
    run_parser.add_argument("--log-level", default="INFO",
                           choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    run_parser.add_argument("--log-file", default=None, help="Log to file instead of stderr")
    run_parser.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    run_parser.add_argument("--rotate-keys", action="store_true", help="Rotate keys before starting")
    run_parser.add_argument("--gui", action="store_true", help="Enable web GUI dashboard on port+1 (off by default)")
    run_parser.add_argument(
        "--gui-bind", default="127.0.0.1",
        help="Bind address for the GUI dashboard (default: 127.0.0.1, "
             "loopback only). Set to 0.0.0.0 to expose to a LAN or to a "
             "reverse proxy on a different host. INSECURE if not behind "
             "TLS — see docs/REVERSE_PROXY.md.",
    )
    run_parser.add_argument("--no-gui", action="store_true", help=argparse.SUPPRESS)  # Legacy compat
    run_parser.add_argument("--allowed-peers", default=None,
                           help="Comma-separated list of allowed mDNS peer names (allowlist)")
    run_parser.add_argument("--passphrase-file", default=None,
                           help="Read passphrase from file (preferred over env var)")
    run_parser.add_argument("--open-discovery", action="store_true",
                           help="Allow mDNS auto-connect to any peer (insecure, default: deny)")
    run_parser.add_argument("--allow-plaintext-ws", action="store_true",
                           help="Allow plaintext ws:// connections (insecure, default: try wss first)")
    # v0.4: mesh routing
    run_parser.add_argument("--mesh-routing", default="relay",
                           choices=["off", "passive", "relay"],
                           help="Mesh routing mode: off=no routing, passive=learn but don't relay, "
                                "relay=full participation (default: relay)")
    run_parser.add_argument("--max-hops", type=int, default=5,
                           help="Maximum hop count for relayed messages (default: 5)")
    run_parser.add_argument("--route-announce-interval", type=float, default=30.0,
                           help="Seconds between routing-table broadcasts (default: 30)")
    run_parser.add_argument("--route-ttl", type=float, default=90.0,
                           help="Seconds before learned routes expire (default: 90)")
    run_parser.add_argument("--routes-path", default="~/.ironmesh/routes.json",
                           help="Persistent routes file (HMAC-protected)")
    # v0.4: capabilities
    run_parser.add_argument("--capability", action="append", default=[],
                           help="Declare a capability this node provides (repeatable, e.g. llm:llama3)")
    run_parser.add_argument("--capabilities-path", default="~/.ironmesh/capabilities.json",
                           help="Persistent capability registry path")
    run_parser.add_argument("--capability-announce-interval", type=float, default=60.0,
                           help="Seconds between capability gossip announcements (default: 60)")
    # v0.5: Reticulum (LoRa) transport
    run_parser.add_argument("--reticulum", action="store_true",
                           help="Enable Reticulum transport (requires rns package)")
    run_parser.add_argument("--rns-configdir", default=os.path.expanduser("~/.reticulum"),
                           help="Reticulum config directory (default: ~/.reticulum)")
    run_parser.add_argument("--rns-announce-interval", type=float, default=300.0,
                           help="Seconds between RNS announces (default: 300)")
    run_parser.add_argument("--rns-connect", default=None,
                           help="Comma-separated RNS destination hashes to connect on startup")
    run_parser.add_argument("--rns-no-ratchets", action="store_true",
                           help="Disable per-packet ratchets on the RNS destination "
                                "(default: ratchets on; only disable for old-RNS interop)")
    run_parser.add_argument("--rns-ratchet-interval", type=float, default=1800.0,
                           help="Seconds between ratchet key rotations (default: 1800)")
    run_parser.add_argument("--rns-retained-ratchets", type=int, default=8,
                           help="Number of past ratchet keys retained for in-flight packets (default: 8)")
    run_parser.add_argument("--rns-admin-identities", default=None,
                           help="Comma-separated RNS identity hashes (hex) permitted "
                                "to call /im/admin/* RPC paths. Empty = admin RPC "
                                "disabled. Override via IRONMESH_RNS_ADMIN_IDENTITIES env var.")
    run_parser.add_argument("--rns-skip-handshake", action="store_true",
                           help="Skip the IronMesh stage-1 handshake (passphrase "
                                "challenge/verify) on RNS Links where both peers "
                                "advertise the `hskip` feature. Saves three round-"
                                "trips on LoRa. Identity authentication is provided "
                                "by the RNS Link itself. Default: off.")
    # v0.9.1: LXMF interop (Sideband / Nomadnet)
    run_parser.add_argument("--lxmf", action="store_true",
                           help="Enable the LXMF delivery identity listener "
                                "(requires the lxmf extra). Lets Sideband and "
                                "Nomadnet users message this node.")
    run_parser.add_argument("--lxmf-storage", default="~/.ironmesh/lxmf",
                           help="LXMF identity + message storage path "
                                "(default: ~/.ironmesh/lxmf)")
    run_parser.add_argument("--lxmf-display-name", default="IronMesh",
                           help="Display name shown to other LXMF users (default: IronMesh)")
    run_parser.add_argument("--lxmf-default-peer", default=None,
                           help="IronMesh peer_id to forward unmapped inbound LXMF "
                                "messages to. Without this, unmapped messages are dropped.")
    run_parser.add_argument("--lxmf-propagation-node", action="store_true",
                           help="Also run as an LXMF propagation node — store-and-forward "
                                "infrastructure for offline LXMF peers. Recommended only "
                                "for always-on hosts with persistent storage.")
    run_parser.add_argument("--lxmf-propagation-storage", default="~/.ironmesh/lxmf/propagation",
                           help="Storage path for the propagation node "
                                "(default: ~/.ironmesh/lxmf/propagation)")
    run_parser.add_argument("--lxmf-telemetry-target", default=None,
                           help="LXMF destination hash to receive periodic "
                                "metrics summaries as LXMessages. Any LXMF "
                                "client (Sideband, Nomadnet) can render the "
                                "plain-text body. Leave unset to disable.")
    run_parser.add_argument("--lxmf-telemetry-interval", type=float, default=300.0,
                           help="Seconds between telemetry publishes (default: 300)")
    run_parser.add_argument("--lora-max-payload", type=int, default=128,
                           help="Max payload bytes for RNS/LoRa transport (default: 128, 0 to disable)")
    run_parser.add_argument("--rekey-interval", type=float, default=1800.0,
                           help="Session key rotation interval in seconds (default: 1800, 0 to disable)")
    run_parser.add_argument("--min-protocol-version", default="ironmesh/0.3",
                           help="Reject peers below this protocol version (default: ironmesh/0.3)")

    # v0.4: observability
    run_parser.add_argument("--metrics-format", default="prometheus",
                           choices=["prometheus", "json"],
                           help="Metrics exposition format (default: prometheus)")
    run_parser.add_argument("--log-format", default="text",
                           choices=["text", "json"],
                           help="Log output format (default: text)")

    # v0.8.5: pending-trust message gate (opt-in)
    run_parser.add_argument("--require-message-promotion", action="store_true",
                            help="Hold MSGs from new TOFU-pinned peers in a "
                                 "pending queue until an operator promotes them. "
                                 "Default off — preserves pre-v0.8.5 behavior. "
                                 "Recommended on for OpenClaw deployments.")
    run_parser.add_argument("--pending-trust-queue-cap", type=int, default=100,
                            help="Per-peer cap on the pending-trust queue. "
                                 "Oldest message is evicted on overflow. "
                                 "Default: 100.")
    run_parser.add_argument("--trust-path", default=None,
                            help="Override the trust store JSON path. "
                                 "Defaults to ~/.ironmesh/known_peers.json. "
                                 "Set explicitly when running multiple "
                                 "daemons on one host.")

    # --- trust ---
    trust_parser = sub.add_parser("trust", help="Manage peer trust (TOFU)")
    trust_parser.add_argument("--keys-path", default="~/.ironmesh/keys.json",
                              help="Identity keys file (needed for trust store MAC)")
    trust_parser.add_argument("--keys-passphrase", default=None,
                              help="Passphrase to decrypt identity keys")
    trust_parser.add_argument("--trust-path", default=None,
                              help="Override trust store path (default ~/.ironmesh/known_peers.json). "
                                   "Use when targeting a non-default daemon's trust file.")
    trust_parser.add_argument("--audit-path", default=None,
                              help="Override audit log path. If unset and --trust-path is "
                                   "provided, derives <trust-path-dir>/audit.log so trust "
                                   "mutations land in the daemon's audit log (where the "
                                   "daemon's counter-sync loop can pick them up). Falls "
                                   "back to ~/.ironmesh/audit.log otherwise.")
    trust_sub = trust_parser.add_subparsers(dest="trust_command")
    list_parser = trust_sub.add_parser("list", help="List trusted peers")
    list_parser.add_argument("--show-caps", action="store_true",
                             help="Include the capability-binding "
                                  "column (baseline / pending / unknown)")
    revoke_parser = trust_sub.add_parser("revoke", help="Revoke trust for a peer")
    revoke_parser.add_argument("node_id", help="Node ID to revoke")
    revoke_parser.add_argument("--broadcast", action="store_true",
                               help="Also broadcast a signed REVOCATION to online peers")
    revoke_parser.add_argument("--reason", default="",
                               help="Reason for revocation")
    revoke_parser.add_argument("--gui-url", default="ws://127.0.0.1:8767/ws",
                               help="Local bridge GUI WS URL (for --broadcast)")
    revoke_parser.add_argument("--token", default=None,
                               help="GUI token (required for --broadcast)")
    trust_sub.add_parser("list-revoked", help="List revoked peers")

    # v0.8.5.2: trust state mutation (matches the v0.8.5 trust gate states).
    set_state_parser = trust_sub.add_parser(
        "set-state",
        help="Flip a peer's trust state (pending|trusted|blocked|pending-cap-change)",
    )
    set_state_parser.add_argument("node_id", help="Node ID to update")
    set_state_parser.add_argument("state",
                                   choices=["pending", "trusted", "blocked",
                                            "pending-cap-change"],
                                   help="New trust state")

    # v0.8.5.6: capability-set binding operator surface.
    cap_promote = trust_sub.add_parser(
        "cap-promote",
        help="Accept a peer's pending capability-set change and re-promote "
             "to trusted. See docs/TRUST_BINDING.md.",
    )
    cap_promote.add_argument("node_id", nargs="?", default=None,
                             help="Node ID to re-promote (omit with --all)")
    cap_promote.add_argument("--all", action="store_true",
                             help="Re-promote every peer currently in "
                                  "pending-cap-change state")
    cap_promote.add_argument("--trust-path", default=None,
                             help="Override the trust store path "
                                  "(default: ~/.ironmesh/known_peers.json)")
    cap_promote.add_argument("--keys-path", default="~/.ironmesh/keys.json",
                             help="Path to identity keypair (needed to MAC the "
                                  "trust store)")

    list_cap = trust_sub.add_parser(
        "list-cap-pending",
        help="List peers currently in pending-cap-change with the diff "
             "from their accepted baseline",
    )
    list_cap.add_argument("--trust-path", default=None,
                          help="Override the trust store path")
    list_cap.add_argument("--keys-path", default="~/.ironmesh/keys.json")
    list_cap.add_argument("--json", action="store_true",
                          help="Emit JSON instead of human-readable text")

    cap_diff = trust_sub.add_parser(
        "cap-diff",
        help="Show the capability-set diff for a peer "
             "(baseline vs pending or current)",
    )
    cap_diff.add_argument("node_id", help="Node ID to inspect")
    cap_diff.add_argument("--trust-path", default=None)
    cap_diff.add_argument("--keys-path", default="~/.ironmesh/keys.json")

    # v0.8.5.7: operator surface completion.
    cap_reject = trust_sub.add_parser(
        "cap-reject",
        help="Reject a peer's pending capability-set change; keep the "
             "existing baseline and (optionally) block the peer.",
    )
    cap_reject.add_argument("node_id", nargs="?", default=None,
                            help="Node ID to reject (omit with --all)")
    cap_reject.add_argument("--all", action="store_true",
                            help="Reject every peer currently in "
                                 "pending-cap-change state")
    cap_reject.add_argument("--block", action="store_true",
                            help="Also flip trust_state to 'blocked' "
                                 "so future messages from this peer are "
                                 "silently dropped at the gate")
    cap_reject.add_argument("--trust-path", default=None)
    cap_reject.add_argument("--keys-path", default="~/.ironmesh/keys.json")

    cap_status = trust_sub.add_parser(
        "cap-status",
        help="Detailed capability-binding status for a single peer "
             "(baseline hash, pending hash, accepted_at, last_seen).",
    )
    cap_status.add_argument("node_id", help="Node ID to inspect")
    cap_status.add_argument("--trust-path", default=None)
    cap_status.add_argument("--keys-path", default="~/.ironmesh/keys.json")
    cap_status.add_argument("--json", action="store_true",
                            help="Emit JSON instead of human-readable text")

    # --- keys ---
    keys_parser = sub.add_parser("keys", help="Key management")
    keys_sub = keys_parser.add_subparsers(dest="keys_command")
    gen_parser = keys_sub.add_parser("generate", help="Generate new keypair")
    gen_parser.add_argument("--path", default="~/.ironmesh/keys.json")
    gen_parser.add_argument("--passphrase", default=None, help="Encrypt key file with passphrase")
    info_parser = keys_sub.add_parser("info", help="Show key info")
    info_parser.add_argument("--path", default="~/.ironmesh/keys.json")
    info_parser.add_argument("--passphrase", default=None)

    kc_store = keys_sub.add_parser(
        "keychain-store",
        help="Save the mesh passphrase to the OS keychain (requires "
             "pip install ironmesh[keychain])",
    )
    kc_store.add_argument("--name", required=True,
                          help="Node name; the keychain entry is "
                               "service='ironmesh', user='<name>'")
    kc_store.add_argument("--passphrase-from-env", action="store_true",
                          help="Read the passphrase from "
                               "IRONMESH_PASSPHRASE_NEW instead of prompting "
                               "(useful for automation)")

    kc_clear = keys_sub.add_parser(
        "keychain-clear",
        help="Remove the OS-keychain passphrase entry for a node",
    )
    kc_clear.add_argument("--name", required=True,
                          help="Node name whose entry to remove")

    keys_sub.add_parser(
        "keychain-check",
        help="Report whether the OS keychain backend is usable on this "
             "system",
    )

    # --- backup / restore ---
    backup_parser = sub.add_parser("backup", help="Create an encrypted backup of node state")
    backup_parser.add_argument("--out", required=True, help="Output backup file path")
    backup_parser.add_argument("--keys-path", default="~/.ironmesh/keys.json")
    backup_parser.add_argument("--trust-path", default="~/.ironmesh/known_peers.json")
    backup_parser.add_argument("--audit-path", default="~/.ironmesh/audit.log")

    restore_parser = sub.add_parser("restore", help="Restore from an encrypted backup")
    restore_parser.add_argument("--in", dest="in_path", required=True, help="Backup file path")
    restore_parser.add_argument("--keys-path", default="~/.ironmesh/keys.json")
    restore_parser.add_argument("--trust-path", default="~/.ironmesh/known_peers.json")
    restore_parser.add_argument("--audit-path", default="~/.ironmesh/audit.log")
    restore_parser.add_argument("--force", action="store_true",
                                help="Overwrite existing destination files")

    # --- audit ---
    audit_parser = sub.add_parser("audit", help="Audit log tools")
    audit_sub = audit_parser.add_subparsers(dest="audit_command")
    av = audit_sub.add_parser("verify", help="Verify audit log HMAC chain")
    av.add_argument("--path", default="~/.ironmesh/audit.log")
    av.add_argument("--archives", action="store_true",
                    help="Also verify rotated archives")
    av.add_argument(
        "--rotate-corrupt", action="store_true",
        help="If tamper is detected, archive the corrupted log to "
             "<path>.corrupted-<ISO timestamp> and let the daemon "
             "start a fresh chain on next write. Recovery for the "
             "operator-runbook case where two daemons collided on "
             "the same audit path.",
    )
    ae = audit_sub.add_parser("export", help="Export signed audit log bundle")
    ae.add_argument("--path", default="~/.ironmesh/audit.log")
    ae.add_argument("--out", required=True, help="Output JSON file")
    ae.add_argument("--keys-path", default="~/.ironmesh/keys.json")
    ae.add_argument("--keys-passphrase", default=None)
    avx = audit_sub.add_parser("verify-export", help="Verify a signed audit export")
    avx.add_argument("file", help="Signed export JSON file")

    # v0.8.5.7: operator triage — filtered audit tail + event-type stats.
    at = audit_sub.add_parser(
        "tail",
        help="Print audit entries, newest-first, optionally filtered "
             "by event type and age. Does NOT verify the chain — use "
             "`ironmesh audit verify` for that.",
    )
    at.add_argument("--path", default="~/.ironmesh/audit.log")
    at.add_argument("--event", default=None,
                    help="Only print entries with this event type "
                         "(e.g. PEER_CAP_SET_CHANGED). Repeatable via "
                         "comma: --event=A,B,C")
    at.add_argument("--since", default=None,
                    help="Only entries newer than this relative window "
                         "(e.g. 1h, 15m, 2d) or an absolute ISO-8601 "
                         "timestamp. Default: all.")
    at.add_argument("--limit", type=int, default=200,
                    help="Maximum entries to print (default 200)")
    at.add_argument("--json", action="store_true",
                    help="Emit JSON-lines instead of text")

    ast_ = audit_sub.add_parser(
        "stats",
        help="Summarize audit events by type over a recent window "
             "(useful for at-a-glance triage).",
    )
    ast_.add_argument("--path", default="~/.ironmesh/audit.log")
    ast_.add_argument("--since", default="1h",
                      help="Window size (e.g. 1h, 15m, 24h). Default 1h.")

    # --- session ---
    session_parser = sub.add_parser("session", help="Session management")
    session_sub = session_parser.add_subparsers(dest="session_command")
    sr = session_sub.add_parser("rotate", help="Force session key rotation with a peer")
    sr.add_argument("peer_id", help="Peer node_id to rotate session with")
    sr.add_argument("--gui-url", default="ws://127.0.0.1:8767/ws",
                    help="Local bridge GUI WebSocket URL")
    sr.add_argument("--token", required=True, help="GUI token")

    # --- doctor (v0.8.5.2) ---
    doctor_parser = sub.add_parser(
        "doctor",
        help="One-shot diagnostic — trust file, schema, queues, gate flag, key file, port",
    )
    doctor_parser.add_argument("--keys-path", default="~/.ironmesh/keys.json")
    doctor_parser.add_argument("--keys-passphrase", default=None)
    doctor_parser.add_argument("--db-path", default="~/.ironmesh/data.db")
    doctor_parser.add_argument("--trust-path", default=None,
                                help="Trust file path (default ~/.ironmesh/known_peers.json)")
    doctor_parser.add_argument("--port", type=int, default=8765,
                                help="Port the daemon binds to — checked for conflicts")
    doctor_parser.add_argument("--bind", default="0.0.0.0",
                                help="Bind address — checked alongside --port")

    # --- setup ---
    setup_parser = sub.add_parser(
        "setup",
        help="Interactive first-run wizard: node name, passphrase, keys, trust gate",
    )
    setup_parser.add_argument("--name", default=None,
                              help="Agent name (default: prompt with hostname)")
    setup_parser.add_argument("--port", type=int, default=None,
                              help="Daemon port (default: prompt with 8765)")
    setup_parser.add_argument("--keys-path", default="~/.ironmesh/keys.json",
                              help="Where to write the encrypted keypair")
    setup_parser.add_argument("--passphrase-file", default="~/.ironmesh/passphrase",
                              help="Where to write the passphrase file")
    setup_parser.add_argument("--allowed-peers", default=None,
                              help="Comma-separated peer allowlist (default: prompt)")
    setup_parser.add_argument("--enable-trust-gate", action="store_true",
                              help="Enable the pending-trust gate (default: prompt)")
    setup_parser.add_argument("--no-trust-gate", action="store_true",
                              help="Skip the pending-trust gate (default: prompt)")
    setup_parser.add_argument("--non-interactive", action="store_true",
                              help="Take defaults for any unspecified option; do not prompt. "
                                   "Requires --passphrase-file to point at an existing file "
                                   "OR --passphrase-from-env to read IRONMESH_SETUP_PASSPHRASE.")
    setup_parser.add_argument("--passphrase-from-env", action="store_true",
                              help="In --non-interactive mode, read the passphrase from "
                                   "IRONMESH_SETUP_PASSPHRASE instead of prompting.")
    setup_parser.add_argument("--force", action="store_true",
                              help="Overwrite existing key file / passphrase file without "
                                   "prompting.")

    # --- upgrade ---
    upgrade_parser = sub.add_parser(
        "upgrade",
        help="Check PyPI for a newer version and print the upgrade command",
    )
    upgrade_parser.add_argument(
        "--timeout", type=float, default=5.0,
        help="HTTP timeout in seconds for the PyPI metadata fetch (default: 5)",
    )
    upgrade_parser.add_argument(
        "--json", action="store_true",
        help="Emit a JSON status report instead of human-readable text",
    )

    # --- demo ---
    demo_parser = sub.add_parser(
        "demo",
        help="Spawn two local agents, exchange an encrypted ping, print RTT",
    )
    demo_parser.add_argument("--port", type=int, default=18765,
                             help="Base port (uses --port and --port+2, default: 18765)")
    demo_parser.add_argument("--timeout", type=float, default=30.0,
                             help="Max seconds to wait for discovery + reply (default: 30)")
    demo_parser.add_argument("--gui", action="store_true",
                             help="Enable the dashboard on alice's port+1 and keep both "
                                  "agents running (Ctrl-C to stop). Useful for screenshots.")

    # --- Backward compatibility: allow flags directly on root parser ---
    parser.add_argument("--name", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, default=8765, help=argparse.SUPPRESS)
    # --passphrase REMOVED from root parser — use --passphrase-file or env var
    parser.add_argument("--keys-path", default="~/.ironmesh/keys.json", help=argparse.SUPPRESS)
    parser.add_argument("--db-path", default="~/.ironmesh/data.db", help=argparse.SUPPRESS)
    parser.add_argument("--rotate-keys", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--log-level", default="INFO", help=argparse.SUPPRESS)
    parser.add_argument("--log-file", default=None, help=argparse.SUPPRESS)

    return parser.parse_args()


# v0.8.5.2: maximum bytes read from a passphrase file. A legitimate
# passphrase is at most a few hundred chars; 4096 is generous and
# prevents hanging on /dev/urandom or exhausting memory on a huge file.
_PASSPHRASE_FILE_MAX_BYTES = 4096


def _read_passphrase_file_safe(path: str) -> str:
    """Read a passphrase file with defensive bounds + mode warnings.

    Protects against:
      - Infinite reads on device files (/dev/urandom, /dev/zero)
      - Memory exhaustion from a huge file
      - World-readable passphrase files (logs a warning; doesn't reject)
      - Empty or whitespace-only files (raises ValueError)
    """
    resolved = os.path.expanduser(path)
    st = os.stat(resolved)
    # Reject non-regular files so a symlink to /dev/urandom can't hang.
    import stat as _stat
    if not _stat.S_ISREG(st.st_mode):
        raise ValueError(
            f"passphrase file {path} is not a regular file "
            f"(mode={oct(st.st_mode)}); refusing to read"
        )
    # Warn if world- or group-readable on POSIX. Windows NTFS permissions
    # don't map cleanly to these bits, so the check is a best-effort.
    try:
        if (st.st_mode & 0o077) != 0 and os.name == "posix":
            import logging
            logging.getLogger("ironmesh.cli").warning(
                "passphrase file %s has permissive mode %s — recommend `chmod 600`",
                path, oct(st.st_mode & 0o777),
            )
    except Exception:
        pass
    with open(resolved, "rb") as f:
        raw = f.read(_PASSPHRASE_FILE_MAX_BYTES + 1)
    if len(raw) > _PASSPHRASE_FILE_MAX_BYTES:
        raise ValueError(
            f"passphrase file {path} exceeds {_PASSPHRASE_FILE_MAX_BYTES} "
            "bytes — likely wrong file"
        )
    try:
        text = raw.decode("utf-8").strip("\r\n").strip()
    except UnicodeDecodeError:
        raise ValueError(f"passphrase file {path} is not valid UTF-8")
    if not text:
        raise ValueError(f"passphrase file {path} is empty")
    return text


def get_passphrase(node_name: Optional[str] = None):
    """Obtain passphrase from secure sources only.

    Priority:
        1. --passphrase-file > IRONMESH_PASSPHRASE_FILE
        2. IRONMESH_PASSPHRASE_KEYCHAIN=true (or 1/yes) → query OS keychain
           (requires `pip install ironmesh[keychain]`; service="ironmesh",
           username=node_name)
        3. IRONMESH_PASSPHRASE (env var, with warning)
        4. Interactive getpass

    Never accepts passphrase via CLI argv (visible in ps aux).
    """
    # 1. Prefer IRONMESH_PASSPHRASE_FILE over env var (avoids /proc/environ exposure).
    passphrase_file = os.environ.get("IRONMESH_PASSPHRASE_FILE")
    if passphrase_file:
        try:
            passphrase = _read_passphrase_file_safe(passphrase_file)
            if passphrase:
                return passphrase
        except (IOError, OSError, ValueError) as e:
            print(f"ERROR: Cannot read passphrase file {passphrase_file}: {e}")
            sys.exit(1)
    # 2. OS keychain backend if explicitly opted in
    keychain_flag = os.environ.get("IRONMESH_PASSPHRASE_KEYCHAIN", "").lower()
    if keychain_flag in ("1", "true", "yes"):
        if not node_name:
            print("ERROR: IRONMESH_PASSPHRASE_KEYCHAIN requires a node name.")
            print("       Pass --name to ironmesh run, or set IRONMESH_NAME.")
            sys.exit(1)
        try:
            from ironmesh import keychain as _kc
            stored = _kc.load(node_name)
            if stored:
                return stored
            print(f"ERROR: IRONMESH_PASSPHRASE_KEYCHAIN is set but no entry "
                  f"found for service='ironmesh', user='{node_name}'.")
            print("       Store one with:")
            print(f"           ironmesh keys keychain-store --name {node_name}")
            sys.exit(1)
        except _kc.KeychainUnavailable as exc:  # type: ignore[attr-defined]
            print(f"ERROR: IRONMESH_PASSPHRASE_KEYCHAIN is set but: {exc}")
            sys.exit(1)
        except Exception as exc:
            print(f"ERROR: Failed to read passphrase from OS keychain: {exc}")
            sys.exit(1)
    # 3. Env var fallback
    env = os.environ.get("IRONMESH_PASSPHRASE")
    if env:
        # Warn about env var risk
        print("WARNING: Reading passphrase from IRONMESH_PASSPHRASE env var.")
        print("         Environment variables may be visible via /proc. Prefer IRONMESH_PASSPHRASE_FILE.\n")
        return env
    # 4. Interactive prompt via getpass (hidden input, not in process list)
    if sys.stdin.isatty():
        try:
            passphrase = getpass.getpass("Enter IronMesh passphrase: ")
            if passphrase:
                return passphrase
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(1)
    # No default — require explicit passphrase
    print("ERROR: Passphrase required. Secure methods:")
    print("       1. --passphrase-file <path>     (file, chmod 600)")
    print("       2. IRONMESH_PASSPHRASE_FILE      (env var pointing to file)")
    print("       3. IRONMESH_PASSPHRASE_KEYCHAIN  (true/1/yes — requires "
          "pip install ironmesh[keychain] and a stored entry)")
    print("       4. Interactive prompt            (getpass, not in ps aux)")
    print("       --passphrase flag was REMOVED (leaks in process list).")
    sys.exit(1)


def setup_logging(level: str = "INFO", log_file: str = None,
                  log_format: str = "text"):
    """Configure root logger.

    Args:
        level: log level name (DEBUG/INFO/WARNING/ERROR).
        log_file: optional file path; defaults to stderr.
        log_format: "text" (default) or "json" for structured logs.
    """
    handlers = []
    if log_file:
        handlers.append(logging.FileHandler(os.path.expanduser(log_file)))
    else:
        handlers.append(logging.StreamHandler())

    if log_format == "json":
        from ironmesh.bridge import JsonFormatter
        formatter = JsonFormatter()
        for h in handlers:
            h.setFormatter(formatter)
        # Use root logger directly to bypass basicConfig's default formatter
        root = logging.getLogger()
        root.setLevel(getattr(logging, level.upper(), logging.INFO))
        # Clear any existing handlers to avoid duplicates
        for old in list(root.handlers):
            root.removeHandler(old)
        for h in handlers:
            root.addHandler(h)
    else:
        logging.basicConfig(
            level=getattr(logging, level.upper(), logging.INFO),
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            handlers=handlers,
        )


def _apply_profile(args):
    """Apply a `--profile=secure|dev|offline` preset.

    Profiles set boolean flags to safe defaults but never override an
    explicit user-supplied value. When the user combines a profile
    with a flag that conflicts with the profile's intent, log a clear
    WARNING and let the explicit flag win (argparse-consistent).

    Returns the list of warning messages so the caller can also log
    them through the structured logger once it is set up.
    """
    profile = getattr(args, "profile", None)
    if profile is None:
        return []

    warnings = []

    if profile == "secure":
        # Production hardening: pending-trust gate ON, no plaintext-ws.
        if not getattr(args, "require_message_promotion", False):
            args.require_message_promotion = True
        if getattr(args, "allow_plaintext_ws", False):
            warnings.append(
                "profile=secure was overridden: --allow-plaintext-ws is set "
                "explicitly, secure profile would have left it OFF. "
                "Consider removing the flag for a real deployment."
            )
        if getattr(args, "open_discovery", False):
            warnings.append(
                "profile=secure was overridden: --open-discovery is set "
                "explicitly, secure profile would have left it OFF. "
                "Consider removing the flag for a real deployment."
            )
    elif profile == "dev":
        # Same-machine localhost shortcuts. Insecure by design.
        if not getattr(args, "open_discovery", False):
            args.open_discovery = True
        if not getattr(args, "allow_plaintext_ws", False):
            args.allow_plaintext_ws = True
    elif profile == "offline":
        # Reticulum/LoRa transport only.
        if hasattr(args, "reticulum") and not getattr(args, "reticulum", False):
            args.reticulum = True
        # Note: leaving allowed_peers / open_discovery untouched —
        # an offline mesh may still use mDNS on a local LAN segment.

    return warnings


def cmd_run(args):
    """Start the bridge daemon."""
    name = getattr(args, "name", None)
    if not name:
        print("ERROR: --name is required. Usage: ironmesh run --name alice")
        return 1

    profile_warnings = _apply_profile(args)

    log_level = getattr(args, "log_level", "INFO")
    if getattr(args, "debug", False):
        log_level = "DEBUG"
    setup_logging(
        log_level,
        getattr(args, "log_file", None),
        getattr(args, "log_format", "text"),
    )
    log = logging.getLogger("ironmesh.cli")

    # Re-emit any profile-application warnings through the structured
    # logger now that it is set up.
    profile = getattr(args, "profile", None)
    if profile is not None:
        log.info("Profile active: %s", profile)
    for w in profile_warnings:
        log.warning(w)

    # Support --passphrase-file as highest priority
    passphrase_file = getattr(args, "passphrase_file", None)
    if passphrase_file:
        try:
            passphrase = _read_passphrase_file_safe(passphrase_file)
        except (IOError, OSError, ValueError) as e:
            print(f"ERROR: Cannot read passphrase file {passphrase_file}: {e}")
            return 1
    else:
        passphrase = get_passphrase(node_name=name)

    from ironmesh import __version__
    banner = f"""
+---------------------------------------------------+
|  IronMesh v{__version__:<38s}|
|  Zero-config encrypted A2A protocol               |
+---------------------------------------------------+
|  Agent:  {name:<42s}|
|  Port:   {str(args.port):<42s}|
+---------------------------------------------------+
"""
    print(banner)

    if len(passphrase) < 8:
        print("WARNING: Passphrase is short (< 8 chars). Consider using a stronger passphrase.\n")

    # Handle key rotation
    if getattr(args, "rotate_keys", False):
        import asyncio

        from ironmesh.bridge import rotate_keys
        log.info("Key rotation requested...")
        asyncio.run(rotate_keys(args.keys_path))
        log.info("Key rotation complete. Starting with new keys.")

    from ironmesh.bridge import BridgeDaemon

    # Parse allowed peers list
    allowed_peers_raw = getattr(args, "allowed_peers", None)
    allowed_peers = None
    if allowed_peers_raw:
        allowed_peers = [p.strip() for p in allowed_peers_raw.split(",") if p.strip()]

    # Default-deny mDNS — require --open-discovery or --allowed-peers
    open_discovery = getattr(args, "open_discovery", False)
    if allowed_peers is None and not open_discovery:
        # Default-deny: disable mDNS auto-connect unless explicitly allowed
        log.warning("mDNS auto-connect disabled (default-deny). "
                    "Use --allowed-peers or --open-discovery to enable.")
    elif open_discovery:
        log.warning(
            "INSECURE: --open-discovery is set. mDNS auto-connect to ANY "
            "peer is enabled, bypassing the default-deny allowlist. This "
            "flag is for localhost testing only. Use --allowed-peers in "
            "any real deployment."
        )

    # TLS preference
    allow_plaintext_ws = getattr(args, "allow_plaintext_ws", False)
    if allow_plaintext_ws:
        log.warning(
            "INSECURE: --allow-plaintext-ws is set. WebSocket connections "
            "may fall back to plaintext ws:// instead of requiring wss://. "
            "This flag is for localhost testing only. Generate a TLS cert "
            "and pass --tls-cert/--tls-key in any real deployment."
        )

    # Pending-trust message gate deprecation notice (default-on in v0.9)
    require_msg_promotion = (
        getattr(args, "require_message_promotion", False)
        or os.environ.get("IRONMESH_REQUIRE_MSG_PROMOTION", "").lower() in ("1", "true", "yes")
    )
    if not require_msg_promotion:
        log.warning(
            "DEPRECATION: pending-trust message gate is opt-in in v0.8.x. "
            "It will be enabled by default in v0.9. To prepare, set "
            "IRONMESH_REQUIRE_MSG_PROMOTION=true or pass "
            "--require-message-promotion now. To keep the legacy "
            "trust-on-first-message behavior in v0.9 and later, you will "
            "need to pass an explicit --no-message-promotion flag (not "
            "yet implemented). See docs/migration/v0_9_default_deny.md."
        )

    daemon = BridgeDaemon(
        name=name,
        port=args.port,
        passphrase=passphrase,
        keys_path=args.keys_path,
        db_path=getattr(args, "db_path", "~/.ironmesh/data.db"),
        keys_passphrase=getattr(args, "keys_passphrase", None),
        tls_cert=getattr(args, "tls_cert", None),
        tls_key=getattr(args, "tls_key", None),
        bind_address=getattr(args, "bind", "0.0.0.0"),
        log_level=log_level,
        gui=getattr(args, "gui", False) and not getattr(args, "no_gui", False),
        gui_bind=getattr(args, "gui_bind", "127.0.0.1"),
        allowed_peers=allowed_peers,
        open_discovery=open_discovery,
        allow_plaintext_ws=allow_plaintext_ws,
        # v0.4
        mesh_routing=getattr(args, "mesh_routing", "relay"),
        max_hops=getattr(args, "max_hops", 5),
        route_announce_interval=getattr(args, "route_announce_interval", 30.0),
        route_ttl=getattr(args, "route_ttl", 90.0),
        routes_path=getattr(args, "routes_path", "~/.ironmesh/routes.json"),
        capabilities=getattr(args, "capability", []),
        capabilities_path=getattr(args, "capabilities_path",
                                  "~/.ironmesh/capabilities.json"),
        capability_announce_interval=getattr(
            args, "capability_announce_interval", 60.0),
        metrics_format=getattr(args, "metrics_format", "prometheus"),
        log_format=getattr(args, "log_format", "text"),
        # v0.5: Reticulum
        rns_enabled=getattr(args, "reticulum", False),
        rns_configdir=getattr(args, "rns_configdir", None),
        rns_announce_interval=getattr(args, "rns_announce_interval", 300.0),
        rns_connect=getattr(args, "rns_connect", None),
        rns_ratchets_enabled=not getattr(args, "rns_no_ratchets", False),
        rns_ratchet_interval=getattr(args, "rns_ratchet_interval", 1800.0),
        rns_retained_ratchets=getattr(args, "rns_retained_ratchets", 8),
        rns_admin_identities=_parse_admin_identities(
            getattr(args, "rns_admin_identities", None)
            or os.environ.get("IRONMESH_RNS_ADMIN_IDENTITIES")
        ),
        rns_skip_handshake=getattr(args, "rns_skip_handshake", False),
        # v0.9.1: LXMF
        lxmf_enabled=getattr(args, "lxmf", False),
        lxmf_storage=getattr(args, "lxmf_storage", "~/.ironmesh/lxmf"),
        lxmf_display_name=getattr(args, "lxmf_display_name", "IronMesh"),
        lxmf_default_peer=getattr(args, "lxmf_default_peer", None),
        lxmf_propagation_node=getattr(args, "lxmf_propagation_node", False),
        lxmf_propagation_storage=getattr(args, "lxmf_propagation_storage",
                                           "~/.ironmesh/lxmf/propagation"),
        lxmf_telemetry_target=getattr(args, "lxmf_telemetry_target", None),
        lxmf_telemetry_interval=getattr(args, "lxmf_telemetry_interval", 300.0),
        # v0.5.2: QoS + rekey
        lora_max_payload=getattr(args, "lora_max_payload", 128),
        rekey_interval=getattr(args, "rekey_interval", 1800.0),
        # v0.6.0
        min_protocol_version=getattr(args, "min_protocol_version", "ironmesh/0.3"),
        # v0.8.5: pending-trust message gate
        require_message_promotion=getattr(args, "require_message_promotion", False),
        pending_trust_queue_cap=getattr(args, "pending_trust_queue_cap", 100),
        trust_path=getattr(args, "trust_path", None),
    )

    try:
        log.info("Starting IronMesh Bridge daemon...")
        daemon.run()
    except KeyboardInterrupt:
        print("\nBridge daemon stopped")
    except Exception as e:
        log.error("Bridge daemon failed: %s", e)
        return 1
    return 0


def cmd_trust(args):
    """Manage peer trust."""
    from ironmesh import keys as ew_keys
    from ironmesh.trust import TrustStore
    # Audit C-03: TrustStore is bound to the agent identity. Load keys
    # to derive the MAC key. Require a passphrase to decrypt them.
    keys_path = getattr(args, "keys_path", "~/.ironmesh/keys.json")
    pp = getattr(args, "keys_passphrase", None) or os.environ.get("IRONMESH_PASSPHRASE")
    if not pp:
        pp = getpass.getpass("Identity key passphrase (for trust store MAC): ")
    try:
        keypair = ew_keys.load_keys(keys_path, passphrase=pp)
    except Exception as e:
        print(f"Error: failed to load identity keys: {e}")
        return 1
    trust_path = getattr(args, "trust_path", None)
    if trust_path:
        store = TrustStore(agent_key=keypair.ed25519_secret[:32], path=trust_path)
    else:
        store = TrustStore(agent_key=keypair.ed25519_secret[:32])

    # v0.8.5.6: shared audit-log helper for every CLI mutation.
    # Opens lazily so read-only commands don't touch the audit log.
    _audit_cache = {"log": None}

    def _audit_log_event(event: str, details: dict) -> None:
        from ironmesh.audit import AuditLog
        if _audit_cache["log"] is None:
            audit_key = hashlib.sha256(
                keypair.ed25519_secret + b"ironmesh-audit-v1"
            ).digest()
            # Resolve the audit log path so operator mutations land in
            # the same file the target daemon tails. Without this, the
            # CLI writes to ~/.ironmesh/audit.log but a daemon using a
            # custom --db-path keeps its audit log next to its db, so
            # the daemon's scanner loop never sees the operator event
            # and the mirrored counter never bumps.
            audit_path = getattr(args, "audit_path", None)
            if not audit_path and getattr(args, "trust_path", None):
                audit_path = os.path.join(
                    os.path.dirname(os.path.expanduser(args.trust_path)),
                    "audit.log",
                )
            if audit_path:
                _audit_cache["log"] = AuditLog(
                    path=audit_path, hmac_key=audit_key,
                )
            else:
                _audit_cache["log"] = AuditLog(hmac_key=audit_key)
        try:
            _audit_cache["log"].log(event, details)
        except Exception as e:
            # Don't fail the CLI command — the trust mutation has
            # already landed — but surface the audit-emit failure so
            # a forensic gap doesn't accumulate silently.
            print(
                f"WARNING: audit log emit for {event} failed: {e}. "
                "The mutation was applied but no audit record was written. "
                "Check disk space / file permissions on "
                f"{getattr(_audit_cache['log'], '_path', '~/.ironmesh/audit.log')}.",
                file=sys.stderr,
            )

    trust_cmd = getattr(args, "trust_command", None)
    if trust_cmd == "list":
        peers = store.list_peers()
        if not peers:
            print("No trusted peers.")
            return 0
        show_caps = getattr(args, "show_caps", False)
        # v0.8.5.7: `time` is imported at module top; don't re-import
        # locally here or Python's scoping rule makes `time` a local
        # for the entire cmd_trust function, breaking other branches
        # (cap-status) that also call time.strftime.
        if show_caps:
            # v0.8.5.7: include capability-binding status column so
            # operators can see at a glance which peers have a pinned
            # baseline vs which are pending vs which have no cap hash
            # yet (pre-v0.8.5.6 peers, or peers that haven't yet
            # advertised capabilities).
            print(f"{'Node ID':<20s} {'Fingerprint':<18s} {'State':<18s} "
                  f"{'Caps':<10s} {'Last Seen':<20s}")
            print("-" * 92)
            for p in peers:
                last = (time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(p["last_seen"]))
                        if p.get("last_seen") else "N/A")
                state = p.get("trust_state", "trusted")
                rec = store.get_peer(p["node_id"]) or {}
                if rec.get("capability_hash_pending"):
                    cap_col = "pending"
                elif rec.get("capability_hash"):
                    cap_col = "baseline"
                else:
                    cap_col = "unknown"
                print(f"{p['node_id']:<20s} {p['fingerprint']:<18s} "
                      f"{state:<18s} {cap_col:<10s} {last:<20s}")
        else:
            print(f"{'Node ID':<20s} {'Fingerprint':<18s} {'State':<10s} "
                  f"{'First Seen':<24s} {'Last Seen':<24s}")
            print("-" * 96)
            for p in peers:
                first = (time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(p["first_seen"]))
                         if p["first_seen"] else "N/A")
                last = (time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(p["last_seen"]))
                        if p["last_seen"] else "N/A")
                state = p.get("trust_state", "trusted")
                print(f"{p['node_id']:<20s} {p['fingerprint']:<18s} "
                      f"{state:<10s} {first:<24s} {last:<24s}")
    elif trust_cmd == "revoke":
        node_id = args.node_id
        broadcast = getattr(args, "broadcast", False)
        if broadcast:
            if not args.token:
                print("Error: --token is required when using --broadcast")
                return 1
            import asyncio
            import json as _json
            try:
                import websockets
            except ImportError:
                print("Error: websockets package required")
                return 1

            async def do_broadcast():
                url = f"{args.gui_url}?token={args.token}"
                async with websockets.connect(url, open_timeout=5) as ws:
                    await asyncio.wait_for(ws.recv(), timeout=5)  # snapshot
                    await ws.send(_json.dumps({
                        "action": "broadcast_revocation",
                        "target_node_id": node_id,
                        "reason": args.reason,
                    }))
                    resp = await asyncio.wait_for(ws.recv(), timeout=10)
                    data = _json.loads(resp)
                    if data.get("type") == "revoke_ack":
                        print(f"Broadcast REVOCATION for {node_id}")
                        return 0
                    print(f"Error: {data}")
                    return 1

            return asyncio.run(do_broadcast())
        else:
            if store.revoke_peer(node_id):
                from ironmesh.audit import EVENT_PEER_REVOKED_LOCAL
                _audit_log_event(EVENT_PEER_REVOKED_LOCAL, {
                    "peer_id": node_id,
                    "actor": "cli",
                    "reason": getattr(args, "reason", ""),
                })
                print(f"Trust revoked for {node_id} (local only)")
            else:
                print(f"Peer {node_id} not found in trust store")
    elif trust_cmd == "list-revoked":
        revoked = store.list_revoked()
        if not revoked:
            print("No revoked peers.")
            return 0
        print(f"{'Node ID':<22s} {'Revoker':<22s} {'Timestamp':<20s} {'Reason'}")
        print("-" * 80)
        for r in revoked:
            ts = time.strftime("%Y-%m-%d %H:%M:%S",
                               time.localtime(r.get("timestamp", 0)))
            print(f"{r['node_id']:<22s} {r.get('revoker','?'):<22s} "
                  f"{ts:<20s} {r.get('reason','')}")
    elif trust_cmd == "set-state":
        node_id = args.node_id
        new_state = args.state
        # v0.8.5.6: capture the prior state so the audit event
        # records the actual transition. Must peek BEFORE mutating.
        rec = store.get_peer(node_id)
        old_state = rec.get("trust_state") if rec else None
        if store.set_trust_state(node_id, new_state):
            from ironmesh.audit import (
                EVENT_PEER_BLOCKED,
                EVENT_PEER_PROMOTED,
                EVENT_PEER_STATE_CHANGED,
            )
            # Prefer the pre-existing specific events where they fit
            # (operators searching the audit log tend to grep by name).
            if new_state == "trusted":
                _audit_log_event(EVENT_PEER_PROMOTED, {
                    "peer_id": node_id, "actor": "cli",
                    "old_state": old_state, "new_state": new_state,
                })
            elif new_state == "blocked":
                _audit_log_event(EVENT_PEER_BLOCKED, {
                    "peer_id": node_id, "actor": "cli",
                    "old_state": old_state, "new_state": new_state,
                })
            else:
                _audit_log_event(EVENT_PEER_STATE_CHANGED, {
                    "peer_id": node_id, "actor": "cli",
                    "old_state": old_state, "new_state": new_state,
                })
            print(f"Trust state for {node_id} -> {new_state}")
            print("Note: a running daemon won't pick this up until it next "
                  "constructs a TrustStore (every gate evaluation does this, "
                  "so the change applies on the next inbound MSG).")
            return 0
        else:
            print(f"Peer {node_id} not in trust store. Run 'ironmesh trust list' to see known peers.")
            return 1
    elif trust_cmd == "cap-promote":
        # v0.8.5.6: operator action — accept pending cap-set changes.
        # Audit events (EVENT_PEER_CAP_ACCEPTED) are fired alongside the
        # state transitions so operator actions surface on the same
        # audit timeline as daemon-observed events.
        from ironmesh.audit import EVENT_PEER_CAP_ACCEPTED
        targets = []
        if getattr(args, "all", False):
            targets = [p["node_id"] for p in
                       store.list_by_capability_status("pending-cap-change")]
            if not targets:
                print("No peers in pending-cap-change.")
                return 0
        else:
            if not args.node_id:
                print("ERROR: pass <node_id> or --all.")
                return 2
            targets = [args.node_id]
        promoted = 0
        failed = 0
        for nid in targets:
            rec = store.get_peer(nid)
            if rec is None:
                print(f"  [SKIP] {nid}: unknown peer")
                failed += 1
                continue
            if rec.get("capability_hash_pending") is None:
                print(f"  [SKIP] {nid}: no pending capability change")
                failed += 1
                continue
            old_hash = rec.get("capability_hash") or "(none)"
            new_hash = rec.get("capability_hash_pending")
            ok = store.accept_capability_change(nid)
            if ok:
                store.set_trust_state(nid, "trusted")
                _audit_log_event(EVENT_PEER_CAP_ACCEPTED, {
                    "peer": nid,
                    "old_hash": old_hash,
                    "new_hash": new_hash,
                    "trust_state_effective": "trusted",
                    "actor": "cli",
                })
                print(f"  [OK]   {nid}: {old_hash[:12]}... -> {new_hash[:12]}... -> trusted")
                promoted += 1
            else:
                print(f"  [FAIL] {nid}: accept_capability_change returned False")
                failed += 1
        print()
        print(f"Promoted {promoted} peer(s); {failed} skipped/failed.")
        return 0 if failed == 0 else 1
    elif trust_cmd == "list-cap-pending":
        pending = store.list_by_capability_status("pending-cap-change")
        if getattr(args, "json", False):
            import json as _json
            print(_json.dumps(pending, default=str, indent=2))
            return 0
        if not pending:
            print("No peers in pending-cap-change.")
            return 0
        print(f"{len(pending)} peer(s) in pending-cap-change:")
        print()
        for entry in pending:
            nid = entry["node_id"]
            old_hash = entry.get("capability_hash") or "(none)"
            new_hash = entry.get("pending_hash") or "(none)"
            old_set = set(entry.get("capability_set") or [])
            new_set = set(entry.get("pending_set") or [])
            added = sorted(new_set - old_set)
            removed = sorted(old_set - new_set)
            print(f"  {nid}")
            print(f"    fingerprint   : {entry.get('fingerprint', '?')}")
            print(f"    baseline hash : {old_hash[:24]}...")
            print(f"    pending hash  : {new_hash[:24]}...")
            if added:
                print(f"    + added       : {', '.join(added)}")
            if removed:
                print(f"    - removed     : {', '.join(removed)}")
            print()
        print("Re-promote with: ironmesh trust cap-promote <node_id>")
        print("Or all at once: ironmesh trust cap-promote --all")
        return 0
    elif trust_cmd == "cap-diff":
        nid = args.node_id
        rec = store.get_peer(nid)
        if rec is None:
            print(f"Peer {nid} not in trust store.")
            return 1
        baseline_set = sorted(rec.get("capability_set") or [])
        pending_set = sorted(rec.get("capability_set_pending") or [])
        print(f"Peer: {nid}")
        print(f"  fingerprint  : {rec.get('fingerprint', '?')}")
        print(f"  trust state  : {rec.get('trust_state', 'trusted')}")
        print(f"  baseline hash: "
              f"{(rec.get('capability_hash') or '(none)')[:24]}...")
        if rec.get("capability_hash_pending"):
            print(f"  pending hash : "
                  f"{rec.get('capability_hash_pending')[:24]}...")
        print(f"  baseline set ({len(baseline_set)}): "
              f"{', '.join(baseline_set) or '(empty)'}")
        if pending_set:
            added = sorted(set(pending_set) - set(baseline_set))
            removed = sorted(set(baseline_set) - set(pending_set))
            print(f"  pending set  ({len(pending_set)}): "
                  f"{', '.join(pending_set)}")
            if added:
                print(f"    + added    : {', '.join(added)}")
            if removed:
                print(f"    - removed  : {', '.join(removed)}")
        else:
            print("  pending set  : (none — peer not in pending-cap-change)")
        return 0
    elif trust_cmd == "cap-reject":
        # v0.8.5.7: the operator's explicit "no" to a cap change.
        # Clears the pending hash + pending set without touching the
        # accepted baseline. --block also flips trust_state to blocked
        # in one shot for the common "this change is suspicious"
        # response flow.
        from ironmesh.audit import (
            EVENT_PEER_BLOCKED,
            EVENT_PEER_STATE_CHANGED,
        )
        targets = []
        if getattr(args, "all", False):
            targets = [p["node_id"] for p in
                       store.list_by_capability_status("pending-cap-change")]
            if not targets:
                print("No peers in pending-cap-change.")
                return 0
        else:
            if not args.node_id:
                print("ERROR: pass <node_id> or --all.")
                return 2
            targets = [args.node_id]
        want_block = getattr(args, "block", False)
        rejected = 0
        failed = 0
        for nid in targets:
            rec = store.get_peer(nid)
            if rec is None:
                print(f"  [SKIP] {nid}: unknown peer")
                failed += 1
                continue
            if rec.get("capability_hash_pending") is None:
                print(f"  [SKIP] {nid}: no pending capability change")
                failed += 1
                continue
            pending_hash = rec.get("capability_hash_pending")
            # Clear the pending stash in-memory + save
            rec.pop("capability_hash_pending", None)
            rec.pop("capability_set_pending", None)
            rec["cap_rejected_at"] = time.time()
            if not store._save():
                print(f"  [FAIL] {nid}: trust store save refused")
                failed += 1
                continue
            # Decide trust_state: block or restore to trusted
            new_state = "blocked" if want_block else "trusted"
            if store.set_trust_state(nid, new_state):
                _audit_log_event(
                    EVENT_PEER_BLOCKED if want_block
                    else EVENT_PEER_STATE_CHANGED,
                    {
                        "peer_id": nid,
                        "actor": "cli",
                        "reason": "cap-reject",
                        "rejected_pending_hash": pending_hash,
                        "old_state": "pending-cap-change",
                        "new_state": new_state,
                    },
                )
                marker = "BLOCKED" if want_block else "trusted"
                print(f"  [OK]   {nid}: pending hash {pending_hash[:12]}... "
                      f"rejected -> {marker}")
                rejected += 1
            else:
                print(f"  [FAIL] {nid}: set_trust_state returned False")
                failed += 1
        print()
        print(f"Rejected {rejected} peer(s); {failed} skipped/failed.")
        return 0 if failed == 0 else 1
    elif trust_cmd == "cap-status":
        # v0.8.5.7: single-peer operator diagnostic.
        nid = args.node_id
        rec = store.get_peer(nid)
        if rec is None:
            print(f"Peer {nid} not in trust store.")
            return 1
        if getattr(args, "json", False):
            import json as _json
            out = {
                "node_id": nid,
                "fingerprint": rec.get("fingerprint"),
                "trust_state": rec.get("trust_state", "trusted"),
                "first_seen": rec.get("first_seen"),
                "last_seen": rec.get("last_seen"),
                "capability_hash": rec.get("capability_hash"),
                "capability_set": rec.get("capability_set"),
                "cap_first_observed": rec.get("cap_first_observed"),
                "cap_accepted_at": rec.get("cap_accepted_at"),
                "cap_rejected_at": rec.get("cap_rejected_at"),
                "capability_hash_pending": rec.get("capability_hash_pending"),
                "capability_set_pending": rec.get("capability_set_pending"),
            }
            print(_json.dumps(out, default=str, indent=2))
            return 0

        def _fmtt(v):
            if not v:
                return "(never)"
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v))

        print(f"Peer: {nid}")
        print(f"  fingerprint        : {rec.get('fingerprint', '?')}")
        print(f"  trust_state        : {rec.get('trust_state', 'trusted')}")
        print(f"  first_seen         : {_fmtt(rec.get('first_seen'))}")
        print(f"  last_seen          : {_fmtt(rec.get('last_seen'))}")
        print()
        print("Capability binding")
        baseline_hash = rec.get("capability_hash")
        if baseline_hash:
            print(f"  baseline hash      : {baseline_hash[:32]}...")
            print(f"  baseline set ({len(rec.get('capability_set') or [])})")
            for c in sorted(rec.get("capability_set") or []):
                print(f"    - {c}")
            print(f"  cap_first_observed : "
                  f"{_fmtt(rec.get('cap_first_observed'))}")
            print(f"  cap_accepted_at    : "
                  f"{_fmtt(rec.get('cap_accepted_at'))}")
        else:
            print("  baseline hash      : (unknown — peer has not "
                  "advertised caps yet)")
        pending_hash = rec.get("capability_hash_pending")
        if pending_hash:
            print()
            print("PENDING cap change awaiting operator review:")
            print(f"  pending hash       : {pending_hash[:32]}...")
            baseline_set = set(rec.get("capability_set") or [])
            pending_set = set(rec.get("capability_set_pending") or [])
            added = sorted(pending_set - baseline_set)
            removed = sorted(baseline_set - pending_set)
            if added:
                print(f"  added              : {', '.join(added)}")
            if removed:
                print(f"  removed            : {', '.join(removed)}")
            print()
            print(f"  Accept  : ironmesh trust cap-promote {nid}")
            print(f"  Reject  : ironmesh trust cap-reject {nid}")
            print(f"  Block   : ironmesh trust cap-reject {nid} --block")
        if rec.get("cap_rejected_at"):
            print(f"  cap_rejected_at    : "
                  f"{_fmtt(rec.get('cap_rejected_at'))}")
        return 0
    else:
        print("Usage: ironmesh trust [list [--show-caps]|revoke <node_id>|"
              "list-revoked|set-state <node_id> <state>|cap-promote "
              "[<node_id>|--all]|cap-reject [<node_id>|--all] [--block]|"
              "cap-status <node_id>|list-cap-pending|cap-diff <node_id>]")

    return 0


def cmd_keys(args):
    """Key management commands."""
    keys_cmd = getattr(args, "keys_command", None)

    if keys_cmd == "generate":
        from ironmesh.keys import generate_keypair, save_keys
        keypair = generate_keypair()
        key_passphrase = args.passphrase
        # Force key encryption — prompt if no passphrase given
        if not key_passphrase and sys.stdin.isatty():
            key_passphrase = getpass.getpass("Enter passphrase to encrypt key file: ")
            if key_passphrase:
                confirm = getpass.getpass("Confirm passphrase: ")
                if key_passphrase != confirm:
                    print("ERROR: Passphrases do not match.")
                    return 1
        save_keys(keypair, args.path, passphrase=key_passphrase)
        print(f"Keypair generated -> {args.path}")
        print(f"Encrypted: {'yes' if key_passphrase else 'no (INSECURE)'}")
        print(f"Fingerprint: {keypair.get_fingerprint()}")
        print(f"Public key:  {keypair.get_public_key_base64()}")
    elif keys_cmd == "info":
        from ironmesh.keys import load_keys
        try:
            keys = load_keys(args.path, passphrase=args.passphrase)
            print(f"Key file:    {args.path}")
            print(f"Agent name:  {keys.agent_name or '(not set)'}")
            print(f"Fingerprint: {keys.get_fingerprint()}")
            print(f"Public key:  {keys.get_public_key_base64()}")
            print(f"Encrypted:   {'yes' if args.passphrase else 'no'}")
        except FileNotFoundError:
            print(f"Key file not found: {args.path}")
            return 1
        except ValueError as e:
            print(f"Error: {e}")
            return 1
    elif keys_cmd == "keychain-store":
        from ironmesh import keychain as _kc
        node = args.name
        if getattr(args, "passphrase_from_env", False):
            passphrase = os.environ.get("IRONMESH_PASSPHRASE_NEW", "")
            if not passphrase:
                print("ERROR: --passphrase-from-env requires "
                      "IRONMESH_PASSPHRASE_NEW to be set and non-empty.")
                return 1
        else:
            try:
                passphrase = getpass.getpass(
                    f"Passphrase to store for service='ironmesh' user='{node}': "
                )
                confirm = getpass.getpass("Confirm: ")
            except (EOFError, KeyboardInterrupt):
                print()
                return 1
            if passphrase != confirm:
                print("ERROR: Passphrases do not match.")
                return 1
        if len(passphrase) < 12:
            print("ERROR: Passphrase must be at least 12 characters.")
            return 1
        try:
            _kc.store(node, passphrase)
        except _kc.KeychainUnavailable as exc:
            print(f"ERROR: {exc}")
            return 1
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1
        print(f"Stored passphrase in OS keychain (service='ironmesh', "
              f"user='{node}').")
        print("To use it on startup:")
        print("  export IRONMESH_PASSPHRASE_KEYCHAIN=true")
        print(f"  ironmesh run --name {node} ...")
    elif keys_cmd == "keychain-clear":
        from ironmesh import keychain as _kc
        node = args.name
        try:
            removed = _kc.clear(node)
        except _kc.KeychainUnavailable as exc:
            print(f"ERROR: {exc}")
            return 1
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1
        if removed:
            print(f"Removed OS-keychain entry for service='ironmesh', "
                  f"user='{node}'.")
        else:
            print(f"No OS-keychain entry found for service='ironmesh', "
                  f"user='{node}'.")
    elif keys_cmd == "keychain-check":
        from ironmesh import keychain as _kc
        if _kc.is_available():
            print("OS keychain backend: AVAILABLE")
            print("To use it: store a passphrase, then set "
                  "IRONMESH_PASSPHRASE_KEYCHAIN=true:")
            print("  ironmesh keys keychain-store --name <node>")
            print("  export IRONMESH_PASSPHRASE_KEYCHAIN=true")
        else:
            print("OS keychain backend: NOT AVAILABLE")
            print("Reason: either `keyring` is not installed "
                  "(pip install ironmesh[keychain]) or no system backend "
                  "is configured (Linux: kwallet/gnome-keyring/etc.).")
            return 1
    else:
        print("Usage: ironmesh keys [generate|info|"
              "keychain-store|keychain-clear|keychain-check] [args...]")

    return 0


def cmd_backup(args):
    """Create an encrypted backup archive."""
    from ironmesh import backup as backup_mod
    passphrase = getpass.getpass("Backup passphrase (min 12 chars): ")
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        print("Passphrases do not match")
        return 1
    try:
        backup_mod.create_backup(
            out_path=args.out,
            passphrase=passphrase,
            keys_path=args.keys_path,
            trust_path=args.trust_path,
            audit_path=args.audit_path,
        )
        print(f"Backup created: {args.out}")
        return 0
    except ValueError as e:
        print(f"Error: {e}")
        return 1


def cmd_restore(args):
    """Restore from an encrypted backup archive."""
    from ironmesh import backup as backup_mod
    passphrase = getpass.getpass("Backup passphrase: ")
    try:
        manifest = backup_mod.restore_backup(
            in_path=args.in_path,
            passphrase=passphrase,
            keys_path=args.keys_path,
            trust_path=args.trust_path,
            audit_path=args.audit_path,
            force=args.force,
        )
        print(f"Restored backup (created {manifest.get('created_at')})")
        print(f"  node_id: {manifest.get('node_id')}")
        print(f"  includes: {manifest.get('includes')}")
        return 0
    except ValueError as e:
        print(f"Error: {e}")
        return 1


def cmd_audit(args):
    """Audit log tools."""
    from ironmesh import audit as audit_mod
    sub = getattr(args, "audit_command", None)

    if sub == "verify":
        path = os.path.expanduser(args.path)
        if args.archives:
            ok, checked, first_bad = audit_mod.verify_archived_chain(path)
        else:
            ok, checked, first_bad = audit_mod.verify_chain(path)
        if ok:
            print(f"OK — verified {checked} entries")
            return 0
        # Tamper detected. With --rotate-corrupt, archive the bad chain
        # and start a fresh one so the daemon can resume writing without
        # the read-only latch tripping. Without the flag, exit non-zero
        # so operators can triage manually.
        rotate = bool(getattr(args, "rotate_corrupt", False))
        if not rotate:
            print(f"TAMPER DETECTED at entry {first_bad} (checked {checked})")
            return 1
        # Rotate: rename the corrupted file aside, leave a sealing
        # advisory in its place so a fresh chain begins on next write.
        import time as _time
        ts = _time.strftime("%Y-%m-%dT%H-%M-%S", _time.localtime())
        archived = f"{path}.corrupted-{ts}"
        try:
            os.rename(path, archived)
        except FileNotFoundError:
            print(f"TAMPER DETECTED but log file vanished at {path}")
            return 1
        except OSError as e:
            print(f"TAMPER DETECTED at entry {first_bad}; rotate failed: {e}")
            return 1
        print(
            f"TAMPER DETECTED at entry {first_bad} (checked {checked})\n"
            f"Corrupted log archived to: {archived}\n"
            f"Fresh chain will start on next daemon write to: {path}\n"
            f"Restart any daemons sharing this audit path."
        )
        return 0

    if sub == "export":
        from ironmesh import keys as ew_keys
        kp_pass = args.keys_passphrase or os.environ.get("IRONMESH_PASSPHRASE")
        if not kp_pass:
            kp_pass = getpass.getpass("Identity key passphrase: ")
        try:
            keypair = ew_keys.load_keys(args.keys_path, passphrase=kp_pass)
        except Exception as e:
            print(f"Failed to load keys: {e}")
            return 1
        try:
            audit_mod.export_signed(
                audit_path=os.path.expanduser(args.path),
                out_path=args.out,
                signing_key=keypair.get_signing_key(),
                signer_fingerprint=keypair.get_fingerprint(),
            )
            print(f"Exported signed audit bundle to {args.out}")
            return 0
        except Exception as e:
            print(f"Export failed: {e}")
            return 1

    if sub == "verify-export":
        try:
            result = audit_mod.verify_signed_export(args.file)
            if result["valid"]:
                print(f"OK — signature valid from {result['signer']}")
                print(f"  entries: {result['entry_count']}")
                print(f"  chain:   {'intact' if result['chain_ok'] else 'BROKEN'}")
                return 0 if result["chain_ok"] else 1
            else:
                print(f"INVALID signature: {result.get('error')}")
                return 1
        except Exception as e:
            print(f"Verify failed: {e}")
            return 1

    if sub == "tail":
        # v0.8.5.7: filtered audit tail for operator triage.
        import json as _json
        path = os.path.expanduser(args.path)
        if not os.path.exists(path):
            print(f"No audit log at {path}")
            return 1
        since_ts = _parse_since(args.since) if args.since else 0.0
        events = None
        if args.event:
            events = {s.strip() for s in args.event.split(",") if s.strip()}
        out = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = _json.loads(line)
                    except Exception:
                        continue  # torn / malformed lines: skip
                    if since_ts and d.get("timestamp", 0) < since_ts:
                        continue
                    if events and d.get("event") not in events:
                        continue
                    out.append(d)
        except Exception as e:
            print(f"Failed to read audit log: {e}")
            return 1
        out = out[-int(args.limit):] if args.limit else out
        if args.json:
            for d in out:
                print(_json.dumps(d, default=str))
            return 0
        if not out:
            print("(no entries match)")
            return 0
        for d in out:
            ts = time.strftime("%Y-%m-%d %H:%M:%S",
                               time.localtime(d.get("timestamp", 0)))
            event = d.get("event", "?")
            details = d.get("details") or {}
            # Compact one-line format: ts  EVENT  key=val key=val ...
            pairs = " ".join(f"{k}={v!r}" for k, v in details.items()
                             if not isinstance(v, (list, dict))
                             or len(str(v)) < 60)
            print(f"{ts}  {event:<28s}  {pairs}")
        return 0

    if sub == "stats":
        # v0.8.5.7: summary counts by event type over a recent window.
        import json as _json
        from collections import Counter
        path = os.path.expanduser(args.path)
        if not os.path.exists(path):
            print(f"No audit log at {path}")
            return 1
        since_ts = _parse_since(args.since)
        counter: Counter = Counter()
        total = 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = _json.loads(line)
                    except Exception:
                        continue
                    if since_ts and d.get("timestamp", 0) < since_ts:
                        continue
                    counter[d.get("event", "?")] += 1
                    total += 1
        except Exception as e:
            print(f"Failed to read audit log: {e}")
            return 1
        if total == 0:
            print(f"No entries in the last {args.since}.")
            return 0
        print(f"Audit events in the last {args.since}: {total} total")
        print("-" * 52)
        for event, n in counter.most_common():
            print(f"  {n:>6d}  {event}")
        return 0

    print("Usage: ironmesh audit [verify|export|verify-export|tail|stats]")
    return 1


def _parse_since(s: str) -> float:
    """Parse a relative window (e.g. 1h, 15m, 2d) or ISO-8601 into a
    POSIX timestamp cutoff. Returns 0.0 for 'all time' / unparseable.
    """
    if not s:
        return 0.0
    s = s.strip()
    # Relative: <N>[smhd]
    if len(s) >= 2 and s[:-1].isdigit() and s[-1] in "smhd":
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[s[-1]]
        return time.time() - int(s[:-1]) * mult
    # Absolute ISO-ish
    try:
        from datetime import datetime
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return 0.0


def cmd_doctor(args):
    """v0.8.5.2: one-shot diagnostic. Prints a checklist and exits non-zero
    on any failed check. Designed to be safe to run on a host with a live
    daemon (read-only, no mutations)."""
    import socket
    import sqlite3

    keys_path = os.path.expanduser(args.keys_path)
    db_path = os.path.expanduser(args.db_path)
    trust_path = os.path.expanduser(
        args.trust_path or "~/.ironmesh/known_peers.json"
    )

    failures = 0
    print("ironmesh doctor — IronMesh installation diagnostic")
    print("=" * 60)

    # 1. Identity key file readable + decryptable.
    print(f"[1/7] Identity key file: {keys_path}")
    if not os.path.exists(keys_path):
        print("      FAIL — file does not exist (run 'ironmesh keys generate')")
        failures += 1
        keypair = None
    else:
        keypair = None
        try:
            from ironmesh.keys import load_keys
            pp = args.keys_passphrase or os.environ.get("IRONMESH_PASSPHRASE")
            # Try in order: (a) the provided passphrase, (b) no passphrase
            # (plaintext key file), (c) interactive prompt IF there's a tty.
            # Never hang on a closed stdin — doctor is often run headless.
            attempt_errors = []
            for pp_try in (pp, None):
                try:
                    keypair = load_keys(keys_path, passphrase=pp_try)
                    break
                except Exception as e:
                    attempt_errors.append(str(e))
            if keypair is None and sys.stdin.isatty():
                try:
                    prompt_pp = getpass.getpass("      Identity key passphrase: ")
                    keypair = load_keys(keys_path, passphrase=prompt_pp)
                except Exception as e:
                    attempt_errors.append(str(e))
            if keypair is not None:
                print(f"      OK — fingerprint {keypair.get_fingerprint()}")
            else:
                print(f"      FAIL — could not decrypt key file. "
                      f"Set IRONMESH_PASSPHRASE or pass --keys-passphrase. "
                      f"(tried errors: {attempt_errors[-1]})")
                failures += 1
        except Exception as e:
            print(f"      FAIL — {e}")
            failures += 1

    # 2. Trust file readable + integrity check passes.
    print(f"[2/7] Trust store: {trust_path}")
    if not os.path.exists(trust_path):
        print("      OK — file does not exist yet (will be created on first peer)")
    elif keypair is None:
        print("      SKIP — keys did not load")
    else:
        try:
            from ironmesh.trust import TrustStore
            ts = TrustStore(agent_key=keypair.ed25519_secret[:32], path=trust_path)
            n = len(ts._peers)
            n_pending = sum(1 for p in ts.list_peers() if p.get("trust_state") == "pending")
            n_blocked = sum(1 for p in ts.list_peers() if p.get("trust_state") == "blocked")
            if n == 0 and os.path.getsize(trust_path) > 100:
                print("      WARN — trust file exists but loaded 0 peers (MAC failure?). "
                      "Check the daemon's CRITICAL log lines, and consider --trust-path "
                      "if multiple daemons share this host.")
                failures += 1
            else:
                print(f"      OK — {n} pinned peers ({n_pending} pending, {n_blocked} blocked)")
        except Exception as e:
            print(f"      FAIL — {e}")
            failures += 1

    # 3. SQLite schema version.
    print(f"[3/7] Message store: {db_path}")
    if not os.path.exists(db_path):
        print("      OK — DB does not exist yet (will be created at daemon startup)")
    else:
        try:
            conn = sqlite3.connect(db_path)
            try:
                cur = conn.execute("SELECT value FROM _meta WHERE key='schema_version'")
                row = cur.fetchone()
                ver = int(row[0]) if row else 0
            finally:
                conn.close()
            if ver < 3:
                print(f"      WARN — schema v{ver} (latest is v3 in v0.8.5+). "
                      f"Will auto-migrate on next daemon start.")
            else:
                print(f"      OK — schema v{ver}")
        except Exception as e:
            print(f"      FAIL — {e}")
            failures += 1

    # 4. Pending-trust queue health.
    print("[4/7] Pending-trust queue (SQLite v3 only):")
    if not os.path.exists(db_path):
        print("      SKIP — DB not present")
    else:
        try:
            conn = sqlite3.connect(db_path)
            try:
                # Table only exists at schema v3.
                cur = conn.execute(
                    "SELECT source_node_id, COUNT(*) FROM pending_trust_messages "
                    "GROUP BY source_node_id"
                )
                rows = cur.fetchall()
            except sqlite3.OperationalError:
                rows = None
            finally:
                conn.close()
            if rows is None:
                print("      OK — table not present (schema pre-v3)")
            elif not rows:
                print("      OK — 0 messages awaiting promotion")
            else:
                total = sum(r[1] for r in rows)
                print(f"      INFO — {total} message(s) queued across {len(rows)} peer(s):")
                for nid, ct in rows[:5]:
                    print(f"        {nid[:16]}…  count={ct}")
        except Exception as e:
            print(f"      FAIL — {e}")
            failures += 1

    # 5. Gate flag + queue cap from env (if a daemon were started now).
    print("[5/7] Gate environment:")
    gate_env = os.environ.get("IRONMESH_REQUIRE_MSG_PROMOTION", "").lower()
    cap_env = os.environ.get("IRONMESH_PENDING_QUEUE_CAP")
    trust_env = os.environ.get("IRONMESH_TRUST_PATH")
    print(f"      IRONMESH_REQUIRE_MSG_PROMOTION = "
          f"{'on' if gate_env in ('1','true','yes') else 'off'}{' (' + gate_env + ')' if gate_env else ''}")
    print(f"      IRONMESH_PENDING_QUEUE_CAP     = {cap_env or '100 (default)'}")
    print(f"      IRONMESH_TRUST_PATH            = {trust_env or '(default)'}")
    print("      OK — env reported (informational; CLI flags override env)")

    # 6. Port availability.
    print(f"[6/7] Port {args.port} on {args.bind}:")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((args.bind, args.port))
        sock.close()
        print("      OK — port is free (no daemon currently bound)")
    except OSError as e:
        sock.close()
        # In-use can mean a healthy daemon — informational, not a failure.
        print(f"      INFO — bind failed ({e}); a daemon may already be running here")

    # 7. Audit log presence + chain integrity (light check).
    # Derive the audit log path from --db-path so the code look at the file
    # the target daemon actually writes to. Without this derivation,
    # doctor on a custom-db-path daemon would inspect ~/.ironmesh/audit.log
    # while the daemon writes to <db-dir>/audit.log — and report on a
    # different log entirely.
    audit_path = os.path.join(os.path.dirname(db_path), "audit.log")
    print(f"[7/7] Audit log: {audit_path}")
    if not os.path.exists(audit_path):
        print("      OK — audit log does not exist yet (will be created on daemon start)")
    else:
        try:
            from ironmesh.audit import verify_chain
            ok, entries, first_bad = verify_chain(
                audit_path,
                keys_path=keys_path,
                keys_passphrase=args.keys_passphrase
                or os.environ.get("IRONMESH_PASSPHRASE"),
            )
            if ok:
                print(f"      OK — chain verifies clean ({entries} entries)")
            else:
                print(
                    f"      WARN — chain TAMPER at entry {first_bad} "
                    f"(of {entries} scanned). New writes from this start "
                    f"forward will chain cleanly. See OPERATOR_RUNBOOK §4."
                )
                failures += 1
        except ImportError:
            print("      SKIP — verify_chain not available in this build")
        except Exception as e:
            print(f"      FAIL — {e}")
            failures += 1

    print("=" * 60)
    if failures == 0:
        print("ALL CHECKS PASSED")
        return 0
    print(f"{failures} CHECK(S) FAILED — see above for remediation")
    return 1


def cmd_session(args):
    """Session management commands."""
    sub = getattr(args, "session_command", None)
    if sub == "rotate":
        import asyncio
        import json as _json
        try:
            import websockets
        except ImportError:
            print("Error: websockets package required")
            return 1

        async def do_rotate():
            url = f"{args.gui_url}?token={args.token}"
            async with websockets.connect(url, open_timeout=5) as ws:
                await asyncio.wait_for(ws.recv(), timeout=5)  # snapshot
                await ws.send(_json.dumps({
                    "action": "rotate_session",
                    "peer_id": args.peer_id,
                }))
                resp = await asyncio.wait_for(ws.recv(), timeout=10)
                data = _json.loads(resp)
                if data.get("type") == "rotate_ack":
                    print(f"Session rotation triggered for {args.peer_id}")
                    return 0
                else:
                    print(f"Error: {data}")
                    return 1

        return asyncio.run(do_rotate())

    print("Usage: ironmesh session rotate <peer_id> --token <token>")
    return 1


def cmd_demo(args):
    """Spawn two local agents and exchange an encrypted ping.

    The demo connects the two agents directly by host:port rather than
    relying on mDNS, so it's reliable on Windows (where zeroconf over
    localhost is inconsistent). No persistent state is created.
    Returns 0 on success, 1 on timeout or handshake failure.
    """
    import tempfile
    import time

    from ironmesh.agent import Agent

    setup_logging("ERROR")
    # The demo legitimately generates some cosmetic noise on Windows
    # (websocket scan probes, one-time trust-store init). Silence it.
    for noisy in ("websockets", "websockets.server", "websockets.client",
                  "ironmesh.bridge", "ironmesh.discovery"):
        logging.getLogger(noisy).setLevel(logging.CRITICAL)
    logging.getLogger("ironmesh.trust").setLevel(logging.CRITICAL + 1)

    # Each agent also binds port+1 for its metrics endpoint, so the two
    # agents need at least 2 ports of headroom between them.
    port_a = args.port
    port_b = args.port + 2
    passphrase = "ironmesh-demo-passphrase-ephemeral"

    print(f"IronMesh demo -- two agents on 127.0.0.1:{port_a} and :{port_b}",
          flush=True)
    print("(temporary keys in a temp dir; no state written to ~/.ironmesh)",
          flush=True)
    print(flush=True)

    with tempfile.TemporaryDirectory(
        prefix="ironmesh-demo-", ignore_cleanup_errors=True,
    ) as tmp:
        def _daemon_kwargs(tag: str, allowed: list[str]) -> dict:
            root = os.path.join(tmp, tag)
            os.makedirs(root, exist_ok=True)
            return dict(
                keys_path=os.path.join(root, "keys.json"),
                db_path=os.path.join(root, "data.db"),
                routes_path=os.path.join(root, "routes.json"),
                capabilities_path=os.path.join(root, "capabilities.json"),
                allowed_peers=allowed,
            )

        alice = Agent(
            "demo-alice", port=port_a, passphrase=passphrase,
            open_discovery=False, allow_plaintext=True,
            gui=args.gui,
            **_daemon_kwargs("alice", allowed=["demo-bob"]),
        )
        bob = Agent(
            "demo-bob", port=port_b, passphrase=passphrase,
            open_discovery=False, allow_plaintext=True,
            **_daemon_kwargs("bob", allowed=["demo-alice"]),
        )

        received: list[tuple[float, bytes]] = []

        @bob.on_message()
        def _on_msg(peer_id: str, payload: bytes) -> None:
            received.append((time.monotonic(), payload))

        alice.run(foreground=False)
        bob.run(foreground=False)

        try:
            # mDNS on the local LAN will bring the two agents together;
            # the allowed_peers filter keeps them from dialing anyone else.
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                bob_peer = alice.peer_by_name("demo-bob")
                alice_peer = bob.peer_by_name("demo-alice")
                if bob_peer and alice_peer:
                    break
                time.sleep(0.25)
            else:
                print(f"[fail] peers did not handshake within "
                      f"{args.timeout:.0f}s.", flush=True)
                return 1

            print("[ok]   handshake complete (encrypted session established).",
                  flush=True)

            t0 = time.monotonic()
            alice.send_sync("demo-bob", b"ping")
            reply_deadline = time.monotonic() + min(10.0, args.timeout)
            while time.monotonic() < reply_deadline and not received:
                time.sleep(0.02)

            if not received:
                print("[fail] bob did not receive the ping.", flush=True)
                return 1

            t1, payload = received[0]
            latency_ms = (t1 - t0) * 1000
            print(f"[ok]   bob received {payload!r} in {latency_ms:.1f} ms.",
                  flush=True)
            print(flush=True)

            if args.gui:
                gui_port = port_a + 1
                token = alice.daemon._gui_token
                print("Dashboard URL (token on its own line so terminals can't crop it):",
                      flush=True)
                print(f"  http://127.0.0.1:{gui_port}/", flush=True)
                print(flush=True)
                print("GUI token:", flush=True)
                print(f"  {token}", flush=True)
                print(flush=True)
                print("Full URL to paste into a browser:", flush=True)
                print(f"  http://127.0.0.1:{gui_port}/?token={token}",
                      flush=True)
                print(flush=True)
                print("Both agents stay up. Ctrl-C to stop.", flush=True)
                try:
                    while True:
                        time.sleep(1.0)
                except KeyboardInterrupt:
                    print(flush=True)
                return 0

            print("That's an NaCl SecretBox + Ed25519 session between two",
                  flush=True)
            print("agents. Next: examples/ollama_swarm.py for a real demo.",
                  flush=True)
            return 0
        finally:
            # KeyboardInterrupt during the 5s stop-timeout is fine to
            # swallow; the BridgeDaemon's loop-exception handler takes
            # care of the Windows proactor shutdown race.
            for stop_fn in (alice.stop, bob.stop):
                try:
                    stop_fn()
                except KeyboardInterrupt:
                    pass


def cmd_upgrade(args):
    """Check PyPI for a newer version of ironmesh.

    Network-only — does not actually upgrade. Prints the exact pip /
    docker commands to run if a newer version is available. Exits 0
    if up to date or if the user is on a *newer* version than PyPI's
    latest (e.g. running from a local git checkout). Exits 1 only on
    network failure or if PyPI returns a malformed response.
    """
    import json as _json
    import urllib.error
    import urllib.request

    from ironmesh import __version__ as installed

    timeout = float(getattr(args, "timeout", 5.0))
    as_json = bool(getattr(args, "json", False))

    url = "https://pypi.org/pypi/ironmesh/json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            payload = _json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if as_json:
            print(_json.dumps({
                "installed": installed,
                "latest": None,
                "status": "error",
                "error": str(exc),
            }))
        else:
            print(f"ironmesh upgrade: could not reach PyPI ({exc})")
        return 1
    except (ValueError, KeyError) as exc:
        if as_json:
            print(_json.dumps({
                "installed": installed,
                "latest": None,
                "status": "error",
                "error": f"PyPI returned malformed metadata: {exc}",
            }))
        else:
            print(f"ironmesh upgrade: PyPI returned malformed metadata ({exc})")
        return 1

    latest = payload.get("info", {}).get("version", "")
    if not latest:
        if as_json:
            print(_json.dumps({
                "installed": installed,
                "latest": None,
                "status": "error",
                "error": "no version field in PyPI response",
            }))
        else:
            print("ironmesh upgrade: PyPI response did not include a version")
        return 1

    # Tuple compare so 0.8.5.10 > 0.8.5.9 (lexicographic compare would fail)
    def _vt(v):
        out = []
        for chunk in v.split("."):
            try:
                out.append(int(chunk))
            except ValueError:
                out.append(chunk)
        return tuple(out)

    try:
        is_newer = _vt(latest) > _vt(installed)
        is_older = _vt(latest) < _vt(installed)
    except TypeError:
        # Fall back to string compare on unparseable mixed versions
        is_newer = latest > installed
        is_older = latest < installed

    if is_newer:
        status = "outdated"
    elif is_older:
        status = "ahead"
    else:
        status = "current"

    if as_json:
        print(_json.dumps({
            "installed": installed,
            "latest": latest,
            "status": status,
        }))
        return 0

    print(f"Installed: ironmesh=={installed}")
    print(f"Latest:    ironmesh=={latest}")
    if status == "outdated":
        print()
        print(f"A newer release is available: v{latest}")
        print()
        print("Upgrade with one of:")
        print(f"  pip install -U ironmesh=={latest}")
        print(f"  docker pull wiztheagent/ironmesh:{latest}")
        print()
        print("Release notes:")
        print(f"  https://github.com/WizTheAgent/IronMesh/releases/tag/v{latest}")
    elif status == "ahead":
        print()
        print(f"You are on v{installed}, ahead of PyPI's latest v{latest}.")
        print("(Probably running from a local git checkout — no action needed.)")
    else:
        print()
        print("Up to date.")
    return 0


def cmd_setup(args):
    """Interactive first-run wizard.

    Walks the operator through node name, port, passphrase, key
    generation, peer allowlist, and pending-trust gate. Writes the
    passphrase file (chmod 600) and the encrypted keypair, prints the
    exact ironmesh run command to start the daemon.

    --non-interactive runs the same flow without prompts using the
    flag values + safe defaults; required for CI / automation.
    """
    import os
    import socket
    import stat
    from pathlib import Path

    interactive = not args.non_interactive

    def _prompt(label, default=None):
        if not interactive:
            return default
        suffix = f" [{default}]" if default is not None else ""
        try:
            value = input(f"{label}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        return value or default

    def _yes_no(label, default=True):
        if not interactive:
            return default
        suffix = " [Y/n]" if default else " [y/N]"
        try:
            ans = input(f"{label}{suffix}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not ans:
            return default
        return ans in ("y", "yes")

    print()
    print("IronMesh first-run setup")
    print("=" * 40)
    print()
    if interactive:
        print("This wizard configures one IronMesh node end-to-end:")
        print("  1. Pick a node name and port")
        print("  2. Set the shared passphrase (must match every peer)")
        print("  3. Generate an encrypted identity keypair")
        print("  4. Optionally enable the pending-trust message gate")
        print()
        print("Press Ctrl-C at any time to abort. No files are written")
        print("until the final confirmation.")
        print()

    # 1. Node name
    default_name = args.name or socket.gethostname().split(".")[0]
    name = _prompt("Node name", default_name)
    if not name:
        print("ERROR: node name is required.")
        return 1

    # 2. Port
    default_port = args.port or 8765
    port_raw = _prompt("Port", str(default_port))
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        print(f"ERROR: invalid port '{port_raw}'.")
        return 1

    # 3. Passphrase
    pass_path = Path(os.path.expanduser(args.passphrase_file))
    pass_existing = pass_path.is_file()
    write_pass = True
    passphrase = None

    if pass_existing and not args.force:
        if interactive:
            keep = _yes_no(
                f"Found existing passphrase at {pass_path} — keep it?",
                default=True,
            )
        else:
            keep = True
        if keep:
            write_pass = False
            try:
                passphrase = pass_path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                print(f"ERROR: cannot read existing passphrase file: {exc}")
                return 1

    if write_pass:
        if not interactive:
            if args.passphrase_from_env:
                passphrase = os.environ.get("IRONMESH_SETUP_PASSPHRASE", "")
                if not passphrase:
                    print("ERROR: --passphrase-from-env set but "
                          "IRONMESH_SETUP_PASSPHRASE is empty.")
                    return 1
            elif pass_existing:
                # Already covered above; should not reach here
                pass
            else:
                print("ERROR: --non-interactive requires either an existing "
                      "passphrase file at --passphrase-file OR "
                      "--passphrase-from-env with IRONMESH_SETUP_PASSPHRASE.")
                return 1
        else:
            print()
            print("Set the shared passphrase. Every peer on the mesh must")
            print("use this exact passphrase. Minimum 12 characters.")
            while True:
                p1 = getpass.getpass("Passphrase: ")
                if len(p1) < 12:
                    print("Too short — minimum 12 characters.")
                    continue
                p2 = getpass.getpass("Confirm:    ")
                if p1 != p2:
                    print("Passphrases do not match. Try again.")
                    continue
                passphrase = p1
                break

        # Write the passphrase file with strict permissions
        pass_path.parent.mkdir(parents=True, exist_ok=True)
        pass_path.write_text(passphrase, encoding="utf-8")
        try:
            pass_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            # Windows / non-POSIX filesystems may reject chmod; skip silently
            pass

    if not passphrase or len(passphrase) < 12:
        print("ERROR: passphrase is missing or too short.")
        return 1

    # 4. Identity keys
    keys_path = Path(os.path.expanduser(args.keys_path))
    write_keys = True
    if keys_path.is_file() and not args.force:
        if interactive:
            keep_keys = _yes_no(
                f"Found existing keypair at {keys_path} — keep it?",
                default=True,
            )
        else:
            keep_keys = True
        if keep_keys:
            write_keys = False

    if write_keys:
        from ironmesh.keys import generate_keypair, save_keys
        keys_path.parent.mkdir(parents=True, exist_ok=True)
        keypair = generate_keypair()
        save_keys(keypair, str(keys_path), passphrase=passphrase)
        try:
            keys_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            pass
        fingerprint = keypair.get_fingerprint()
    else:
        from ironmesh.keys import load_keys
        try:
            keypair = load_keys(str(keys_path), passphrase=passphrase)
            fingerprint = keypair.get_fingerprint()
        except Exception as exc:
            print(f"ERROR: could not load existing keypair: {exc}")
            return 1

    # 5. Allowed peers
    if args.allowed_peers is not None:
        allowed_peers = args.allowed_peers
    else:
        allowed_peers = _prompt(
            "Allowed peer names (comma-separated, blank = none)",
            default="",
        )
        if allowed_peers is None:
            allowed_peers = ""

    # 6. Pending-trust gate
    if args.enable_trust_gate:
        gate = True
    elif args.no_trust_gate:
        gate = False
    elif interactive:
        print()
        print("Pending-trust gate: when enabled, messages from any peer")
        print("you have not yet promoted are queued at the daemon and")
        print("require operator approval before delivery. Becomes the")
        print("default in v0.9.")
        gate = _yes_no("Enable the pending-trust gate now?", default=True)
    else:
        gate = True

    # Summary
    print()
    print("Setup complete")
    print("=" * 40)
    print(f"  Node name        : {name}")
    print(f"  Port             : {port}")
    print(f"  Passphrase file  : {pass_path}  "
          f"{'(new)' if write_pass else '(existing)'}")
    print(f"  Identity keys    : {keys_path}  "
          f"{'(new)' if write_keys else '(existing)'}")
    print(f"  Fingerprint      : {fingerprint}")
    if allowed_peers:
        print(f"  Allowed peers    : {allowed_peers}")
    else:
        print("  Allowed peers    : (none — default-deny)")
    print(f"  Pending-trust    : {'enabled' if gate else 'disabled (opt-in)'}")
    print()

    # Build the run command
    run_cmd = [
        "ironmesh run",
        f"--name {name}",
        f"--port {port}",
        f"--passphrase-file {pass_path}",
        f"--keys-path {keys_path}",
    ]
    if allowed_peers:
        run_cmd.append(f"--allowed-peers {allowed_peers}")
    if gate:
        run_cmd.append("--require-message-promotion")

    print("Start the daemon with:")
    print()
    print("  " + " \\\n      ".join(run_cmd))
    print()
    print("Or set the env var once and shorten the command:")
    print(f"  export IRONMESH_PASSPHRASE_FILE={pass_path}")
    if gate:
        print("  export IRONMESH_REQUIRE_MSG_PROMOTION=true")
    print(f"  ironmesh run --name {name} --port {port}"
          f"{' --allowed-peers ' + allowed_peers if allowed_peers else ''}")
    print()
    print("Next steps:")
    print("  - Repeat this wizard on a second machine with the SAME")
    print("    passphrase file (copy it via USB / age / paper).")
    print("  - Add each node's name to the other's --allowed-peers.")
    print("  - See docs/QUICKSTART.md for the full walkthrough,")
    print("    docs/deployments/homelab.md for a CrewAI + Ollama recipe,")
    print("    docs/NAT_TRAVERSAL.md for cross-network setups.")
    return 0


def _ensure_utf8_stdio() -> None:
    """Reconfigure stdout/stderr to UTF-8 if the inherited locale would
    otherwise crash on the unicode characters in the help/log strings.

    On Linux hosts where ``LANG=en_US`` (no encoding suffix) is set,
    Python 3 defaults stdout to latin-1; an em-dash in argparse help
    output then raises UnicodeEncodeError before the user sees anything.
    Fix: set the streams to UTF-8 with ``errors='replace'`` so the CLI
    is locale-agnostic.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(stream, "reconfigure"):
                cur = (getattr(stream, "encoding", "") or "").lower()
                if not cur.startswith("utf"):
                    stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            # Reconfiguration is best-effort; if the stream doesn't
            # support it (some test runners wrap stdout), let it pass.
            pass


def main():
    _ensure_utf8_stdio()
    args = parse_args()
    command = getattr(args, "command", None)

    if command == "trust":
        return cmd_trust(args)
    elif command == "keys":
        return cmd_keys(args)
    elif command == "backup":
        return cmd_backup(args)
    elif command == "restore":
        return cmd_restore(args)
    elif command == "audit":
        return cmd_audit(args)
    elif command == "doctor":
        return cmd_doctor(args)
    elif command == "session":
        return cmd_session(args)
    elif command == "run":
        return cmd_run(args)
    elif command == "demo":
        return cmd_demo(args)
    elif command == "setup":
        return cmd_setup(args)
    elif command == "upgrade":
        return cmd_upgrade(args)
    elif args.name:
        # Backward compatibility: no subcommand but --name given -> run
        return cmd_run(args)
    else:
        print("IronMesh — Zero-config encrypted A2A protocol\n")
        print("Usage:")
        print("  ironmesh demo                          # spawn two agents on localhost and exchange a ping")
        print("  ironmesh setup                         # interactive first-run wizard")
        print("  ironmesh upgrade                       # check PyPI for a newer release")
        print("  ironmesh run --name <agent> [--port 8765]")
        print("  ironmesh trust list")
        print("  ironmesh trust revoke <node_id>")
        print("  ironmesh keys generate [--path <path>] [--passphrase <pass>]")
        print("  ironmesh keys info [--path <path>]")
        print("  ironmesh backup --out <file>")
        print("  ironmesh restore --in <file> [--force]")
        print("  ironmesh audit verify [--path <path>] [--archives]")
        print("  ironmesh audit export --out <file>")
        print("  ironmesh audit verify-export <file>")
        print("  ironmesh doctor [--port <port>] [--trust-path <path>]")
        print("  ironmesh session rotate <peer_id> --token <token>")
        return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
