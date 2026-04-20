#!/usr/bin/env python3
"""IronMesh CLI — Command-line entry point for the bridge daemon.

Supports bridge daemon, key management, trust management, and metrics.
"""

import argparse
import getpass
import logging
import os
import sys


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
    trust_sub = trust_parser.add_subparsers(dest="trust_command")
    trust_sub.add_parser("list", help="List trusted peers")
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
        help="Flip a peer's trust state (pending|trusted|blocked)",
    )
    set_state_parser.add_argument("node_id", help="Node ID to update")
    set_state_parser.add_argument("state",
                                   choices=["pending", "trusted", "blocked"],
                                   help="New trust state")

    # --- keys ---
    keys_parser = sub.add_parser("keys", help="Key management")
    keys_sub = keys_parser.add_subparsers(dest="keys_command")
    gen_parser = keys_sub.add_parser("generate", help="Generate new keypair")
    gen_parser.add_argument("--path", default="~/.ironmesh/keys.json")
    gen_parser.add_argument("--passphrase", default=None, help="Encrypt key file with passphrase")
    info_parser = keys_sub.add_parser("info", help="Show key info")
    info_parser.add_argument("--path", default="~/.ironmesh/keys.json")
    info_parser.add_argument("--passphrase", default=None)

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
    ae = audit_sub.add_parser("export", help="Export signed audit log bundle")
    ae.add_argument("--path", default="~/.ironmesh/audit.log")
    ae.add_argument("--out", required=True, help="Output JSON file")
    ae.add_argument("--keys-path", default="~/.ironmesh/keys.json")
    ae.add_argument("--keys-passphrase", default=None)
    avx = audit_sub.add_parser("verify-export", help="Verify a signed audit export")
    avx.add_argument("file", help="Signed export JSON file")

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


# v0.8.5.2-R5: maximum bytes read from a passphrase file. A legitimate
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


def get_passphrase():
    """Obtain passphrase from secure sources only.

    Priority: --passphrase-file > IRONMESH_PASSPHRASE_FILE > IRONMESH_PASSPHRASE > getpass.
    Never accepts passphrase via CLI argv (visible in ps aux).
    """
    # Prefer IRONMESH_PASSPHRASE_FILE over env var (avoids /proc/environ exposure).
    passphrase_file = os.environ.get("IRONMESH_PASSPHRASE_FILE")
    if passphrase_file:
        try:
            passphrase = _read_passphrase_file_safe(passphrase_file)
            if passphrase:
                return passphrase
        except (IOError, OSError, ValueError) as e:
            print(f"ERROR: Cannot read passphrase file {passphrase_file}: {e}")
            sys.exit(1)
    env = os.environ.get("IRONMESH_PASSPHRASE")
    if env:
        # Warn about env var risk
        print("WARNING: Reading passphrase from IRONMESH_PASSPHRASE env var.")
        print("         Environment variables may be visible via /proc. Prefer IRONMESH_PASSPHRASE_FILE.\n")
        return env
    # Interactive prompt via getpass (hidden input, not in process list)
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
    print("       1. --passphrase-file <path>  (file, chmod 600)")
    print("       2. IRONMESH_PASSPHRASE_FILE  (env var pointing to file)")
    print("       3. Interactive prompt         (getpass, not in ps aux)")
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


def cmd_run(args):
    """Start the bridge daemon."""
    name = getattr(args, "name", None)
    if not name:
        print("ERROR: --name is required. Usage: ironmesh run --name alice")
        return 1

    log_level = getattr(args, "log_level", "INFO")
    if getattr(args, "debug", False):
        log_level = "DEBUG"
    setup_logging(
        log_level,
        getattr(args, "log_file", None),
        getattr(args, "log_format", "text"),
    )
    log = logging.getLogger("ironmesh.cli")

    # Support --passphrase-file as highest priority
    passphrase_file = getattr(args, "passphrase_file", None)
    if passphrase_file:
        try:
            passphrase = _read_passphrase_file_safe(passphrase_file)
        except (IOError, OSError, ValueError) as e:
            print(f"ERROR: Cannot read passphrase file {passphrase_file}: {e}")
            return 1
    else:
        passphrase = get_passphrase()

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

    trust_cmd = getattr(args, "trust_command", None)
    if trust_cmd == "list":
        peers = store.list_peers()
        if not peers:
            print("No trusted peers.")
            return 0
        print(f"{'Node ID':<20s} {'Fingerprint':<18s} {'State':<10s} {'First Seen':<24s} {'Last Seen':<24s}")
        print("-" * 96)
        import time
        for p in peers:
            first = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p["first_seen"])) if p["first_seen"] else "N/A"
            last = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p["last_seen"])) if p["last_seen"] else "N/A"
            state = p.get("trust_state", "trusted")
            print(f"{p['node_id']:<20s} {p['fingerprint']:<18s} {state:<10s} {first:<24s} {last:<24s}")
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
        import time
        for r in revoked:
            ts = time.strftime("%Y-%m-%d %H:%M:%S",
                               time.localtime(r.get("timestamp", 0)))
            print(f"{r['node_id']:<22s} {r.get('revoker','?'):<22s} "
                  f"{ts:<20s} {r.get('reason','')}")
    elif trust_cmd == "set-state":
        node_id = args.node_id
        new_state = args.state
        if store.set_trust_state(node_id, new_state):
            print(f"Trust state for {node_id} -> {new_state}")
            print("Note: a running daemon won't pick this up until it next "
                  "constructs a TrustStore (every gate evaluation does this, "
                  "so the change applies on the next inbound MSG).")
            return 0
        else:
            print(f"Peer {node_id} not in trust store. Run 'ironmesh trust list' to see known peers.")
            return 1
    else:
        print("Usage: ironmesh trust [list|revoke <node_id>|list-revoked|"
              "set-state <node_id> <pending|trusted|blocked>]")

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
    else:
        print("Usage: ironmesh keys [generate|info] --path <path>")

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
        else:
            print(f"TAMPER DETECTED at entry {first_bad} (checked {checked})")
            return 1

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

    print("Usage: ironmesh audit [verify|export|verify-export]")
    return 1


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
    audit_path = os.path.expanduser("~/.ironmesh/audit.log")
    print(f"[7/7] Audit log: {audit_path}")
    if not os.path.exists(audit_path):
        print("      OK — audit log does not exist yet (will be created on daemon start)")
    else:
        try:
            from ironmesh.audit import verify_chain
            ok, msg = verify_chain(audit_path)
            if ok:
                print(f"      OK — {msg}")
            else:
                print(f"      WARN — {msg}")
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


def main():
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
    elif args.name:
        # Backward compatibility: no subcommand but --name given -> run
        return cmd_run(args)
    else:
        print("IronMesh — Zero-config encrypted A2A protocol\n")
        print("Usage:")
        print("  ironmesh demo                          # spawn two agents on localhost and exchange a ping")
        print("  ironmesh setup                         # interactive first-run wizard")
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
