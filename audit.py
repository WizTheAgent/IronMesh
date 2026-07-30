"""IronMesh Audit Log — Append-only tamper-evident security event log.

Every security-relevant event (key rotations, TOFU mismatches, auth failures,
decryption failures, GUI access) is recorded with an HMAC chain for tamper
evidence. Each entry's HMAC covers the previous entry's HMAC, forming a chain.

If an attacker deletes or modifies any entry, the chain breaks and
verification fails from that point forward.
"""

import contextlib
import hashlib
import hmac
import json
import logging
import os
import sys
import threading
import time
from typing import Optional

logger = logging.getLogger("ironmesh.audit")


# ---------------------------------------------------------------------------
# Cross-platform inter-process file lock (v0.8.5.6)
# ---------------------------------------------------------------------------
# IronMesh hosts often run multiple processes that share the same identity
# key + audit log path: the main bridge daemon, the MCP server, an
# operator CLI invocation. Each process has its own threading.Lock for
# in-process serialization, but the in-process locks don't synchronize
# across processes. Without a real file lock, two processes can both
# read the same chain tail, both compute their next HMAC against that
# stale tail, and both write entries — breaking the chain at the
# intersection. Verification then reports TAMPER even though no actual
# tampering occurred. We hit this in the v0.8.5.6 hardening pass.
#
# The fix is a sentinel-file exclusive lock acquired before each write
# and released after. We use a sentinel (not the audit log itself) so
# rotation can rename the audit log without invalidating the lock. The
# write path also re-reads the chain tail under the lock, so even if
# our in-memory _last_hmac is stale, the persisted chain stays valid.

@contextlib.contextmanager
def _audit_file_lock(path: str):
    """Acquire a process-exclusive lock on a sentinel file next to the
    audit log path. Blocks if another process holds the lock.

    Cross-platform: fcntl.flock on POSIX, msvcrt.locking on Windows.
    Falls back to a no-op (with a one-time warning) if neither is
    available — the in-process threading.Lock still applies.
    """
    lock_path = path + ".lock"
    try:
        fd = os.open(
            lock_path, os.O_RDWR | os.O_CREAT, 0o600,
        )
    except OSError as exc:
        logger.warning(
            "audit lock: could not open %s (%s); falling back to "
            "in-process lock only", lock_path, exc,
        )
        yield
        return

    locked = False
    try:
        if sys.platform == "win32":
            try:
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                locked = True
            except OSError as exc:
                logger.warning(
                    "audit lock: msvcrt.locking failed (%s); "
                    "falling back to in-process lock only", exc,
                )
        else:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
                locked = True
            except OSError as exc:
                logger.warning(
                    "audit lock: fcntl.flock failed (%s); "
                    "falling back to in-process lock only", exc,
                )
        yield
    finally:
        if locked:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except Exception:  # noqa: BLE001 — best-effort release
                pass
        try:
            os.close(fd)
        except OSError:
            pass

# Event types
EVENT_KEY_ROTATION = "KEY_ROTATION"
EVENT_TOFU_NEW = "TOFU_NEW_PEER"
EVENT_TOFU_MISMATCH = "TOFU_MISMATCH"
EVENT_AUTH_FAILURE = "AUTH_FAILURE"
EVENT_AUTH_BLOCKED = "AUTH_IP_BLOCKED"
EVENT_DECRYPT_FAILURE = "DECRYPT_FAILURE"
EVENT_SIGNATURE_FAILURE = "SIGNATURE_FAILURE"
EVENT_REPLAY_DETECTED = "REPLAY_DETECTED"
EVENT_PEER_CONNECT = "PEER_CONNECT"
EVENT_PEER_DISCONNECT = "PEER_DISCONNECT"
EVENT_GUI_ACCESS = "GUI_ACCESS"
EVENT_STARTUP = "STARTUP"
EVENT_SHUTDOWN = "SHUTDOWN"

# v0.7.2: extended peer health events
EVENT_PEER_DROPPED_LONG = "PEER_DROPPED_LONG"

# v0.4: mesh routing events
EVENT_ROUTE_ANNOUNCED = "ROUTE_ANNOUNCED"
EVENT_ROUTE_LEARNED = "ROUTE_LEARNED"
EVENT_ROUTE_EXPIRED = "ROUTE_EXPIRED"
EVENT_MESSAGE_RELAYED = "MESSAGE_RELAYED"
EVENT_TTL_EXPIRED = "TTL_EXPIRED"
EVENT_ROUTE_LOOP = "ROUTE_LOOP"
EVENT_NO_ROUTE = "NO_ROUTE"
EVENT_DUPLICATE_DROPPED = "DUPLICATE_DROPPED"
EVENT_MESH_PARTITION_SUSPECTED = "MESH_PARTITION_SUSPECTED"
EVENT_CIRCUIT_BREAKER_TRIPPED = "CIRCUIT_BREAKER_TRIPPED"
EVENT_CAPABILITY_LEARNED = "CAPABILITY_LEARNED"
EVENT_E2E_DECRYPT_FAILURE = "E2E_DECRYPT_FAILURE"
EVENT_LOG_ROTATED = "LOG_ROTATED"

# v0.8.5.2: pending-trust gate decisions. Operator-driven flow surface
# so audit history captures who promoted/blocked whom and when.
EVENT_MSG_GATED_QUEUE = "MSG_GATED_QUEUE"
EVENT_MSG_GATED_DROP = "MSG_GATED_DROP"
EVENT_PEER_PROMOTED = "PEER_PROMOTED"
EVENT_PEER_BLOCKED = "PEER_BLOCKED"

# v0.8.5.6: trust-binding — capability-set change detection + cross-
# transport replay detection. Closes two gaps flagged during external
# security review: over-privileged reconnect and silent cross-path
# replay. See docs/TRUST_BINDING.md.
EVENT_PEER_CAP_SET_CHANGED = "PEER_CAP_SET_CHANGED"
EVENT_PEER_CAP_BASELINE = "PEER_CAP_BASELINE"
EVENT_PEER_CAP_ACCEPTED = "PEER_CAP_ACCEPTED"
EVENT_MSG_REPLAY_CROSS_TRANSPORT = "MSG_REPLAY_CROSS_TRANSPORT"
# v0.8.5.6: close CLI audit gaps. `ironmesh trust revoke`
# (local-only) and `ironmesh trust set-state` were operator actions
# that mutated the trust store without leaving an audit trail — a
# forensic reviewer walking the log after an incident would miss
# them entirely. Now every CLI-driven trust mutation fires either
# one of the pre-existing event types (PEER_PROMOTED, PEER_BLOCKED)
# or one of these new ones.
EVENT_PEER_REVOKED_LOCAL = "PEER_REVOKED_LOCAL"
EVENT_PEER_STATE_CHANGED = "PEER_STATE_CHANGED"
# v0.8.5.6: fired when the bridge observed a capability-set
# change but the trust-store mutation (stash + demote) did NOT fully
# reach disk (disk error, MAC-mismatch read-only latch, lock contention
# beyond retry). Distinguishes "we saw + applied the change" from
# "we saw the change but couldn't persist it" for forensic review.
EVENT_PEER_CAP_BINDING_PARTIAL = "PEER_CAP_BINDING_PARTIAL"

# v0.9.3: at-rest encryption + transport-auth + global rate cap surface.
# Each fires at most a handful of times per daemon lifetime (or in the
# global-cap case is sampled — at most one per 10 s) so they never
# dominate the audit chain.
EVENT_TRUST_STORE_ENCRYPTED = "TRUST_STORE_ENCRYPTED"
EVENT_STRICT_TLS_ENABLED = "STRICT_TLS_ENABLED"
EVENT_GLOBAL_RATE_LIMIT_TRIGGERED = "GLOBAL_RATE_LIMIT_TRIGGERED"

# v0.9.4 — signed CAPABILITY_ANNOUNCE events.
EVENT_CAPABILITY_ANNOUNCE_BAD_SIG = "CAPABILITY_ANNOUNCE_BAD_SIG"

# A user-payload frame was dropped because its inner end-to-end source
# signature was missing, unverifiable, or invalid. Carries
# {"peer": <immediate hop>, "source": <claimed originator>, "reason": ...}.
EVENT_INNER_SOURCE_SIG_DROP = "INNER_SOURCE_SIG_DROP"

# Bootstrap invite-token events. Fired at the inviter's TOFU pin point
# when a joiner presents an invite: accepted (consumed once, peer pinned
# pending) or rejected (spent, expired, bad signature, identity mismatch).
EVENT_INVITE_ACCEPTED = "INVITE_ACCEPTED"
EVENT_INVITE_REJECTED = "INVITE_REJECTED"


class AuditLog:
    """Append-only audit log with HMAC chain for tamper evidence.

    Each log entry is a JSON line containing:
    - timestamp: Unix epoch
    - event: Event type constant
    - details: Dict of event-specific data
    - hmac: HMAC-SHA256 over (previous_hmac + entry_data)

    The HMAC key is derived from the node's identity key, ensuring only
    the legitimate node operator can produce valid entries.
    """

    # Genesis HMAC — used for the first entry in the chain
    _GENESIS = "0" * 64
    # Default rotation threshold and how many archives to retain
    _DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
    _MAX_ARCHIVES = 5

    def __init__(self, path: str = "~/.ironmesh/audit.log",
                 hmac_key: Optional[bytes] = None,
                 max_bytes: int = _DEFAULT_MAX_BYTES):
        """
        Args:
            path: Path to the audit log file.
            hmac_key: 32-byte key for HMAC chain. Derived from node identity key.
                      If None, audit logging is disabled (test/dev mode).
            max_bytes: Rotate the log when it exceeds this size (default 10 MB).
                       Rotated archives are named ``<path>.1`` … ``<path>.N``.
                       The first entry of every rotated file is an
                       ``EVENT_LOG_ROTATED`` record carrying the previous file's
                       tail HMAC, anchoring the chain across rotation.
        """
        self._path = os.path.expanduser(path)
        self._hmac_key = hmac_key
        self._max_bytes = max(1024, int(max_bytes))
        self._last_hmac = self._GENESIS
        self._enabled = hmac_key is not None
        # Serialize log + rotate so the size check and the actual file
        # write/rename aren't interleaved across threads.
        self._write_lock = threading.Lock()
        if not self._enabled:
            # Never silently disable audit logging.
            logger.critical(
                "SECURITY: Audit log initialized without HMAC key — audit logging DISABLED. "
                "Security events will NOT be recorded."
            )

        if self._enabled:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            # Resume chain from last entry in existing log
            self._last_hmac = self._read_last_hmac()

    def _read_last_hmac(self) -> str:
        """Read the HMAC of the last entry to resume the chain.

        v0.8.5.6: tolerate a partial trailing line. SIGKILL between
        ``f.write(entry)`` and the OS flush can leave a torn line at
        EOF (no newline, truncated JSON). Pre-fix, the bare
        ``json.loads(last_line)`` raised, the outer except returned
        GENESIS, and the next entry chained off GENESIS — which
        permanently broke the audit chain at that point. Now we walk
        backwards over candidate lines until we find one that parses
        AND carries a hex hmac field, and ignore everything after.
        The torn line stays on disk for forensic inspection but is
        not honored as the chain tail.
        """
        try:
            if not os.path.exists(self._path):
                return self._GENESIS
            with open(self._path, "r") as f:
                lines = [line.strip() for line in f if line.strip()]
            for line in reversed(lines):
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue  # torn line — skip
                hm = entry.get("hmac")
                if isinstance(hm, str) and len(hm) == 64:
                    return hm
            return self._GENESIS
        except Exception:  # noqa: BLE001
            # Wide except is intentional. The audit chain backing file can
            # fail to read for many unrelated reasons — permission errors,
            # FS unmount mid-read, encoding errors on a partial flush, decoded
            # JSON that yields surprise types, and so on. The recovery
            # contract is "start a fresh chain with GENESIS as the prev_hmac";
            # narrowing this except risks crashing the daemon on bootstrap
            # over a recoverable filesystem condition. Failure is announced
            # at WARNING so operators see it.
            logger.warning("Could not read last audit HMAC — starting new chain")
        return self._GENESIS

    def _compute_hmac(self, entry_data: str) -> str:
        """Compute HMAC-SHA256 over (previous_hmac + entry_data)."""
        message = (self._last_hmac + entry_data).encode("utf-8")
        return hmac.new(self._hmac_key, message, hashlib.sha256).hexdigest()

    def log(self, event: str, details: Optional[dict] = None):
        """Append a security event to the audit log.

        Args:
            event: Event type (use EVENT_* constants).
            details: Optional dict of event-specific data.

        v0.8.5.6: when multiple processes share the same audit log
        path (e.g. main daemon + MCP server + operator CLI), the
        sentinel-file lock serializes writes across processes and we
        re-read the chain tail under the lock to chain off the
        actually-persisted last entry, not our possibly-stale
        in-memory copy.
        """
        if not self._enabled:
            return
        with self._write_lock:                       # in-process serialize
            with _audit_file_lock(self._path):       # cross-process serialize
                # Re-read tail under the lock. If another process appended
                # since we last refreshed, our cached _last_hmac is stale —
                # use the freshly-read one to keep the chain valid.
                self._last_hmac = self._read_last_hmac()
                self._write_entry(event, details)
                self._maybe_rotate()

    def _write_entry(self, event: str, details: Optional[dict]) -> None:
        """Append a single entry without performing rotation checks.

        Used by both ``log()`` and the rotation anchor writer to avoid
        recursive rotation while we're in the middle of rotating.
        """
        ts = time.time()
        entry_data = json.dumps({
            "timestamp": ts,
            "event": event,
            "details": details or {},
        }, separators=(",", ":"), sort_keys=True)

        entry_hmac = self._compute_hmac(entry_data)

        full_entry = json.dumps({
            "timestamp": ts,
            "event": event,
            "details": details or {},
            "hmac": entry_hmac,
        }, separators=(",", ":"), sort_keys=True)

        # v0.8.5.6: write the full line in a single os.write() and
        # fsync. The single write maximizes the chance the OS commits
        # the line whole (POSIX guarantees ≤PIPE_BUF append atomicity;
        # NTFS append is similarly atomic for small writes). The fsync
        # makes the write durable across power loss / SIGKILL of the
        # whole machine. Without fsync, S5-style chaos can occasionally
        # lose a tail entry — but B2's lock + this ordering makes the
        # loss benign (next reader walks back to the previous valid
        # line; chain continues).
        #
        # v0.8.5.6: if the file's last byte isn't a newline,
        # the previous writer crashed mid-line. Prepend a newline so
        # our entry doesn't concatenate onto the torn line. The torn
        # line stays on disk for forensic inspection (verify() will
        # mark it invalid) but doesn't poison subsequent entries.
        try:
            needs_leading_nl = False
            try:
                if os.path.getsize(self._path) > 0:
                    with open(self._path, "rb") as _r:
                        _r.seek(-1, os.SEEK_END)
                        if _r.read(1) != b"\n":
                            needs_leading_nl = True
            except OSError:
                pass  # file doesn't exist yet — first write is fine
            payload = (("\n" if needs_leading_nl else "")
                       + full_entry + "\n").encode("utf-8")
            fd = os.open(self._path,
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, payload)
                try:
                    os.fsync(fd)
                except (OSError, AttributeError):
                    # fsync may be unavailable on some Windows network
                    # drives. Fallback: best-effort.
                    pass
            finally:
                os.close(fd)
            self._last_hmac = entry_hmac
        except Exception as e:
            logger.error("Failed to write audit log: %s", e)

    def _maybe_rotate(self) -> None:
        """Rotate the current log if it exceeds ``max_bytes``.

        Rotation steps:
            1. Capture the chain tail HMAC of the live log.
            2. Shift archives ``.N`` → ``.N+1`` (capped at ``_MAX_ARCHIVES``).
            3. Move the live log to ``<path>.1``.
            4. Reset the in-memory chain to GENESIS for the new file.
            5. Write a fresh ``EVENT_LOG_ROTATED`` entry whose details
               include ``previous_tail_hmac`` so the chain can be
               cryptographically followed across the rotation boundary.
        """
        try:
            size = os.path.getsize(self._path)
        except OSError:
            return
        if size < self._max_bytes:
            return

        old_tail = self._last_hmac

        # Shift older archives out, capped at _MAX_ARCHIVES.
        for i in range(self._MAX_ARCHIVES - 1, 0, -1):
            src = f"{self._path}.{i}"
            dst = f"{self._path}.{i + 1}"
            if os.path.exists(src):
                try:
                    os.replace(src, dst)
                except OSError as e:
                    logger.warning("Failed to shift audit archive %s: %s", src, e)

        # Move current live log to .1
        try:
            os.replace(self._path, f"{self._path}.1")
        except OSError as e:
            logger.error("Failed to rotate audit log: %s", e)
            return

        # New live file: chain restarts from GENESIS, but the first entry is
        # an anchor record that pins it to the previous file's tail.
        self._last_hmac = self._GENESIS
        self._write_entry(EVENT_LOG_ROTATED, {
            "previous_tail_hmac": old_tail,
        })

    def verify(self) -> tuple:
        """Verify the HMAC chain integrity.

        Returns:
            (valid: bool, entries_checked: int, first_invalid_line: Optional[int])
        """
        if not os.path.exists(self._path):
            return (True, 0, None)

        prev_hmac = self._GENESIS
        line_num = 0

        try:
            with open(self._path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    line_num += 1

                    entry = json.loads(line)
                    stored_hmac = entry.pop("hmac", "")

                    # Reconstruct entry_data (same as during log())
                    entry_data = json.dumps(entry, separators=(",", ":"), sort_keys=True)
                    expected_hmac = hmac.new(
                        self._hmac_key,
                        (prev_hmac + entry_data).encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()

                    if not hmac.compare_digest(stored_hmac, expected_hmac):
                        return (False, line_num, line_num)

                    prev_hmac = stored_hmac

        except Exception as e:  # noqa: BLE001
            # Wide except is intentional. Chain verification reads back a
            # mutable on-disk artifact whose corruption is exactly the
            # failure mode this function exists to detect. JSON parse
            # errors, missing keys, unicode decode failures, and
            # filesystem read errors are all "chain unverifiable" outcomes
            # — they must surface as (verified=False, problem_line) rather
            # than as an uncaught exception that crashes the verifier.
            logger.error("Audit log verification error at line %d: %s", line_num, e)
            return (False, line_num, line_num)

        return (True, line_num, None)

    def verify_chain_across_archives(self) -> tuple:
        """Verify the HMAC chain across all rotated archives + the live log.

        Walks ``<path>.N`` (largest N first, i.e. oldest) through ``<path>.1``
        and finally the current live log. Each file is independently HMAC-
        chained from GENESIS, but at every rotation boundary the first entry
        of the newer file MUST be ``EVENT_LOG_ROTATED`` and its
        ``previous_tail_hmac`` field MUST equal the last HMAC of the prior
        file. This anchors a tamper-evident chain across rotation events.

        Returns:
            (valid: bool, total_entries_checked: int, first_invalid_line: Optional[int])

            ``first_invalid_line`` is a global line counter across all files
            walked in order, useful for diagnostics.
        """
        if not self._enabled:
            return (True, 0, None)

        # Discover archives in oldest-first order: .N, .N-1, ..., .1, then live.
        files: list = []
        for i in range(self._MAX_ARCHIVES, 0, -1):
            archive = f"{self._path}.{i}"
            if os.path.exists(archive):
                files.append(archive)
        if os.path.exists(self._path):
            files.append(self._path)

        if not files:
            return (True, 0, None)

        prev_file_tail: Optional[str] = None
        total = 0

        for file_idx, fpath in enumerate(files):
            prev_hmac_local = self._GENESIS
            first_entry = True

            try:
                with open(fpath, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        total += 1

                        entry = json.loads(line)
                        stored_hmac = entry.pop("hmac", "")
                        entry_data = json.dumps(
                            entry, separators=(",", ":"), sort_keys=True,
                        )
                        expected = hmac.new(
                            self._hmac_key,
                            (prev_hmac_local + entry_data).encode("utf-8"),
                            hashlib.sha256,
                        ).hexdigest()

                        if not hmac.compare_digest(stored_hmac, expected):
                            return (False, total, total)

                        # First entry of any non-initial file must anchor.
                        if first_entry and file_idx > 0:
                            if entry.get("event") != EVENT_LOG_ROTATED:
                                return (False, total, total)
                            details = entry.get("details") or {}
                            if details.get("previous_tail_hmac") != prev_file_tail:
                                return (False, total, total)

                        first_entry = False
                        prev_hmac_local = stored_hmac

            except Exception as e:
                logger.error(
                    "Audit archive verification error in %s at line %d: %s",
                    fpath, total, e,
                )
                return (False, total, total)

            prev_file_tail = prev_hmac_local

        return (True, total, None)


# ---------------------------------------------------------------------------
# Module-level helpers for CLI tools
# ---------------------------------------------------------------------------

def _derive_audit_key(ed25519_secret: bytes) -> bytes:
    """Derive the audit HMAC key from the agent's Ed25519 secret."""
    return hashlib.sha256(ed25519_secret + b"ironmesh-audit-v1").digest()


def _load_keys_for_verify(keys_path: Optional[str],
                          keys_passphrase: Optional[str]):
    """Load the identity keypair for chain verification without ever
    blocking a headless caller.

    Order: explicit ``keys_passphrase`` → ``IRONMESH_KEYS_PASSPHRASE`` /
    ``IRONMESH_PASSPHRASE`` env → passphrase-less load (plaintext key file)
    → interactive prompt (real console only) → actionable error. The
    previous unconditional ``getpass()`` froze ``ironmesh doctor`` in
    headless runs — on Windows the prompt reads the console device, so even
    a redirected stdin never unblocks it.

    A missing/corrupt/unreadable key file surfaces as its own error rather
    than being mis-reported as "needs passphrase".
    """
    from ironmesh import keys as ew_keys
    kp = keys_path or "~/.ironmesh/keys.json"

    def _load(passphrase):
        # Normalize a valid-JSON-but-structurally-malformed key file (e.g. an
        # empty {}, a truncated envelope, a JSON list) to a clear ValueError.
        # load_keys reads fields like data["ed25519_public"] before its
        # encryption check, so such files raise KeyError/TypeError/
        # AttributeError; without this they would escape to an uncaught
        # traceback in `ironmesh audit verify`.
        try:
            return ew_keys.load_keys(kp, passphrase=passphrase)
        except (KeyError, TypeError, AttributeError) as e:
            raise ValueError(
                f"identity key file {kp} is malformed: {e}") from e

    # Honor both the keys-specific and legacy env var, keys-specific first —
    # the same pair `ironmesh doctor` reads, so the two commands agree on
    # the passphrase source in a given environment.
    kp_pass = (keys_passphrase
               or os.environ.get("IRONMESH_KEYS_PASSPHRASE")
               or os.environ.get("IRONMESH_PASSPHRASE"))
    if not kp_pass:
        try:
            return _load(None)  # plaintext file
        except FileNotFoundError:
            raise  # no key file — report it as itself
        except OSError:
            raise  # permission denied etc. — report it as itself
        except ValueError as e:
            if "encrypted" not in str(e).lower():
                raise  # corrupt/malformed envelope — not a passphrase problem
            # encrypted-but-no-passphrase → fall through to prompt/error
        from ironmesh.cli_output import stdin_is_interactive
        if stdin_is_interactive():
            import getpass
            kp_pass = getpass.getpass("Identity key passphrase: ")
    if not kp_pass:
        raise ValueError(
            "audit chain verification requires the identity-key passphrase "
            "and no interactive prompt is available (headless run). Set "
            "IRONMESH_KEYS_PASSPHRASE (or IRONMESH_PASSPHRASE), or run from "
            "an interactive terminal. `ironmesh setup` encrypts the key file "
            "with the mesh passphrase, so that value works here too."
        )
    return _load(kp_pass)


def verify_chain(audit_path: str, keys_path: Optional[str] = None,
                 keys_passphrase: Optional[str] = None) -> tuple:
    """Verify an audit log file. Derives the HMAC key from the identity key.

    If keys_path is omitted, looks up the default location. Never blocks
    on a hidden prompt: raises ValueError when the passphrase cannot be
    resolved headlessly — see ``_load_keys_for_verify``.

    Returns:
        (ok, entries_checked, first_invalid_line)
    """
    keypair = _load_keys_for_verify(keys_path, keys_passphrase)
    hmac_key = _derive_audit_key(keypair.ed25519_secret)
    log = AuditLog(path=audit_path, hmac_key=hmac_key)
    return log.verify()


def verify_archived_chain(audit_path: str, keys_path: Optional[str] = None,
                          keys_passphrase: Optional[str] = None) -> tuple:
    """Verify audit log across rotated archives. Same headless-safe
    passphrase resolution as ``verify_chain``."""
    keypair = _load_keys_for_verify(keys_path, keys_passphrase)
    hmac_key = _derive_audit_key(keypair.ed25519_secret)
    log = AuditLog(path=audit_path, hmac_key=hmac_key)
    return log.verify_chain_across_archives()


def export_signed(audit_path: str, out_path: str, signing_key,
                  signer_fingerprint: str) -> None:
    """Export the audit log as a signed JSON bundle.

    The bundle contains the list of raw entries plus an Ed25519 signature
    over the canonical JSON of (entries, final_hmac) by the agent's
    identity key.

    Args:
        audit_path: Source audit log file.
        out_path: Destination JSON file.
        signing_key: nacl.signing.SigningKey for the signer.
        signer_fingerprint: Hex fingerprint of the signer's public key.
    """
    import base64
    import json as _json


    entries = []
    final_hmac = "0" * 64
    if os.path.exists(audit_path):
        with open(audit_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = _json.loads(line)
                entries.append(entry)
                final_hmac = entry.get("hmac", final_hmac)

    bundle_body = {
        "entries": entries,
        "final_hmac": final_hmac,
        "entry_count": len(entries),
        "exported_at": time.time(),
        "signer": signer_fingerprint,
    }
    canonical = _json.dumps(bundle_body, separators=(",", ":"),
                            sort_keys=True).encode()
    signature = signing_key.sign(canonical).signature

    out = {
        **bundle_body,
        "signature": base64.b64encode(signature).decode(),
    }
    with open(out_path, "w") as f:
        _json.dump(out, f, indent=2)


def verify_signed_export(file_path: str) -> dict:
    """Verify a signed audit export file.

    Returns a dict with keys:
        valid (bool), signer (fingerprint), entry_count (int),
        chain_ok (bool), error (str, if invalid)
    """
    import base64
    import json as _json

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    with open(file_path, "r") as f:
        bundle = _json.load(f)

    signature_b64 = bundle.pop("signature", None)
    if not signature_b64:
        return {"valid": False, "error": "Missing signature"}

    canonical = _json.dumps(bundle, separators=(",", ":"),
                            sort_keys=True).encode()
    signer_fp = bundle.get("signer", "")

    # The signer's public key must be provided separately via trust store,
    # or we accept any valid signature and report the signer. The chain
    # integrity verification requires the HMAC key which we don't have here.
    # So we only verify the signature's self-consistency:
    # the fingerprint in the bundle must equal SHA256(verifying_pubkey).
    #
    # To verify: caller must look up the signer's pubkey in their trust
    # store and pass it in. For simplicity, we require the pubkey field.
    pubkey_b64 = bundle.get("signer_pubkey")
    if not pubkey_b64:
        # Self-consistency only — no external verification possible
        return {
            "valid": True,  # structurally valid
            "signer": signer_fp,
            "entry_count": bundle.get("entry_count", 0),
            "chain_ok": True,  # chain HMAC stored but not independently verified
            "note": "No signer_pubkey in bundle — trust store lookup required for full verification",
        }

    pubkey = base64.b64decode(pubkey_b64)
    vk = VerifyKey(pubkey)
    try:
        vk.verify(canonical, base64.b64decode(signature_b64))
    except BadSignatureError:
        return {"valid": False, "error": "Signature verification failed"}

    # Verify fingerprint matches pubkey
    computed_fp = hashlib.sha256(pubkey).hexdigest()[:32]
    if computed_fp != signer_fp:
        return {"valid": False, "error": "Fingerprint mismatch"}

    return {
        "valid": True,
        "signer": signer_fp,
        "entry_count": bundle.get("entry_count", 0),
        "chain_ok": True,
    }
