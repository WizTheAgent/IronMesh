"""IronMesh TOFU (Trust-On-First-Use) peer key pinning.

On first connection to a peer, saves their Ed25519 identity public key.
On subsequent connections, compares — if key changed, warns of possible MITM.
Trust store file is integrity-protected with HMAC and (since v0.9.3)
encrypted at rest with a SecretBox key derived from the agent identity
secret. Pre-existing plaintext stores migrate forward on the next save.
"""

import base64
import contextlib
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import sys
import threading
import time
import weakref
from typing import Dict, List, Optional, Tuple

try:  # pragma: no cover — exercised on every install with pynacl
    from nacl.exceptions import CryptoError
    from nacl.secret import SecretBox
    from nacl.utils import random as nacl_random
    _HAS_NACL = True
except ImportError:  # pragma: no cover — keeps tests importable without pynacl
    CryptoError = Exception  # type: ignore[misc,assignment]
    SecretBox = None  # type: ignore[assignment]
    nacl_random = None  # type: ignore[assignment]
    _HAS_NACL = False

logger = logging.getLogger("ironmesh.trust")

DEFAULT_TRUST_PATH = "~/.ironmesh/known_peers.json"


# ---------------------------------------------------------------------------
# v0.8.5.6: cross-process exclusive lock on the trust file.
#
# Without inter-process locking, concurrent operator actions on the same
# host (e.g. two `ironmesh trust cap-promote` invocations, or one CLI
# call racing the daemon's own cap-binding observe path) each load the
# file independently, mutate their in-memory copies, and call _save().
# Each _save() writes through a shared `<path>.tmp` filename — on
# Windows the second writer's open(..., "w") fights with the first
# writer's os.replace, throws WinError 32, and silently drops the
# write. The mutating method (e.g. accept_capability_change) returns
# True regardless because it only checks in-memory state, not whether
# _save persisted. The result is N processes claiming success, zero
# durable changes on disk.
#
# Mirroring the audit-log fix (B2): hold a sentinel-file flock around
# every _save(). Reads happen under the same lock so a concurrent
# writer can't shred a half-modified file out from under us.
# ---------------------------------------------------------------------------

# v0.8.5.6: Windows msvcrt.locking is a PROCESS-level lock.
# When two THREADS in one process try to acquire it on the same fd, the
# OS returns "Resource deadlock avoided" (EDEADLK) because it sees the
# lock is already held by THIS process — there's no thread granularity.
# POSIX fcntl.flock has the same cross-thread semantics. So the file
# lock alone serializes cross-process, but multiple threads inside a
# single daemon could still stampede. Layer an in-process threading.Lock
# per (canonical) trust path so one Python process can only enter the
# critical section serially.
_trust_inproc_locks_mutex = threading.Lock()
_trust_inproc_locks: "weakref.WeakValueDictionary[str, threading.Lock]" = (
    weakref.WeakValueDictionary()
)


def _get_inproc_lock(path: str) -> threading.Lock:
    key = os.path.abspath(os.path.expanduser(path))
    with _trust_inproc_locks_mutex:
        lk = _trust_inproc_locks.get(key)
        if lk is None:
            lk = threading.Lock()
            _trust_inproc_locks[key] = lk
        return lk


@contextlib.contextmanager
def _trust_file_lock(path: str):
    # v0.8.5.6: acquire the in-process lock first so concurrent
    # threads inside this Python process serialize before contending
    # for the OS file lock. (msvcrt.locking and fcntl.flock are both
    # process-level, not thread-level.)
    inproc = _get_inproc_lock(path)
    inproc.acquire()
    lock_path = path + ".lock"
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        logger.warning(
            "trust lock: could not open %s (%s); falling back to "
            "in-process lock only", lock_path, exc,
        )
        try:
            yield
        finally:
            inproc.release()
        return

    locked = False
    try:
        if sys.platform == "win32":
            try:
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                locked = True
            except OSError as exc:
                # Now expected ONLY across processes; intra-process
                # collisions never reach this branch because of the
                # in-process lock above. Silenced to debug to keep
                # the operator log clean during normal multi-daemon
                # operation.
                logger.debug(
                    "trust lock: msvcrt.locking failed (%s); "
                    "falling back to in-process lock only", exc,
                )
        else:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
                locked = True
            except OSError as exc:
                logger.debug(
                    "trust lock: fcntl.flock failed (%s); "
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
            except Exception:  # noqa: BLE001
                pass
        try:
            os.close(fd)
        except OSError:
            pass
        # v0.8.5.6: release the in-process lock LAST so the next
        # waiting thread doesn't see a stale OS-lock state.
        inproc.release()

# Legacy MAC key (home-directory-derived) — kept only for one-shot
# migration away from the v0.5 format. No new trust stores should rely
# on it; every TrustStore must be bound to the agent's identity key.
_LEGACY_MAC_KEY = hashlib.sha256(
    b"ironmesh-trust-store-v1:" + os.path.expanduser("~").encode()
).digest()


def _derive_mac_key(agent_key: bytes) -> bytes:
    """Derive the trust store HMAC key from the agent's identity secret."""
    if not isinstance(agent_key, (bytes, bytearray)) or len(agent_key) < 16:
        raise ValueError(
            "TrustStore requires an agent_key of at least 16 bytes "
            "(pass the Ed25519 secret or a derivative)."
        )
    return hashlib.sha256(bytes(agent_key) + b"ironmesh-trust-store-v1").digest()


def _derive_box_key(agent_key: bytes) -> bytes:
    """Derive the at-rest SecretBox key for trust-store payload encryption.

    Distinct domain separator from ``_derive_mac_key`` so the HMAC and
    SecretBox keys are independent even though both are bound to the
    same underlying identity secret. SecretBox keys are 32 bytes; SHA-256
    output happens to be the right size.
    """
    if not isinstance(agent_key, (bytes, bytearray)) or len(agent_key) < 16:
        raise ValueError(
            "TrustStore requires an agent_key of at least 16 bytes "
            "(pass the Ed25519 secret or a derivative)."
        )
    return hashlib.sha256(
        bytes(agent_key) + b"ironmesh-trust-store-encryption-v1"
    ).digest()


# Trust-store envelope versions.
#
# v1: legacy plaintext envelope ``{"peers": ..., "revoked": ..., "_mac": ...}``
#     written by every daemon up to and including v0.9.2. Loaders accept it
#     for one-shot forward migration.
# v2: encrypted envelope ``{"version": 2, "ciphertext": "<b64>", "_mac": "..."}``.
#     ``ciphertext`` is the SecretBox encryption of the v1 inner JSON
#     (``{"peers", "revoked"}``); ``_mac`` is HMAC-SHA256 over
#     ``"v=2|c=<ciphertext>"`` so the MAC binds both the version label and
#     the exact bytes that were encrypted.
_TRUST_ENVELOPE_VERSION = 2


# ---------------------------------------------------------------------------
# v0.8.5.6: capability-set binding — hash a peer's advertised capability
# set into a stable 32-byte value so we can detect changes across
# reconnects and re-gate over-privileged peers.
# ---------------------------------------------------------------------------

_CAP_HASH_PREFIX = b"ironmesh-cap-hash-v1:"


def canonical_capability_hash(capabilities) -> str:
    """Compute a stable SHA-256 hex digest over a capability set.

    Canonical form: capability tokens are stripped, deduplicated,
    sorted lexicographically, joined with '\\n', UTF-8 encoded, and
    prefixed with a domain separator before hashing. Stable against
    list reordering and insignificant whitespace; case-sensitive by
    design (capability matching is case-sensitive).

    Returns the hex digest as a 64-character string. Empty capability
    sets hash to a well-defined non-zero value (the hash of the empty
    canonical form, not a sentinel).
    """
    if capabilities is None:
        capabilities = ()
    cleaned = []
    seen = set()
    for cap in capabilities:
        if cap is None:
            continue
        s = str(cap).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        cleaned.append(s)
    cleaned.sort()
    payload = _CAP_HASH_PREFIX + "\n".join(cleaned).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class TrustStore:
    """TOFU key pinning database backed by JSON file with integrity MAC."""

    # Per-process dedup of integrity-check-FAILED CRITICAL logs.
    # The startup audit-chain verify path + each new daemon instance
    # reconstructs a TrustStore against the same on-disk file; logging
    # CRITICAL every iteration produces unbounded log noise. Keyed by
    # ``(path, stored_mac)`` so a genuine new failure (different MAC
    # appears in the file) re-fires the CRITICAL, while the lock-loop
    # silently downgrades to DEBUG.
    _mac_failure_logged: set = set()

    def __init__(self, agent_key: bytes, path: str = DEFAULT_TRUST_PATH):
        """
        Args:
            agent_key: Secret bytes bound to this node's identity (e.g.
                ``keypair.ed25519_secret[:32]``). The HMAC key is derived
                from this. Must be at least 16 bytes.
            path: Path to trust store JSON file.
        """
        self.path = os.path.expanduser(path)
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._mac_key: bytes = _derive_mac_key(agent_key)
        self._box_key: bytes = _derive_box_key(agent_key)
        self._peers: Dict[str, dict] = {}
        self._revoked: Dict[str, dict] = {}  # v0.6: node_id -> {revoker, timestamp, reason}
        # v0.8.5.6: when _load() detects a MAC mismatch, the in-memory
        # peers dict is empty BUT the on-disk file is intact. If we then
        # accept any write (e.g. an opportunistic TOFU pin from a routine
        # peer reconnect), we'd serialize {peers: {}, peers...} on top
        # of the actual file — silently wiping every other pinned peer.
        # The catastrophic v0.8.5.6 wipe was exactly this: a colliding
        # process on the same host wrote the file with a different MAC key,
        # and our daemon's next save flattened the file to a single peer.
        # This flag latches True on a MAC mismatch and causes every _save()
        # to refuse rather than overwrite. Operators must explicitly
        # rebuild the trust store (delete the file, or run with --trust-path)
        # to clear it.
        self._readonly_due_to_mac_failure: bool = False
        self._load()

    def _compute_mac(self, data: str) -> str:
        """Compute HMAC-SHA256 over trust store data."""
        return hmac_mod.new(self._mac_key, data.encode(), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # v0.9.3: at-rest envelope (encrypted v2 + plaintext v1 fallback)
    # ------------------------------------------------------------------

    def _encrypt_inner(self, inner_json: str) -> str:
        """SecretBox-encrypt the inner peers/revoked JSON. Returns base64."""
        if not _HAS_NACL or SecretBox is None:
            raise RuntimeError(
                "Trust-store encryption requires pynacl. Install with "
                "`pip install pynacl` or downgrade IronMesh to <0.9.3."
            )
        box = SecretBox(self._box_key)
        nonce = nacl_random(SecretBox.NONCE_SIZE)  # type: ignore[misc]
        ct = box.encrypt(inner_json.encode("utf-8"), nonce)
        # ``ct`` is nonce||ciphertext (NaCl ``EncryptedMessage`` bytes form).
        return base64.b64encode(bytes(ct)).decode("ascii")

    def _decrypt_inner(self, b64_ct: str) -> str:
        """Inverse of ``_encrypt_inner``. Raises on tamper or wrong key."""
        if not _HAS_NACL or SecretBox is None:
            raise RuntimeError(
                "Trust-store decryption requires pynacl. Install with "
                "`pip install pynacl` or downgrade IronMesh to <0.9.3."
            )
        try:
            raw = base64.b64decode(b64_ct.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("trust-store ciphertext is not valid base64") from exc
        box = SecretBox(self._box_key)
        plaintext = box.decrypt(raw)
        return plaintext.decode("utf-8")

    @staticmethod
    def _v2_mac_input(ciphertext_b64: str) -> str:
        """Canonical bytes the v2 envelope MAC covers."""
        return f"v={_TRUST_ENVELOPE_VERSION}|c={ciphertext_b64}"

    def _serialize_envelope(self) -> str:
        """Build the on-disk v2 envelope JSON for current in-memory state."""
        inner = {"peers": self._peers, "revoked": self._revoked}
        inner_json = json.dumps(inner, sort_keys=True, separators=(",", ":"))
        ciphertext_b64 = self._encrypt_inner(inner_json)
        envelope = {
            "version": _TRUST_ENVELOPE_VERSION,
            "ciphertext": ciphertext_b64,
            "_mac": self._compute_mac(self._v2_mac_input(ciphertext_b64)),
        }
        return json.dumps(envelope, indent=2)

    def _deserialize_envelope(self, raw) -> Optional[Tuple[Dict[str, dict], Dict[str, dict]]]:
        """Parse a loaded envelope dict into (peers, revoked).

        Handles v2 (encrypted) and v1 (legacy plaintext) shapes. Returns
        ``None`` on integrity / decryption failure; the caller is
        responsible for setting the read-only latch and surfacing the
        operator-facing log line. The legacy MAC migration path stays
        in ``_load`` because it has special "save once with new key"
        semantics that don't fit a pure parse helper.
        """
        if not isinstance(raw, dict):
            return None

        version = raw.get("version")
        if version == _TRUST_ENVELOPE_VERSION:
            ciphertext_b64 = raw.get("ciphertext")
            stored_mac = raw.get("_mac")
            if not isinstance(ciphertext_b64, str) or not isinstance(stored_mac, str):
                return None
            expected_mac = self._compute_mac(self._v2_mac_input(ciphertext_b64))
            if not hmac_mod.compare_digest(stored_mac, expected_mac):
                return None
            try:
                inner_json = self._decrypt_inner(ciphertext_b64)
            except (CryptoError, ValueError, RuntimeError):
                return None
            try:
                inner = json.loads(inner_json)
            except json.JSONDecodeError:
                return None
            peers = inner.get("peers", {}) if isinstance(inner, dict) else {}
            revoked = inner.get("revoked", {}) if isinstance(inner, dict) else {}
            return (peers, revoked)

        # Legacy v1 (plaintext) — migrate forward on next save.
        if "_mac" in raw:
            return None  # v1 path is handled inline in ``_load`` because
            # of the legacy-MAC migration branch.
        if isinstance(raw, dict):
            inner = raw.get("peers", raw) if "peers" in raw else raw
            if isinstance(inner, dict):
                # No MAC at all (very old store) — accept and migrate.
                return (inner, raw.get("revoked", {}) if isinstance(raw, dict) else {})
        return None

    def _atomic_write(self, payload: str) -> bool:
        """Write ``payload`` to ``self.path`` atomically. Caller holds the lock."""
        tmp_path = "{}.{}.{}.tmp".format(self.path, os.getpid(), threading.get_ident())
        try:
            with open(tmp_path, "w") as f:
                f.write(payload)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except (OSError, AttributeError):
                    pass
            os.replace(tmp_path, self.path)
            return True
        except (IOError, OSError) as e:
            logger.error("Failed to save trust store: %s", e)
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            return False

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                raw = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("Failed to load trust store: %s", e)
            self._peers = {}
            return

        if not isinstance(raw, dict):
            self._peers = {}
            return

        # v2 (encrypted): version label present + ciphertext field.
        if raw.get("version") == _TRUST_ENVELOPE_VERSION:
            decoded = self._deserialize_envelope(raw)
            if decoded is not None:
                self._peers, self._revoked = decoded
                return
            stored_mac = raw.get("_mac", "")
            # Log CRITICAL once per (path, stored_mac) pair to keep
            # the audit-chain-verify loop from spamming the log. A
            # genuine new failure (different stored_mac) re-fires.
            mac_key = (self.path, stored_mac)
            if mac_key in TrustStore._mac_failure_logged:
                logger.debug(
                    "Trust store v2 envelope still locked read-only at %s",
                    self.path,
                )
            else:
                TrustStore._mac_failure_logged.add(mac_key)
                logger.critical(
                    "Trust store integrity check FAILED at %s (v2 envelope) — "
                    "stored_mac=%s. The file was written by a different agent "
                    "key, tampered, or corrupted. TRUST STORE LOCKED READ-ONLY "
                    "— _save() will refuse until you remove the colliding "
                    "writer and reset the file.",
                    self.path,
                    (stored_mac[:16] + "…") if stored_mac else "<missing>",
                )
            self._peers = {}
            self._readonly_due_to_mac_failure = True
            return

        # Legacy v1 (plaintext, with HMAC). Verify, migrate forward on next
        # save. Same agent-key migration path as before for the very-old
        # home-directory-derived MAC.
        if "_mac" in raw:
            stored_mac = raw.pop("_mac")
            data_str = json.dumps(raw, sort_keys=True, separators=(",", ":"))
            expected_mac = self._compute_mac(data_str)
            if hmac_mod.compare_digest(stored_mac, expected_mac):
                self._peers = raw.get("peers", raw)
                self._revoked = raw.get("revoked", {})
                logger.info(
                    "Trust store loaded from legacy plaintext envelope; "
                    "migrating to encrypted v%d on next save.",
                    _TRUST_ENVELOPE_VERSION,
                )
                return
            old_mac = hmac_mod.new(
                _LEGACY_MAC_KEY, data_str.encode(), hashlib.sha256
            ).hexdigest()
            if hmac_mod.compare_digest(stored_mac, old_mac):
                logger.info(
                    "Trust store: migrating from legacy MAC key to "
                    "agent-bound MAC (and to encrypted v%d envelope)",
                    _TRUST_ENVELOPE_VERSION,
                )
                self._peers = raw.get("peers", raw)
                self._save()
                return
            # Dedup as above — log CRITICAL once per (path, stored_mac)
            # pair to keep the audit-chain-verify loop from spamming.
            mac_key = (self.path, stored_mac)
            if mac_key in TrustStore._mac_failure_logged:
                logger.debug(
                    "Trust store legacy envelope still locked read-only at %s",
                    self.path,
                )
            else:
                TrustStore._mac_failure_logged.add(mac_key)
                logger.critical(
                    "Trust store integrity check FAILED at %s — "
                    "stored_mac=%s expected_mac=%s peers_in_file=%d. "
                    "If you run multiple daemons on this host, give each "
                    "its own --trust-path to avoid silent collisions; "
                    "otherwise the file may be tampered. TRUST STORE "
                    "LOCKED READ-ONLY — _save() will refuse until you "
                    "remove the colliding writer and reset the file.",
                    self.path,
                    stored_mac[:16] + "…",
                    expected_mac[:16] + "…",
                    len(raw.get("peers", {})),
                )
            self._peers = {}
            self._readonly_due_to_mac_failure = True
            return

        # Very-old MAC-less plaintext. Migrate on next save.
        self._peers = raw.get("peers", raw) if "peers" in raw else raw
        self._revoked = raw.get("revoked", {})

    def _save(self) -> bool:
        """Persist current state to disk under a cross-process lock.

        Returns True on successful durable write, False if the write
        was refused (read-only latch) or failed (I/O error,
        Windows tmp-file collision under contention). Callers that
        mutate then call ``_save()`` should treat ``False`` as "the
        in-memory mutation did not reach disk" and react accordingly
        (e.g. roll back the in-memory state, or surface an error to
        the operator).
        """
        # v0.8.5.6: refuse to write when the on-disk file has a
        # MAC we don't recognize. Otherwise every pinned peer in that
        # file gets clobbered the next time anyone calls _save().
        if self._readonly_due_to_mac_failure:
            logger.error(
                "Trust store at %s is LOCKED read-only (MAC mismatch on "
                "load). Refusing to save — would silently overwrite a "
                "file written by a different identity. Resolve the "
                "underlying collision (separate --trust-path per "
                "daemon, or remove the foreign file) and restart.",
                self.path,
            )
            return False
        # v0.8.5.6: hold a cross-process flock around the
        # tmp-write + rename so two processes can't trash each other's
        # in-flight tmp file.
        try:
            payload = self._serialize_envelope()
        except RuntimeError as e:
            logger.error("Failed to serialize trust store: %s", e)
            return False
        with _trust_file_lock(self.path):
            return self._atomic_write(payload)

    @staticmethod
    def fingerprint(pubkey_b64: str) -> str:
        """Compute SHA-256 fingerprint of a base64-encoded public key."""
        import base64
        raw = base64.b64decode(pubkey_b64)
        return hashlib.sha256(raw).hexdigest()[:32]

    def verify_peer(self, node_id: str, identity_public_b64: str) -> str:
        """Verify a peer's identity key against stored trust.

        Returns:
            "new" — first time seeing this peer, should pin
            "trusted" — key matches stored key
            "mismatch" — key changed since first seen (possible MITM!)
        """
        stored = self._peers.get(node_id)
        if stored is None:
            return "new"

        if stored.get("pubkey") == identity_public_b64:
            # Update last_seen
            stored["last_seen"] = time.time()
            self._save()
            return "trusted"

        return "mismatch"

    def pin_peer(self, node_id: str, identity_public_b64: str,
                 trust_state: str = "trusted",
                 pinned_via: Optional[str] = None):
        """Pin a peer's identity key (first-use trust).

        Args:
            trust_state: Initial trust state for the new pin. Defaults to
                "trusted" for backwards compatibility. Callers can pass
                "pending" when ``require_message_promotion`` is enabled
                so the peer's MSGs queue until an operator promotes.
            pinned_via: Optional provenance marker for how this pin was
                established (e.g. ``"invite"`` for the bootstrap-token
                path). Purely informational for audit / UX — it is NOT a
                trust state and does not affect gating. Omitted from the
                record when None to keep legacy pins byte-identical.
        """
        if trust_state not in ("pending", "trusted", "blocked", "pending-cap-change"):
            raise ValueError(f"invalid trust_state: {trust_state!r}")
        fp = self.fingerprint(identity_public_b64)
        now = time.time()
        record = {
            "pubkey": identity_public_b64,
            "fingerprint": fp,
            "first_seen": now,
            "last_seen": now,
            "trust_state": trust_state,
        }
        if pinned_via is not None:
            record["pinned_via"] = pinned_via
        self._peers[node_id] = record
        self._save()
        logger.info("Pinned peer %s (fingerprint: %s, trust_state: %s, via: %s)",
                    node_id, fp, trust_state, pinned_via or "tofu")

    def revoke_peer(self, node_id: str) -> bool:
        """Revoke trust for a peer."""
        if node_id in self._peers:
            del self._peers[node_id]
            self._save()
            logger.info("Revoked trust for peer %s", node_id)
            return True
        return False

    def mark_revoked(self, target_node_id: str, revoker_node_id: str,
                     timestamp: float, reason: str = "") -> None:
        """v0.6: Mark a peer as revoked via signed broadcast.

        The target is removed from ``_peers`` (TOFU pin is dropped) and
        added to ``_revoked``. Future connections from this node_id will
        be rejected by the bridge.
        """
        self._revoked[target_node_id] = {
            "revoker": revoker_node_id,
            "timestamp": timestamp,
            "reason": reason,
        }
        # Also drop any existing TOFU pin
        self._peers.pop(target_node_id, None)
        self._save()
        logger.warning("Peer %s marked REVOKED by %s (reason: %s)",
                       target_node_id, revoker_node_id, reason or "none")

    def is_revoked(self, node_id: str) -> bool:
        """Return True if the peer has been revoked."""
        return node_id in self._revoked

    def list_revoked(self) -> List[dict]:
        """List all revoked peers with revocation details."""
        return [
            {"node_id": nid, **data}
            for nid, data in self._revoked.items()
        ]

    def clear_revocation(self, node_id: str) -> bool:
        """Administratively clear a revocation (allows re-pinning)."""
        if node_id in self._revoked:
            del self._revoked[node_id]
            self._save()
            logger.info("Cleared revocation for peer %s", node_id)
            return True
        return False

    def list_peers(self) -> List[dict]:
        """List all trusted peers."""
        result = []
        for node_id, data in self._peers.items():
            result.append({
                "node_id": node_id,
                "fingerprint": data.get("fingerprint", ""),
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
                "trust_state": data.get("trust_state", "trusted"),
            })
        return result

    def get_peer(self, node_id: str) -> Optional[dict]:
        return self._peers.get(node_id)

    # ------------------------------------------------------------------
    # v0.8.5: pending-trust state machine
    # ------------------------------------------------------------------

    def get_trust_state(self, node_id: str) -> str:
        """Return the per-peer trust state.

        Returns one of: "pending", "trusted", "blocked".

        For pinned peers without an explicit ``trust_state`` field
        (pre-v0.8.5 stores), returns "trusted" — backwards-compatible
        default so the gate doesn't retroactively quarantine anyone.

        For peers we've never seen (not in ``_peers``), returns "pending".
        Returns "blocked" for peers in ``_revoked``.
        """
        if node_id in self._revoked:
            return "blocked"
        rec = self._peers.get(node_id)
        if rec is None:
            return "pending"
        return rec.get("trust_state", "trusted")

    def set_trust_state(self, node_id: str, state: str) -> bool:
        """Update the trust state for an already-pinned peer.

        Returns True when the peer existed and was updated. Operators
        flip "pending" → "trusted" via this entry point. Use
        ``mark_revoked`` for the wire-level REVOCATION flow when you
        want network-wide propagation; ``set_trust_state(.., "blocked")``
        is a local-only quiet block.
        """
        if state not in ("pending", "trusted", "blocked", "pending-cap-change"):
            raise ValueError(f"invalid trust_state: {state!r}")
        rec = self._peers.get(node_id)
        if rec is None:
            return False
        # v0.8.5.6: honor _save()'s return value. If the save
        # was refused (read-only latch) or failed (disk error),
        # roll back the in-memory mutation and return False so the
        # caller can surface the failure rather than claiming success.
        old_state = rec.get("trust_state")
        rec["trust_state"] = state
        if not self._save():
            rec["trust_state"] = old_state
            logger.warning(
                "set_trust_state rolled back for %s: _save() did not persist",
                node_id,
            )
            return False
        logger.info("Trust state for %s -> %s", node_id, state)
        return True

    def list_by_trust_state(self, state: str) -> List[dict]:
        """List peers in a specific trust state. Useful for dashboards."""
        out = []
        for node_id, data in self._peers.items():
            if data.get("trust_state", "trusted") == state:
                out.append({
                    "node_id": node_id,
                    "fingerprint": data.get("fingerprint", ""),
                    "first_seen": data.get("first_seen"),
                    "last_seen": data.get("last_seen"),
                    "trust_state": data.get("trust_state", "trusted"),
                    "capability_hash": data.get("capability_hash"),
                    "capability_set": list(data.get("capability_set") or []),
                })
        return out

    # ------------------------------------------------------------------
    # v0.8.5.6: capability-set binding
    # ------------------------------------------------------------------

    def observe_capabilities(self, node_id: str, capabilities) -> dict:
        """Compare a peer's observed capability set to the stored one.

        Returns a dict describing the action taken:

            {"status": "first-observation",
             "hash": <hex>,
             "set": [...]}
                → Peer is either new or was migrated from a pre-v0.8.5.6
                trust file (no capability_hash stored yet). The observed
                hash is recorded as the baseline. Caller should NOT
                re-gate; this is the TOFU-for-capabilities path.

            {"status": "match",
             "hash": <hex>,
             "set": [...]}
                → Observed hash equals stored hash. No action needed.

            {"status": "changed",
             "old_hash": <hex>, "new_hash": <hex>,
             "old_set": [...], "new_set": [...],
             "added": [...], "removed": [...]}
                → Capability set differs. Caller should demote the peer
                to ``pending-cap-change`` and emit the
                ``PEER_CAP_SET_CHANGED`` audit event. The stored hash
                is NOT updated here; a successful operator re-promotion
                calls ``accept_capability_change`` to record the new
                baseline.

            {"status": "pending-match",
             "hash": <hex>, "set": [...]}
                → Peer is already in pending-cap-change and re-announced
                the same pending set. Caller should NOT re-fire
                ``PEER_CAP_SET_CHANGED``; the event already surfaced on
                the first observation of the change.

            {"status": "reverted",
             "hash": <hex>, "set": [...],
             "cleared_pending_hash": <hex>}
                → Peer was pending-cap-change but the observed set now
                matches the stored baseline again. The pending stash
                has been cleared. Caller should decide whether to
                re-promote the peer automatically or surface the
                revert to an operator (bridge policy logs an audit
                event and leaves trust_state alone).

            {"status": "unknown-peer"}
                → node_id is not in the trust store at all. Caller
                should not have called this method; it's an error
                sentinel.

        This method updates ``last_seen`` as a side effect (the peer
        was just observed, regardless of the match verdict).
        """
        rec = self._peers.get(node_id)
        if rec is None:
            return {"status": "unknown-peer"}

        observed_set = sorted({str(c).strip() for c in (capabilities or [])
                               if c and str(c).strip()})
        observed_hash = canonical_capability_hash(observed_set)
        stored_hash = rec.get("capability_hash")
        stored_set = list(rec.get("capability_set") or [])
        pending_hash = rec.get("capability_hash_pending")

        rec["last_seen"] = time.time()

        if stored_hash is None:
            # First observation or post-upgrade migration path.
            rec["capability_hash"] = observed_hash
            rec["capability_set"] = observed_set
            rec["cap_first_observed"] = time.time()
            self._save()
            logger.info(
                "Peer %s capability baseline recorded: %d caps, hash %s...",
                node_id, len(observed_set), observed_hash[:12],
            )
            return {
                "status": "first-observation",
                "hash": observed_hash,
                "set": observed_set,
            }

        if stored_hash == observed_hash:
            # Observed set matches the accepted baseline. If a pending
            # change was previously stashed, the peer just reverted —
            # clear the stash so we don't later accept a no-op "change"
            # via accept_capability_change.
            if pending_hash is not None:
                rec.pop("capability_hash_pending", None)
                rec.pop("capability_set_pending", None)
                self._save()
                logger.info(
                    "Peer %s capability set REVERTED to baseline "
                    "(cleared pending hash %s...)",
                    node_id, pending_hash[:12],
                )
                return {
                    "status": "reverted",
                    "hash": observed_hash,
                    "set": observed_set,
                    "cleared_pending_hash": pending_hash,
                }
            # Pure match — no state change. Skip the full _save() write
            # to avoid a disk rewrite on every 30s announce per peer;
            # last_seen is an in-memory bookkeeping value the operator
            # surface can recompute from the audit log if needed.
            return {"status": "match", "hash": observed_hash, "set": observed_set}

        # Stored hash != observed hash. Either a first-time change, or
        # the peer has already been demoted and is re-announcing the
        # same pending set. Distinguish so we don't spam audit events.
        if pending_hash is not None and pending_hash == observed_hash:
            # Re-announce of the already-pending set. No state change,
            # no new audit event.
            return {
                "status": "pending-match",
                "hash": observed_hash,
                "set": observed_set,
            }

        added = sorted(set(observed_set) - set(stored_set))
        removed = sorted(set(stored_set) - set(observed_set))
        self._save()
        logger.warning(
            "Peer %s capability set CHANGED: +%d -%d caps "
            "(old hash %s..., new hash %s...)",
            node_id, len(added), len(removed),
            stored_hash[:12], observed_hash[:12],
        )
        return {
            "status": "changed",
            "old_hash": stored_hash,
            "new_hash": observed_hash,
            "old_set": stored_set,
            "new_set": observed_set,
            "added": added,
            "removed": removed,
        }

    def accept_capability_change(self, node_id: str) -> bool:
        """Record a peer's current observed capability set as the new
        baseline. Called after an operator re-promotes a peer that
        was demoted to ``pending-cap-change``. Returns True if the
        peer exists and the baseline was updated.

        This does NOT flip the peer's trust_state — the caller (CLI /
        MCP / dashboard handler) is responsible for that separate
        action (typically ``set_trust_state(..., "trusted")``).
        """
        # v0.8.5.6: take the trust file lock and re-read from
        # disk inside the lock. Without this, two concurrent operator
        # cap-promote calls each load the file, both see pending,
        # both call accept, and both fire PEER_CAP_ACCEPTED audit
        # events for the same change. Holding the lock + re-reading
        # makes the second caller see pending already cleared and
        # return False honestly.
        with _trust_file_lock(self.path):
            self._load()  # refresh in-memory from disk under the lock
            rec = self._peers.get(node_id)
            if rec is None:
                return False
            pending = rec.get("capability_hash_pending")
            pending_set = rec.get("capability_set_pending")
            if pending is None:
                # Either we never had a pending change, or another
                # process already accepted ours since the caller
                # opened this TrustStore. Either way: nothing to do.
                return False
            rec["capability_hash"] = pending
            rec["capability_set"] = list(pending_set or [])
            rec.pop("capability_hash_pending", None)
            rec.pop("capability_set_pending", None)
            rec["cap_accepted_at"] = time.time()
            # We already hold the trust file lock — call the write helper
            # directly instead of going through _save() (which would try
            # to re-acquire the same flock).
            if self._readonly_due_to_mac_failure:
                logger.error(
                    "accept_capability_change: trust store at %s is "
                    "LOCKED read-only — refusing to save", self.path,
                )
                return False
            try:
                payload = self._serialize_envelope()
            except RuntimeError as e:
                logger.error("accept_capability_change: serialize failed: %s", e)
                return False
            if not self._atomic_write(payload):
                return False
            logger.info(
                "Peer %s capability baseline updated to hash %s...",
                node_id, pending[:12],
            )
            return True

    def list_by_capability_status(self, status: str) -> List[dict]:
        """List peers whose capability-binding status matches ``status``.

        Valid values: "pending-cap-change", "cap-baseline", "cap-unknown".
        """
        out = []
        for node_id, data in self._peers.items():
            has_hash = data.get("capability_hash") is not None
            pending = data.get("capability_hash_pending") is not None
            match = False
            if status == "pending-cap-change":
                match = pending
            elif status == "cap-baseline":
                match = has_hash and not pending
            elif status == "cap-unknown":
                match = not has_hash
            if match:
                out.append({
                    "node_id": node_id,
                    "fingerprint": data.get("fingerprint", ""),
                    "trust_state": data.get("trust_state", "trusted"),
                    "capability_hash": data.get("capability_hash"),
                    "capability_set": list(data.get("capability_set") or []),
                    "pending_hash": data.get("capability_hash_pending"),
                    "pending_set": list(data.get("capability_set_pending") or []),
                })
        return out

    def stash_pending_capability_change(self, node_id: str,
                                        observed_caps) -> bool:
        """Record the pending (not-yet-accepted) capability set for a
        peer whose hash changed. Returns True on success.

        Called by the bridge when ``observe_capabilities`` returns
        ``status=changed``. The operator later runs
        ``accept_capability_change`` (via CLI / MCP / dashboard) to
        promote the pending set to the baseline.
        """
        rec = self._peers.get(node_id)
        if rec is None:
            return False
        observed_set = sorted({str(c).strip() for c in (observed_caps or [])
                               if c and str(c).strip()})
        # v0.8.5.6: honor _save()'s return value. Roll back on
        # failure so callers can detect it and skip downstream side
        # effects (e.g. the PEER_CAP_SET_CHANGED audit event should
        # NOT fire if the stash didn't reach disk).
        old_hash = rec.get("capability_hash_pending")
        old_set = rec.get("capability_set_pending")
        rec["capability_hash_pending"] = canonical_capability_hash(observed_set)
        rec["capability_set_pending"] = observed_set
        if not self._save():
            if old_hash is None:
                rec.pop("capability_hash_pending", None)
            else:
                rec["capability_hash_pending"] = old_hash
            if old_set is None:
                rec.pop("capability_set_pending", None)
            else:
                rec["capability_set_pending"] = old_set
            logger.warning(
                "stash_pending_capability_change rolled back for %s: "
                "_save() did not persist", node_id,
            )
            return False
        return True
