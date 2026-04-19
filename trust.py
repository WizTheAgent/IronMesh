"""IronMesh TOFU (Trust-On-First-Use) peer key pinning.

On first connection to a peer, saves their Ed25519 identity public key.
On subsequent connections, compares — if key changed, warns of possible MITM.
Trust store file is integrity-protected with HMAC to detect tampering.
"""

import hashlib
import hmac as hmac_mod
import json
import logging
import os
import time
from typing import Dict, List, Optional

logger = logging.getLogger("ironmesh.trust")

DEFAULT_TRUST_PATH = "~/.ironmesh/known_peers.json"

# Legacy MAC key (home-directory-derived) — kept only for one-shot
# migration away from the v0.5 format. No new trust stores should rely
# on it. Audit C-03 requires every TrustStore to be bound to the
# agent's identity key.
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


class TrustStore:
    """TOFU key pinning database backed by JSON file with integrity MAC."""

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
        self._peers: Dict[str, dict] = {}
        self._revoked: Dict[str, dict] = {}  # v0.6: node_id -> {revoker, timestamp, reason}
        self._load()

    def _compute_mac(self, data: str) -> str:
        """Compute HMAC-SHA256 over trust store data."""
        return hmac_mod.new(self._mac_key, data.encode(), hashlib.sha256).hexdigest()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    raw = json.load(f)
                # Verify integrity MAC if present
                if isinstance(raw, dict) and "_mac" in raw:
                    stored_mac = raw.pop("_mac")
                    data_str = json.dumps(raw, sort_keys=True, separators=(",", ":"))
                    expected_mac = self._compute_mac(data_str)
                    if hmac_mod.compare_digest(stored_mac, expected_mac):
                        self._peers = raw.get("peers", raw)
                        self._revoked = raw.get("revoked", {}) if isinstance(raw, dict) else {}
                    else:
                        # Audit C-03: one-shot migration from legacy
                        # home-directory-derived MAC to agent-key MAC.
                        old_mac = hmac_mod.new(
                            _LEGACY_MAC_KEY, data_str.encode(), hashlib.sha256
                        ).hexdigest()
                        if hmac_mod.compare_digest(stored_mac, old_mac):
                            logger.info("Trust store: migrating from legacy MAC key to agent-bound MAC")
                            self._peers = raw.get("peers", raw)
                            self._save()  # Re-save with new key
                        else:
                            # v0.8.5.2: include MAC context + multi-daemon hint.
                            # The most common cause is two daemons on one host
                            # writing the same trust file with different keypairs
                            # (the v0.8.4 collision pattern fixed by --trust-path
                            # in v0.8.5+). Tampering is the other possibility.
                            logger.critical(
                                "Trust store integrity check FAILED at %s — "
                                "stored_mac=%s expected_mac=%s peers_in_file=%d. "
                                "If you run multiple daemons on this host, give "
                                "each its own --trust-path to avoid silent "
                                "collisions; otherwise the file may be tampered.",
                                self.path,
                                stored_mac[:16] + "…",
                                expected_mac[:16] + "…",
                                len(raw.get("peers", {})) if isinstance(raw, dict) else 0,
                            )
                            self._peers = {}
                            return
                elif isinstance(raw, dict):
                    # Legacy format without MAC — migrate on next save
                    self._peers = raw.get("peers", raw) if "peers" in raw else raw
                else:
                    self._peers = {}
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("Failed to load trust store: %s", e)
                self._peers = {}

    def _save(self):
        try:
            # Wrap peers + revoked in envelope with MAC
            envelope = {"peers": self._peers, "revoked": self._revoked}
            data_str = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
            envelope["_mac"] = self._compute_mac(data_str)
            # v0.8.5.2: atomic write via temp + rename so SIGKILL / power loss
            # mid-write can't leave a truncated trust file. Operators would
            # otherwise lose every pinned peer on an unclean shutdown.
            tmp_path = self.path + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump(envelope, f, indent=2)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except (OSError, AttributeError):
                    pass  # fsync unavailable on some platforms (e.g. Windows on network drives)
            os.replace(tmp_path, self.path)  # atomic on POSIX; atomic on same-drive NTFS
        except IOError as e:
            logger.error("Failed to save trust store: %s", e)

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
                 trust_state: str = "trusted"):
        """Pin a peer's identity key (first-use trust).

        Args:
            trust_state: Initial trust state for the new pin. Defaults to
                "trusted" for backwards compatibility. Callers can pass
                "pending" when ``require_message_promotion`` is enabled
                so the peer's MSGs queue until an operator promotes.
        """
        if trust_state not in ("pending", "trusted", "blocked"):
            raise ValueError(f"invalid trust_state: {trust_state!r}")
        fp = self.fingerprint(identity_public_b64)
        now = time.time()
        self._peers[node_id] = {
            "pubkey": identity_public_b64,
            "fingerprint": fp,
            "first_seen": now,
            "last_seen": now,
            "trust_state": trust_state,
        }
        self._save()
        logger.info("Pinned peer %s (fingerprint: %s, trust_state: %s)",
                    node_id, fp, trust_state)

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
        if state not in ("pending", "trusted", "blocked"):
            raise ValueError(f"invalid trust_state: {state!r}")
        rec = self._peers.get(node_id)
        if rec is None:
            return False
        rec["trust_state"] = state
        self._save()
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
                })
        return out
