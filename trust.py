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
                            logger.critical("Trust store integrity check FAILED — file may be tampered")
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
            with open(self.path, "w") as f:
                json.dump(envelope, f, indent=2)
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

    def pin_peer(self, node_id: str, identity_public_b64: str):
        """Pin a peer's identity key (first-use trust)."""
        fp = self.fingerprint(identity_public_b64)
        now = time.time()
        self._peers[node_id] = {
            "pubkey": identity_public_b64,
            "fingerprint": fp,
            "first_seen": now,
            "last_seen": now,
        }
        self._save()
        logger.info("Pinned peer %s (fingerprint: %s)", node_id, fp)

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
            })
        return result

    def get_peer(self, node_id: str) -> Optional[dict]:
        return self._peers.get(node_id)
