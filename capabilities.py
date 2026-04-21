"""IronMesh capability registry — local + remote capability advertisements.

Capabilities are short string identifiers (typically ``namespace:name``,
e.g. ``llm:llama3``, ``tool:filesystem``) that nodes advertise so other
agents on the mesh can discover services. The registry holds:

    - The local node's own advertised capabilities
    - Capabilities learned from remote nodes via ``CAPABILITY_ANNOUNCE``
      messages (which propagate via mesh routing).

Glob matching uses :func:`fnmatch.fnmatchcase` so callers can do
``find("llm:*")`` to discover any LLM provider on the mesh.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("ironmesh.capabilities")


class CapabilityRegistry:
    """Tracks local and remote capabilities and supports pattern lookup.

    The registry is an in-memory store, optionally persisted to disk
    HMAC-protected. Persistence is best-effort: a corrupt or missing
    file is silently treated as empty.
    """

    def __init__(self, my_node_id: str, persist_path: Optional[str] = None,
                 hmac_key: Optional[bytes] = None):
        self._my_node_id = my_node_id
        self._persist_path = (
            os.path.expanduser(persist_path) if persist_path else None
        )
        self._hmac_key = hmac_key
        # Audit M-09: validate HMAC key presence at init when persistence
        # is enabled — otherwise the registry silently persists unsigned
        # state that a malicious reader/writer could tamper.
        if self._persist_path and not self._hmac_key:
            logger.critical(
                "CapabilityRegistry persist_path=%s without hmac_key — "
                "persisted state will NOT be integrity-protected",
                self._persist_path,
            )
        # node_id -> set[capability]
        self._remote: Dict[str, Set[str]] = {}
        # local capabilities (kept separate so they're never overwritten by a
        # remote announcement that happens to claim our id)
        self._local: Set[str] = set()
        # node_id -> last update timestamp (for housekeeping)
        self._updated: Dict[str, float] = {}

    # ----- local -----

    def advertise_local(self, capability: str) -> None:
        if not isinstance(capability, str) or not capability:
            return
        self._local.add(capability)
        self._updated[self._my_node_id] = time.time()

    def remove_local(self, capability: str) -> None:
        self._local.discard(capability)
        self._updated[self._my_node_id] = time.time()

    def set_local(self, capabilities) -> None:
        """v0.8.5.6 — replace the entire local capability set in one shot.

        ``advertise_local`` is purely additive, which means a daemon
        that calls ``load()`` (picking up caps from a previous run)
        and then ``advertise_local()`` for each cap from its current
        config ends up announcing the *union* of old + new. If the
        operator restarted the daemon with a different ``--role`` or
        a different capability set, the previously-persisted caps
        keep getting announced as ghost capabilities. Call this
        instead when the caller has an authoritative cap list and
        wants the local set to mirror it exactly.
        """
        new = {str(c).strip() for c in (capabilities or [])
               if c and str(c).strip()}
        self._local = new
        self._updated[self._my_node_id] = time.time()

    def local_capabilities(self) -> List[str]:
        return sorted(self._local)

    # ----- remote -----

    def learn_remote(self, node_id: str, capabilities: List[str]) -> int:
        """Replace the cached capability set for a remote node.

        Returns the number of capabilities added or changed.
        """
        if not node_id or node_id == self._my_node_id:
            return 0
        new_set = {c for c in capabilities if isinstance(c, str) and c}
        old_set = self._remote.get(node_id, set())
        delta = len(new_set.symmetric_difference(old_set))
        self._remote[node_id] = new_set
        self._updated[node_id] = time.time()
        return delta

    def forget_remote(self, node_id: str) -> None:
        self._remote.pop(node_id, None)
        self._updated.pop(node_id, None)

    # ----- query -----

    def find(self, pattern: str) -> List[Tuple[str, str]]:
        """Return a list of (node_id, capability) pairs matching the pattern.

        Pattern uses fnmatch glob syntax. Both local and remote capabilities
        are searched.
        """
        results: List[Tuple[str, str]] = []
        for cap in self._local:
            if fnmatch.fnmatchcase(cap, pattern):
                results.append((self._my_node_id, cap))
        for node_id, caps in self._remote.items():
            for cap in caps:
                if fnmatch.fnmatchcase(cap, pattern):
                    results.append((node_id, cap))
        return results

    def all(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {self._my_node_id: sorted(self._local)}
        for node_id, caps in self._remote.items():
            out[node_id] = sorted(caps)
        return out

    def remote_nodes(self) -> List[str]:
        return list(self._remote.keys())

    def __len__(self) -> int:
        total = len(self._local)
        for caps in self._remote.values():
            total += len(caps)
        return total

    # ----- persistence -----

    def save(self) -> bool:
        if not self._persist_path or self._hmac_key is None:
            return False
        body = json.dumps({
            "my_node_id": self._my_node_id,
            "local": sorted(self._local),
            "remote": {k: sorted(v) for k, v in self._remote.items()},
        }, separators=(",", ":"), sort_keys=True)
        mac = hmac.new(self._hmac_key, body.encode("utf-8"),
                       hashlib.sha256).hexdigest()
        try:
            os.makedirs(os.path.dirname(self._persist_path) or ".", exist_ok=True)
            # v0.8.5.6 B11 fix: atomic write via temp + rename.
            # Non-atomic truncate+write could leave an empty
            # capabilities.json under SIGKILL, losing every known
            # cap on next start.
            tmp_path = self._persist_path + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump({"hmac": mac, "body": body}, f)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except (OSError, AttributeError):
                    pass
            os.replace(tmp_path, self._persist_path)
            return True
        except Exception as e:
            logger.debug("Capability save failed: %s", e)
            return False

    def load(self) -> bool:
        if not self._persist_path or self._hmac_key is None:
            return False
        if not os.path.exists(self._persist_path):
            return False
        try:
            with open(self._persist_path) as f:
                data = json.load(f)
            stored = data.get("hmac", "")
            body = data.get("body", "")
            expected = hmac.new(self._hmac_key, body.encode("utf-8"),
                                hashlib.sha256).hexdigest()
            if not hmac.compare_digest(stored, expected):
                logger.warning("Capability file failed HMAC verification")
                return False
            obj = json.loads(body)
            if obj.get("my_node_id") != self._my_node_id:
                logger.info("Capability file is for a different node — ignoring")
                return False
            self._local = set(obj.get("local", []))
            self._remote = {k: set(v) for k, v in obj.get("remote", {}).items()}
            return True
        except Exception as e:
            logger.warning("Capability load failed: %s", e)
            return False

    def announcement_payload(self) -> dict:
        return {
            "origin": self._my_node_id,
            "capabilities": sorted(self._local),
        }
