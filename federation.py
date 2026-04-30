"""IronMesh Multi-Mesh Federation Gateway.

Bridges two independent IronMesh meshes with policy-controlled
capability sharing. Each mesh keeps its own trust boundary — the
gateway is a member of both, forwarding messages that match its
policy rules.

Usage::

    from ironmesh.federation import FederationGateway

    gw = FederationGateway(
        mesh_a={"name": "gw-alpha", "port": 8780, "passphrase": "mesh-a-pass"},
        mesh_b={"name": "gw-beta",  "port": 8781, "passphrase": "mesh-b-pass"},
        policy={"allow": ["llm:*", "tool:search"], "deny": ["tool:filesystem"]},
    )
    gw.run()

Architecture:
    - Runs TWO Agent instances (one per mesh), each with separate identity.
    - Subscribes to MSG events on both buses.
    - When a message arrives on mesh-A destined for a capability only
      available on mesh-B, the gateway forwards it (re-encrypts with
      mesh-B's session keys automatically via send_sync).
    - Policy: allow/deny lists based on capability glob patterns.
    - Every cross-mesh forward is logged as EVENT_FEDERATION_FORWARD.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from ironmesh.agent import Agent

logger = logging.getLogger("ironmesh.federation")

FORWARD_PREFIX = b"[FED] "


class FederationPolicy:
    """Policy engine for cross-mesh message forwarding.

    v0.9.2 adds **per-source rules**. The policy document can now carry
    a ``per_source`` list whose entries override the global allow/deny
    when the sending peer's node_id or agent name matches a glob::

        {
            "allow": ["llm:*"],
            "deny":  ["tool:filesystem"],
            "per_source": [
                {"source": "ops-*",     "allow": ["*"]},
                {"source": "guest-*",   "deny":  ["*"]},
                {"source": "trader-*",  "allow": ["tool:trade:read"],
                                        "deny":  ["tool:trade:write"]}
            ]
        }

    Per-source rules are evaluated in document order; the first match
    wins. Falls through to the global allow/deny if no rule matches.
    Backwards compatible: omit ``per_source`` and behavior is unchanged
    from v0.9.1.
    """

    def __init__(self, allow: Optional[List[str]] = None,
                 deny: Optional[List[str]] = None,
                 per_source: Optional[List[Dict[str, Any]]] = None):
        self.allow_patterns = allow or ["*"]
        self.deny_patterns = deny or []
        self.per_source: List[Dict[str, Any]] = []
        for entry in per_source or []:
            if not isinstance(entry, dict):
                continue
            src = entry.get("source")
            if not src or not isinstance(src, str):
                continue
            self.per_source.append({
                "source": src,
                "allow": list(entry.get("allow", ["*"])),
                "deny": list(entry.get("deny", [])),
            })

    def should_forward(self, capability: str,
                        source: Optional[str] = None) -> bool:
        # Per-source override: first matching `source` glob wins.
        if source:
            for rule in self.per_source:
                if fnmatch.fnmatch(source, rule["source"]):
                    if any(fnmatch.fnmatch(capability, p) for p in rule["deny"]):
                        return False
                    return any(fnmatch.fnmatch(capability, p) for p in rule["allow"])
        # Global rules
        if any(fnmatch.fnmatch(capability, p) for p in self.deny_patterns):
            return False
        return any(fnmatch.fnmatch(capability, p) for p in self.allow_patterns)

    def to_dict(self) -> Dict:
        out = {"allow": self.allow_patterns, "deny": self.deny_patterns}
        if self.per_source:
            out["per_source"] = self.per_source
        return out


class FederationGateway:
    """Bridges two IronMesh meshes with policy-controlled forwarding."""

    def __init__(
        self,
        mesh_a: Dict[str, Any],
        mesh_b: Dict[str, Any],
        policy: Optional[Dict] = None,
        config_path: str = "~/.ironmesh/federation.json",
    ):
        policy = policy or {}
        self.policy = FederationPolicy(
            allow=policy.get("allow"),
            deny=policy.get("deny"),
            per_source=policy.get("per_source"),
        )
        self.config_path = os.path.expanduser(config_path)

        self.agent_a = Agent(
            mesh_a["name"],
            port=mesh_a.get("port", 8780),
            passphrase=mesh_a.get("passphrase"),
            **{k: v for k, v in mesh_a.items() if k not in ("name", "port", "passphrase")},
        )
        self.agent_b = Agent(
            mesh_b["name"],
            port=mesh_b.get("port", 8781),
            passphrase=mesh_b.get("passphrase"),
            **{k: v for k, v in mesh_b.items() if k not in ("name", "port", "passphrase")},
        )

        self.stats = {
            "forwarded_a_to_b": 0,
            "forwarded_b_to_a": 0,
            "denied": 0,
            "errors": 0,
        }
        self._running = False

    def _forward_handler(self, source_agent: Agent, dest_agent: Agent,
                          direction: str):
        """Create a bus handler that forwards matching messages.

        v0.8.5.2: targeted forwarding — only delivers to peers on the
        destination mesh that actually advertise a policy-allowed
        capability. Previously forwarded to ALL peers on the dest mesh
        if ANY peer there advertised an allowed capability, which could
        leak cross-mesh traffic to unrelated participants.
        """
        def handler(peer_id: str, payload: bytes):
            if payload.startswith(FORWARD_PREFIX):
                return

            # Map each dest-mesh peer to its advertised capabilities.
            # discover("*") returns (node_id, capability) tuples.
            peer_caps: Dict[str, List[str]] = {}
            for nid, cap in dest_agent.discover("*"):
                peer_caps.setdefault(nid, []).append(cap)

            # For each dest peer, forward only if AT LEAST ONE of its
            # advertised capabilities passes the policy. A peer with no
            # advertised capabilities never receives forwarded traffic.
            forwarded_any = False
            for target_nid, caps in peer_caps.items():
                matched_cap = next(
                    (c for c in caps if self.policy.should_forward(c, source=peer_id)),
                    None,
                )
                if matched_cap is None:
                    continue
                try:
                    dest_agent.reply(target_nid, FORWARD_PREFIX + payload)
                    self.stats[f"forwarded_{direction}"] += 1
                    forwarded_any = True
                    logger.info(
                        "FED %s: %s → %s (%d bytes, cap=%s)",
                        direction, peer_id[:12],
                        target_nid[:12], len(payload), matched_cap,
                    )
                except Exception as e:
                    self.stats["errors"] += 1
                    logger.warning("FED forward error: %s", e)

            if not forwarded_any:
                self.stats["denied"] += 1

        return handler

    def run(self, foreground: bool = True):
        """Start both mesh agents and the forwarding bridge."""
        self._running = True

        self.agent_a.run(foreground=False)
        self.agent_b.run(foreground=False)

        @self.agent_a.on_message()
        def a_to_b(peer_id, payload):
            self._forward_handler(self.agent_a, self.agent_b, "a_to_b")(peer_id, payload)

        @self.agent_b.on_message()
        def b_to_a(peer_id, payload):
            self._forward_handler(self.agent_b, self.agent_a, "b_to_a")(peer_id, payload)

        self.agent_a._wire_handlers()
        self.agent_b._wire_handlers()

        logger.info("Federation gateway running")
        logger.info("  Mesh A: %s (port %d)", self.agent_a.name, self.agent_a.daemon.port)
        logger.info("  Mesh B: %s (port %d)", self.agent_b.name, self.agent_b.daemon.port)
        logger.info("  Policy: %s", json.dumps(self.policy.to_dict()))

        if not foreground:
            return

        try:
            while self._running:
                time.sleep(30)
                logger.info("FED stats: %s", json.dumps(self.stats))
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self._running = False
        self.agent_a.stop()
        self.agent_b.stop()
        logger.info("Federation gateway stopped")
