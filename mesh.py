"""IronMesh multi-hop routing — RoutingTable, DedupCache, CircuitBreaker, MeshRouter.

Routing model:
    Proactive distance-vector with split horizon + poisoned reverse. Each node
    periodically announces its routing table to direct neighbors. Neighbors
    install routes with cost = announced_cost + 1, preferring lower-cost paths.
    Loop prevention: routes back to the announcer are sent with cost=infinity
    (poisoned reverse) and the relay path embeds a hop list checked at each step.

Per-message reliability:
    - TTL-based hard cap (max_hops, default 5) prevents unbounded forwarding.
    - Per-source sharded dedup cache prevents replay/loop amplification while
      capping the blast radius of any single malicious source.
    - Circuit breaker opens after 3 consecutive failures within 60s; failed
      next-hops are skipped until the breaker closes.

Persistence:
    Routes are saved to disk HMAC-protected. On startup, routes load with a
    shortened TTL so stale entries refresh quickly while still avoiding the
    cold-start black hole.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from typing import Dict, List, Optional

from ironmesh.audit import (
    EVENT_CIRCUIT_BREAKER_TRIPPED,
    EVENT_DUPLICATE_DROPPED,
    EVENT_MESH_PARTITION_SUSPECTED,
    EVENT_MESSAGE_RELAYED,
    EVENT_MSG_REPLAY_CROSS_TRANSPORT,
    EVENT_NO_ROUTE,
    EVENT_ROUTE_ANNOUNCED,
    EVENT_ROUTE_EXPIRED,
    EVENT_ROUTE_LEARNED,
    EVENT_ROUTE_LOOP,
    EVENT_TTL_EXPIRED,
)

logger = logging.getLogger("ironmesh.mesh")


# ---------------------------------------------------------------------------
# RoutingTable
# ---------------------------------------------------------------------------

INFINITY_COST = 16  # RIP-style infinity (low number to support split horizon)


class RoutingTable:
    """Distance-vector routing table with split horizon + poisoned reverse.

    Each entry maps:
        destination_node_id -> {
            next_hop: peer_id,
            cost: int (hop count),
            learned_from: peer_id (who announced this route),
            updated: timestamp,
        }
    """

    def __init__(self, my_node_id: str, ttl: float = 90.0):
        self._my_node_id = my_node_id
        self._ttl = ttl
        self._routes: Dict[str, dict] = {}

    @property
    def my_node_id(self) -> str:
        return self._my_node_id

    def add_route(
        self,
        dst: str,
        next_hop: str,
        cost: int,
        learned_from: str,
        now: Optional[float] = None,
    ) -> bool:
        """Install or update a route. Lower cost wins; ties refresh.

        Returns True if the table was changed.
        """
        if dst == self._my_node_id:
            return False  # never install routes to self
        if cost <= 0 or cost >= INFINITY_COST:
            # Treat infinity as withdrawal: drop existing route via this learner
            existing = self._routes.get(dst)
            if existing and existing.get("learned_from") == learned_from:
                self._routes.pop(dst, None)
                return True
            return False

        ts = now if now is not None else time.time()
        existing = self._routes.get(dst)
        if existing is None:
            self._routes[dst] = {
                "next_hop": next_hop,
                "cost": cost,
                "learned_from": learned_from,
                "updated": ts,
            }
            return True

        # Refresh from same learner
        if existing.get("learned_from") == learned_from:
            existing["next_hop"] = next_hop
            existing["cost"] = cost
            existing["updated"] = ts
            return True

        # Different learner: prefer lower cost
        if cost < existing["cost"]:
            self._routes[dst] = {
                "next_hop": next_hop,
                "cost": cost,
                "learned_from": learned_from,
                "updated": ts,
            }
            return True

        return False

    def get_next_hop(self, dst: str) -> Optional[str]:
        entry = self._routes.get(dst)
        if entry is None:
            return None
        return entry["next_hop"]

    def get_cost(self, dst: str) -> Optional[int]:
        entry = self._routes.get(dst)
        if entry is None:
            return None
        return entry["cost"]

    def get_route(self, dst: str) -> Optional[dict]:
        entry = self._routes.get(dst)
        if entry is None:
            return None
        return dict(entry)

    def all_destinations(self) -> List[str]:
        return list(self._routes.keys())

    def __len__(self) -> int:
        return len(self._routes)

    def expire_old(self, now: Optional[float] = None) -> List[str]:
        """Remove routes older than TTL. Returns list of expired destinations."""
        ts = now if now is not None else time.time()
        expired = [
            dst for dst, route in self._routes.items()
            if ts - route["updated"] > self._ttl
        ]
        for dst in expired:
            self._routes.pop(dst, None)
        return expired

    def to_announcement(self, exclude_peer: Optional[str] = None) -> List[dict]:
        """Build a routing announcement for a specific neighbor.

        Implements split horizon with poisoned reverse:
        - Routes whose ``learned_from`` is the recipient are advertised with
          cost=INFINITY_COST (poisoned reverse) so the recipient knows we
          are not a backup path for them.
        - All other routes are advertised at their actual cost.
        - Self route (cost=0) is always included.
        """
        out = [{"destination": self._my_node_id, "cost": 0}]
        for dst, route in self._routes.items():
            if dst == exclude_peer:
                continue
            if exclude_peer is not None and route.get("learned_from") == exclude_peer:
                # Poisoned reverse: tell the announcer we don't reach them via them
                out.append({"destination": dst, "cost": INFINITY_COST})
            else:
                out.append({"destination": dst, "cost": route["cost"]})
        return out

    # ----- persistence -----

    def to_serializable(self) -> dict:
        return {
            "my_node_id": self._my_node_id,
            "ttl": self._ttl,
            "routes": self._routes,
        }

    def save(self, path: str, hmac_key: bytes) -> None:
        # v0.8.5.6: atomic write via temp + rename so a
        # SIGKILL / power loss between truncate and write can't
        # leave an empty routes.json (which wiped every learned
        # route on the next daemon start). Mirrors the pattern in
        # trust._save.
        path = os.path.expanduser(path)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        body = json.dumps(self.to_serializable(), separators=(",", ":"), sort_keys=True)
        mac = hmac.new(hmac_key, body.encode("utf-8"), hashlib.sha256).hexdigest()
        tmp_path = path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump({"hmac": mac, "body": body}, f)
            f.flush()
            try:
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                pass
        os.replace(tmp_path, path)

    def load(self, path: str, hmac_key: bytes,
             refresh_ttl: float = 30.0) -> bool:
        """Load routes from disk with HMAC verification.

        Args:
            path: route store path.
            hmac_key: HMAC verification key.
            refresh_ttl: Loaded routes are stamped to expire after this many
                         seconds, so the daemon refreshes them quickly on startup.
        Returns True on success, False on missing/corrupt file.
        """
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            return False
        try:
            with open(path) as f:
                data = json.load(f)
            stored = data.get("hmac", "")
            body = data.get("body", "")
            expected = hmac.new(hmac_key, body.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(stored, expected):
                logger.warning("Routes file %s failed HMAC verification — ignoring", path)
                return False
            obj = json.loads(body)
            if obj.get("my_node_id") != self._my_node_id:
                logger.info("Routes file is for a different node — ignoring")
                return False
            now = time.time()
            for dst, route in obj.get("routes", {}).items():
                if dst == self._my_node_id:
                    continue
                # Stamp with shortened TTL
                route["updated"] = now - max(0.0, self._ttl - refresh_ttl)
                self._routes[dst] = route
            return True
        except Exception as e:
            logger.warning("Failed to load routes from %s: %s", path, e)
            return False


# ---------------------------------------------------------------------------
# DedupCache (per-source sharded LRU)
# ---------------------------------------------------------------------------

class DedupCache:
    """Per-source sharded message-id dedup cache.

    Bounds memory consumption under malicious flooding:
        - At most ``sources_max`` distinct sources are tracked at once.
        - Each source can occupy at most ``per_source_max`` entries.
        - Entries expire after ``ttl`` seconds.
        - LRU eviction at the source level when the source budget is exceeded.
    """

    def __init__(
        self,
        sources_max: int = 128,
        per_source_max: int = 1024,
        ttl: float = 300.0,
    ):
        self._sources_max = sources_max
        self._per_source_max = per_source_max
        self._ttl = ttl
        # OrderedDict for LRU at source level: source -> OrderedDict[msg_id] = ts
        self._sources: "OrderedDict[str, OrderedDict[str, float]]" = OrderedDict()
        # Audit M-07: serialize dedup access. mesh relays can be called
        # from multiple incoming connection coroutines concurrently.
        self._lock = threading.Lock()

    def is_duplicate(self, source: str, msg_id: str) -> bool:
        with self._lock:
            bucket = self._sources.get(source)
            if not bucket:
                return False
            return msg_id in bucket

    def add(self, source: str, msg_id: str, now: Optional[float] = None) -> None:
        ts = now if now is not None else time.time()
        with self._lock:
            self._add_locked(source, msg_id, ts)

    def _add_locked(self, source: str, msg_id: str, ts: float) -> None:
        """Lock-free add. Caller MUST hold ``self._lock``."""
        bucket = self._sources.get(source)
        if bucket is None:
            bucket = OrderedDict()
            self._sources[source] = bucket
        else:
            self._sources.move_to_end(source)

        bucket[msg_id] = ts
        bucket.move_to_end(msg_id)

        while len(bucket) > self._per_source_max:
            bucket.popitem(last=False)
        while len(self._sources) > self._sources_max:
            self._sources.popitem(last=False)

    def check_and_add(
        self, source: str, msg_id: str, now: Optional[float] = None,
    ) -> bool:
        """Atomic test-and-add: return True if this ``(source, msg_id)``
        pair was already seen (caller should drop it as a duplicate), or
        False if it was newly added (caller should process it).

        Fixes the TOCTOU race between ``is_duplicate`` and ``add`` that
        let two concurrent deliveries of the same frame both pass the
        duplicate check when they arrived on different tasks. Added in
        v0.8.3 audit.
        """
        ts = now if now is not None else time.time()
        with self._lock:
            bucket = self._sources.get(source)
            if bucket and msg_id in bucket:
                return True
            self._add_locked(source, msg_id, ts)
            return False

    def check_and_add_with_transport(
        self, source: str, msg_id: str, transport: str,
        now: Optional[float] = None,
    ) -> dict:
        """v0.8.5.6 — atomic test-and-add with transport tracking.

        Returns a result dict:

            {"duplicate": False}
                — New entry; caller should process the frame.

            {"duplicate": True,
             "original_transport": <str>,
             "this_transport": <str>,
             "cross_transport": <bool>,
             "time_delta_s": <float>}
                — Duplicate. ``cross_transport`` is True when the same
                  (source, msg_id) was first seen on a *different*
                  transport than ``transport``. Caller should drop the
                  frame either way and, if ``cross_transport`` is True,
                  emit the ``MSG_REPLAY_CROSS_TRANSPORT`` audit event.

        Existing ``check_and_add`` callers are unaffected — they don't
        track transport and remain backwards-compatible.

        Internal storage: each bucket entry is now a tuple
        ``(timestamp, transport)``. Old-format bucket entries (bare
        ``float``) are still readable; the transport is reported as
        ``None`` for them.
        """
        ts = now if now is not None else time.time()
        with self._lock:
            bucket = self._sources.get(source)
            if bucket and msg_id in bucket:
                stored = bucket[msg_id]
                if isinstance(stored, tuple):
                    original_ts, original_transport = stored
                else:
                    # Legacy entry from check_and_add (bare float).
                    original_ts, original_transport = stored, None
                cross = (original_transport is not None
                         and original_transport != transport)
                return {
                    "duplicate": True,
                    "original_transport": original_transport,
                    "this_transport": transport,
                    "cross_transport": cross,
                    "time_delta_s": max(0.0, ts - original_ts),
                }
            self._add_locked_with_transport(source, msg_id, ts, transport)
            return {"duplicate": False}

    def _add_locked_with_transport(
        self, source: str, msg_id: str, ts: float, transport: str,
    ) -> None:
        """Lock-free add that records the originating transport.

        Caller MUST hold ``self._lock``. Storage shape: tuple
        ``(timestamp, transport)`` for transport-aware adds; bare
        ``float`` for legacy ``add`` / ``_add_locked`` callers.
        """
        bucket = self._sources.get(source)
        if bucket is None:
            bucket = OrderedDict()
            self._sources[source] = bucket
        else:
            self._sources.move_to_end(source)

        bucket[msg_id] = (ts, transport)
        bucket.move_to_end(msg_id)

        while len(bucket) > self._per_source_max:
            bucket.popitem(last=False)
        while len(self._sources) > self._sources_max:
            self._sources.popitem(last=False)

    def cleanup_expired(self, now: Optional[float] = None) -> int:
        # v0.8.5.6: must hold self._lock for the entire scan + delete pass.
        # Pre-fix, cleanup_expired iterated self._sources WITHOUT the lock
        # while every other mutator (add / check_and_add /
        # check_and_add_with_transport) took the lock. Concurrent frame
        # arrival could mutate the OrderedDict mid-iteration, raising
        # "dict changed size during iteration" or skipping entries.
        ts = now if now is not None else time.time()
        removed = 0
        with self._lock:
            empty_sources = []
            for source, bucket in self._sources.items():
                # Bucket values may be bare ``float`` (legacy add path) or
                # ``(float, transport)`` tuples (v0.8.5.6 transport-aware path).
                stale = []
                for k, v in bucket.items():
                    stored_ts = v[0] if isinstance(v, tuple) else v
                    if ts - stored_ts > self._ttl:
                        stale.append(k)
                for k in stale:
                    bucket.pop(k, None)
                    removed += 1
                if not bucket:
                    empty_sources.append(source)
            for source in empty_sources:
                self._sources.pop(source, None)
        return removed

    def size(self) -> int:
        return sum(len(b) for b in self._sources.values())

    def source_count(self) -> int:
        return len(self._sources)


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """Per-peer circuit breaker.

    Opens after ``failure_threshold`` failures within ``window`` seconds.
    Stays open for ``cooldown`` seconds before allowing another attempt.
    """

    STATE_CLOSED = "closed"
    STATE_OPEN = "open"

    def __init__(
        self,
        failure_threshold: int = 3,
        window: float = 60.0,
        cooldown: float = 60.0,
    ):
        self._threshold = failure_threshold
        self._window = window
        self._cooldown = cooldown
        # peer_id -> {failures: list[float], opened_at: Optional[float]}
        self._state: Dict[str, dict] = {}
        self._on_trip = None  # Optional callback (peer_id) -> None

    def set_trip_callback(self, callback) -> None:
        self._on_trip = callback

    def _ensure(self, peer_id: str) -> dict:
        st = self._state.get(peer_id)
        if st is None:
            st = {"failures": [], "opened_at": None}
            self._state[peer_id] = st
        return st

    def record_success(self, peer_id: str) -> None:
        st = self._ensure(peer_id)
        st["failures"] = []
        st["opened_at"] = None

    def record_failure(self, peer_id: str, now: Optional[float] = None) -> None:
        ts = now if now is not None else time.time()
        st = self._ensure(peer_id)
        st["failures"].append(ts)
        st["failures"] = [t for t in st["failures"] if ts - t <= self._window]
        if len(st["failures"]) >= self._threshold and st["opened_at"] is None:
            st["opened_at"] = ts
            logger.warning("Circuit breaker tripped for peer %s", peer_id)
            if self._on_trip is not None:
                try:
                    self._on_trip(peer_id)
                except Exception as e:
                    logger.debug("Circuit breaker callback error: %s", e)

    def is_open(self, peer_id: str, now: Optional[float] = None) -> bool:
        st = self._state.get(peer_id)
        if st is None or st.get("opened_at") is None:
            return False
        ts = now if now is not None else time.time()
        if ts - st["opened_at"] > self._cooldown:
            # Cooldown expired — close the breaker (half-open behavior)
            st["opened_at"] = None
            st["failures"] = []
            return False
        return True

    def state(self, peer_id: str) -> str:
        return self.STATE_OPEN if self.is_open(peer_id) else self.STATE_CLOSED

    def all_peers(self) -> List[str]:
        return list(self._state.keys())


# ---------------------------------------------------------------------------
# MeshRouter
# ---------------------------------------------------------------------------

class MeshRouter:
    """Multi-hop mesh routing engine.

    Holds the routing table, dedup cache, and circuit breaker. Owns the
    periodic announce + cleanup background loops. Provides relay decisions
    for ``BridgeDaemon._dispatch_message`` and route lookups for
    ``BridgeDaemon.send_message``.
    """

    def __init__(self, daemon, config):
        self.daemon = daemon
        self.config = config
        # Mesh routing emits signed route announcements and
        # persists routes to an HMAC-protected file. Both require the
        # daemon's keypair to derive MAC keys. Refuse to start without it.
        if not getattr(daemon, "_keypair", None):
            raise RuntimeError(
                "MeshRouter requires daemon keypair — routes are HMAC-protected "
                "using a key derived from the agent identity."
            )
        self._mode = getattr(config, "mesh_routing", "relay")
        # Audit L-08: validate routing mode early.
        if self._mode not in ("off", "passive", "relay"):
            raise ValueError(
                f"Invalid mesh_routing mode: {self._mode!r} "
                "(expected 'off', 'passive', or 'relay')"
            )
        self.table = RoutingTable(
            my_node_id=daemon.node_id,
            ttl=getattr(config, "route_ttl", 90.0),
        )
        self.dedup = DedupCache(
            sources_max=getattr(config, "dedup_sources_max", 128),
            per_source_max=getattr(config, "dedup_per_source_max", 1024),
            ttl=getattr(config, "dedup_cache_ttl", 300.0),
        )
        self.circuit_breaker = CircuitBreaker()
        self._sequence_number = 0
        self._last_partition_check: Dict[str, float] = {}
        self._save_pending = False
        self._save_task: Optional[asyncio.Task] = None
        self._announce_interval = max(
            1.0, float(getattr(config, "route_announce_interval", 30.0))
        )
        self._cleanup_interval = 60.0
        self._routes_path = os.path.expanduser(
            getattr(config, "routes_path", "~/.ironmesh/routes.json")
        )
        self._stopped = False

        # Wire circuit-breaker trip events to audit log
        def _on_trip(peer_id: str):
            self._audit_log(EVENT_CIRCUIT_BREAKER_TRIPPED, {"peer": peer_id})
        self.circuit_breaker.set_trip_callback(_on_trip)

    # ----- helpers -----

    def _audit_log(self, event: str, details: dict) -> None:
        audit = getattr(self.daemon, "_audit", None)
        if audit is not None:
            try:
                audit.log(event, details)
            except Exception as e:
                logger.debug("Audit log failed: %s", e)

    def _direct_peers(self) -> List[str]:
        """Return ids of currently online, mesh-capable directly-connected peers."""
        result = []
        for pid, state in self.daemon.peers.items():
            if not state.is_online:
                continue
            if pid not in self.daemon.ws_clients:
                continue
            if not getattr(state, "supports_mesh", True):
                continue
            result.append(pid)
        return result

    def get_route(self, dst: str) -> Optional[str]:
        """Return next hop for ``dst`` or None if unreachable / circuit-broken."""
        if dst == self.daemon.node_id:
            return None
        # Direct connection always preferred
        if dst in self.daemon.ws_clients and not self.circuit_breaker.is_open(dst):
            return dst
        next_hop = self.table.get_next_hop(dst)
        if next_hop is None:
            return None
        if self.circuit_breaker.is_open(next_hop):
            return None
        if next_hop not in self.daemon.ws_clients:
            return None
        return next_hop

    # ----- persistence -----

    def _audit_hmac_key(self) -> Optional[bytes]:
        """Derive a stable HMAC key from the daemon's identity for routes file."""
        keypair = getattr(self.daemon, "_keypair", None)
        if keypair is None:
            return None
        return hashlib.sha256(
            keypair.ed25519_secret + b"ironmesh-routes-v1"
        ).digest()

    def load_persisted_routes(self) -> bool:
        key = self._audit_hmac_key()
        if key is None:
            return False
        return self.table.load(self._routes_path, key, refresh_ttl=30.0)

    def save_routes(self) -> None:
        key = self._audit_hmac_key()
        if key is None:
            return
        try:
            self.table.save(self._routes_path, key)
        except Exception as e:
            logger.debug("Failed to save routes: %s", e)

    def schedule_save(self) -> None:
        """Debounced save: marks pending; the cleanup loop persists periodically."""
        self._save_pending = True

    # ----- announce / receive -----

    def build_announcement_payload(self, neighbor: str) -> dict:
        self._sequence_number += 1
        return {
            "origin": self.daemon.node_id,
            "routes": self.table.to_announcement(exclude_peer=neighbor),
            "sequence_number": self._sequence_number,
        }

    async def send_announcement(self, neighbor: str) -> None:
        from ironmesh import protocol as ew_protocol  # local to avoid circular

        payload_dict = self.build_announcement_payload(neighbor)
        payload_bytes = json.dumps(payload_dict, separators=(",", ":")).encode()
        frame = ew_protocol.Frame(
            msg_type=ew_protocol.MessageType.ROUTE_ANNOUNCE,
            payload=payload_bytes,
            source=self.daemon.node_id,
            destination=neighbor,
        )
        try:
            await self.daemon._send_frame(neighbor, frame)
            self._audit_log(EVENT_ROUTE_ANNOUNCED, {
                "to": neighbor,
                "route_count": len(payload_dict["routes"]),
            })
        except Exception as e:
            logger.debug("Failed to announce routes to %s: %s", neighbor, e)

    async def announce_loop(self) -> None:
        """Periodically broadcast routes to direct neighbors."""
        while not self._stopped and getattr(self.daemon, "_running", False):
            await asyncio.sleep(self._announce_interval)
            if self._mode == "off":
                continue
            for neighbor in self._direct_peers():
                try:
                    await self.send_announcement(neighbor)
                except Exception as e:
                    logger.debug("announce_loop error for %s: %s", neighbor, e)

    async def cleanup_loop(self) -> None:
        """Periodically expire stale routes + dedup entries; persist if dirty."""
        while not self._stopped and getattr(self.daemon, "_running", False):
            await asyncio.sleep(self._cleanup_interval)
            try:
                expired = self.table.expire_old()
                for dst in expired:
                    self._audit_log(EVENT_ROUTE_EXPIRED, {"destination": dst})
                if expired:
                    self.schedule_save()

                self.dedup.cleanup_expired()

                # Partition detection: any destination unreachable > 2*TTL
                now = time.time()
                for dst in self.table.all_destinations():
                    route = self.table.get_route(dst)
                    if route is None:
                        continue
                    if now - route["updated"] > 2 * self.table._ttl:
                        last = self._last_partition_check.get(dst, 0)
                        if now - last > 300:  # at most once every 5 min per dst
                            self._last_partition_check[dst] = now
                            self._audit_log(EVENT_MESH_PARTITION_SUSPECTED, {
                                "destination": dst,
                            })

                if self._save_pending:
                    self.save_routes()
                    self._save_pending = False
            except Exception as e:
                logger.debug("cleanup_loop error: %s", e)

    async def handle_route_announce(self, peer_id: str, payload: bytes) -> None:
        """Process a ROUTE_ANNOUNCE payload from a directly-connected peer."""
        if self._mode == "off":
            return
        # Audit M-10: bound payload before parsing.
        if len(payload) > 1_048_576:
            logger.warning("ROUTE_ANNOUNCE from %s too large: %d bytes",
                           peer_id, len(payload))
            return
        try:
            data = json.loads(payload)
        except Exception as e:
            logger.warning("Bad ROUTE_ANNOUNCE from %s: %s", peer_id, e)
            return
        # Audit M-06: require dict payload.
        if not isinstance(data, dict):
            logger.warning("ROUTE_ANNOUNCE from %s not a dict: %s",
                           peer_id, type(data).__name__)
            return
        origin = data.get("origin")
        routes = data.get("routes", [])
        if not isinstance(routes, list):
            return
        # Mark direct neighbor as relay-capable
        peer_state = self.daemon.peers.get(peer_id)
        if peer_state:
            peer_state.last_route_announce = time.time()
            peer_state.is_relay_capable = True

        learned = 0
        for entry in routes:
            # v0.8.5.6: bound + validate every per-entry field
            # before letting it reach add_route (which uses ``dst`` as
            # a dict key — non-hashable values would crash the whole
            # handler). Also enforce a sane upper bound on the route
            # list to limit per-announce work.
            if not isinstance(entry, dict):
                continue
            try:
                dst = entry.get("destination")
                cost = int(entry.get("cost", INFINITY_COST))
            except Exception:
                continue
            if not isinstance(dst, str) or not dst:
                continue
            if dst == self.daemon.node_id:
                continue
            # Routes via this neighbor cost +1
            new_cost = cost + 1
            if self.table.add_route(
                dst=dst,
                next_hop=peer_id,
                cost=new_cost,
                learned_from=peer_id,
            ):
                learned += 1
                self._audit_log(EVENT_ROUTE_LEARNED, {
                    "destination": dst,
                    "next_hop": peer_id,
                    "cost": new_cost,
                })
        if learned:
            self.schedule_save()
        logger.debug("ROUTE_ANNOUNCE from %s: %d routes (origin=%s, learned=%d)",
                     peer_id, len(routes), origin, learned)

    # ----- relay -----

    async def relay_message(self, frame, from_peer: str,
                            transport: Optional[str] = None) -> bool:
        """Forward a frame whose destination is not us. Returns True on success.

        ``transport`` (v0.8.5.6) is the name of the transport that
        delivered this frame to us — typically ``"ws"`` or ``"rns"``.
        When supplied, the dedup cache tracks origin transport per
        msg_id and emits the ``MSG_REPLAY_CROSS_TRANSPORT`` audit event
        when a duplicate arrives via a different transport than the
        original. Callers that don't know or don't care leave it as
        ``None`` and the legacy dedup behavior is preserved.
        """
        if self._mode != "relay":
            # passive mode silently drops
            return False

        # Audit M-12: refuse to relay stale messages (default 24h
        # freshness window). Prevents ancient queued traffic from being
        # replayed into the mesh after a long partition heals.
        ts = getattr(frame, "timestamp", None)
        if ts is not None:
            age = time.time() - ts
            if age > 86400:
                logger.warning(
                    "Rejecting stale relayed message from %s (age=%.0fs)",
                    frame.source, age,
                )
                return False

        # Dedup — atomic check-and-add so two concurrent deliveries of
        # the same frame can't both pass the dup check (v0.8.3 audit).
        # v0.8.5.6: when transport is known, also track origin transport
        # so cross-transport replay attempts surface in the audit log.
        if transport is not None:
            dedup_result = self.dedup.check_and_add_with_transport(
                frame.source, frame.msg_id, transport,
            )
            if dedup_result.get("duplicate"):
                self._audit_log(EVENT_DUPLICATE_DROPPED, {
                    "source": frame.source, "msg_id": frame.msg_id,
                })
                if dedup_result.get("cross_transport"):
                    # Bump Prometheus counter + emit OTel event +
                    # durable audit record so cross-transport replay
                    # is observable without scraping the log. The
                    # bridge daemon's helper bundles the counter
                    # reservation and audit emit so the two stay
                    # consistent even when the audit write fails.
                    try:
                        from ironmesh.telemetry import emit_event
                        emit_event(
                            "msg.replay.cross_transport", frame.source,
                            {
                                "msg_id": frame.msg_id,
                                "original_transport": dedup_result.get(
                                    "original_transport"),
                                "replay_transport": dedup_result.get(
                                    "this_transport"),
                            },
                        )
                    except Exception:
                        pass
                    self.daemon._emit_audit_with_reservation(
                        "msg_replay_cross_transport",
                        EVENT_MSG_REPLAY_CROSS_TRANSPORT, {
                            "peer": frame.source,
                            "msg_id": frame.msg_id,
                            "original_transport": dedup_result.get(
                                "original_transport"),
                            "replay_transport": dedup_result.get(
                                "this_transport"),
                            "time_delta_ms": int(round(
                                dedup_result.get("time_delta_s", 0.0) * 1000)),
                        },
                    )
                return False
        else:
            if self.dedup.check_and_add(frame.source, frame.msg_id):
                self._audit_log(EVENT_DUPLICATE_DROPPED, {
                    "source": frame.source, "msg_id": frame.msg_id,
                })
                return False

        # TTL check
        if frame.ttl <= 0:
            self._audit_log(EVENT_TTL_EXPIRED, {
                "source": frame.source, "msg_id": frame.msg_id,
            })
            return False

        # Loop check
        if self.daemon.node_id in frame.hops:
            self._audit_log(EVENT_ROUTE_LOOP, {
                "source": frame.source, "msg_id": frame.msg_id,
                "hops": list(frame.hops),
            })
            return False

        # Decrement and append hop
        frame.ttl -= 1
        if not isinstance(frame.hops, list):
            frame.hops = []
        frame.hops.append(self.daemon.node_id)

        next_hop = self.get_route(frame.destination)
        if next_hop is None:
            self._audit_log(EVENT_NO_ROUTE, {
                "destination": frame.destination,
                "msg_id": frame.msg_id,
            })
            await self._send_unreachable(frame.source, frame.destination, frame.msg_id)
            return False

        try:
            await self.daemon._send_frame(next_hop, frame)
            self.circuit_breaker.record_success(next_hop)
            self._audit_log(EVENT_MESSAGE_RELAYED, {
                "source": frame.source,
                "destination": frame.destination,
                "next_hop": next_hop,
                "msg_id": frame.msg_id,
            })
            metrics = getattr(self.daemon, "metrics", None)
            if metrics is not None:
                metrics.messages_relayed = getattr(metrics, "messages_relayed", 0) + 1
            return True
        except Exception as e:
            self.circuit_breaker.record_failure(next_hop)
            logger.warning("Relay to %s failed: %s", next_hop, e)
            return False

    async def _send_unreachable(self, original_source: str, destination: str,
                                original_msg_id: str) -> None:
        from ironmesh import protocol as ew_protocol
        # Best-effort: only send if we have a route back to the source
        next_hop = self.get_route(original_source)
        if next_hop is None:
            return
        payload = json.dumps({
            "destination": destination,
            "original_msg_id": original_msg_id,
            "reason": "no_route",
        }, separators=(",", ":")).encode()
        frame = ew_protocol.Frame(
            msg_type=ew_protocol.MessageType.ROUTE_UNREACHABLE,
            payload=payload,
            source=self.daemon.node_id,
            destination=original_source,
        )
        try:
            await self.daemon._send_frame(next_hop, frame)
        except Exception as e:
            logger.debug("Failed to send ROUTE_UNREACHABLE: %s", e)

    def stop(self) -> None:
        self._stopped = True
