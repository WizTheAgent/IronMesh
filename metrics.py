"""Metrics and observability for the IronMesh bridge daemon.

``Metrics`` is the daemon's in-memory counter block. ``MetricsMixin``
carries the ``BridgeDaemon`` methods that maintain and expose those
counters: audit-mirrored counter bookkeeping (reserve / scan /
reconcile across restarts and log rotation), the JSON and Prometheus
exposition renderers, and the standalone ``/metrics`` HTTP endpoint
used when the GUI is disabled.

``bridge.py`` composes the mixin back into ``BridgeDaemon`` via
inheritance — all state lives on the daemon instance; this module
holds behavior only.
"""

import asyncio
import json
import logging
import os
import time

logger = logging.getLogger("ironmesh.bridge")


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
        # v0.9.2: per-feature counters for the new agent-interop surfaces.
        # Kept coarse (no label dimension) so the metrics surface stays
        # cheap even on nodes with hundreds of peers; strategy/side
        # breakdowns are available via the OTel spans.
        self.capability_routes_attempted = 0
        self.capability_routes_succeeded = 0
        self.capability_routes_no_match = 0
        # Server-side increments when SKIP_OFFER hits the wire; client-side
        # increments handshake_skips_activated when the offer is accepted.
        # Healthy fleet sums should match — divergence surfaces send
        # failures, downgrade-rejects, or asymmetric eligibility.
        # handshake_skips_rejected fires client-side on any malformed or
        # downgrade-attempt SKIP_OFFER (missing binding, non-hex binding,
        # or sentinel mismatch). Should be ~0 on healthy meshes; a spike
        # is alert-worthy — either a buggy peer or an attack attempt.
        self.handshake_skips_offered = 0
        self.handshake_skips_activated = 0
        self.handshake_skips_rejected = 0
        self.group_broadcasts_sent = 0
        self.group_broadcasts_received = 0
        self.group_broadcasts_deduped = 0
        # v0.9.3: posture + at-rest gauges and global-cap counter.
        # ``trust_store_version`` reflects the on-disk envelope version
        # the daemon is reading: 1 = legacy plaintext (auto-migrating),
        # 2 = encrypted at rest, 0 = no file yet.
        # ``strict_tls_enabled`` is 1 when --strict-tls is set, else 0.
        # ``global_msg_rate_limit_total`` increments each time the
        # global daemon-wide cap rejects an inbound message.
        self.trust_store_version = 0
        self.strict_tls_enabled = 0
        self.global_msg_rate_limit_total = 0
        # v0.9.4 (signed capability announcement): signed CAPABILITY_ANNOUNCE — counts rejected
        # announces (missing inner sig where required, bad sig, stale,
        # replay-dedup hit). Healthy fleets sum near zero.
        self.capability_announce_bad_signature_total = 0

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
            "trust_store_version": self.trust_store_version,
            "strict_tls_enabled": self.strict_tls_enabled,
            "global_msg_rate_limit_total": self.global_msg_rate_limit_total,
            "peer_promoted": self.peer_promoted,
            "peer_blocked": self.peer_blocked,
            "capability_routes_attempted": self.capability_routes_attempted,
            "capability_routes_succeeded": self.capability_routes_succeeded,
            "capability_routes_no_match": self.capability_routes_no_match,
            "handshake_skips_offered": self.handshake_skips_offered,
            "handshake_skips_activated": self.handshake_skips_activated,
            "handshake_skips_rejected": self.handshake_skips_rejected,
            "group_broadcasts_sent": self.group_broadcasts_sent,
            "group_broadcasts_received": self.group_broadcasts_received,
            "group_broadcasts_deduped": self.group_broadcasts_deduped,
            "capability_announce_bad_signature_total": self.capability_announce_bad_signature_total,
        }


class MetricsMixin:
    """Counter bookkeeping + metrics rendering for ``BridgeDaemon``."""

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

    def _inc_metric(self, counter_name: str) -> None:
        """Defensive counter +=1 for v0.9.x metrics that may not exist
        on every Metrics shape (older test fixtures, downgrade paths).
        Use this instead of bare `self.metrics.X += 1` when the
        attribute could be absent. For audit-mirrored counters use
        `_reserve_counter_bump` instead — it serializes against the
        audit scanner.
        """
        try:
            cur = getattr(self.metrics, counter_name)
            setattr(self.metrics, counter_name, cur + 1)
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
        # Start from current EOF — the code count events emitted from this
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
        writes re-grow the live file past the stored offset before
        the next scan (the naive size<offset check misses this).
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
             "gauge", "Number of remote nodes whose capabilities the code have learned"),
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
            # v0.9.2 agent-interop surfaces
            ("capability_routes_attempted", "ironmesh_capability_routes_attempted_total",
             "counter", "send_to_capability calls regardless of outcome"),
            ("capability_routes_succeeded", "ironmesh_capability_routes_succeeded_total",
             "counter", "send_to_capability calls that reached at least one peer"),
            ("capability_routes_no_match", "ironmesh_capability_routes_no_match_total",
             "counter", "send_to_capability calls that found no online candidate"),
            ("handshake_skips_offered", "ironmesh_handshake_skips_offered_total",
             "counter", "SKIP_OFFER frames sent by this node as the server side of an RNS Link handshake"),
            ("handshake_skips_activated", "ironmesh_handshake_skips_activated_total",
             "counter", "SKIP_OFFER frames accepted by this node as the client side (skip is fully on)"),
            ("handshake_skips_rejected", "ironmesh_handshake_skips_rejected_total",
             "counter", "SKIP_OFFER frames rejected by this node (malformed or wrong channel binding — possible downgrade attempt)"),
            ("group_broadcasts_sent", "ironmesh_group_broadcasts_sent_total",
             "counter", "Outbound packets sent to the RNS GROUP broadcast destination"),
            ("group_broadcasts_received", "ironmesh_group_broadcasts_received_total",
             "counter", "Inbound packets from the RNS GROUP broadcast destination (post-dedup)"),
            ("group_broadcasts_deduped", "ironmesh_group_broadcasts_deduped_total",
             "counter", "GROUP broadcast packets suppressed by the payload-hash dedup cache"),
            # v0.9.3: at-rest + transport-auth + global-cap surface
            ("trust_store_version", "ironmesh_trust_store_version", "gauge",
             "Trust-store envelope version on disk: 0=absent, 1=legacy plaintext, 2=encrypted at rest"),
            ("strict_tls_enabled", "ironmesh_strict_tls_enabled", "gauge",
             "1 when --strict-tls is set on this daemon, else 0. Outbound WSS requires CA-validated certs in strict mode."),
            ("global_msg_rate_limit_total", "ironmesh_global_msg_rate_limit_total", "counter",
             "Inbound messages dropped by the daemon-wide --max-msgs-per-sec cap"),
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
