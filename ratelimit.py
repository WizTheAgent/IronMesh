"""Abuse-resistance limits for the IronMesh bridge daemon.

``RateLimitMixin`` carries the ``BridgeDaemon`` methods that throttle
hostile or runaway traffic: the per-IP auth-failure window (brute-force
lockout on the shared passphrase) and the per-peer outbound bandwidth
token bucket.

``bridge.py`` composes the mixin back into ``BridgeDaemon`` via
inheritance — all state lives on the daemon instance; this module
holds behavior only.
"""

import asyncio
import logging
import time

from ironmesh import protocol as ew_protocol
from ironmesh.audit import EVENT_AUTH_BLOCKED, EVENT_AUTH_FAILURE

logger = logging.getLogger("ironmesh.bridge")


class RateLimitMixin:
    """Auth-failure lockout + bandwidth throttling for ``BridgeDaemon``."""

    async def _is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked due to too many auth failures.

        Serialized access to ``_auth_failures`` to prevent
        concurrent handshakes from bypassing the rate limit.
        """
        async with self._auth_failures_lock:
            failures = self._auth_failures.get(ip, [])
            now = time.time()
            # Prune old failures
            recent = [t for t in failures if now - t < self._auth_failure_window]
            self._auth_failures[ip] = recent
            if len(recent) >= self._auth_max_failures:
                # Check if still within block duration from latest failure
                if recent and now - recent[-1] < self._auth_block_duration:
                    return True
            return False

    async def _record_auth_failure(self, ip: str):
        """Record an auth failure for an IP address."""
        async with self._auth_failures_lock:
            if ip not in self._auth_failures:
                self._auth_failures[ip] = []
            self._auth_failures[ip].append(time.time())
            count = len(self._auth_failures[ip])
        # Audit log is thread-safe independently; fire outside the lock.
        if self._audit:
            self._audit.log(EVENT_AUTH_FAILURE, {"ip": ip, "failure_count": count})
            if count >= self._auth_max_failures:
                self._audit.log(EVENT_AUTH_BLOCKED, {"ip": ip, "duration_seconds": self._auth_block_duration})

    async def _clear_ip_auth_history(self, ip: str) -> bool:
        """Clear the auth-failure history for an IP that successfully
        presented a TOFU-pinned (or fresh-pin) identity.

        The auth-failure / IP-block window exists to defeat brute force
        on the shared passphrase. Once a peer has authenticated AND
        passed TOFU identity verification, they are no longer a
        brute-force candidate, so retaining the block on their source
        IP only creates a dead zone for legitimate reconnects.
        Returns True iff the history was non-empty (i.e. we cleared a
        real block, not a no-op).
        """
        async with self._auth_failures_lock:
            had_history = bool(self._auth_failures.get(ip))
            self._auth_failures.pop(ip, None)
        if had_history:
            logger.info(
                "Auth-failure history for %s cleared after valid "
                "TOFU-pinned identity authenticated", ip,
            )
        return had_history

    async def _gate_peer_bandwidth(self, peer_id: str, n_bytes: int) -> bool:
        """v0.7.2: throttle outbound bandwidth per-peer.

        Returns True if the bytes were admitted (possibly after a brief
        wait). Returns False if the wait would exceed ``_peer_bandwidth_max_wait``
        — caller should drop the frame and record the miss.

        When rate is 0, the throttle is disabled and admissions are free.
        """
        if self._peer_bandwidth_rate <= 0:
            return True
        bucket = self._peer_bandwidth_limiters.get(peer_id)
        if bucket is None:
            bucket = ew_protocol.TokenBucket(
                rate=float(self._peer_bandwidth_rate),
                burst=int(self._peer_bandwidth_burst),
            )
            self._peer_bandwidth_limiters[peer_id] = bucket
        # Large frames may exceed the bucket burst; clamp to burst so we
        # don't deadlock waiting for an impossible refill.
        cost = min(int(n_bytes), bucket.burst)
        wait = bucket.wait_time(cost)
        if wait > self._peer_bandwidth_max_wait:
            logger.warning(
                "Bandwidth throttle dropping %d bytes to %s — wait %.1fs > ceiling %.1fs",
                n_bytes, peer_id, wait, self._peer_bandwidth_max_wait,
            )
            # Counter incremented at the gate so it's accurate regardless
            # of what the caller does with the False return.
            self._peer_bandwidth_drops_total += 1
            return False
        if wait > 0:
            await asyncio.sleep(wait)
        bucket.consume(cost)
        return True
