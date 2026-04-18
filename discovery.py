"""IronMesh local-first agent discovery via mDNS (Zeroconf).

Agents announce themselves on the LAN and discover each other automatically.
Uses event-based synchronization to prevent startup race conditions.
"""

import logging
import socket
import threading
from typing import Callable, Dict, Optional

from zeroconf import ServiceBrowser, ServiceInfo, ServiceStateChange, Zeroconf

MDNS_TYPE = "_ironmesh._tcp.local."

log = logging.getLogger("ironmesh.discovery")


def _local_ip() -> str:
    """Get the primary LAN IP address using a route-based fallback chain.

    v0.7.2: we intentionally prefer route-based detection (UDP connect to
    gateway) over ``getaddrinfo(hostname)``. On multi-NIC systems (dev
    boxes with VirtualBox Host-Only adapters, WSL, Docker bridges, VPN
    interfaces, etc.), ``getaddrinfo`` often returns the wrong adapter —
    e.g. 192.168.56.1 (VBox) ahead of the real LAN IP. Remote
    peers then try to dial an unroutable address and see timeouts.

    Strategies in order:
      1. UDP-connect to common RFC1918 gateways, read our outbound IP.
      2. UDP-connect to 8.8.8.8 (only works when internet is up).
      3. ``getaddrinfo(hostname)`` — last resort; may return wrong NIC.
      4. ``127.0.0.1`` — loopback, clearly broken.

    No packets are actually transmitted (UDP connect just resolves the
    source IP the kernel would use for that route).
    """
    # Strategy 1: Ask the kernel which interface routes to common LAN
    # gateways. This is the most reliable multi-NIC signal.
    for gateway in ("192.168.1.1", "192.168.0.1", "10.0.0.1", "172.16.0.1"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((gateway, 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            continue
        finally:
            s.close()

    # Strategy 2: Route to public DNS if internet is reachable.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    finally:
        s.close()

    # Strategy 3: Fall back to hostname resolution. Unreliable on multi-NIC
    # but usually correct on single-NIC servers.
    try:
        hostname = socket.gethostname()
        addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for _family, _, _, _, sockaddr in addrs:
            ip = sockaddr[0]
            if ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass

    return "127.0.0.1"


def announce(agent_name: str, ws_port: int, zeroconf: Zeroconf,
             public_key: Optional[str] = None,
             bind_address: Optional[str] = None,
             identity_pubkey_bytes: Optional[bytes] = None) -> ServiceInfo:
    """Register an mDNS service for this agent.

    Note: the full public_key is intentionally NOT broadcast via mDNS
    to prevent passive identity fingerprinting. Keys are exchanged during
    handshake.

    v0.6: an optional 8-byte (16 hex chars) truncated SHA-256 of the
    identity public key is included as ``idhash``. This lets peers
    correlate a mDNS announcement with a known/pinned identity BEFORE
    the handshake, enabling smarter reconnect decisions and duplicate
    detection without leaking the full key.
    """
    import hashlib
    ip = bind_address if (bind_address and bind_address != "0.0.0.0") else _local_ip()
    props = {
        "agent": agent_name.encode(),
        "port": str(ws_port).encode(),
        "proto": b"ironmesh/0.6",
    }
    if identity_pubkey_bytes:
        idhash = hashlib.sha256(identity_pubkey_bytes).hexdigest()[:16]
        props["idhash"] = idhash.encode()
    # Deliberately do NOT include the full public_key in mDNS properties.
    # Identity keys are exchanged during the authenticated handshake.

    svc = ServiceInfo(
        MDNS_TYPE,
        f"{agent_name}.{MDNS_TYPE}",
        addresses=[socket.inet_aton(ip)],
        port=ws_port,
        properties=props,
        server=f"{agent_name}.local.",
    )
    zeroconf.register_service(svc)
    log.info("mDNS announce: %s @ %s:%d", agent_name, ip, ws_port)
    return svc


def register_service(agent_name: str, port: int,
                     public_key: Optional[str] = None,
                     bind_address: Optional[str] = None,
                     identity_pubkey_bytes: Optional[bytes] = None) -> "_MDNSHandle":
    """Convenience wrapper — creates Zeroconf instance and announces.

    v0.7.2: when ``bind_address`` is an explicit IP (not 0.0.0.0 or empty),
    restrict Zeroconf to that interface so queries on other NICs (VBox,
    WSL, Docker bridge) aren't answered. Prevents cross-NIC announcement
    leakage on multi-homed dev hosts.
    """
    if bind_address and bind_address not in ("0.0.0.0", "::"):
        try:
            zc = Zeroconf(interfaces=[bind_address])
        except Exception:
            # Some Zeroconf versions reject interface lists for certain
            # IPs — fall back to all-interfaces mode rather than failing.
            log.warning("Zeroconf(interfaces=[%s]) rejected; using default",
                        bind_address)
            zc = Zeroconf()
    else:
        zc = Zeroconf()
    svc = announce(agent_name, port, zc, public_key=public_key,
                   bind_address=bind_address,
                   identity_pubkey_bytes=identity_pubkey_bytes)
    return _MDNSHandle(zc, svc)


class _MDNSHandle:
    """Handle for closing mDNS registration."""

    def __init__(self, zc: Zeroconf, svc: ServiceInfo):
        self._zc = zc
        self._svc = svc

    def close(self):
        try:
            self._zc.unregister_service(self._svc)
            self._zc.close()
        except Exception:
            pass


class AgentListener:
    """Discover other IronMesh agents on the LAN via mDNS.

    Uses proper ServiceStateChange enum comparison and handles
    Added, Updated, and Removed events.

    Includes rate limiting on discovery events to prevent flood/DoS
    via mDNS announcements.
    """

    # Max discovery events per second before throttling
    _DISCOVERY_RATE_LIMIT = 10
    _DISCOVERY_WINDOW = 1.0  # seconds

    def __init__(self, on_discovered: Optional[Callable] = None,
                 on_removed: Optional[Callable] = None):
        """
        Args:
            on_discovered: Callback(agent_name, info_dict) when a peer is found.
            on_removed: Callback(agent_name) when a peer departs.
        """
        self.agents: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._on_discovered = on_discovered
        self._on_removed = on_removed
        self._zc: Optional[Zeroconf] = None
        self._browser: Optional[ServiceBrowser] = None
        # Discovery event rate limiting
        self._discovery_timestamps: list = []
        self._discovery_lock = threading.Lock()

    def start(self, zeroconf: Optional[Zeroconf] = None) -> "AgentListener":
        """Start listening for mDNS services.

        Returns self for chaining.
        """
        self._zc = zeroconf or Zeroconf()
        self._browser = ServiceBrowser(
            self._zc,
            MDNS_TYPE,
            handlers=[self._on_service_state_change],
        )
        self._ready.set()
        log.info("mDNS listener started")
        return self

    def wait_ready(self, timeout: float = 5.0) -> bool:
        """Wait until the listener is fully initialized."""
        return self._ready.wait(timeout)

    def stop(self):
        """Stop the listener and clean up."""
        if self._browser:
            self._browser.cancel()
            self._browser = None
        # Only close zeroconf if we created it
        if self._zc:
            try:
                self._zc.close()
            except Exception:
                pass
            self._zc = None
        self._ready.clear()

    def _is_rate_limited(self) -> bool:
        """Check if discovery events are being received too fast."""
        import time as _time
        now = _time.monotonic()
        with self._discovery_lock:
            # Prune old timestamps
            self._discovery_timestamps = [
                t for t in self._discovery_timestamps
                if now - t < self._DISCOVERY_WINDOW
            ]
            if len(self._discovery_timestamps) >= self._DISCOVERY_RATE_LIMIT:
                return True
            self._discovery_timestamps.append(now)
            return False

    def _on_service_state_change(self, zeroconf: Zeroconf, service_type: str,
                                  name: str, state_change: ServiceStateChange):
        """Handle mDNS service state changes using proper enum comparison."""
        # Rate limit discovery events to prevent flood attacks
        if self._is_rate_limited():
            log.warning("mDNS discovery rate limit exceeded, dropping event for %s", name)
            return
        if state_change in (ServiceStateChange.Added, ServiceStateChange.Updated):
            info = zeroconf.get_service_info(service_type, name)
            if info:
                # Reject oversized TXT records (DoS mitigation)
                total_props_size = sum(
                    len(k) + len(v) for k, v in info.properties.items()
                )
                if total_props_size > 1024:
                    log.warning("mDNS: rejecting oversized TXT record (%d bytes) from %s",
                                total_props_size, name)
                    return
                addr = socket.inet_ntoa(info.addresses[0]) if info.addresses else None
                # Validate mDNS TXT fields rigorously.
                # Malformed UTF-8, oversized strings, or unexpected
                # characters must not reach the callback.
                try:
                    agent_name = info.properties.get(b"agent", b"").decode(
                        "utf-8", errors="strict")
                    port = int(
                        info.properties.get(b"port", b"0").decode("ascii", errors="strict")
                    )
                    pubkey_raw = info.properties.get(b"pubkey", b"")
                    pubkey = pubkey_raw.decode("utf-8", errors="strict") or None if pubkey_raw else None
                    idhash_raw = info.properties.get(b"idhash", b"")
                    idhash = idhash_raw.decode("ascii", errors="strict") or None if idhash_raw else None
                except (ValueError, UnicodeDecodeError) as e:
                    log.warning("mDNS: property decode error on %s: %s", name, e)
                    return

                if not agent_name or len(agent_name) > 256:
                    log.warning("mDNS: rejecting invalid agent_name length=%d",
                                len(agent_name))
                    return
                if not all(c.isalnum() or c in "-_." for c in agent_name):
                    log.warning("mDNS: rejecting agent_name with invalid chars: %r",
                                agent_name[:64])
                    return
                if port <= 0 or port > 65535:
                    log.warning("mDNS: rejecting invalid port %d from %s",
                                port, agent_name)
                    return
                if idhash is not None and (len(idhash) > 64
                                            or not all(c in "0123456789abcdefABCDEF"
                                                       for c in idhash)):
                    log.warning("mDNS: rejecting invalid idhash from %s", agent_name)
                    idhash = None

                if agent_name and addr:
                    peer_info = {
                        "ip": addr,
                        "port": port,
                        "pubkey": pubkey,
                        "idhash": idhash,
                    }
                    with self._lock:
                        is_new = agent_name not in self.agents
                        self.agents[agent_name] = peer_info

                    if is_new:
                        log.info("Discovered agent: %s @ %s:%d", agent_name, addr, port)
                    else:
                        log.debug("Updated agent: %s @ %s:%d", agent_name, addr, port)

                    if self._on_discovered:
                        try:
                            self._on_discovered(agent_name, peer_info)
                        except Exception as e:
                            log.error("Discovery callback error: %s", e)

        elif state_change == ServiceStateChange.Removed:
            # Extract agent name from the service name
            # Format: "agentname._ironmesh._tcp.local."
            agent_name = name.split(".")[0] if "." in name else name
            with self._lock:
                removed = self.agents.pop(agent_name, None)
            if removed:
                log.info("Agent departed: %s", agent_name)
                if self._on_removed:
                    try:
                        self._on_removed(agent_name)
                    except Exception as e:
                        log.error("Removal callback error: %s", e)

    # Legacy compatibility
    def on_service_state_change(self, zeroconf, service_type, name, state_change):
        """Legacy callback interface — delegates to new handler."""
        self._on_service_state_change(zeroconf, service_type, name, state_change)

    def get_agents(self, exclude_own: Optional[str] = None) -> Dict[str, dict]:
        with self._lock:
            return {k: v for k, v in self.agents.items() if k != exclude_own}
