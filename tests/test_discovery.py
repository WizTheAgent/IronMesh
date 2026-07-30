"""Tests for ironmesh.discovery — mDNS agent discovery."""

from unittest.mock import MagicMock, patch

from zeroconf import ServiceStateChange

from ironmesh.discovery import AgentListener, _local_ip


class TestLocalIP:
    def test_returns_string(self):
        ip = _local_ip()
        assert isinstance(ip, str)
        parts = ip.split(".")
        assert len(parts) == 4

    def test_prefers_route_based_over_hostname(self):
        """v0.7.2 multi-NIC safety: gateway-route strategy must run BEFORE
        getaddrinfo(hostname). On VBox/WSL/Docker hosts, getaddrinfo often
        returns a host-only adapter address (e.g. 192.168.56.1) that
        remote peers cannot reach — we want the real LAN IP."""
        # Mock a socket that pretends 192.168.1.1 is reachable and returns
        # 192.168.1.42 as the source IP. Also mock gethostname to return
        # the "bad" 192.168.56.1 to prove we didn't fall back to that path.
        import ironmesh.discovery as disco_mod

        call_log = []

        class FakeSocket:
            def __init__(self, *a, **kw):
                pass

            def connect(self, addr):
                call_log.append(("connect", addr))
                # Succeed on 192.168.1.1; fail on 8.8.8.8 etc
                if addr[0] != "192.168.1.1":
                    raise OSError("unreachable")

            def getsockname(self):
                return ("192.168.1.42", 0)

            def close(self):
                pass

        with patch.object(disco_mod.socket, "socket", FakeSocket), \
             patch.object(disco_mod.socket, "gethostname", return_value="alice"), \
             patch.object(disco_mod.socket, "getaddrinfo",
                          return_value=[(0, 0, 0, "", ("192.168.56.1", 0))]):
            ip = _local_ip()
        assert ip == "192.168.1.42", (
            f"expected route-based detection to pick the real LAN IP, "
            f"got {ip}. Calls: {call_log}"
        )

    def test_falls_back_to_hostname_when_no_gateway(self):
        """If no gateway is reachable, hostname resolution is the last resort."""
        import ironmesh.discovery as disco_mod

        class DeadSocket:
            def __init__(self, *a, **kw):
                pass

            def connect(self, addr):
                raise OSError("network unreachable")

            def getsockname(self):
                return ("127.0.0.1", 0)

            def close(self):
                pass

        with patch.object(disco_mod.socket, "socket", DeadSocket), \
             patch.object(disco_mod.socket, "gethostname", return_value="alice"), \
             patch.object(disco_mod.socket, "getaddrinfo",
                          return_value=[(0, 0, 0, "", ("10.9.8.7", 0))]):
            ip = _local_ip()
        assert ip == "10.9.8.7"

    def test_returns_loopback_if_everything_fails(self):
        import ironmesh.discovery as disco_mod

        class DeadSocket:
            def __init__(self, *a, **kw):
                pass

            def connect(self, addr):
                raise OSError("no network")

            def getsockname(self):
                return ("127.0.0.1", 0)

            def close(self):
                pass

        with patch.object(disco_mod.socket, "socket", DeadSocket), \
             patch.object(disco_mod.socket, "gethostname", side_effect=OSError), \
             patch.object(disco_mod.socket, "getaddrinfo", side_effect=OSError):
            ip = _local_ip()
        assert ip == "127.0.0.1"


class TestRegisterService:
    def test_explicit_bind_restricts_zeroconf(self, tmp_path):
        """v0.7.2: explicit bind_address should pass through to Zeroconf(interfaces=...)
        so the service only answers queries on the specified interface."""
        import ironmesh.discovery as disco_mod

        captured_interfaces = {}

        class FakeZC:
            def __init__(self, interfaces=None):
                captured_interfaces["interfaces"] = interfaces

            def register_service(self, svc):
                pass

            def close(self):
                pass

        with patch.object(disco_mod, "Zeroconf", FakeZC):
            disco_mod.register_service(
                agent_name="test",
                port=8765,
                bind_address="192.168.1.10",
            )
        assert captured_interfaces["interfaces"] == ["192.168.1.10"]

    def test_zero_bind_uses_default_zeroconf(self):
        """0.0.0.0 or unset bind → Zeroconf with no interface restriction."""
        import ironmesh.discovery as disco_mod

        captured = {}

        class FakeZC:
            def __init__(self, interfaces=None):
                captured["interfaces"] = interfaces

            def register_service(self, svc):
                pass

            def close(self):
                pass

        with patch.object(disco_mod, "Zeroconf", FakeZC):
            disco_mod.register_service(agent_name="test", port=8765,
                                        bind_address="0.0.0.0")
        assert captured.get("interfaces") is None

    def test_close_uses_close_not_explicit_unregister(self):
        """_MDNSHandle.close() must call only Zeroconf.close() and NOT
        unregister_service(): close() already unregisters every service
        (goodbye packets), while the explicit call schedules
        async_unregister_service on zeroconf's loop thread and leaks a
        'coroutine was never awaited' RuntimeWarning during a racy teardown
        (e.g. `ironmesh demo`)."""
        import ironmesh.discovery as disco_mod

        calls = []

        class FakeZC:
            def __init__(self, interfaces=None):
                pass

            def register_service(self, svc):
                pass

            def unregister_service(self, svc):
                calls.append("unregister_service")

            def close(self):
                calls.append("close")

        with patch.object(disco_mod, "Zeroconf", FakeZC):
            handle = disco_mod.register_service(agent_name="t", port=8765)
            handle.close()
        assert calls == ["close"], (
            "close() must not call unregister_service explicitly; "
            f"observed {calls}")


class TestAgentListener:
    def test_initial_state(self):
        listener = AgentListener()
        assert len(listener.agents) == 0

    def test_on_discovered_callback(self):
        discovered = []
        listener = AgentListener(on_discovered=lambda name, info: discovered.append(name))

        # Mock zeroconf and service info
        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.addresses = [b"\xc0\xa8\x01\x01"]  # 192.168.1.1
        mock_info.properties = {
            b"agent": b"test-agent",
            b"port": b"8765",
            b"pubkey": b"AAAA",
        }
        mock_zc.get_service_info.return_value = mock_info

        listener._on_service_state_change(
            mock_zc, "_ironmesh._tcp.local.",
            "test-agent._ironmesh._tcp.local.",
            ServiceStateChange.Added,
        )

        assert "test-agent" in listener.agents
        assert listener.agents["test-agent"]["ip"] == "192.168.1.1"
        assert listener.agents["test-agent"]["port"] == 8765
        assert len(discovered) == 1

    def test_on_removed_callback(self):
        removed = []
        listener = AgentListener(on_removed=lambda name: removed.append(name))

        # First add the agent
        listener.agents["test-agent"] = {"ip": "1.2.3.4", "port": 8765}

        # Then simulate removal
        mock_zc = MagicMock()
        listener._on_service_state_change(
            mock_zc, "_ironmesh._tcp.local.",
            "test-agent._ironmesh._tcp.local.",
            ServiceStateChange.Removed,
        )

        assert "test-agent" not in listener.agents
        assert len(removed) == 1

    def test_get_agents_excludes_own(self):
        listener = AgentListener()
        listener.agents["me"] = {"ip": "1.2.3.4", "port": 8765}
        listener.agents["other"] = {"ip": "5.6.7.8", "port": 8766}
        agents = listener.get_agents(exclude_own="me")
        assert "me" not in agents
        assert "other" in agents

    def test_update_existing_agent(self):
        listener = AgentListener()
        mock_zc = MagicMock()
        mock_info = MagicMock()
        mock_info.addresses = [b"\xc0\xa8\x01\x01"]
        mock_info.properties = {b"agent": b"test", b"port": b"8765"}
        mock_zc.get_service_info.return_value = mock_info

        # Add
        listener._on_service_state_change(
            mock_zc, "_ironmesh._tcp.local.", "test._ironmesh._tcp.local.",
            ServiceStateChange.Added,
        )
        assert listener.agents["test"]["port"] == 8765

        # Update with new port
        mock_info.properties[b"port"] = b"9999"
        listener._on_service_state_change(
            mock_zc, "_ironmesh._tcp.local.", "test._ironmesh._tcp.local.",
            ServiceStateChange.Updated,
        )
        assert listener.agents["test"]["port"] == 9999

    def test_ready_event(self):
        listener = AgentListener()
        assert not listener._ready.is_set()
        # Simulate start (without actual Zeroconf)
        listener._ready.set()
        assert listener.wait_ready(timeout=0.1)
