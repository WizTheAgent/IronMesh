"""Unit tests for the multi-homed peer address selection helper.

Covers the v0.9.4.2 fix where the mDNS callback prefers an advertised
address whose /24 matches one of the local host's IPv4 interfaces
instead of always picking the first announced address.
"""
from __future__ import annotations

import pytest

from ironmesh.bridge import (
    _ipv4_to_int,
    _select_closest_subnet_address,
)


class TestIPv4Parse:
    def test_valid_dotted_quad(self):
        assert _ipv4_to_int("192.168.1.1") == 0xC0A80101
        assert _ipv4_to_int("0.0.0.0") == 0
        assert _ipv4_to_int("255.255.255.255") == 0xFFFFFFFF

    @pytest.mark.parametrize("bad", [
        "", "192.168.1", "192.168.1.1.1", "192.168.1.256",
        "a.b.c.d", "192.168.-1.1", None,
    ])
    def test_invalid_returns_none(self, bad):
        assert _ipv4_to_int(bad) is None


class TestSelectClosestSubnetAddress:
    def test_single_candidate_returned_verbatim(self):
        # Single-address path: legacy behaviour, no subnet matching.
        assert _select_closest_subnet_address(["10.0.0.5"], []) == "10.0.0.5"
        assert _select_closest_subnet_address(["10.0.0.5"], [0xC0A80100]) == "10.0.0.5"

    def test_no_local_prefixes_falls_back_to_first(self):
        # If interface enumeration failed, we have no /24 to compare
        # against — preserve the historical first-announced behaviour
        # rather than guessing.
        candidates = ["10.0.0.5", "192.168.1.5"]
        assert _select_closest_subnet_address(candidates, []) == "10.0.0.5"

    def test_picks_matching_subnet(self):
        # Local host is on 192.168.1.0/24. Peer advertises a VPN
        # address (10.0.0.5) first, then the LAN address — we should
        # prefer the LAN one.
        candidates = ["10.0.0.5", "192.168.1.50"]
        local_prefixes = [0xC0A80100]  # 192.168.1.0/24
        assert _select_closest_subnet_address(candidates, local_prefixes) == "192.168.1.50"

    def test_picks_first_when_no_match(self):
        # Local host is on 192.168.1.0/24. Peer's advertised
        # addresses live on unrelated subnets — fall back to first.
        candidates = ["10.0.0.5", "172.16.0.5"]
        local_prefixes = [0xC0A80100]
        assert _select_closest_subnet_address(candidates, local_prefixes) == "10.0.0.5"

    def test_multiple_local_prefixes(self):
        # Multi-homed local host: both LAN and VPN. A peer on the
        # same LAN should still be picked from the LAN address.
        candidates = ["172.16.0.7", "192.168.1.50"]
        local_prefixes = [0xC0A80100, 0xAC100000]  # 192.168.1.0/24 + 172.16.0.0/24
        result = _select_closest_subnet_address(candidates, local_prefixes)
        # Contract: the first candidate to match a local prefix wins.
        # 172.16.0.7 is first in the candidate list and matches the
        # 172.16.0.0/24 prefix, so it must be the result.
        assert result == "172.16.0.7"

    def test_malformed_address_in_candidates_is_skipped(self):
        # Defensive: a malformed address shouldn't crash the picker.
        candidates = ["not-an-ip", "192.168.1.50"]
        local_prefixes = [0xC0A80100]
        assert _select_closest_subnet_address(candidates, local_prefixes) == "192.168.1.50"

    def test_empty_candidates_returns_empty(self):
        # Defensive sentinel for an unreachable call-site condition.
        assert _select_closest_subnet_address([], [0xC0A80100]) == ""
