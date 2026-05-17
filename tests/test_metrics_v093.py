"""Tests for v0.9.3 metrics + audit-event constants.

Confirms that the new gauges + counter are exposed via the Metrics
class and that the audit module exposes the new event constants.
"""

from __future__ import annotations

import audit as audit_mod
from bridge import Metrics


def test_metrics_to_dict_includes_v093_fields() -> None:
    m = Metrics()
    snapshot = m.to_dict()
    assert "trust_store_version" in snapshot
    assert "strict_tls_enabled" in snapshot
    assert "global_msg_rate_limit_total" in snapshot

    # Defaults are well-defined.
    assert snapshot["trust_store_version"] == 0
    assert snapshot["strict_tls_enabled"] == 0
    assert snapshot["global_msg_rate_limit_total"] == 0


def test_metrics_global_rate_limit_increments() -> None:
    m = Metrics()
    m.global_msg_rate_limit_total += 1
    m.global_msg_rate_limit_total += 1
    assert m.to_dict()["global_msg_rate_limit_total"] == 2


def test_audit_module_exposes_v093_event_constants() -> None:
    assert audit_mod.EVENT_TRUST_STORE_ENCRYPTED == "TRUST_STORE_ENCRYPTED"
    assert audit_mod.EVENT_STRICT_TLS_ENABLED == "STRICT_TLS_ENABLED"
    assert (
        audit_mod.EVENT_GLOBAL_RATE_LIMIT_TRIGGERED
        == "GLOBAL_RATE_LIMIT_TRIGGERED"
    )


def test_strict_tls_gauge_settable() -> None:
    m = Metrics()
    m.strict_tls_enabled = 1
    assert m.to_dict()["strict_tls_enabled"] == 1


def test_trust_store_version_gauge_settable() -> None:
    m = Metrics()
    m.trust_store_version = 2
    assert m.to_dict()["trust_store_version"] == 2
