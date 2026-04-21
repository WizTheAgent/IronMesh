"""OpenTelemetry instrumentation wrapper.

Lazy-init: importing this module on a vanilla install is cheap and
safe even when `opentelemetry-*` packages are absent. The exported
`tracer` is either a real OTel tracer (when the SDK is installed AND
`OTEL_*` env vars are configured) or a no-op shim that accepts the
same `start_as_current_span` / `start_span` calls and returns dummy
contexts.

Configuration (all standard OpenTelemetry env vars):

    OTEL_SERVICE_NAME=ironmesh                 # default if unset
    OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
    OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
    OTEL_RESOURCE_ATTRIBUTES=node.name=alice,deployment.env=homelab

Setting OTEL_EXPORTER_OTLP_ENDPOINT activates real export. Without
it, the tracer is a no-op even if the SDK is installed — useful for
dev/test where you don't want span chatter.

Install with:

    pip install ironmesh[otel]

See docs/OBSERVABILITY.md for end-to-end setup including a reference
Grafana dashboard.
"""
from __future__ import annotations

import os
from contextlib import contextmanager, nullcontext
from typing import Any, Iterator, Optional

# ---------------------------------------------------------------------------
# Lazy SDK detection
# ---------------------------------------------------------------------------
_TRACER: Any = None
_INITIALIZED = False
_OTEL_AVAILABLE: Optional[bool] = None


def _otel_available() -> bool:
    global _OTEL_AVAILABLE
    if _OTEL_AVAILABLE is None:
        try:
            import opentelemetry  # noqa: F401
            _OTEL_AVAILABLE = True
        except ImportError:
            _OTEL_AVAILABLE = False
    return _OTEL_AVAILABLE


def _init_tracer() -> Any:
    """Build a real OTel tracer if the SDK is installed AND the
    user has configured an OTLP endpoint. Otherwise return None
    (callers fall through to the no-op path)."""
    if not _otel_available():
        return None
    if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        # SDK installed but unconfigured — keep telemetry off so dev
        # / test runs don't accidentally export.
        return None
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        service = os.environ.get("OTEL_SERVICE_NAME", "ironmesh")
        resource = Resource.create({"service.name": service})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        return trace.get_tracer("ironmesh")
    except Exception:
        # Any init failure → silent fall-through to no-op. Telemetry
        # must never break the daemon.
        return None


def get_tracer() -> Any:
    """Return the lazily-initialized tracer (real or None)."""
    global _TRACER, _INITIALIZED
    if not _INITIALIZED:
        _TRACER = _init_tracer()
        _INITIALIZED = True
    return _TRACER


# ---------------------------------------------------------------------------
# No-op-friendly span helper
# ---------------------------------------------------------------------------

@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    """Context manager that opens an OTel span if a tracer is active,
    or yields a null context otherwise.

    Usage:
        with span("ironmesh.handshake", peer="alice"):
            do_handshake(...)

    The yielded value is either a real OTel span (call `.set_attribute()`,
    `.add_event()`, `.set_status()` on it) or `None`. Callers that want
    to add attributes mid-span should check for None.
    """
    tracer = get_tracer()
    if tracer is None:
        with nullcontext(None) as null_span:
            yield null_span
        return
    with tracer.start_as_current_span(name, attributes=attributes) as sp:
        yield sp


def set_attribute(sp: Any, key: str, value: Any) -> None:
    """No-op-safe wrapper for `span.set_attribute(key, value)`."""
    if sp is None:
        return
    try:
        sp.set_attribute(key, value)
    except Exception:
        pass


def record_exception(sp: Any, exc: BaseException) -> None:
    """No-op-safe wrapper for `span.record_exception(exc)`."""
    if sp is None:
        return
    try:
        sp.record_exception(exc)
    except Exception:
        pass


# v0.8.5.7: point-in-time event emission for things that happen outside
# a request scope (cap-binding observations, cross-transport replay,
# operator state transitions). Opens a zero-duration span so dashboards
# that group by trace/span name pick them up like any other signal.
def emit_event(name: str, subject: str, attributes: Optional[dict] = None) -> None:
    """Emit a single point-in-time event as a zero-duration span.

    Safe to call from any code path — falls through to a no-op if OTel
    isn't installed or isn't configured with an OTLP endpoint.

    Args:
        name: dotted event name (e.g. ``peer.cap.set_changed``).
        subject: the entity the event is about (typically a node_id or
                 peer fingerprint). Attached as ``subject`` attribute.
        attributes: additional attributes to attach.
    """
    tracer = get_tracer()
    if tracer is None:
        return
    try:
        attrs = {"subject": subject}
        if attributes:
            for k, v in attributes.items():
                try:
                    attrs[k] = v
                except Exception:
                    pass
        with tracer.start_as_current_span(name, attributes=attrs):
            pass
    except Exception:
        # Telemetry must never break the daemon.
        pass


def is_active() -> bool:
    """True if telemetry is actually exporting; False on no-op path."""
    return get_tracer() is not None
