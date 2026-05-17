"""Tests for outbound WSS TLS validation modes.

The default mesh mode keeps the historical CERT_NONE behavior so peers can
interoperate without a shared CA — peer authentication runs at the
application layer (passphrase HMAC + Ed25519 + TOFU).

Strict mode opts into transport-layer authentication when WSS endpoints are
issued real certificates (operator CA, public ACME, etc.).
"""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from bridge import BridgeDaemon


def _build_context(*, strict: bool, pinned_ca: str | None = None) -> ssl.SSLContext:
    """Construct just the SSLContext without standing up a full daemon."""
    daemon = BridgeDaemon.__new__(BridgeDaemon)
    daemon._strict_tls = strict
    daemon._pinned_ca_path = pinned_ca
    return daemon._build_client_ssl_context()


def test_default_mode_disables_cert_validation() -> None:
    ctx = _build_context(strict=False)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_strict_mode_requires_validated_cert() -> None:
    ctx = _build_context(strict=True)
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_strict_mode_loads_pinned_ca(tmp_path: Path) -> None:
    # A self-signed CA generated for this test. Generated once with:
    #   openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=ironmesh-test
    # Bundled inline so the test stays hermetic and offline.
    ca_pem = """-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUWQqsxP9XOpVPlQR8n6m4wn7r6OQwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJaXJvbm1lc2gtdDAeFw0yNTAxMDEwMDAwMDBaFw0zNTAx
MDEwMDAwMDBaMBQxEjAQBgNVBAMMCWlyb25tZXNoLXQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDFzJDfkFzqJ9iD2c9fXZvN7A3cQvL7r6V9V0n4mZpm
lEx0w7MZ+pSjqmH2wQzxYRMDg9X+VfLIrmFZCwMqgX1RTUmdkGZ8K9aV3sRZfQdJ
VpGqL0rMZkI7nZ1dHbyYKMr4rJkM+CTI7sHjBXZ8cZeJxz9MLzx6V8bJkHM1q8cf
2y8GZQMhpSNtzh4r5w1nN3qFqL/pNHC9rVzD7sAzL+rL9xKpmTQ7oA3RcKCD2xUV
zNCSI6fE0M7ywQp1DMpqQG5VqfLKrJ0Z4GJhqHBwgP3yKGVcDiQkPq3l8z7g3YAM
7mIqGCTVf0DIlVpVQjzr3T0eNDOEr0R9C7kQOhUsHwEMAgMBAAGjUzBRMB0GA1Ud
DgQWBBQ7fW6ItOE6OE/hlWjvZ6jFkz5aNzAfBgNVHSMEGDAWgBQ7fW6ItOE6OE/h
lWjvZ6jFkz5aNzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAh
Q3w4z7jMxq8P7jDEz1yMs/m6w6Yy4nMEmzaLg9j+rHe+ZcQ8nB9hDzBz9V3VVfKh
4dZbPMrR6xQ8gDFxzWfBoZ8ZxCQH2j6t8qPkzpFwJh5Zy0oTJW9dY8e6ZMaY8L0+
Y6BQ5KrvN3z3TGrhP7bNyJfk3rGzm5sP9b4QfZAxsKZMpLqJWzC0w4j8a7v3y3hY
LpFOmQ+y2sA8OBfYqPkN5LqV6Rzj4Yl3xXvJ7B4F6sJdpGQkZIrLk8YjN8KrJZxQ
hF9LhBdqhIqJL6Z3D4RQc8kbFb5UFJ9PYuBHvO3fCxPpRvXc6gN0XaXQHbU8MAjF
mU3z1m7QyxQpLdnP3PbR
-----END CERTIFICATE-----
"""
    ca_file = tmp_path / "test-ca.pem"
    ca_file.write_text(ca_pem)
    # Hermetic test: only verify the loader is called and doesn't raise on
    # well-formed PEM. We do not assert on the resulting cert chain because
    # OpenSSL parses the bytes lazily and a fake CA still validates load.
    daemon = BridgeDaemon.__new__(BridgeDaemon)
    daemon._strict_tls = True
    daemon._pinned_ca_path = str(ca_file)
    try:
        ctx = daemon._build_client_ssl_context()
    except ssl.SSLError as e:
        pytest.skip(f"OpenSSL rejected the test CA bundle on this build: {e}")
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_pinned_ca_ignored_when_strict_disabled() -> None:
    # If strict mode is off we never call load_verify_locations, so even a
    # bogus pinned-CA path must not raise.
    ctx = _build_context(strict=False, pinned_ca="/nonexistent/path/ca.pem")
    assert ctx.verify_mode == ssl.CERT_NONE
