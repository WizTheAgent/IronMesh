"""Shared test fixtures for IronMesh test suite."""

import os
import sys
import tempfile
import pytest
import pytest_asyncio

# Ensure ironmesh package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def tmp_dir(tmp_path):
    """Provide a temporary directory for test artifacts."""
    return tmp_path


@pytest.fixture
def keys_path(tmp_path):
    """Provide a temporary path for key storage."""
    return str(tmp_path / "keys.json")


@pytest.fixture
def db_path(tmp_path):
    """Provide a temporary path for database."""
    return str(tmp_path / "test.db")


@pytest.fixture
def trust_path(tmp_path):
    """Provide a temporary path for trust store."""
    return str(tmp_path / "known_peers.json")


@pytest.fixture
def sample_keypair():
    """Generate a sample Ed25519 keypair."""
    from ironmesh.keys import generate_keypair
    return generate_keypair("test-agent")


@pytest.fixture
def sample_ephemeral():
    """Generate a sample ephemeral X25519 keypair."""
    from ironmesh.keys import generate_ephemeral
    return generate_ephemeral()


@pytest.fixture
def shared_secret():
    """Generate a shared secret by performing ECDH between two ephemeral keypairs."""
    from ironmesh.crypto import ecdh_exchange
    from ironmesh.keys import generate_ephemeral
    priv_a, pub_a = generate_ephemeral()
    priv_b, pub_b = generate_ephemeral()
    return ecdh_exchange(priv_a, pub_b)
