"""Shared test fixtures for IronMesh test suite."""

import os
import sys
import tempfile
import pytest
import pytest_asyncio

# Ensure ironmesh package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# v0.8.5.6: isolate EVERY test's IronMesh state from the
# real `~/.ironmesh/` directory. Before this, integration tests like
# itest-alice / gate-alice / lc-toolkit-smoke spawned `Agent(...)`
# processes with auto-generated identity keys but DEFAULT trust paths,
# silently clobbering the real trust file on a developer's box (B7
# cascade). This autouse session fixture redirects the HOME env var
# and IronMesh's DEFAULT_* path constants to a temp tree before any
# test module imports `ironmesh`.
_TEST_HOME = None


@pytest.fixture(autouse=True, scope="session")
def _isolate_ironmesh_state():
    """Redirect default-path resolution for ~/.ironmesh/* to a temp
    home, so integration tests that spawn real Agent processes can't
    poison the developer's / CI host's production trust store, keys
    file, capabilities cache, routes table, or audit log.
    """
    global _TEST_HOME
    _TEST_HOME = tempfile.mkdtemp(prefix="ironmesh-test-home-")
    os.makedirs(os.path.join(_TEST_HOME, ".ironmesh"), exist_ok=True)
    # Win32 honors USERPROFILE for os.path.expanduser("~"); POSIX
    # uses HOME. Override both to be safe.
    old_home = os.environ.get("HOME")
    old_userprofile = os.environ.get("USERPROFILE")
    os.environ["HOME"] = _TEST_HOME
    os.environ["USERPROFILE"] = _TEST_HOME
    # Also expose an explicit IRONMESH_TRUST_PATH env for code paths
    # that consult it directly (MCP server, CLI).
    old_trust = os.environ.get("IRONMESH_TRUST_PATH")
    os.environ["IRONMESH_TRUST_PATH"] = os.path.join(
        _TEST_HOME, ".ironmesh", "known_peers.json",
    )
    try:
        yield _TEST_HOME
    finally:
        # Restore (some CI systems assert on env stability across sessions)
        for k, v in (
            ("HOME", old_home),
            ("USERPROFILE", old_userprofile),
            ("IRONMESH_TRUST_PATH", old_trust),
        ):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        try:
            import shutil
            shutil.rmtree(_TEST_HOME, ignore_errors=True)
        except Exception:
            pass


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
