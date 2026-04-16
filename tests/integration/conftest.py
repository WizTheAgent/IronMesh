"""Shared fixtures for the integration test suite.

These tests stand up **real** Agent processes (in-process threads), not
mocks. They're slower than the unit suite and we keep them in a
separate directory so the default pytest run stays fast.

Run explicitly with:

    pytest tests/integration -q

CI has a dedicated job that installs the real framework dependencies
(langchain-core, crewai, pyautogen) before invoking this directory.
"""
from __future__ import annotations

import time
import uuid
from typing import Iterator

import pytest

from ironmesh import Agent


INTEGRATION_PASSPHRASE = "integration-test-passphrase-12"


def _unique_port() -> int:
    """Return a port in a range that's unlikely to collide with other tests
    or the user's local `ironmesh run`. Each call returns a distinct value
    within the session."""
    global _port_cursor
    try:
        _port_cursor  # noqa: B018
    except NameError:
        _port_cursor = 30000 + (uuid.uuid4().int % 1000) * 10
    p = _port_cursor
    _port_cursor += 4  # space by 4 so each agent's port+1 metrics doesn't clash
    return p


@pytest.fixture
def two_node_mesh() -> Iterator[tuple[Agent, Agent]]:
    """Two real agents ``alice`` and ``bob`` on localhost, handshaken.

    Each test gets a fresh pair to avoid cross-test pollution of trust
    stores or databases. Both agents are torn down at fixture exit even
    if the test raises.
    """
    port_a = _unique_port()
    port_b = port_a + 2

    import tempfile
    import os

    # Use a temp dir per pair so keys/trust/state don't leak across tests.
    tmp = tempfile.mkdtemp(prefix="ironmesh-itest-")

    def kw(name: str, allowed: list[str]) -> dict:
        root = os.path.join(tmp, name)
        os.makedirs(root, exist_ok=True)
        return dict(
            keys_path=os.path.join(root, "keys.json"),
            db_path=os.path.join(root, "data.db"),
            routes_path=os.path.join(root, "routes.json"),
            capabilities_path=os.path.join(root, "capabilities.json"),
            allowed_peers=allowed,
        )

    alice = Agent(
        "itest-alice", port=port_a,
        passphrase=INTEGRATION_PASSPHRASE,
        open_discovery=False, allow_plaintext=True,
        **kw("alice", ["itest-bob"]),
    )
    bob = Agent(
        "itest-bob", port=port_b,
        passphrase=INTEGRATION_PASSPHRASE,
        open_discovery=False, allow_plaintext=True,
        **kw("bob", ["itest-alice"]),
    )

    alice.run(foreground=False)
    bob.run(foreground=False)

    # Wait up to 15 s for the handshake. mDNS can be slow on CI.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if alice.peer_by_name("itest-bob") and bob.peer_by_name("itest-alice"):
            break
        time.sleep(0.2)
    else:
        alice.stop()
        bob.stop()
        pytest.fail("two_node_mesh fixture: peers did not handshake in 15 s")

    try:
        yield alice, bob
    finally:
        alice.stop()
        bob.stop()


def wait_for(predicate, timeout: float = 10.0, step: float = 0.1) -> bool:
    """Poll a predicate until it returns truthy or ``timeout`` elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return False
