"""Live end-to-end exercise of the v0.8.5 pending-trust message gate.

Stands up two real Agent processes (in-process threads). Alice runs
with the gate on; Bob runs default. Asserts that:

  - When Bob sends a MSG to Alice, the message queues at Alice's
    daemon (not delivered to Alice's @on_message handler).
  - The pending_trust_messages SQLite table holds the queued payload.
  - After ``promote_pending_peer`` drains the queue, the handler fires
    in arrival order.
  - Subsequent MSGs from Bob deliver immediately (peer is now trusted).
  - Block discards an in-flight queue and silently drops new MSGs.

This is the only test that exercises the full stack across the wire
— it complements ``tests/test_trust_gate.py`` which mocks the daemon.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import time
import uuid
from typing import Iterator

import pytest

from ironmesh import Agent

from .conftest import wait_for, INTEGRATION_PASSPHRASE


def _unique_port() -> int:
    """Local port-cursor copy so we don't perturb the shared one."""
    return 30000 + (uuid.uuid4().int % 1000) * 10 + 200


@pytest.fixture
def gated_two_node_mesh() -> Iterator[tuple[Agent, Agent]]:
    """Alice (gate on) <-> Bob (gate off). Handshake completes; Bob is
    pinned at Alice in 'pending' state; Alice is pinned at Bob in
    'trusted' state."""
    port_a = _unique_port()
    port_b = port_a + 2
    tmp = tempfile.mkdtemp(prefix="ironmesh-gate-e2e-")

    def kw(name: str, allowed: list[str]) -> dict:
        root = os.path.join(tmp, name)
        os.makedirs(root, exist_ok=True)
        return dict(
            keys_path=os.path.join(root, "keys.json"),
            db_path=os.path.join(root, "data.db"),
            routes_path=os.path.join(root, "routes.json"),
            capabilities_path=os.path.join(root, "capabilities.json"),
            trust_path=os.path.join(root, "known_peers.json"),
            allowed_peers=allowed,
        )

    alice = Agent(
        "gate-alice", port=port_a,
        passphrase=INTEGRATION_PASSPHRASE,
        open_discovery=False, allow_plaintext=True,
        require_message_promotion=True,   # ← THE GATE
        pending_trust_queue_cap=10,
        **kw("alice", ["gate-bob"]),
    )
    bob = Agent(
        "gate-bob", port=port_b,
        passphrase=INTEGRATION_PASSPHRASE,
        open_discovery=False, allow_plaintext=True,
        # No gate on Bob — he's just a regular peer.
        **kw("bob", ["gate-alice"]),
    )

    alice.run(foreground=False)
    bob.run(foreground=False)

    # Wait up to 15 s for the handshake.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if alice.peer_by_name("gate-bob") and bob.peer_by_name("gate-alice"):
            break
        time.sleep(0.2)
    else:
        alice.stop()
        bob.stop()
        pytest.fail("gated_two_node_mesh: peers did not handshake in 15 s")

    try:
        yield alice, bob
    finally:
        alice.stop()
        bob.stop()


def _bob_node_id_at_alice(alice: Agent) -> str:
    rec = alice.peer_by_name("gate-bob")
    assert rec, "Alice should know about Bob after handshake"
    return rec["node_id"]


def _run_on_alice(alice: Agent, coro):
    """Helper: run an async daemon method on Alice's loop from the test thread."""
    fut = asyncio.run_coroutine_threadsafe(coro, alice._loop)
    return fut.result(timeout=10)


class TestGateE2E:
    def test_bobs_msgs_queue_at_alice_until_promoted(self, gated_two_node_mesh):
        alice, bob = gated_two_node_mesh
        bob_id = _bob_node_id_at_alice(alice)

        # Alice's app-side handler — should NOT fire while Bob is pending.
        received: list[bytes] = []

        @alice.on_message("MSG")
        def _on_msg(peer_id: str, payload: bytes):
            received.append(payload)

        # _wire_handlers ran during alice.run(); re-wire so the
        # post-run-registered handler reaches the bus.
        alice._wire_handlers()

        # Bob sends three MSGs.
        bob.send_sync("gate-alice", "msg-1")
        bob.send_sync("gate-alice", "msg-2")
        bob.send_sync("gate-alice", "msg-3")

        # Give the wire a moment.
        ok = wait_for(
            lambda: _run_on_alice(
                alice, alice.daemon._db.pending_trust_count_for(bob_id),
            ) == 3,
            timeout=10,
        )
        assert ok, "Alice's pending-trust queue should hold all 3 of Bob's MSGs"
        # Handler must NOT have fired — gate held the messages.
        assert received == [], "no MSGs should reach Alice's app while Bob is pending"

        # Promote Bob via the daemon's operator API.
        result = _run_on_alice(alice, alice.daemon.promote_pending_peer(bob_id))
        assert result == {"ok": True, "drained": 3, "error": None}

        # The drain re-publishes through the bus. Wait for the handler to fire.
        ok = wait_for(lambda: len(received) == 3, timeout=5)
        assert ok, f"after promote, all 3 drained MSGs should reach the handler (got {len(received)})"
        assert [p.decode() for p in received] == ["msg-1", "msg-2", "msg-3"]

        # Subsequent MSGs deliver immediately, not via the queue.
        bob.send_sync("gate-alice", "msg-4")
        ok = wait_for(lambda: len(received) == 4, timeout=5)
        assert ok, "post-promote MSGs should deliver via the trusted fast path"
        # And the queue should still be empty.
        assert _run_on_alice(
            alice, alice.daemon._db.pending_trust_count_for(bob_id),
        ) == 0

    def test_block_discards_queue_and_silences_new_msgs(self, gated_two_node_mesh):
        alice, bob = gated_two_node_mesh
        bob_id = _bob_node_id_at_alice(alice)

        received: list[bytes] = []

        @alice.on_message("MSG")
        def _on_msg(peer_id: str, payload: bytes):
            received.append(payload)

        alice._wire_handlers()

        # Bob sends two MSGs while pending.
        bob.send_sync("gate-alice", "noisy-1")
        bob.send_sync("gate-alice", "noisy-2")
        ok = wait_for(
            lambda: _run_on_alice(
                alice, alice.daemon._db.pending_trust_count_for(bob_id),
            ) == 2,
            timeout=10,
        )
        assert ok

        # Block — drops the queue, sets state to 'blocked'.
        result = _run_on_alice(alice, alice.daemon.block_pending_peer(bob_id))
        assert result == {"ok": True, "discarded": 2, "error": None}
        assert _run_on_alice(
            alice, alice.daemon._db.pending_trust_count_for(bob_id),
        ) == 0
        # And those messages never reached Alice's app.
        assert received == []

        # New MSGs from blocked Bob silently drop.
        bob.send_sync("gate-alice", "should-be-dropped")
        # Give it a beat — the gate's drop is synchronous on the dispatch path.
        time.sleep(1.0)
        assert received == [], "blocked peer's MSGs must not reach the handler"

    def test_list_pending_trust_surfaces_bobs_queue(self, gated_two_node_mesh):
        alice, bob = gated_two_node_mesh
        bob_id = _bob_node_id_at_alice(alice)

        bob.send_sync("gate-alice", "queued-msg")
        ok = wait_for(
            lambda: _run_on_alice(
                alice, alice.daemon._db.pending_trust_count_for(bob_id),
            ) == 1,
            timeout=10,
        )
        assert ok

        listing = _run_on_alice(alice, alice.daemon.list_pending_trust())
        by_id = {p["node_id"]: p for p in listing}
        assert bob_id in by_id, "Bob should appear in Alice's pending list"
        assert by_id[bob_id]["queued_count"] == 1
