"""End-to-end walkthrough of the capability-set binding feature (v0.8.5.6+).

This example runs entirely in-process with two simulated TrustStore
owners — one acting as the local daemon, one acting as an operator's
CLI session — so you can watch the whole cap-change -> pending -> accept
-> baseline-updated flow without needing a live mesh.

Run it:

    python examples/cap_binding_workflow.py

What you'll see:

1. A peer is pinned with an initial capability set (role:assistant +
   llm:llama3). The trust store records a canonical SHA-256 hash of
   those caps as the baseline.
2. The peer "reconnects" advertising a different capability set
   (role:admin instead of role:assistant). The observe path detects
   the change, stashes the new set as pending, and demotes the peer to
   pending-cap-change. The PEER_CAP_SET_CHANGED audit event fires.
3. An operator reviews the diff (added role:admin, removed
   role:assistant), decides the change is legitimate, and calls
   accept_capability_change — equivalent to
   ``ironmesh trust cap-promote <node_id>`` on the CLI or the
   ACCEPT button in the dashboard's PENDING CAP CHANGE panel.
4. The pending set becomes the new baseline. PEER_CAP_ACCEPTED fires.
5. On the next reconnect with the now-accepted caps, observe returns
   "match" and the peer stays trusted.

No network, no sockets, no LLM calls. Just the core
TrustStore.observe_capabilities / stash / accept cycle that the live
daemon exercises on every CAPABILITY_ANNOUNCE from a pinned peer.
"""
from __future__ import annotations

import os
import tempfile

from ironmesh.trust import TrustStore, canonical_capability_hash


def banner(step: str, title: str) -> None:
    line = "-" * 64
    print()
    print(line)
    print(f"{step}  {title}")
    print(line)


def dump_peer(store: TrustStore, node_id: str, label: str) -> None:
    rec = store.get_peer(node_id)
    print(f"  [{label}] trust_state    = {store.get_trust_state(node_id)}")
    print(f"  [{label}] capability_set = {rec.get('capability_set')}")
    print(f"  [{label}] baseline hash  = "
          f"{(rec.get('capability_hash') or 'none')[:16]}...")
    pending = rec.get("capability_hash_pending")
    if pending is not None:
        print(f"  [{label}] pending hash   = {pending[:16]}...")
        print(f"  [{label}] pending set    = "
              f"{rec.get('capability_set_pending')}")


def main() -> int:
    # A fresh throwaway store so re-runs are idempotent. In production
    # this is ~/.ironmesh/known_peers.json, MAC-keyed to the daemon's
    # Ed25519 identity secret.
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "known_peers.json")
        agent_key = b"\x00" * 32  # test key; NOT for production

        peer_id = "a" * 32
        peer_pub = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

        # --------------------------------------------------------------
        banner("1/5", "Pin the peer + record initial capability baseline")
        # --------------------------------------------------------------
        store = TrustStore(agent_key=agent_key, path=path)
        store.pin_peer(peer_id, peer_pub, trust_state="trusted")

        initial_caps = ["role:assistant", "llm:llama3"]
        result = store.observe_capabilities(peer_id, initial_caps)
        print(f"  observe_capabilities -> status={result['status']!r}")
        print(f"  baseline hash = {result['hash'][:16]}...")
        dump_peer(store, peer_id, "after pin")

        # --------------------------------------------------------------
        banner("2/5", "Peer reconnects with a DIFFERENT capability set")
        # --------------------------------------------------------------
        # Imagine the peer's operator just added --role admin to their
        # launch flags. When the daemon's periodic CAPABILITY_ANNOUNCE
        # arrives, observe_capabilities catches the hash drift.
        new_caps = ["role:admin", "llm:llama3"]
        result = store.observe_capabilities(peer_id, new_caps)
        print(f"  observe_capabilities -> status={result['status']!r}")
        print(f"  added   = {result.get('added')}")
        print(f"  removed = {result.get('removed')}")

        # The bridge daemon wires this to stash_pending_capability_change +
        # set_trust_state('pending-cap-change'). Doing it by hand here.
        store.stash_pending_capability_change(peer_id, new_caps)
        store.set_trust_state(peer_id, "pending-cap-change")
        # At this point the daemon would emit EVENT_PEER_CAP_SET_CHANGED
        # to the audit log and bump the peer_cap_set_changed Prometheus
        # counter. Inbound MSGs from this peer queue until promotion.
        print("  -> EVENT_PEER_CAP_SET_CHANGED would fire here")
        print("  -> metric ironmesh_peer_cap_set_changed_total += 1")
        dump_peer(store, peer_id, "after change")

        # --------------------------------------------------------------
        banner("3/5", "Operator reviews the diff (dashboard / CLI)")
        # --------------------------------------------------------------
        # Equivalent CLI:
        #     ironmesh trust list-cap-pending
        #     ironmesh trust cap-diff <node_id>
        pending = store.list_by_capability_status("pending-cap-change")
        print(f"  list_by_capability_status('pending-cap-change'): "
              f"{len(pending)} peer(s) awaiting review")
        for row in pending:
            print(f"    node_id = {row['node_id']}")
            print(f"    baseline_set = {row['capability_set']}")
            print(f"    pending_set  = {row['pending_set']}")

        # --------------------------------------------------------------
        banner("4/5", "Operator accepts the change — new baseline pinned")
        # --------------------------------------------------------------
        # Equivalent CLI:
        #     ironmesh trust cap-promote <node_id>
        # Equivalent dashboard:
        #     click ACCEPT in the PENDING CAP CHANGE panel
        accepted = store.accept_capability_change(peer_id)
        store.set_trust_state(peer_id, "trusted")
        print(f"  accept_capability_change returned {accepted}")
        print("  -> EVENT_PEER_CAP_ACCEPTED fires with actor marker")
        print("  -> metric ironmesh_peer_cap_accepted_total += 1")
        dump_peer(store, peer_id, "after accept")

        # --------------------------------------------------------------
        banner("5/5", "Next reconnect with accepted caps -> silent match")
        # --------------------------------------------------------------
        result = store.observe_capabilities(peer_id, new_caps)
        print(f"  observe_capabilities -> status={result['status']!r}")
        print("  (no audit event, no state change — steady state)")
        dump_peer(store, peer_id, "steady state")

        # Sanity: the stored baseline now hashes to the canonical
        # form of the accepted set.
        assert store.get_peer(peer_id)["capability_hash"] == \
            canonical_capability_hash(new_caps)
        assert store.get_trust_state(peer_id) == "trusted"

        print()
        print("Done. Full flow completed without any network or LLM call.")
        print("In a live deployment, replace the manual stash + set_trust_state")
        print("calls with the bridge daemon's CAPABILITY_ANNOUNCE handler — see")
        print("BridgeDaemon._handle_cap_observation in ironmesh/bridge.py.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
