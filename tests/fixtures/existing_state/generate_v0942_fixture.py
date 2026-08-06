"""Generate the golden v0.9.4.2 existing-state fixture.

This script is **NOT** run by the test suite or CI. It is the recorded
provenance for the checked-in fixture under ``v0_9_4_2/``: it must be run
against a **real** ``ironmesh==0.9.4.2`` install (an isolated venv), so the
on-disk artifacts are byte-for-byte what the released 0.9.4.2 daemon wrote —
never HEAD's idea of the old format. The existing-state tests then point the
CURRENT code at a copy of these artifacts and assert it reads / migrates /
verifies them across the 0.9.4.2 -> HEAD version boundary.

Why a real artifact (not synthesized by HEAD): a fixture built with HEAD's own
``_derive_legacy_storage_key`` / ``AuditLog`` would only validate HEAD's
*assumption* of the old format — it would pass even if that assumption were
wrong. Writing the DB with 0.9.4.2's own ``MessageStore`` (under the storage
key 0.9.4.2's ``bridge.py`` derives: ``sha256(passphrase + "ironmesh-storage-v1")``,
no format prefix, no persisted salt), the trust store with 0.9.4.2's
``TrustStore``, and the audit chain with 0.9.4.2's ``AuditLog`` closes that gap.

Regenerate (from the repo root, with a 0.9.4.2 venv at $VENV):
    "$VENV/Scripts/python.exe" tests/fixtures/existing_state/generate_v0942_fixture.py \
        --out tests/fixtures/existing_state/v0_9_4_2

Everything is deliberately generic (alice / bob / carol, neutral bodies) so the
checked-in fixture carries no host/identifier content.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import os
import shutil
import sys

import ironmesh
from ironmesh.audit import AuditLog, _derive_audit_key
from ironmesh.keys import generate_keypair, save_keys
from ironmesh.store import MessageStore
from ironmesh.trust import TrustStore

# The documented test passphrase. Not a secret — it protects only this
# synthetic throwaway identity that exists solely as a test fixture.
TEST_PASSPHRASE = "existing-state-v0942-pass"

# Messages the daemon "received"/"sent" (msg_id -> plaintext body).
MESSAGES = [
    ("m-0001", "alice", "Alice", "self", "MSG", b"first delivered body", "inbound"),
    ("m-0002", "self", "Self", "bob", "MSG", b"second delivered body", "outbound"),
    ("m-0003", "carol", "Carol", "self", "MSG", b"third delivered body", "inbound"),
]
# Offline-queued messages for a peer (peer_node_id -> list of (msg_id, source, body)).
PENDING = [
    ("q-0001", "alice", b"queued while bob offline #1"),
    ("q-0002", "alice", b"queued while bob offline #2"),
]
AUDIT_EVENTS = [
    ("NODE_START", {"version": "0.9.4.2"}),
    ("PEER_PINNED", {"peer": "bob"}),
    ("PEER_PINNED", {"peer": "carol"}),
    ("MESSAGE_SENT", {"msg_id": "m-0002"}),
    ("NODE_STOP", {}),
]


def _legacy_storage_key(passphrase: str) -> bytes:
    """Exactly what 0.9.4.2 bridge.py derives and hands to MessageStore:
    an unsalted SHA-256 of ``passphrase + "ironmesh-storage-v1"``. Computed
    here under the 0.9.4.2 interpreter/stdlib, so it is 0.9.4.2's value,
    not a HEAD borrowing."""
    return hashlib.sha256((passphrase + "ironmesh-storage-v1").encode()).digest()


async def _build_db(db_path: str, storage_key: bytes) -> None:
    store = MessageStore(db_path, storage_key=storage_key)
    await store.open()
    for msg_id, source, source_display, destination, msg_type, body, direction in MESSAGES:
        await store.store_message(msg_id, source, source_display, destination,
                                  msg_type, body, direction)
    for msg_id, source, body in PENDING:
        ok = await store.queue_for_peer("bob-node", msg_id, source, "MSG", body)
        if not ok:
            raise RuntimeError(f"0.9.4.2 queue_for_peer refused {msg_id}")
    await store.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True,
                    help="output directory for the fixture (created/overwritten)")
    args = ap.parse_args()

    ver = getattr(ironmesh, "__version__", "?")
    if not ver.startswith("0.9.4.2"):
        print(f"REFUSING: this must run against a real ironmesh==0.9.4.2, "
              f"found {ver} at {ironmesh.__file__}", file=sys.stderr)
        return 2

    out = os.path.abspath(args.out)
    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(out)

    keys_path = os.path.join(out, "keys.json")
    trust_path = os.path.join(out, "known_peers.json")
    db_path = os.path.join(out, "data.db")
    audit_path = os.path.join(out, "audit.log")

    # --- identity (v3 master-seed envelope, Argon2id at rest) ---
    identity = generate_keypair("alice")
    save_keys(identity, keys_path, passphrase=TEST_PASSPHRASE)

    # --- peers to pin ---
    bob = generate_keypair("bob")
    carol = generate_keypair("carol")
    bob_pub = base64.b64encode(bob.ed25519_public).decode()
    carol_pub = base64.b64encode(carol.ed25519_public).decode()
    bob_node = bob.get_fingerprint()
    carol_node = carol.get_fingerprint()

    # --- trust store (v2 encrypted+MAC envelope, keyed to the identity secret) ---
    ts = TrustStore(agent_key=identity.ed25519_secret[:32], path=trust_path)
    ts.pin_peer(bob_node, bob_pub, "trusted")
    ts.pin_peer(carol_node, carol_pub, "trusted")

    # --- message DB (legacy unsalted-SHA-256 storage key, no v2 prefix) ---
    storage_key = _legacy_storage_key(TEST_PASSPHRASE)
    asyncio.run(_build_db(db_path, storage_key))

    # --- audit chain (HMAC key derived from the identity secret) ---
    alog = AuditLog(path=audit_path, hmac_key=_derive_audit_key(identity.ed25519_secret))
    for event, details in AUDIT_EVENTS:
        alog.log(event, details)

    # --- manifest of expected values for the tests to assert against ---
    manifest = {
        "generated_by": f"ironmesh=={ver} (real wheel, isolated venv)",
        "note": "DO NOT synthesize from HEAD. Regenerate only from a real "
                "0.9.4.2 install via generate_v0942_fixture.py.",
        "passphrase": TEST_PASSPHRASE,
        "identity": {
            "agent_name": "alice",
            "fingerprint": identity.get_fingerprint(),
            "ed25519_public_b64": base64.b64encode(identity.ed25519_public).decode(),
        },
        "peers": [
            {"node_id": bob_node, "identity_public_b64": bob_pub},
            {"node_id": carol_node, "identity_public_b64": carol_pub},
        ],
        "messages": [
            {"msg_id": m[0], "source": m[1], "destination": m[3],
             "direction": m[6], "payload_b64": base64.b64encode(m[5]).decode()}
            for m in MESSAGES
        ],
        "pending": {
            "peer_node_id": "bob-node",
            "items": [
                {"msg_id": p[0], "source": p[1],
                 "payload_b64": base64.b64encode(p[2]).decode()}
                for p in PENDING
            ],
        },
        "audit_entry_count": len(AUDIT_EVENTS),
    }
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)

    files = sorted(os.listdir(out))
    print(f"Wrote golden 0.9.4.2 fixture to {out}")
    for name in files:
        size = os.path.getsize(os.path.join(out, name))
        print(f"  {name:20s} {size:8d} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
