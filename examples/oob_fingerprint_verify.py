"""Demo: verify a peer's pinned fingerprint against an out-of-band value.

The pattern: read a peer's fingerprint over a phone call / signed
message / printed sticker / QR code, paste it in here, and confirm
the local pin matches. This is the same logic that backs the
``ironmesh trust verify`` CLI subcommand — surfaced here as a
script so it can be embedded in a larger setup pipeline.

Run:
    python examples/oob_fingerprint_verify.py \\
        --node-id <peer-node-id> \\
        --expected ab:cd:ef:12:34:56:78:90  # what the peer told you OOB
"""

from __future__ import annotations

import argparse
import sys

# Reuse the shared helper so behavior matches the CLI exactly.
# Use the installed package path — bare `from cli import …` only works
# inside the source tree, breaks for downstream `pip install ironmesh`
# users with ModuleNotFoundError.
from ironmesh.cli import fingerprint_matches  # type: ignore[attr-defined]
from ironmesh.keys import load_keys
from ironmesh.trust import TrustStore


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--node-id", required=True)
    p.add_argument("--expected", required=True,
                   help="Fingerprint received OOB. Whitespace + ':' ignored. "
                        "Prefix of >=8 hex chars accepted.")
    p.add_argument("--keys-path", default="~/.ironmesh/keys.json")
    p.add_argument("--keys-passphrase", default=None)
    p.add_argument("--trust-path", default="~/.ironmesh/known_peers.json")
    args = p.parse_args()

    try:
        keypair = load_keys(args.keys_path, passphrase=args.keys_passphrase)
    except Exception as e:
        print(f"ERROR: load keys: {e}", file=sys.stderr)
        return 1
    store = TrustStore(agent_key=keypair.ed25519_secret[:32],
                       path=args.trust_path)

    rec = store.get_peer(args.node_id)
    if rec is None:
        print(f"Peer {args.node_id} is not pinned.")
        return 1

    actual = rec.get("fingerprint") or ""
    if fingerprint_matches(actual, args.expected):
        print(f"OK: peer {args.node_id} fingerprint matches.")
        print(f"    expected = {args.expected}")
        print(f"    pinned   = {actual}")
        return 0

    print(f"MISMATCH: peer {args.node_id} fingerprint does NOT match.")
    print(f"    expected = {args.expected}")
    print(f"    pinned   = {actual}")
    print()
    print("Either you mistyped the expected value, the peer rotated keys, "
          "or this pin is impersonated. Investigate before continuing.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
