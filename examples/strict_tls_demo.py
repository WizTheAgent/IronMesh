"""Minimal demo: run an Agent with --strict-tls equivalent settings.

Default mesh mode trusts self-signed WSS certs and authenticates peers
at the application layer (passphrase HMAC + Ed25519 + TOFU). This
example shows how to opt into transport-layer authentication on top —
useful when WSS endpoints are issued real certificates by an operator
CA, internal Let's Encrypt, or public ACME.

Run:
    IRONMESH_PASSPHRASE=your-strong-passphrase \\
    python examples/strict_tls_demo.py [--ca-bundle /etc/ssl/private-ca.pem]

The agent simply joins the mesh and prints incoming messages.
"""

from __future__ import annotations

import argparse
import os

from ironmesh.agent import Agent


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--name", default="strict-tls-demo")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--ca-bundle", default=None,
                   help="Private CA bundle path. When omitted, the system "
                        "trust store is used as the trust anchor.")
    args = p.parse_args()

    pp = os.environ.get("IRONMESH_PASSPHRASE")
    if not pp:
        raise SystemExit("Set IRONMESH_PASSPHRASE before running.")

    agent = Agent(
        name=args.name,
        port=args.port,
        passphrase=pp,
        # Strict TLS knobs flow through Agent's **daemon_kwargs catch-all.
        strict_tls=True,
        pinned_ca_path=args.ca_bundle,
    )

    @agent.on_message()
    def handle(peer_id: str, payload: bytes) -> None:
        print(f"[{args.name}] from {peer_id}: {payload.decode(errors='replace')}")

    print(f"[{args.name}] strict-TLS mode ON. trust anchor = "
          f"{args.ca_bundle or 'system trust store'}")
    agent.run()


if __name__ == "__main__":
    main()
