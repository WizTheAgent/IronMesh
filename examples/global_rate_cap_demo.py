"""Demo: configure the global daemon-wide message rate cap.

The default per-peer cap is sufficient when every peer is mutually
trusted. For deployments that may face hostile peers, the daemon
exposes a global cap on top of the per-peer one. This example starts
an agent with a deliberately low cap so a burst of messages exceeds
it and the operator can see the limiter in action via Prometheus
metrics or audit log.

Run:
    IRONMESH_PASSPHRASE=your-strong-passphrase \\
    python examples/global_rate_cap_demo.py --rate 5
"""

from __future__ import annotations

import argparse
import os

from ironmesh.agent import Agent


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--name", default="cap-demo")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--rate", type=float, default=5.0,
                   help="Inbound msgs/s cap across all peers (burst = ceil(rate)).")
    args = p.parse_args()

    pp = os.environ.get("IRONMESH_PASSPHRASE")
    if not pp:
        raise SystemExit("Set IRONMESH_PASSPHRASE before running.")

    agent = Agent(
        name=args.name,
        port=args.port,
        passphrase=pp,
        max_msgs_per_sec=args.rate,
    )

    @agent.on_message()
    def handle(peer_id: str, payload: bytes) -> None:
        print(f"[{args.name}] from {peer_id}: {payload.decode(errors='replace')}")

    print(f"[{args.name}] global cap ON: {args.rate} msg/s. "
          "Excess inbound is rejected with RATE_LIMITED. "
          "Watch ironmesh_global_msg_rate_limit_total in Prometheus.")
    agent.run()


if __name__ == "__main__":
    main()
