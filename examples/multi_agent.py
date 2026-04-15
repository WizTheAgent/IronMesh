#!/usr/bin/env python3
"""IronMesh multi-agent coordination example.

Demonstrates 3+ agents discovering each other and coordinating.
Run on separate machines or with different ports on the same machine.

Usage:
  python multi_agent.py --name coordinator --port 8765 --role coordinator
  python multi_agent.py --name worker1    --port 8766 --role worker
  python multi_agent.py --name worker2    --port 8767 --role worker
"""

import argparse
import asyncio
import json
import sys
import time

sys.path.insert(0, "..")

from ironmesh.bridge import BridgeDaemon
from ironmesh.protocol import MessageType


async def coordinator_logic(daemon: BridgeDaemon):
    """Coordinator sends tasks to workers and collects results."""
    print("Coordinator waiting for workers...")
    await asyncio.sleep(10)  # Wait for workers to connect

    tasks = [
        {"task_id": 1, "action": "compute", "data": [1, 2, 3, 4, 5]},
        {"task_id": 2, "action": "compute", "data": [10, 20, 30, 40, 50]},
    ]

    workers = [pid for pid, s in daemon.peers.items() if s.is_online]
    print(f"Found {len(workers)} workers: {workers}")

    for i, task in enumerate(tasks):
        if i < len(workers):
            worker = workers[i]
            payload = json.dumps(task).encode()
            await daemon.send_message(worker, "REQ", payload)
            print(f"Dispatched task {task['task_id']} to {worker}")

    # Wait for results
    await asyncio.sleep(30)


async def worker_logic(daemon: BridgeDaemon, name: str):
    """Worker receives tasks and sends back results."""
    results = []

    def on_request(data):
        payload = data.get("payload", b"")
        if isinstance(payload, bytes):
            payload = json.loads(payload)
        task_id = payload.get("task_id")
        action = payload.get("action")
        task_data = payload.get("data", [])

        print(f"Worker {name} received task {task_id}: {action}")

        if action == "compute":
            result = sum(task_data)
            results.append({"task_id": task_id, "result": result})
            print(f"Worker {name} computed: sum({task_data}) = {result}")

            # Send result back
            peer_id = data.get("peer_id")
            if peer_id:
                response = json.dumps({"task_id": task_id, "result": result}).encode()
                asyncio.ensure_future(
                    daemon.send_message(peer_id, "RESP", response)
                )

    daemon.bus.subscribe("REQ", on_request)
    print(f"Worker {name} ready, waiting for tasks...")
    await asyncio.sleep(60)  # Keep running


def main():
    parser = argparse.ArgumentParser(description="IronMesh multi-agent example")
    parser.add_argument("--name", required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--passphrase", default="empire")
    parser.add_argument("--role", choices=["coordinator", "worker"], required=True)
    args = parser.parse_args()

    daemon = BridgeDaemon(
        name=args.name,
        port=args.port,
        passphrase=args.passphrase,
    )

    loop = daemon.run(background=True)

    try:
        if args.role == "coordinator":
            loop.run_until_complete(coordinator_logic(daemon))
        else:
            loop.run_until_complete(worker_logic(daemon, args.name))
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(daemon.shutdown())
        loop.close()


if __name__ == "__main__":
    main()
