"""Pure-RNS client that queries an IronMesh node's public RPC paths.

This example imports only the ``rns`` package — no ironmesh dependency.
That is the point: any RNS-speaking program (a Pythonista script on a
phone, a Sideband plugin, a Nomadnet appbox) can ask an IronMesh node
about its identity, capabilities, and available services without having
to implement the IronMesh wire protocol or carry its dependencies.

Three endpoints are queried:

    /im/info     — node identity card  (name, version, node_id, caps, features)
    /im/cap/list — full capability registry  (local + known remote)
    /im/cap/find — pattern-matched capability lookup  (query: {pattern: str})

Usage:
    python rns_capability_client.py <ironmesh-destination-hash-hex>

The destination hash is the hex string an IronMesh node logs at startup
("Reticulum transport active — destination ...") and re-publishes in
every RNS announce.
"""

from __future__ import annotations

import json
import sys
import time

import RNS

APP_NAME = "ironmesh"
ASPECT = "bridge"

PATH_INFO = "/im/info"
PATH_CAP_LIST = "/im/cap/list"
PATH_CAP_FIND = "/im/cap/find"


def _wait_for_response(receipt: "RNS.RequestReceipt", timeout: float = 30.0) -> bytes:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if receipt.concluded():
            response = receipt.get_response()
            if response is None:
                raise RuntimeError("Request concluded with no response")
            return response if isinstance(response, bytes) else bytes(response)
        time.sleep(0.1)
    raise TimeoutError(f"Request timed out after {timeout:.0f}s")


def query(link: "RNS.Link", path: str, body: bytes = b"") -> dict | list:
    receipt = link.request(path, body, response_callback=None)
    raw = _wait_for_response(receipt)
    return json.loads(raw.decode("utf-8"))


def main(dest_hash_hex: str) -> int:
    RNS.Reticulum()  # use the running shared instance / system rnsd

    dest_hash = bytes.fromhex(dest_hash_hex.replace(":", "").replace(" ", ""))

    if not RNS.Transport.has_path(dest_hash):
        print(f"Requesting path to {dest_hash_hex}...")
        RNS.Transport.request_path(dest_hash)
        await_path = getattr(RNS.Transport, "await_path", None)
        if await_path is not None:
            await_path(dest_hash, timeout=30.0)
        else:
            for _ in range(60):
                if RNS.Transport.has_path(dest_hash):
                    break
                time.sleep(0.5)
        if not RNS.Transport.has_path(dest_hash):
            print("Path resolution failed.", file=sys.stderr)
            return 2

    identity = RNS.Identity.recall(dest_hash)
    if identity is None:
        print("Could not recall identity for destination.", file=sys.stderr)
        return 3

    destination = RNS.Destination(
        identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, ASPECT,
    )
    link = RNS.Link(destination)

    deadline = time.monotonic() + 30.0
    while link.status != RNS.Link.ACTIVE and time.monotonic() < deadline:
        time.sleep(0.1)
    if link.status != RNS.Link.ACTIVE:
        print("Link establishment failed.", file=sys.stderr)
        return 4

    try:
        info = query(link, PATH_INFO)
        print("=== /im/info ===")
        print(json.dumps(info, indent=2))

        cap_list = query(link, PATH_CAP_LIST)
        print("\n=== /im/cap/list ===")
        print(json.dumps(cap_list, indent=2))

        find = query(link, PATH_CAP_FIND, json.dumps({"pattern": "*"}).encode("utf-8"))
        print("\n=== /im/cap/find pattern=* ===")
        print(json.dumps(find, indent=2))
    finally:
        link.teardown()

    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
