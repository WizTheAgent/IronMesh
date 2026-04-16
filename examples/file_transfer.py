#!/usr/bin/env python3
"""IronMesh file transfer example — send binary data between agents.

Usage:
  export IRONMESH_PASSPHRASE='shared-passphrase-12-plus'
  # Receiver:
  python file_transfer.py --name receiver --port 8765
  # Sender:
  python file_transfer.py --name sender   --port 8766 --send path/to/file.txt

The sender discovers the receiver via mDNS and sends the file as binary MSG payload.
"""

import argparse
import asyncio
import base64
import json
import os
import sys

from ironmesh.bridge import BridgeDaemon


async def send_file(daemon: BridgeDaemon, filepath: str):
    """Send a file to the first discovered peer."""
    print(f"Reading file: {filepath}")
    with open(filepath, "rb") as f:
        data = f.read()

    filename = os.path.basename(filepath)
    print(f"File size: {len(data)} bytes")

    # Wait for a peer to connect
    print("Waiting for peer...")
    for _ in range(60):
        await asyncio.sleep(1)
        peers = [pid for pid, s in daemon.peers.items() if s.is_online]
        if peers:
            break
    else:
        print("No peers found. Exiting.")
        return

    peer_id = peers[0]
    print(f"Sending '{filename}' to {peer_id}...")

    # Send file metadata + data as JSON payload
    payload = json.dumps({
        "filename": filename,
        "size": len(data),
        "data": base64.b64encode(data).decode(),
    }).encode()

    msg_id = await daemon.send_message(peer_id, "MSG", payload)
    print(f"File sent! (msg_id: {msg_id})")


async def receive_files(daemon: BridgeDaemon, output_dir: str):
    """Listen for incoming file transfers."""
    os.makedirs(output_dir, exist_ok=True)

    def on_message(msg_data):
        payload = msg_data.get("payload", b"")
        if isinstance(payload, bytes):
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                return

            if "filename" in data and "data" in data:
                filename = data["filename"]
                file_data = base64.b64decode(data["data"])
                outpath = os.path.join(output_dir, filename)
                with open(outpath, "wb") as f:
                    f.write(file_data)
                print(f"Received file: {filename} ({len(file_data)} bytes) -> {outpath}")

    daemon.bus.subscribe("MSG", on_message)
    print(f"Listening for files (saving to {output_dir})...")
    await asyncio.sleep(300)  # Listen for 5 minutes


def main():
    parser = argparse.ArgumentParser(description="IronMesh file transfer")
    parser.add_argument("--name", required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--send", default=None, help="File path to send")
    parser.add_argument("--output-dir", default="./received_files")
    args = parser.parse_args()

    passphrase = os.environ.get("IRONMESH_PASSPHRASE")
    if not passphrase:
        sys.exit("Set IRONMESH_PASSPHRASE env var (12+ chars) before running.")

    daemon = BridgeDaemon(
        name=args.name,
        port=args.port,
        passphrase=passphrase,
    )

    loop = daemon.run(background=True)

    try:
        if args.send:
            loop.run_until_complete(send_file(daemon, args.send))
        else:
            loop.run_until_complete(receive_files(daemon, args.output_dir))
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(daemon.shutdown())
        loop.close()


if __name__ == "__main__":
    main()
