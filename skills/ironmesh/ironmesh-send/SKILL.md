---
name: ironmesh-send
description: Send an application message (MSG) to a specific IronMesh peer. Use when the user asks to "send X to agent Y" or "ping peer Z". Has side effects — only invoke when the user explicitly asks.
allowed-tools: [Bash]
---

# Send a message over IronMesh

Push a MSG frame to a named peer using the local daemon. Waits briefly
for the daemon to ACK then reports the message id.

## When to use

- User asks to send a message, signal, or command to another agent
- After `ironmesh-peers <target>` confirms the peer is online
- For ops tasks: broadcast a reload signal, kick off a remote job, etc.

## When NOT to use

- If the peer is offline and the user didn't authorize queueing — ask first
- Don't send secrets via MSG unless the user knows it'll be stored
  (encrypted at rest) in the peer's `messages` table

## How to run

```bash
: "${IRONMESH_GUI_PORT:=8766}"
: "${IRONMESH_GUI_TOKEN:?set IRONMESH_GUI_TOKEN}"

TARGET="${1:?usage: send <peer-name-or-node-id> <payload> [priority]}"
PAYLOAD="${2:?payload required}"
PRIORITY="${3:-NORMAL}"

# Find the node_id for this agent name (if not already a node_id).
if [ ${#TARGET} -ne 32 ]; then
    NODE_ID=$(curl -sS "http://127.0.0.1:${IRONMESH_GUI_PORT}/api/mesh_stats?token=${IRONMESH_GUI_TOKEN}" \
        | python3 -c "
import json, sys
name = sys.argv[1]
d = json.load(sys.stdin)
for p in d['peers']:
    if p['name'] == name:
        print(p['node_id']); sys.exit(0)
sys.exit(1)
" -- "$TARGET")
    if [ -z "$NODE_ID" ]; then
        echo "ERROR: peer '$TARGET' not found in mesh_stats"
        echo "Available peers:"
        curl -sS "http://127.0.0.1:${IRONMESH_GUI_PORT}/api/mesh_stats?token=${IRONMESH_GUI_TOKEN}" \
            | python3 -c "import json,sys; print('  '+'\\n  '.join(p['name'] or p['node_id'][:16] for p in json.load(sys.stdin)['peers']))"
        exit 1
    fi
else
    NODE_ID="$TARGET"
fi

# Use the IronMesh GUI WebSocket to submit a send (same mechanism the
# dashboard uses). We open a WS, send a single JSON command, then close.
python3 - "$NODE_ID" "$PAYLOAD" "$PRIORITY" "$IRONMESH_GUI_PORT" "$IRONMESH_GUI_TOKEN" <<'PY'
import asyncio, json, sys
node_id, payload, priority, port, token = sys.argv[1:6]

async def main():
    import websockets
    uri = f"ws://127.0.0.1:{port}/ws?token={token}"
    async with websockets.connect(uri) as ws:
        # Consume initial snapshot
        await ws.recv()
        await ws.send(json.dumps({
            "action": "send",
            "peer_id": node_id,
            "type": "MSG",
            "payload": payload,
            "priority": priority,
        }))
        # Wait briefly for ACK
        try:
            for _ in range(5):
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=2))
                if msg.get("type") == "send_ack":
                    print(f"ACK: msg_id={msg.get('msg_id')}")
                    return
                if msg.get("type") == "send_error":
                    print(f"ERROR: {msg.get('error')}")
                    return 2
        except asyncio.TimeoutError:
            print("No ACK in 10s — queued or failed silently")
            return 3
asyncio.run(main())
PY
```

## Priority levels

- `CRITICAL` — displaces LOW/NORMAL/HIGH in the offline queue
- `HIGH` — displaces LOW/NORMAL
- `NORMAL` (default)
- `LOW` — dropped first when queue is full of higher priority

Use CRITICAL sparingly: a flooded queue of CRITICAL will refuse to accept
new LOW messages, which could hide legitimate traffic.
