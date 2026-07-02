# IronMesh Web Dashboard

Real-time monitoring and management GUI for IronMesh agent-to-agent communications.

## Overview

The web dashboard is built into the bridge daemon — no extra software, dependencies, or configuration needed. It serves a complete single-page application as embedded HTML directly from the daemon (the page lives in `dashboard_html.py`, served by `dashboard.py`), using the same `websockets` library that powers agent-to-agent communication.

**URL:** `http://127.0.0.1:{port+1}/`
**Example:** If your bridge runs on port 8765, the dashboard is at `http://127.0.0.1:8766/`

## Starting the Dashboard

The dashboard is **disabled by default** and must be explicitly enabled with `--gui`:

```bash
export IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase
ironmesh run --name bob --port 8765 --gui --allowed-peers alice
# Startup banner prints: GUI token: <random-token>
# Dashboard: http://127.0.0.1:8766/?token=<random-token>
```

Without `--gui`, only the legacy metrics-only HTTP server runs (if applicable).

Programmatically:

```python
from ironmesh.bridge import BridgeDaemon

# GUI disabled (default)
daemon = BridgeDaemon(name="wiz", port=8765, passphrase="secret")

# GUI enabled
daemon = BridgeDaemon(name="wiz", port=8765, passphrase="secret", gui=True)
# Access token at: daemon._gui_token
```

## Security

- **Disabled by default:** The GUI must be explicitly enabled with `--gui`. No attack surface when off.
- **Token authentication:** A unique `secrets.token_urlsafe(32)` bearer token is generated per session and printed in the startup banner. Required for all sensitive endpoints (`/metrics`, `/api/state`, `/ws`). Pass via `?token=` query parameter or `Authorization: Bearer` header.
- **Localhost only:** The dashboard binds to `127.0.0.1` — it is not accessible from other machines on the network.
- **Separate from agent traffic:** The encrypted agent-to-agent WebSocket channel on the main port (8765) is completely untouched. The dashboard runs on a separate port (8766).
- **Read + write access:** The dashboard can send messages as the local agent. Only use it on machines you trust.
- **HTML served without auth:** The `/` page (static HTML) is served without a token since it contains no sensitive data. The API endpoints it calls require the token.

## Dashboard Features

### Metrics Cards

Eight cards at the top of the page, updated every 2 seconds:

| Card | Description |
|------|-------------|
| **Uptime** | Time since bridge started |
| **Active Peers** | Number of peers currently online |
| **Messages Sent** | Total outbound messages |
| **Messages Received** | Total inbound messages |
| **Bytes Sent** | Total outbound bytes |
| **Bytes Received** | Total inbound bytes |
| **Handshakes** | Successful / failed handshake count |
| **Rate Limits** | Number of times rate limiting triggered |

### Peer Table

Live table of all known peers with columns:

| Column | Description |
|--------|-------------|
| **Node** | First 12 chars of node ID with color-coded status dot (green=online, red=offline, yellow=handshaking) |
| **Address** | IP:port of the peer |
| **Status** | Current peer state (online, offline, handshaking, etc.) |
| **Verified** | Whether the peer completed full ECDH handshake |
| **Sent** | Messages sent to this peer |
| **Recv** | Messages received from this peer |
| **Latency** | Last measured latency in milliseconds |

### Message Feed

Real-time scrolling log of all agent-to-agent messages. Each entry shows:

- **Timestamp** — Local time of the event
- **Direction arrow** — `↓` for inbound (green), `↑` for outbound (blue), `•` for system events
- **Type** — Message type (MSG, PING, PONG, ACK, CONNECT, DISCONNECT, etc.)
- **Peer** — First 12 chars of the peer node ID
- **Payload** — Message content (truncated to 200 chars)

The feed keeps the last 500 entries and auto-scrolls to the bottom.

### Send Form

At the bottom of the message feed panel:

1. **Select peer** — Dropdown populated with all known peers and their status
2. **Message type** — Defaults to `MSG`, can be changed to any valid message type
3. **Payload** — Text input for the message content
4. **Send button** — Click or press Enter to send

Messages sent from the GUI are encrypted and signed just like any programmatic `send_message()` call — full end-to-end encryption with forward secrecy.

### Start A2A panel (v0.8.2+)

A second row under the send form kicks off a bounded AI-to-AI
dialogue between two peers that advertise `llm:*` capabilities. The
dashboard shuttles `MessageType.CONV` frames between them and streams
the transcript into the message feed live.

Fields:

1. **AI peer A** / **AI peer B** — dropdowns auto-populated with
   only peers that advertise an `llm:*` capability. Must be different
   peers.
2. **Max turns** — spinner (default 4). Each turn = one agent reply.
   The first recipient to receive a frame at `turn >= max_turns`
   sends back an `end / turn-limit` frame and refrains from calling
   its model.
3. **Seed prompt** — the opening message sent to peer A.
4. **Start A2A** — kicks off the `start_dialogue` WS action.

Transcript events stream back as `type:"dialogue_event"` with
`event` set to one of `started`, `turn`, `end`, `error`, `timeout`,
`turn_cap_reached`, or `finished`. The dashboard renders each turn
with its speaker and turn number. See the "WebSocket Protocol"
section below for the full event schema.

Loop prevention (three layers, all active by default):

1. CONV envelope carries `turn` + `max_turns`; every LLM bridge
   returns an end-frame when the cap is hit.
2. `[LLM] ` response prefix stops replies re-triggering generation.
3. Per-conversation cooldown drops duplicate re-plays within 1 s.

Optional budgets (pass `budget_seconds` and/or `budget_bytes` in the
`start_dialogue` payload) end the exchange early with
`end_reason="budget-exceeded"`. An LLM can also self-terminate by
starting its reply with `[DONE] <reason>` — the bridge strips the
marker and emits `end_reason="goal-achieved"`.

## HTTP Endpoints

| Path | Description |
|------|-------------|
| `GET /` | HTML dashboard (single-page app) — no auth required |
| `GET /index.html` | Same as `/` — no auth required |
| `GET /metrics` | Metrics JSON (backward compatible) — **token required** |
| `GET /api/state` | Full state snapshot: metrics + peers + bus history — **token required** |
| `WS /ws` | WebSocket connection for real-time events — **token required** |

## WebSocket Protocol

The dashboard communicates with the bridge via WebSocket at `/ws`.

### Server -> Client Messages

| type | payload | trigger |
|------|---------|---------|
| `snapshot` | `{data: {node_id, name, port, metrics, peers, history}}` | On initial WS connection |
| `state_update` | Same structure as snapshot | Every 2 seconds |
| `message_event` | `{msg_type, peer_id, payload, timestamp}` | On every bus event |
| `peer_event` | `{event: "connected"/"disconnected", peer_id, timestamp}` | On peer connect/disconnect |
| `send_ack` | `{msg_id}` | After successful message send |
| `send_error` | `{error: "description"}` | On send failure or invalid command |
| `dialogue_event` (v0.8.2+) | `{conv_id, event, turn?, speaker?, body?, reason?, ...}` | Transcript tick from a running `start_dialogue` session. `event` is one of `started`, `turn`, `end`, `error`, `timeout`, `turn_cap_reached`, `finished`. |

### Client -> Server Messages

| action | params | effect |
|--------|--------|--------|
| `send_message` | `{to_node, msg_type, payload}` | Encrypts and sends via `daemon.send_message()` |
| `get_history` | `{peer_id (optional), limit}` | Queries SQLite message store |
| `refresh` | (none) | Re-sends full state snapshot |
| `start_dialogue` (v0.8.2+) | `{peer_a, peer_b, seed, max_turns?, turn_timeout?, budget_seconds?, budget_bytes?}` | Runs an in-process AI-to-AI orchestrator that shuttles CONV frames between two peers. Streams back `dialogue_event` messages. |

### Example: Sending a message via WebSocket

```json
{"action": "send_message", "to_node": "abc123def456", "msg_type": "MSG", "payload": "Hello from the dashboard!"}
```

Response:
```json
{"type": "send_ack", "msg_id": "550e8400-e29b-41d4-a716-446655440000"}
```

## Integration with Existing Systems

### curl / scripts

```bash
# Get metrics (token required)
curl http://127.0.0.1:8766/metrics?token=YOUR_GUI_TOKEN

# Or use Authorization header
curl -H "Authorization: Bearer YOUR_GUI_TOKEN" http://127.0.0.1:8766/metrics

# Get full state
curl http://127.0.0.1:8766/api/state?token=YOUR_GUI_TOKEN
```

### Programmatic WebSocket client

```python
import asyncio
import json
import websockets

TOKEN = "YOUR_GUI_TOKEN"  # Printed in startup banner

async def monitor():
    async with websockets.connect(f"ws://127.0.0.1:8766/ws?token={TOKEN}") as ws:
        async for raw in ws:
            msg = json.loads(raw)
            if msg["type"] == "message_event":
                print(f"[{msg['msg_type']}] {msg['peer_id']}: {msg['payload']}")

asyncio.run(monitor())
```

## Troubleshooting

- **Dashboard doesn't load:** Make sure you started with `--gui` and are accessing `http://127.0.0.1:{port+1}/`, not the main agent port.
- **"403 Forbidden" on metrics/state:** You need the bearer token. Check the startup banner for `GUI token: <token>` and append `?token=<token>` to the URL.
- **"connecting" badge stays red:** The WebSocket connection to `/ws` failed. Check that the bridge is still running and you're passing the token.
- **No peers in table:** Peers only appear after they complete the full handshake (passphrase auth + ECDH).
- **Send button does nothing:** Select a peer from the dropdown first. The peer must be online.
- **Dashboard not available:** The GUI is off by default. Start with `--gui` to enable it.
