# IronMesh Quickstart

Get two agents talking on your local network in 5 minutes. No cloud, no internet, no accounts.

## What you need

- Two machines on the same LAN (Raspberry Pi, desktop, laptop, VM — anything that runs Python)
- Python 3.10+
- That's it

## 1. Install

```bash
pip install ironmesh
```

Or from source:

```bash
git clone https://github.com/WizTheAgent/ironmesh.git
cd ironmesh
pip install -e .
```

## 2. Set up your passphrase

The `--passphrase` CLI flag was removed for security (it's visible in `ps aux`). Use a passphrase file instead:

```bash
# On each machine:
mkdir -p ~/.ironmesh
echo "your-strong-shared-passphrase" > ~/.ironmesh/passphrase
chmod 600 ~/.ironmesh/passphrase
export IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase
```

The passphrase must be at least 12 characters and identical on both agents.

## 3. Start Agent A (e.g., your Raspberry Pi)

```bash
ironmesh run --name kingpi --port 8765 --allowed-peers wiz
```

You'll see the startup banner and "WebSocket server started" in the logs. The agent is now announcing itself via mDNS and listening for peers.

## 4. Start Agent B (e.g., your desktop)

On another machine, same LAN:

```bash
ironmesh run --name wiz --port 8765 --allowed-peers kingpi
```

Within seconds you should see both agents discover each other:

```
Discovered agent: kingpi @ 192.168.1.50:8765
Peer kingpi (abc123...) online -- ephemeral ECDH complete
```

That's it. Both agents are now communicating over an encrypted channel. No internet involved.

**What just happened:**
1. Both agents announced themselves via mDNS (zero-config LAN discovery — no identity keys broadcast)
2. They found each other automatically
3. Mutual passphrase authentication — both sides proved they know the secret (HMAC-SHA256)
4. Signed HELLO exchange — Ed25519 signatures with channel binding to prevent handshake splicing
5. TOFU key pinning — each peer's identity key was recorded for future verification
6. Ephemeral X25519 keys were generated and exchanged (forward secrecy)
7. A shared secret was derived via ECDH — ephemeral private keys destroyed
8. All messages are now encrypted (XSalsa20-Poly1305) AND signed (Ed25519) with replay protection

## 5. Generate keys (optional)

Keys are auto-generated on first run and encrypted with your passphrase by default. If you want to generate them manually:

```bash
ironmesh keys generate --path ~/.ironmesh/keys.json --passphrase mykeyspassword
```

> **Note:** Key files are now encrypted by default. If you have legacy plaintext key files, they auto-migrate to encrypted format on next startup.

## 6. Send messages programmatically

```python
from ironmesh.bridge import BridgeDaemon

daemon = BridgeDaemon(name="alice", port=8765, passphrase="mysecretphrase",
                      allowed_peers=["bob"])
loop = daemon.run(background=True)

# After peers connect, send an encrypted message:
import asyncio
asyncio.run_coroutine_threadsafe(
    daemon.send_message("peer_fingerprint", "MSG", b"Hello from Alice!"),
    loop,
)
```

## 7. Open the Dashboard (optional)

The dashboard is **off by default** for security. Enable it with `--gui`:

```bash
ironmesh run --name wiz --port 8765 --gui --allowed-peers kingpi
```

The startup banner will print a bearer token:
```
GUI token: aB3x...yourtoken...7Zq
```

Open your browser with the token:
```
http://127.0.0.1:8766/?token=aB3x...yourtoken...7Zq
```

The built-in web dashboard shows:
- **Metrics cards** — Uptime, peers, messages, bytes, handshakes, rate limits (updates every 2s)
- **Peer table** — All connected peers with status, verification, traffic counts, latency
- **Message feed** — Real-time scrolling log of every message between agents
- **Send form** — Select a peer, type a message, hit Enter to send directly from the browser

The dashboard runs on `port + 1` (e.g., port 8766 when bridge is on 8765). It's localhost-only with token authentication.

## 8. Check metrics (CLI)

The metrics endpoint requires the GUI token when `--gui` is enabled:

```bash
curl http://localhost:8766/metrics?token=YOUR_TOKEN
```

Returns JSON with messages sent/received, active peers, uptime, handshake stats.

## 9. Manage trust

```bash
# See which peers you've connected to
ironmesh trust list

# If a peer's identity key changes unexpectedly, revoke and re-verify
ironmesh trust revoke <node_id>
```

## 10. Try the chat example

```bash
# Set up passphrase file first (see step 2)
# Machine A
python examples/basic_chat.py --name kingpi --port 8765

# Machine B
python examples/basic_chat.py --name wiz --port 8765
```

Type messages and see them appear encrypted on the other side.

## Troubleshooting

- **Agents don't discover each other:**
  - Make sure both machines are on the same LAN/subnet
  - Check firewall rules: mDNS needs UDP port 5353, WebSocket needs TCP port 8765
  - On Linux: `sudo ufw allow 5353/udp && sudo ufw allow 8765/tcp`

- **Auth fails ("wrong passphrase"):**
  - The passphrase must be identical on both agents. Verify the file contents match on both machines.

- **"Passphrase is required" error:**
  - IronMesh requires a passphrase (minimum 12 characters). Set `IRONMESH_PASSPHRASE_FILE` pointing to a file, or `IRONMESH_PASSPHRASE` env var. Interactive getpass prompt works if stdin is a TTY.

- **"Agents don't auto-connect":**
  - mDNS auto-connect is now default-deny. Use `--allowed-peers wiz,kingpi` or `--open-discovery` to enable.

- **Works on localhost but not across machines:**
  - Your router/firewall may be blocking mDNS multicast. Try connecting manually: the `connect_to_peer()` API takes a host and port directly.

## Next steps

- Read [DASHBOARD.md](DASHBOARD.md) for full GUI dashboard documentation
- Read [SECURITY.md](SECURITY.md) to understand the threat model
- Read [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) for the wire format specification
- Check out the `examples/` directory for multi-agent coordination and file transfer
- Hook into the plugin system (`ironmesh.hooks`) for custom message processing
