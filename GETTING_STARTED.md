# IronMesh — 5-minute Dashboard Quickstart

> **Looking for the canonical walkthrough?** See
> [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) for the canonical
> multi-node SDK walkthrough that ends with a working Python `Agent`
> call. For the fastest possible first-look, run `ironmesh demo` —
> it spawns two local agents and confirms your install in 60 seconds
> with no config files.

This page is the **dashboard-focused** 5-minute quickstart: get two
nodes talking over encrypted WebSocket and watch them live in the
browser dashboard. For the full feature list, security model, and
architecture, see [`README.md`](README.md).

## 1. Install (pick one)

**Docker** (recommended for trying it out):

```bash
docker compose up -d   # starts a single node on port 8765
```

**One-line script** (Linux / macOS):

```bash
./scripts/install.sh
# or, once published:
# curl -fsSL https://raw.githubusercontent.com/WizTheAgent/ironmesh/main/scripts/install.sh | bash
```

**Manual** (for developers):

```bash
git clone https://github.com/WizTheAgent/ironmesh
cd ironmesh
pip install -e ".[rns]"
```

## 2. Generate keys and a passphrase

The first node creates a passphrase file; **the same passphrase must be
on every node that joins the mesh** — it's the mutual auth secret.

```bash
# Create a strong passphrase (>= 12 chars), store securely
mkdir -p ~/.ironmesh
echo 'a-strong-passphrase-at-least-12-chars' > ~/.ironmesh/passphrase
chmod 600 ~/.ironmesh/passphrase

# Generate an identity keypair (prompts for key-encryption passphrase)
ironmesh keys generate --path ~/.ironmesh/keys.json
```

> **Encrypted key file note:** if you encrypted the keypair with the
> same passphrase as the mesh (what `ironmesh setup` does), `ironmesh
> run` decrypts it automatically — no extra flag needed. If you chose
> a different key passphrase, the daemon prompts for it on a terminal;
> headlessly, supply it with `--keys-passphrase-file <path>` or the
> `IRONMESH_KEYS_PASSPHRASE` env var (`--keys-passphrase <pass>` also
> works but is discouraged — argv is visible in the process list).
> Alternatively, skip this step: the daemon auto-generates a keypair
> on first run (stored unencrypted, with an `INSECURE` warning in the
> log).

## 3. Start the bridge

```bash
IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase \
    ironmesh run --name alice --port 8765 \
    --gui --allow-plaintext-ws --open-discovery
```

On startup you'll see a **GUI token** printed to the terminal.

## 4. Open the dashboard

In a browser:

```
http://localhost:8766/
```

Click the browser's address bar and append the GUI token:

```
http://localhost:8766/?token=YOUR_TOKEN_HERE
```

You should see the IronMesh dashboard with metrics, peers, and a
message feed.

## 5. Connect a second node

On another machine (same LAN — mDNS auto-discovers):

```bash
# Copy the same passphrase file over
scp ~/.ironmesh/passphrase user@host2:~/.ironmesh/

# On host2 with a DIFFERENT --name
ironmesh keys generate --path ~/.ironmesh/keys.json
IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase \
    ironmesh run --name bob --port 8765 \
    --gui --allow-plaintext-ws --open-discovery
```

Within seconds both dashboards should show the other peer with status
`online`.

## 6. Send a test message

From the Alice dashboard, pick Bob in the peer dropdown, type a
message, click Send.  It should appear in Bob's message feed.

## Next Steps

- **[LLM bridge](examples/llm_bridge.py)** — make a node an encrypted
  Ollama agent so any peer can talk to a local LLM over the mesh.
- **[LXMF gateway](examples/lxmf_gateway.py)** — bridge IronMesh with
  Reticulum's LXMF so Sideband (iOS/Android) and NomadNet users can
  message your IronMesh nodes.
- **[LoRa / Reticulum transport](README.md#lora--reticulum-transport)** —
  run without any internet, over 915 MHz LoRa radio.
- **[Mesh routing](docs/MESH.md)** — multi-hop delivery for 3+ node
  topologies.
- **[Threat model](docs/THREAT_MODEL.md)** — what we defend against and
  what we don't.
- **[Compatibility matrix](ARCHITECTURE.md#14-version-compatibility-matrix)** —
  which features work across versions.

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Passphrase is required" | Set `IRONMESH_PASSPHRASE_FILE` or `--passphrase-file` |
| "TLS unavailable" warning | Add `--allow-plaintext-ws` for LAN-only deployments |
| Peer auto-connect doesn't happen | Add `--open-discovery` or `--allowed-peers peer-name` |
| Dashboard "401 Unauthorized" | Append `?token=<token>` — token is printed at startup |
| TOFU mismatch after re-generating keys | `ironmesh trust revoke <peer-id>` on each node, then reconnect |

## Stop the daemon

`Ctrl-C` in the terminal, or if running as systemd:

```bash
systemctl --user stop ironmesh
```
