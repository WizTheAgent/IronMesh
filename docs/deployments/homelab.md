# Reference Deployment — Homelab

A working reference for the most-asked-about IronMesh setup:
**two IronMesh nodes + one local LLM (Ollama) + a CrewAI crew that
talks to itself across the mesh.** Encrypted end-to-end, runs on
hardware you already own, no cloud, no API keys, no internet.

> **Audience:** anyone who wants to evaluate IronMesh on a Sunday
> afternoon. r/LocalLLaMA, r/selfhosted, r/homelab. Built to be
> reproducible, not scaled to production. For a production blueprint
> see [`production.md`](production.md) (planned).

## What you'll build

```
┌─────────────────────┐                      ┌─────────────────────┐
│   Machine A         │   encrypted mesh     │   Machine B         │
│   (e.g. desktop)    │ ◄──────────────────► │   (e.g. Pi 5)       │
│                     │                      │                     │
│  ironmesh node-a    │                      │  ironmesh node-b    │
│  CrewAI crew        │                      │  CrewAI crew        │
│  (researcher)       │                      │  (writer)           │
│                     │                      │                     │
│  Ollama (llama3.2)  │                      │                     │
│  serving 11434      │                      │                     │
└─────────────────────┘                      └─────────────────────┘
                          │
                          │ both nodes share
                          │ a passphrase via
                          │ secure file
```

Two IronMesh nodes on the same LAN. Machine A also runs Ollama with a
local model. Each machine runs a CrewAI agent (one researcher, one
writer). The researcher (on A) sends a research question to the writer
(on B) over the encrypted mesh; the writer queries Ollama via
A's `llm:llama3.2` capability and returns prose. End-to-end, no cloud.

## Hardware

Either machine can be modest. A reasonable starting point:

| Role | Suggested hardware | Minimum |
|---|---|---|
| **Machine A (LLM host)** | Anything that can run Ollama with a 3B model — e.g. recent x86 desktop, Pi 5 with 8 GB RAM, M-series Mac | 4 GB RAM, modern CPU |
| **Machine B (CrewAI client)** | Pi 4 / Pi 5 / any Linux box / Windows / Mac | 2 GB RAM |
| **Network** | Both on the same LAN, mDNS-capable router | Or use a [NAT overlay](../NAT_TRAVERSAL.md) for cross-network |

Either machine can play either role. The split below is just a
common pattern (heavy LLM on the beefier box, lightweight CrewAI
client on the smaller one).

## Step 1 — Install IronMesh on both machines

```bash
# On both machines
pip install 'ironmesh[rns]'
ironmesh --version
```

`[rns]` pulls in the Reticulum extras even though we won't use them
in this deployment — handy to have if you later add a LoRa hop.

## Step 2 — Generate a shared passphrase

Generate once, copy to both machines via your preferred secure
channel (USB stick, age-encrypted file, paper).

```bash
# On either machine
python -c "import secrets; print(secrets.token_urlsafe(32))"
# example output: 2vGQ7kY...K9pX4z
```

On **each** machine:

```bash
mkdir -p ~/.ironmesh
chmod 700 ~/.ironmesh
echo '<paste-the-passphrase-here>' > ~/.ironmesh/passphrase
chmod 600 ~/.ironmesh/passphrase
export IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase
# Add the export to your ~/.bashrc / ~/.zshrc so it persists
```

## Step 3 — Set up Ollama on Machine A

```bash
# Linux / macOS
curl -fsSL https://ollama.com/install.sh | sh
# Windows: download from https://ollama.com/download/windows

# Pull a small model — llama3.2:3b is a good starting point
ollama pull llama3.2:3b

# Start Ollama in the background (most installers do this for you)
ollama serve &
```

Verify Ollama answers locally:

```bash
curl http://localhost:11434/api/generate -d '{
  "model": "llama3.2:3b",
  "prompt": "Say hi.",
  "stream": false
}'
```

You should see a JSON response. If not, fix Ollama before continuing.

## Step 4 — Start the IronMesh node on Machine A (LLM host)

This node advertises an `llm:llama3.2` capability, so the other node
can discover and use the model over the mesh.

```bash
# On Machine A, terminal 1
ironmesh run --name node-a --port 8765 \
    --allowed-peers node-b \
    --capability llm:llama3.2

# Terminal 2 — start the LLM bridge that listens for mesh requests
# and forwards them to local Ollama
python -m examples.llm_bridge \
    --name node-a-llm --port 8766 \
    --model llama3.2:3b \
    --ollama-host http://localhost:11434
```

The first terminal runs the IronMesh daemon. The second runs the
bridge that translates mesh messages into Ollama calls.

## Step 5 — Start the IronMesh node on Machine B (CrewAI client)

```bash
# On Machine B
ironmesh run --name node-b --port 8765 \
    --allowed-peers node-a
```

Within seconds you should see both daemons announce each other in
their logs:

```
[discovery] discovered node-a @ 192.0.2.10:8765
[handshake] node-a online -- ECDH complete -- llm:llama3.2 advertised
```

## Step 6 — Run the CrewAI crew on Machine B

Install CrewAI:

```bash
pip install 'ironmesh[adapters]' crewai
```

Drop this script into `homelab_crew.py` on Machine B:

```python
"""Two-agent CrewAI crew using IronMesh as the LLM transport."""
from crewai import Agent, Crew, Task
from ironmesh.adapters.crewai_adapter import IronMeshLLM

# Point CrewAI at the mesh-served LLM. The adapter discovers any peer
# advertising llm:llama3.2 and routes prompts there.
llm = IronMeshLLM(capability="llm:llama3.2", agent_name="node-b")

researcher = Agent(
    role="Researcher",
    goal="Find one surprising fact about a topic.",
    backstory="A curious librarian.",
    llm=llm,
)
writer = Agent(
    role="Writer",
    goal="Turn a fact into one short paragraph.",
    backstory="A concise journalist.",
    llm=llm,
)

research = Task(
    description="Find one surprising fact about Reticulum mesh networking.",
    expected_output="One sentence with a citation.",
    agent=researcher,
)
write = Task(
    description="Write a short paragraph based on the fact.",
    expected_output="A two-sentence paragraph for a blog post.",
    agent=writer,
)

crew = Crew(agents=[researcher, writer], tasks=[research, write])
print(crew.kickoff())
```

Run it:

```bash
python homelab_crew.py
```

Both agents are running on Machine B. Their LLM calls travel over the
encrypted mesh to Machine A's `llm:llama3.2` capability, get processed
by Ollama, and return. The researcher's output feeds into the
writer's task. Final output prints to stdout.

## What you've just demonstrated

- **End-to-end encryption** between two machines with no shared
  TLS infrastructure. Just the passphrase you copied in step 2.
- **Capability discovery.** Machine B never had to know Machine A's
  IP address, hostname, or LLM endpoint. It asked the mesh for
  `llm:llama3.2` and got routed.
- **Local AI without cloud.** No OpenAI keys, no Anthropic keys,
  no Hugging Face account. Your prompts stay on your hardware.
- **CrewAI on top of IronMesh.** The same crew code works whether
  the LLM is on the same machine or across the mesh.

## Adding a third node

Add a Pi Zero 2 W as `node-c` running just the IronMesh daemon and
a different CrewAI agent. Same pattern: `ironmesh run --name node-c
--allowed-peers node-a,node-b`. The mesh routes between any peer
pairs; you don't need a star topology.

## Adding LoRa for off-grid resilience

Plug an RNode into one of the machines and add `--reticulum` to its
`ironmesh run` command. See [`LORA_VALIDATION.md`](../LORA_VALIDATION.md)
for the hardware list and `tests/test_reticulum_transport.py` for the
behavior under poor link conditions.

## Adding the operator dashboard

Pass `--gui` to either node's `ironmesh run` command. The startup
banner prints a one-time bearer token. Open
`http://<machine-ip>:8766/?token=<token>` in your browser. You'll see
both peers, the live handshake stages, per-peer latency sparklines,
and a regex-capable message feed.

## Troubleshooting

- **"No peer advertising llm:llama3.2"** — capability didn't propagate.
  Check `--capability llm:llama3.2` is on Machine A's `ironmesh run`,
  and that the LLM bridge process is running.
- **Handshake hangs at "passphrase verifying"** — passphrases differ
  between the two machines. Re-copy the passphrase file.
- **mDNS not finding peers** — your router has multicast filtering
  enabled (common on enterprise WiFi and some mesh routers). Either
  fix the router setting or fall back to manual peer addresses via
  the agent SDK's `connect_to(<host>:<port>)`.
- **Ollama OOMs** — try a smaller model: `ollama pull llama3.2:1b`.

## Going further

- **Production deployment:** harden with TLS, full-disk encryption on
  every node, off-host backups of `~/.ironmesh/`, and a real operator
  dashboard. See `docs/SECURITY.md` "Hardening Recommendations."
- **More than 2 nodes:** see the planned multi-tenant reference
  deployment.
- **Off-grid only:** see the planned off-grid (Heltec V3 + Pi Zero 2 W
  + LoRa) reference deployment.
