# Use cases

Five deployments where IronMesh actually earns its keep. Each section
points at a runnable example or command — not hypothetical code.

---

## 1. Home AI mesh

**You want** several machines in your house to run different AI jobs and
talk to each other: a Raspberry Pi with a local LLM, a desktop running
an image model, a laptop with a voice transcriber.

**Why IronMesh.** No cloud key, no router dependency, no per-device
account. The agents find each other via mDNS and speak an authenticated
encrypted channel with nothing more than a shared passphrase.

**Run it:**

```bash
ollama pull llama3.2:3b
ollama serve &

# Terminal / machine 1 (the thinker)
export IRONMESH_PASSPHRASE='your-12-char-passphrase'
python examples/ollama_swarm.py --role thinker --name thinker --port 8765 \
    --model llama3.2:3b

# Terminal / machine 2 (the asker)
export IRONMESH_PASSPHRASE='your-12-char-passphrase'
python examples/ollama_swarm.py --role asker --name asker --port 8766 \
    --target thinker --prompt "Summarize the last 24h of news in 3 bullets."
```

One host advertises the capability `llm:llama3.2:3b`; the other
discovers it and sends prompts. Drop in more models, more hosts — the
capability-based lookup (`agent.discover("llm:*")`) scales.

Full script: [`examples/ollama_swarm.py`](../examples/ollama_swarm.py).

---

## 2. Offline LLM swarm

**You want** coordinator-and-worker patterns without any internet
dependency: one node splits a job, several workers pick up chunks,
results stream back.

**Why IronMesh.** Encrypted offline queueing means workers can drop off
the network briefly and still pick up work on reconnect. No message
broker required.

**Run it:**

```bash
export IRONMESH_PASSPHRASE='your-12-char-passphrase'

python examples/multi_agent.py --role coordinator --name coord --port 8765
python examples/multi_agent.py --role worker       --name w1    --port 8766
python examples/multi_agent.py --role worker       --name w2    --port 8767
```

The coordinator broadcasts tasks, workers report results, and if a
worker vanishes for a minute its partial state is preserved in the
encrypted SQLite queue.

Script: [`examples/multi_agent.py`](../examples/multi_agent.py).

---

## 3. Robotics / edge coordination

**You want** several robots (or IoT agents) on a shop floor or in a
lab to swap status, share a map, or negotiate who owns which task —
with no cloud round-trip and no per-robot static config.

**Why IronMesh.** Multi-hop mesh routing (`docs/MESH.md`) forwards
messages through intermediate nodes, so you can have a robot near the
gateway and another at the far end of a warehouse talk through
whatever is in between. Identity is pinned per robot, so a swapped-in
replacement unit is rejected until the operator re-pins it.

**Pattern:**

```python
from ironmesh import Agent

agent = Agent("robot-07", passphrase="your-12-char-passphrase")
agent.advertise("robot:forklift", "cap:lift-2000lb")

@agent.on_message("REQ")
def handle_request(peer_id, payload):
    if payload.startswith(b"can-lift:"):
        weight = int(payload.split(b":")[1])
        agent.reply(peer_id, b"yes" if weight <= 2000 else b"no")

agent.run()
```

Any other agent on the mesh can now do
`agent.discover("robot:forklift")` and send `can-lift:1500` to negotiate
a task assignment, over encrypted multi-hop transport.

---

## 4. Air-gapped lab

**You want** agents in an isolated network — a SCIF, a pen-test lab, a
radio-frequency anechoic chamber — to coordinate without any routable
internet path.

**Why IronMesh.** Mutual passphrase authentication plus TOFU key
pinning means joining the mesh takes only a shared secret, not
certificate infrastructure. Every message is signed with Ed25519 and
encrypted with XSalsa20-Poly1305; the tamper-evident audit log
(HMAC-SHA256 chain) gives you a review trail that detects post-hoc
editing.

**Setup sketch:**

```bash
# On every lab machine
sudo ufw allow in on lab0 to any port 8765 proto tcp
sudo ufw allow in on lab0 to any port 5353 proto udp   # mDNS

echo 'shared-secret-for-this-lab-only' > ~/.ironmesh/passphrase
chmod 600 ~/.ironmesh/passphrase
export IRONMESH_PASSPHRASE_FILE=~/.ironmesh/passphrase

# Agents bind only to the isolated lab interface
ironmesh run --name analyst-1 --bind 10.42.0.5 --allowed-peers analyst-2,analyst-3
```

Audit events land in `~/.ironmesh/audit.log` with a chained HMAC;
`ironmesh audit verify` proves the log hasn't been edited.

---

## 5. Prepper / off-grid comms

**You want** AI agents (or just agents-as-messaging) to keep working
when there is no ISP, no cell tower, no grid.

**Why IronMesh.** The same message path runs over LAN *or* LoRa radio
via [Reticulum](https://reticulum.network/). Install an
[RNode](https://unsigned.io/rnode/), enable the transport, and agents
a kilometre apart can exchange signed messages at 915 MHz SF8/BW125 —
measured 100% delivery and 1.07–1.98s RTT across 16–256 byte probes
(see [`docs/LORA_VALIDATION.md`](LORA_VALIDATION.md)).

**Setup:**

```bash
pip install 'ironmesh[rns]'

ironmesh run --name bunker-1 --reticulum \
    --passphrase-file ~/.ironmesh/passphrase

# On another node, announce + connect via RNS destination hash
ironmesh run --name bunker-2 --reticulum \
    --rns-connect <bunker-1-dest-hash> \
    --passphrase-file ~/.ironmesh/passphrase
```

Android users can join the same mesh through
[Sideband](https://unsigned.io/sideband/) + the bundled LXMF gateway
(`examples/lxmf_gateway.py`). End-to-end verified with a Pixel on
actual LoRa hardware.

---

## See also

- Protocol spec: [`docs/PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md)
- Security + threat model: [`docs/SECURITY.md`](SECURITY.md), [`docs/THREAT_MODEL.md`](THREAT_MODEL.md)
- Multi-hop routing details: [`docs/MESH.md`](MESH.md)
- Re-pinning after a peer key change: [`docs/REPIN.md`](REPIN.md)
