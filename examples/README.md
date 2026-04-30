# Examples

Runnable reference agents that use the IronMesh SDK. Each script is
self-contained — `pip install ironmesh` and you can run any of them.

> **First time?** Run `ironmesh demo` first — it spawns two agents
> in subprocess on localhost, runs the handshake, exchanges a hello,
> and tears down. Confirms your install works in 10 seconds without
> touching any of these scripts. The examples below go further:
> two-agent dialogue you can read, multi-agent coordination, LLM
> bridges, capability routing, group broadcast, file transfer, LoRa
> gateway.

Every example expects `IRONMESH_PASSPHRASE` in the environment (12+
characters). The passphrase must match across every peer in the mesh.

```bash
export IRONMESH_PASSPHRASE='any-strong-passphrase-12-plus'
```

## Where to start

Ordered by difficulty. Read the source — they're written to be read.

| # | Example | What you learn |
|---|---|---|
| 1 | [`basic_chat.py`](basic_chat.py) | Two agents, send + receive. The "hello world." |
| 2 | [`multi_agent.py`](multi_agent.py) | Three agents, simple coordination |
| 3 | [`conv_multiturn.py`](conv_multiturn.py) | Multi-turn conversation envelope |
| 4 | [`ai_to_ai_dialogue.py`](ai_to_ai_dialogue.py) | Two agents in structured back-and-forth |
| 5 | [`file_transfer.py`](file_transfer.py) | Larger payloads + chunked delivery |
| 6 | [`llm_bridge.py`](llm_bridge.py) | Bridge a peer to a local Ollama LLM |
| 7 | [`ollama_swarm.py`](ollama_swarm.py) | Multiple Ollama agents talking |
| 8 | [`persona_debate.py`](persona_debate.py) | Two LLM personas, one mediator |
| 9 | [`capability_routing.py`](capability_routing.py) | `send_to_capability` with first/random/all (**v0.9.2+**) |
| 10 | [`group_broadcast.py`](group_broadcast.py) | Mesh-wide shared-secret broadcast (**v0.9.2+**) |
| 11 | [`cap_binding_workflow.py`](cap_binding_workflow.py) | Capability binding TOFU workflow |
| 12 | [`rns_capability_client.py`](rns_capability_client.py) | RNS public capability RPC client |
| 13 | [`lxmf_gateway.py`](lxmf_gateway.py) | Sideband / Nomadnet ↔ IronMesh bridge |
| 14 | [`openclaw/`](openclaw/) | OpenClaw 2026.3.x integration recipes |

If you only have time for one, read `basic_chat.py`. If you have time for two, read `basic_chat.py` then `llm_bridge.py`.

---

## capability_routing.py — capability-aware routing (chunk E, v0.9.2+)

Two `provider` agents advertise the same capability glob (e.g.
`echo:demo`); a `client` agent discovers them via the capability
registry and dispatches via `Agent.send_to_capability` with a
strategy of `first` (best-RTT match), `random` (load distribution),
or `all` (parallel fan-out). The local node is never picked even if
it satisfies the capability. Reference for: capability advertisement
on Agent init, `on_message` handler, `send_to_capability` with each
strategy, the result-dict shape per strategy.

```bash
export IRONMESH_PASSPHRASE='your-shared-passphrase-12-plus'

# Terminal 1 (provider A)
python examples/capability_routing.py --role provider \
    --name provider-a --port 18890

# Terminal 2 (provider B)
python examples/capability_routing.py --role provider \
    --name provider-b --port 18891

# Terminal 3 (client)
python examples/capability_routing.py --role client \
    --name caller --port 18892 --strategy all
```

## group_broadcast.py — mesh-wide shared-secret broadcast (chunk B, v0.9.2+)

Two agents on the same mesh passphrase independently derive the same
HKDF-SHA256 group destination — no key exchange. The sender calls
`broadcast_via_rns_group(payload)`; every peer that enabled
`rns_group_broadcast` and shares the passphrase receives the bytes
via the `on_group_broadcast` hook. Two-phase delivery (RNS GROUP
packet + IronMesh `GROUP_BROADCAST` fan-out) handles both
same-segment and cross-host cases; receivers dedup on payload
SHA-256 so a peer reachable via both phases handles the bytes
exactly once. Reference for: passphrase-derived group identity,
two-phase delivery result dict, `on_group_broadcast` hook signature.

```bash
export IRONMESH_PASSPHRASE='your-shared-passphrase-12-plus'

# Terminal 1 (receiver)
python examples/group_broadcast.py --role receiver --port 18890

# Terminal 2 (sender)
python examples/group_broadcast.py --role sender --port 18891
```

## conv_multiturn.py — minimal ConvEnvelope walkthrough (no LLM)

A scripted ping/pong conversation between two agents using
`ConvEnvelope` for structured multi-turn exchange. No LLM dependency —
both sides are scripted — so this works as a self-contained walkthrough
of the conversation envelope API. The reference for: open a
conversation, exchange bounded turns, recognize end-of-conversation,
no orphaned state.

```bash
# Terminal 1
python examples/conv_multiturn.py --role ponger --port 18890

# Terminal 2
python examples/conv_multiturn.py --role pinger --port 18891 \
    --partner ponger --turns 4
```

## persona_debate.py — two persona-tagged LLM bridges debating a motion

Discovers two peers advertising different `role:<persona>` capabilities
(e.g., `role:assistant` and `role:devil`), seeds a debate motion, and
relays bounded turns between them. Each side responds in character
using its persona preset from `ironmesh.roles`. Pair however you like:
`assistant` vs `devil` for classic debate, `security-analyst` vs `ops`
for a real-world tradeoff discussion, `historian` vs `coder` for
perspective contrast.

Requires two `llm_bridge.py` instances running with different `--role`
flags pointed at an Ollama-compatible backend. See the script's module
docstring for the full setup.

```bash
python examples/persona_debate.py \
    --persona-a assistant --persona-b devil \
    --motion "Self-hosted AI is the only ethical path forward." \
    --turns 6
```

## ai_to_ai_dialogue.py — two AI agents holding a bounded conversation

Demonstrates the "AI agents talk to each other without the user babysitting,
and without looping forever" pattern. Connects to the mesh, picks two
peers that advertise `llm:*`, seeds a prompt, and relays replies back
and forth until a configured turn cap is reached. Three loop-prevention
layers in effect:

1. Responses carry an `[LLM] ` prefix so a reply landing in another
   LLM bridge's inbox never re-triggers generation.
2. Every relayed message has a `[CONV:<id>:<turn>/<max>]` header
   that `llm_bridge.py` reads to enforce the cap.
3. `llm_bridge.py`'s per-conversation cooldown drops accidental
   self-replay.

```bash
export IRONMESH_PASSPHRASE='your-shared-passphrase-12-plus'
python examples/ai_to_ai_dialogue.py \
    --peer-a alice --peer-b bob \
    --seed "Debate whether a Raspberry Pi is a good home server." \
    --turns 4
```

Leave out `--peer-a` / `--peer-b` and the script auto-discovers the
first two peers that advertise any `llm:*` capability.

## ollama_swarm.py — two Ollama agents talking over IronMesh

The flagship demo. One node runs a local Ollama model and answers
prompts; the other sends prompts to it. Works on one machine or across
a LAN. No cloud, no API keys, no internet.

```bash
ollama pull llama3.2:3b
ollama serve &

# Terminal 1 (or machine A) - the thinker
python examples/ollama_swarm.py --role thinker --name thinker --port 8765 \
    --model llama3.2:3b

# Terminal 2 (or machine B) - the asker
python examples/ollama_swarm.py --role asker --name asker --port 8766 \
    --target thinker --prompt "Explain mesh networking in one sentence."
```

The thinker advertises `llm:<model>` as a capability. On a real mesh
with several thinkers you can discover them with
`agent.discover("llm:*")` rather than passing `--target`.

## basic_chat.py

Two agents auto-discover each other and print received messages.

```bash
# Terminal 1
python examples/basic_chat.py --name alice --port 8765

# Terminal 2
python examples/basic_chat.py --name bob --port 8766
```

## multi_agent.py

Coordinator dispatches tasks to workers. Run one coordinator and any
number of workers, each on its own port.

```bash
python examples/multi_agent.py --name coord --port 8765 --role coordinator
python examples/multi_agent.py --name w1    --port 8766 --role worker
python examples/multi_agent.py --name w2    --port 8767 --role worker
```

## file_transfer.py

Binary blob transfer over an IronMesh MSG. Receiver writes to a
directory; sender reads a file and pushes it.

```bash
# Receiver
python examples/file_transfer.py --name receiver --port 8765

# Sender
python examples/file_transfer.py --name sender --port 8766 --send ./somefile.pdf
```

## llm_bridge.py

Turns a node into an encrypted LLM endpoint. Incoming messages are
forwarded to a local Ollama server; the model's response is sent back.
Requires `ollama serve` running with a model pulled.

```bash
ollama pull llama3.2:3b
ollama serve &

python examples/llm_bridge.py \
    --name llm-node --port 8766 \
    --passphrase-file ~/.ironmesh/passphrase \
    --ollama-url http://localhost:11434 \
    --model llama3.2:3b \
    --role security-analyst \
    --tools echo,http-get
```

Supports (v0.8.2+):
- `--role <name>` — persona preset (`assistant`, `security-analyst`,
  `network-engineer`, `historian`, `coder`, `ops`, `devil`). Loads a
  bundled system prompt and advertises `role:<name>` as a capability.
- `--tools <list>` — opt-in tool-use (`echo`, `http-get`, `file-read`
  with `--file-read-allow`). The model can call tools mid-reply with
  `<tool name="X">args</tool>` markers.
- `--keys-path` / `--keys-passphrase` — reuse an existing identity
  instead of generating fresh keys.
- Accepts both plain `MSG` payloads and structured `MessageType.CONV`
  frames. Turn caps, budgets, and `[DONE]` smart termination are all
  handled automatically.

## lxmf_gateway.py

**Extra dependency:** `pip install ironmesh[lxmf]` (pulls `rns` + `lxmf`).

Bridges IronMesh to the Reticulum LXMF ecosystem so messages from a
Sideband phone (or any LXMF client) reach IronMesh peers. See
`docs/TERMUX.md` for the phone-side setup.

```bash
python examples/lxmf_gateway.py \
    --name lxmf-gw --port 8765 \
    --passphrase-file ~/.ironmesh/passphrase
```
