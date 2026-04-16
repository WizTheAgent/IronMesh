# Examples

Runnable reference agents that use the IronMesh SDK. Each script is
self-contained — `pip install ironmesh` and you can run any of them.

Every example expects `IRONMESH_PASSPHRASE` in the environment (12+
characters). The passphrase must match across every peer in the mesh.

```bash
export IRONMESH_PASSPHRASE='any-strong-passphrase-12-plus'
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
    --peer-a gatekeeper --peer-b kingpi \
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

Bridges IronMesh to the Reticulum LXMF ecosystem so messages from a
Sideband phone (or any LXMF client) reach IronMesh peers. See
`docs/TERMUX.md` for the phone-side setup.

```bash
python examples/lxmf_gateway.py \
    --name lxmf-gw --port 8765 \
    --passphrase-file ~/.ironmesh/passphrase
```
