# Examples

Runnable reference agents that use the IronMesh SDK. Each script is
self-contained — `pip install ironmesh` and you can run any of them.

Every example expects `IRONMESH_PASSPHRASE` in the environment (12+
characters). The passphrase must match across every peer in the mesh.

```bash
export IRONMESH_PASSPHRASE='any-strong-passphrase-12-plus'
```

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
    --model llama3.2:3b
```

Any other agent on the mesh can now send a prompt as a MSG payload and
get a model completion back.

## lxmf_gateway.py

Bridges IronMesh to the Reticulum LXMF ecosystem so messages from a
Sideband phone (or any LXMF client) reach IronMesh peers. See
`docs/TERMUX.md` for the phone-side setup.

```bash
python examples/lxmf_gateway.py \
    --name lxmf-gw --port 8765 \
    --passphrase-file ~/.ironmesh/passphrase
```
