# IronMesh — Capability Discovery

IronMesh v0.4 ships a lightweight capability registry so agents can find
services across the mesh. A capability is a short string identifier — by
convention `namespace:name` — that a node advertises to declare what it can
offer (e.g. `llm:llama3`, `tool:filesystem`, `agent:translator`).

The capability layer is built on top of mesh routing: announcements
propagate via the same `MeshRouter` infrastructure, so a capability hosted
on a node 3 hops away is discoverable from anywhere on the mesh.

---

## Advertising local capabilities

### From the CLI

```bash
ironmesh run \
  --name llm-host \
  --capability llm:llama3 \
  --capability llm:phi3 \
  --capability tool:filesystem
```

`--capability` is repeatable. The advertised set is persisted to the file
referenced by `--capabilities-path` (default `~/.ironmesh/capabilities.json`)
under HMAC integrity protection. On startup the persisted set is loaded
and merged with anything passed on the command line.

### From Python

```python
daemon = BridgeDaemon(name="llm-host", port=8765, ...)
await daemon.start()
daemon.advertise_capability("llm:llama3")
daemon.advertise_capability("tool:filesystem")
```

---

## Discovering remote capabilities

```python
# Glob lookup — returns a list of (node_id, capability) pairs.
results = daemon.find_capability("llm:*")
for node_id, cap in results:
    print(f"{node_id} offers {cap}")
```

Pattern syntax is `fnmatch` glob (`*`, `?`, `[abc]`). Some examples:

| Pattern | Matches |
|---|---|
| `llm:*` | `llm:llama3`, `llm:phi3`, `llm:gpt4`, … |
| `tool:filesystem` | exact match only |
| `agent:?translator` | `agent:atranslator`, `agent:btranslator`, … |
| `*` | every advertised capability |

The first node in the result list is your own node if it locally advertises
a matching capability.

---

## How propagation works

Every 60 seconds (with a 10-second initial stagger), each node sends a
`CAPABILITY_ANNOUNCE` control-plane message to all of its **direct**
neighbors. Each announcement contains:

```json
{
  "origin": "<my node id>",
  "capabilities": ["llm:llama3", "tool:filesystem"]
}
```

When a node receives a `CAPABILITY_ANNOUNCE`, it `learn_remote()`s the set
into its local `CapabilityRegistry`, *replacing* any prior set for that
origin (so capabilities can be removed by re-announcing a smaller set).

For nodes that are not direct neighbors, propagation rides on top of mesh
routing: the announcement is destined to the recipient's node id, the
mesh router forwards it through the chain of relays, and the recipient
processes it just like a direct announcement. Relays cannot forge or
modify announcements because announcements (like all other frames) carry
an inner Ed25519 signature over the plaintext.

A node may not impersonate another node: `learn_remote(self_node_id, ...)`
is silently ignored, so a malicious peer cannot push fake capabilities into
your local node's "self" set.

---

## Persistence

The local registry is persisted to `--capabilities-path` (default
`~/.ironmesh/capabilities.json`) using the same HMAC-protected JSON
envelope as the routing table. The HMAC key is derived from the node's
identity key via:

```
hmac_key = SHA256(ed25519_secret + b"ironmesh-capabilities-v1")
```

Persistence covers both the local advertised set and the most recently
learned remote sets. On startup, the file is verified and loaded; a
tampered file or one belonging to a different node id is rejected and an
empty registry is used instead.

---

## Audit events

| Event | Meaning |
|---|---|
| `EVENT_CAPABILITY_LEARNED` | A new or changed capability set was learned from a remote node. The `delta` field reports how many capabilities were added/removed. |

---

## Suggested namespaces

These are not enforced by IronMesh — they're just conventions to keep
discovery sane:

| Namespace | Meaning | Example |
|---|---|---|
| `llm:` | Language model providers | `llm:llama3`, `llm:phi3` |
| `tool:` | Tool/function endpoints | `tool:filesystem`, `tool:browser` |
| `agent:` | Specialized agents | `agent:translator`, `agent:summarizer` |
| `data:` | Datasets / state stores | `data:vector-index` |
| `obs:` | Observability sinks | `obs:metrics`, `obs:logs` |

---

## Limitations and gotchas

- Announcements are control-plane and unencrypted at the e2e layer (they
  are still per-hop encrypted by the mesh's NaCl SecretBox sessions).
  Don't put secrets in capability strings.
- Capability churn (adding/removing dozens of capabilities per second)
  generates traffic. Keep the set stable.
- The `find()` API does a linear scan over all known capabilities. This is
  O(n × patterns), fine for the dozens-to-low-thousands scale IronMesh
  targets — if you have 10⁶ capabilities you have a different problem.

## Discovery from MCP hosts (v0.9.0+)

Agents running under an MCP host (OpenClaw, Claude Desktop, Claude Code)
can discover and use capabilities through the bundled `ironmesh_mcp`
server without writing any Python:

| MCP tool | Purpose |
|---|---|
| `ironmesh_discover_capabilities` | Glob-match capabilities across the mesh — `pattern: "llm:*"` returns every LLM peer |
| `ironmesh_get_peer_capabilities` | Full capability set for one peer (by agent name or 32-hex node_id) |
| `ironmesh_request_service` | REQ/RESP — send a prompt to a capable peer and wait for the matching reply (correlation-id over MSG, default 30 s timeout) |
| `ironmesh_broadcast` | Send a message to every online peer at once |
| `ironmesh_subscribe_events` | Cursor-based event poll (peer connect / disconnect / message arrivals) |

Together these turn capability advertisement from "infrastructure
plumbing" into "tools the agent itself reaches for." Setup:
[`OPENCLAW_MCP_SETUP.md`](OPENCLAW_MCP_SETUP.md).
