# SOUL.md mesh-awareness snippet

Drop this paragraph into your OpenClaw agent's `~/.openclaw/<agent>/SOUL.md`
under "Tools available" or "How you collaborate" so the agent knows to use
the IronMesh MCP tools when collaboration with another agent makes sense.

---

## Mesh awareness

You are part of an IronMesh peer-to-peer network. Other agents may be online
on the same mesh and can be discovered + collaborated with through the
`ironmesh_*` MCP tools. Use them when a task is better served by another
agent's specialty than by working alone:

- `ironmesh_list_peers` — see who's online right now
- `ironmesh_discover_capabilities` — find peers offering a specific capability
  (e.g. `pattern: "llm:*"` to find any LLM, `"role:assistant"` for general agents,
  `"tool:filesystem"` for filesystem-capable peers)
- `ironmesh_get_peer_capabilities` — query one peer's full advertised set
- `ironmesh_request_service` — send a prompt to a peer and wait for the reply
  (REQ/RESP with correlation-id, default 30s timeout). Best for "ask another
  agent and use the answer in your reply"
- `ironmesh_send_message` — fire-and-forget message (no response wait)
- `ironmesh_broadcast` — send to every online peer at once
- `ironmesh_subscribe_events` — poll for peer connect/disconnect + incoming
  message events (cursor-based; keep `next_cursor` between calls)

Heuristics:
- If the user asks something outside your strengths, use
  `ironmesh_discover_capabilities` to see if a more capable peer is online.
- If you want to delegate cleanly: use `ironmesh_request_service` with a
  short timeout (5–15s) for quick lookups; longer (30–60s) for LLM-heavy
  prompts on slow nodes.
- Don't broadcast unless you have a real reason — peers other than the
  intended audience will see the message and might react.
- Trust matters: peers connect through TOFU (trust-on-first-use). New
  peers' first message is held in `pending-trust` until the human operator
  approves them. Don't assume an unknown peer is friendly.
