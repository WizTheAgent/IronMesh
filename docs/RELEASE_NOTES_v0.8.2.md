# IronMesh v0.8.2

**Release date: 2026-04-16**

Feature release: structured multi-turn conversations, agent
personalities, budgets + smart termination, a dashboard UI for
AI-to-AI dialogue, and an optional tool-use registry. No
wire-protocol version bump — the new `CONV` frame is additive.

## Headline: AI agents can have bounded conversations with each other

Two LLM-bridge peers on the mesh can now exchange a structured
dialogue without either side looping indefinitely. Five stacked
protections make it safe:

1. **`MessageType.CONV` envelope** — every turn is a JSON object with
   `conv_id`, `turn`, `max_turns`, `kind`, `body`, optional
   `budget`, `from_role` / `to_role`. Parsed by
   `ironmesh.conversation.ConvEnvelope`. Documented in
   [`docs/PROTOCOL_SPEC.md §4.1`](PROTOCOL_SPEC.md#41-conv-envelope-v082).
2. **Turn cap** — a participant that receives `turn >= max_turns`
   sends an `end / turn-limit` frame and refrains from calling its
   model.
3. **Per-conversation byte + time budgets** — the bridge tracks
   cumulative response bytes and wall-clock time per `conv_id`;
   exceeding either cap emits `end / budget-exceeded`.
4. **Smart termination (`[DONE]`)** — the bridge appends a rider to
   every system prompt telling the model to start its reply with
   `[DONE] <reason>` when the goal is met. The bridge strips the
   marker and emits `end / goal-achieved`.
5. **Prefix / cooldown guards from v0.8.1** — retained: `[LLM]`
   prefix stops replies re-triggering generation, per-conversation
   cooldown drops duplicate re-plays.

## Added

### Structured CONV envelope

- New `MessageType.CONV` and `ironmesh.conversation` module with
  `ConvEnvelope`, `Budget`, `make_reply`, `is_terminal`.
- 22 tests in `tests/test_conversation.py` covering encode/decode,
  forward-compat extras, validation, reply helpers.
- Legacy `[CONV:id:turn/max]` text prefix still accepted by
  `examples/llm_bridge.py` for one release.

### Agent personalities

- `ironmesh.roles` module with 7 presets: `assistant`,
  `security-analyst`, `network-engineer`, `historian`, `coder`,
  `ops`, `devil`.
- `examples/llm_bridge.py` gains a `--role` flag that loads a
  preset system prompt and advertises `role:<name>` as a mesh
  capability, so orchestrators can
  `agent.discover("role:security-analyst")` to find specialists.

### Dashboard "Start A2A" panel

- New GUI WebSocket action `start_dialogue {peer_a, peer_b, seed,
  max_turns, budget_seconds?, budget_bytes?}` runs an in-process
  orchestrator that shuttles `CONV` frames between the two peers.
- Turn-by-turn transcript events (`{type:"dialogue_event",
  event:"turn"|"end"|...}`) stream back via the existing broadcast
  path.
- Dashboard HTML gains a purple **Start A2A** button with two peer
  dropdowns (auto-filtered to `llm:*` capable peers), a turn
  spinner, and a seed-prompt input.

### Tool-use registry

- `ironmesh.tools` module with three bundled tools: `echo`,
  `http-get`, `file-read` (the last gated by a strict operator
  allowlist). Per-call timeouts, per-response call-count cap, hard
  result-size cap.
- `examples/llm_bridge.py` gains `--tools echo,http-get,file-read`,
  `--file-read-allow /some/dir,/another`, `--tool-timeout 8`.
- LLM calls a tool by emitting `<tool name="X">args</tool>`; the
  bridge substitutes `<tool-out name="X">...</tool-out>` before the
  reply is sent. No recursive model call, so no runaway.
- 16 tests in `tests/test_tools.py` cover allowlist enforcement,
  path-traversal rejection, expansion, timeout, and cap behavior.

## Fixed

### GUI message_event blanked `peer_id` and `payload`

`MessageBus.publish` wraps dict payloads in `MappingProxyType` for
immutability. `bridge.py`'s GUI hook checked `isinstance(data, dict)`
to decide whether to iterate — but `MappingProxyType` is **not** a
`dict` subclass, so the check returned `False` and every
`message_event` pushed to WS clients had empty `peer_id` and empty
`payload`. That silently broke the standalone A2A orchestrator and
any dashboard UI wanting to route messages by sender.

Switched to `isinstance(data, collections.abc.Mapping)` so both
dicts and proxies are accepted. Also propagates `msg_id` through to
the event. Regression test in
`tests/test_hardening.py::TestGUIBroadcastMappingProxy`.

## Changed

- `examples/ai_to_ai_dialogue.py` now uses `MessageType.CONV`
  natively, accepts `--budget-seconds` and `--budget-bytes`, and
  bumps `--discovery-timeout` to 60 s with status prints every 5 s
  so the wait is observable.
- `examples/llm_bridge.py` refactored — shared `_dispatch_prompt`
  handles both legacy-prefix and CONV paths through one code route.

## Version ceremony

- Version bumped everywhere (`__init__`, `pyproject.toml`,
  `ironmesh_mcp/server.py`, Dockerfile, docker-compose.yml).
- `docs/PROTOCOL_SPEC.md` gains §4.1 documenting the CONV envelope.
- README "Recent changes" updated.

## Verification

- 559 tests pass on Ubuntu + Windows across Python 3.10 – 3.13
  (+45 new: 22 conversation, 16 tools, 6 roles, 1 GUI regression).
- `ruff check .` clean.
- Verified end-to-end on a real 3-node mesh (Windows desktop +
  Raspberry Pi + NAS): wiz → gatekeeper (hermes3:3b) round-trip
  in 1.9 s with `peer_id` and payload correctly populated on the
  GUI WS stream.

## Install

```bash
pip install --upgrade ironmesh
# or
docker pull wiztheagent/ironmesh:0.8.2
```
