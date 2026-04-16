# IronMesh v0.8.1

**Release date: 2026-04-16**

Bug-fix release on top of v0.8.0. No wire-protocol changes — v0.8.0
peers interoperate with v0.8.1 peers and vice versa.

## The headline fix: 3-node mesh stability

Running three nodes together (a desktop, a Raspberry Pi, and a NAS —
or any triangle of agents that can all discover each other at once)
uncovered a race condition in the server-side handshake teardown:

1. Alice dials Bob. Bob also dials Alice. Two inbound connections
   land on each side at nearly the same time.
2. One handshake wins the atomic `self._peer_lock` check, registers
   its websocket in `ws_clients[peer_id]`, and transitions the peer
   to `ONLINE`.
3. The losing handshake's `finally` block **unconditionally** popped
   `ws_clients[peer_id]`, transitioned the peer back to `OFFLINE`,
   and cleared the session key — clobbering the winner.
4. The winning connection's message loop is now reading ciphertext
   with no session key → every message gets dropped with a
   `No session key for peer X — dropping message` warning. The
   dashboard shows one peer online at a time, flapping constantly.

### The fix

The `finally`-block teardown is now scoped to the *owning* websocket:

```python
async with self._peer_lock:
    if self.ws_clients.get(peer_id) is websocket:
        # We're the registered connection; clean up our state.
        ...
        owned_session = True
    else:
        # A duplicate handshake race — another connection owns
        # the peer entry. Leave it alone.
```

The mirror path in `_do_client_handshake` (which previously had **no
cleanup at all** — leaving stale `ONLINE` state that blocked the
reconnect loop from ever re-dialing) got the same treatment.

### Regression coverage

Two new tests in
`tests/test_hardening.py::TestDuplicateHandshakeTeardown`:

- `test_loser_must_not_teardown_winner` — verifies the losing
  handshake leaves `ws_clients`, `peer_state.is_online`, and
  `peer_state.session_key` intact.
- `test_winner_cleans_up_its_own_state` — verifies the winning
  handshake still cleans itself up normally on exit.

## Other reliability wins

### Windows proactor shutdown no longer trips an AssertionError

CPython's `asyncio.proactor_events` has a known race (issue #109538
family): when an `accept()` completes between `server.close()` and
the socket actually shutting down, the new transport tries to attach
to a server whose `_sockets` is already `None`, raising
`AssertionError`. Python 3.13 still has it.

v0.8.1 installs a scoped exception handler on the daemon's event
loop that matches **only** that specific pattern
(`_start_serving` / `proactor_events` in the context). Every other
exception still flows through the default handler and is surfaced
normally.

### `Agent.peer_by_name()` actually works now

The SDK's `peer_by_name()` and the `name` field returned by
`Agent.peers` looked up `peer_state.agent_name` — an attribute that
the handshake never populated. Every call silently returned `None`.
Now the HELLO-advertised `name` is stored on `PeerState` at the end
of handshake in both the server path (`_handle_connection`) and the
client path (`_do_client_handshake`). `ollama_swarm.py`'s
`--target <name>` now works as documented.

## Added

### `ironmesh demo` subcommand

```bash
ironmesh demo
# IronMesh demo -- two agents on 127.0.0.1:18765 and :18767
# (temporary keys in a temp dir; no state written to ~/.ironmesh)
# [ok]   handshake complete (encrypted session established).
# [ok]   bob received b'ping' in 11.6 ms.
```

Zero flags. Spawns two ephemeral agents on localhost, does the full
mutual-auth + ECDH handshake, measures round-trip latency on one
encrypted ping, and exits. Ports are spaced by 2 because each agent
also binds `port+1` for its metrics endpoint. Pass `--gui` to keep
both agents running with the dashboard enabled (handy for screenshots).

Use this as your 10-second smoke test after `pip install ironmesh`
to prove the install works before wiring up a real deployment.

### `docs/USE_CASES.md`

Five concrete deployment patterns, each with a runnable command or
code snippet: home AI mesh, offline LLM swarm, robotics
coordination, air-gapped lab, off-grid LoRa comms.

### `examples/ollama_swarm.py`

Two local-LLM agents talking over an encrypted IronMesh session.
One node runs Ollama and advertises `llm:<model>` as a capability;
the other discovers it by name and sends a prompt. Works on one
machine or across a LAN. The flagship "multiple AI agents on your
home network, no cloud" demo.

## Changed

### README + site now position IronMesh as a *layer*, not a competitor

Previously the README put IronMesh head-to-head with MCP, A2A, ACP,
and ANP. External audits (Grok, GPT) pointed out this undersells the
project — IronMesh isn't a 5th alternative; it's the transport/
routing/encryption layer that the others sit on top of.

The README (and ironmesh.org) now leads with a stack diagram
showing LangChain / CrewAI / AutoGen and MCP / A2A running *over*
IronMesh, plus a "Why not just use X?" table answering the common
objections (MCP, LangGraph, Tailscale, Reticulum). The feature
comparison table is kept but retitled to acknowledge it's one axis
(offline-first), not a universal ranking.

## What didn't change

- Wire-protocol version is still `ironmesh/0.6`. v0.7.x and v0.8.0
  peers interoperate with v0.8.1 peers.
- API surface unchanged. All v0.8.0 code continues to work.
- Default paths, file formats, key encryption unchanged.

## Verification

- 514 tests pass on Ubuntu + Windows across Python 3.10 – 3.13
  (+ 2 new regression tests)
- `ruff check .` clean
- `bandit -ll` clean (no HIGH findings)
- `pip-audit` clean
- Verified in production on a 3-node mesh (Windows desktop + Raspberry
  Pi + NAS): peers stay stably online across mutual-dial scenarios,
  no session-key-drop warnings in the log.

## Install

```bash
pip install --upgrade ironmesh
# or
docker pull wiztheagent/ironmesh:0.8.1
```
