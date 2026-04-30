# IronMesh v0.8.3

**Release date: 2026-04-16**

Polish release. Dashboard rebuilt to match the ironmesh.org visual
identity, two latent serialization bugs fixed that kept capabilities
and peer names invisible, full end-to-end audit with Hypothesis
fuzzing and a concurrency test suite. **No wire-protocol changes.**
v0.8.2 peers stay on the mesh.

## Headline: the dashboard looks and feels like the site now

The operator-facing dashboard embedded in `bridge.py` used to look
like a generic SaaS panel — a bureaucratic-green "connected" pill, a
sans-serif body, full node fingerprints leaking into the header. It
reads like a different project from ironmesh.org.

v0.8.3 rebuilds the dashboard end-to-end in the site's voice:

- **IRONMESH wordmark** in JetBrains-Mono-style monospace with the
  site's signal-green glow.
- **`v0.8.3 · PRE-1.0` pill** surfaces the release tag as a trust
  signal, matching the site header.
- **Truncated node fingerprint** (`fd08…ce438`) in monospace,
  click-to-copy the full hash.
- **Mesh state pill** — `OPERATIONAL` / `DEGRADED` / `ISOLATED` —
  derived from peer online + verified counts, not the old
  "connecting → connected" SaaS toast.
- **`OFFLINE-FIRST` badge** — pairs with a `<meta http-equiv="Content-
  Security-Policy" content="default-src 'self'; …; frame-ancestors
  'none'">` that locks the rendered page to same-origin at the
  browser layer. Pull the plug on your router — the dashboard keeps
  rendering, because it has to.
- **Bearer token masked-reveal** — the per-session GUI token is
  surfaced in the header as a password field with eye-toggle / copy-
  URL / rotate-request icons. README called this out; the operator
  can now copy the session URL without recovering it from startup
  logs.
- **Six stat cards** — Active Peers, Messages · 15m, Handshakes, Queue
  Depth, Bytes Encrypted, Auth-Fail Blocks — each with a **48-sample
  inline SVG sparkline** rendered client-side from a rolling buffer.
  No charting libraries. No CDN calls.
- **Peer table** — Name, Fingerprint, Transport (`WS` / `RNS` /
  `WS+RNS`), Latency, Trust (`✓ TOFU-PINNED` / `… HANDSHAKING` / `✗
  MISMATCH`), Last-contact (relative + absolute on hover),
  Capabilities pills. TOFU mismatch rows are rendered as an **alarm
  state** (red row background, bold label, kill the connection, don't
  just warn).
- **Handshake state panel** — the site's canonical 3-stage ASCII
  handshake diagram (PASSPHRASE → signed HELLO with channel binding
  + TOFU → ECDH → encrypted+signed messages) baked into the UI
  verbatim. Click any peer row; the stages light green / amber / red
  for that peer's current handshake phase. A deliberate identity
  marker — same diagram, same prose, same monospace, in both the
  marketing site and the operator console.
- **Transport panel** — side-by-side WebSocket LAN and
  Reticulum/LoRa strips. Live peer count + throughput + p50 latency
  on WS; RNS strip disabled with `"install ironmesh[rns] to enable"`
  when Reticulum isn't loaded, matching the site's matter-of-fact
  voice.
- **Hardened terminal feed** — per-line severity gutter (info / ok
  / warn / alarm), pause-tail with play/pause toggle, CSV export,
  regex-or-substring search (`/^foo/i` regex or plain substring),
  `chatter` toggle to opt into PING/PONG visibility. **Auto-scroll
  no longer hijacks** operator scrollback — if you're scrolled up
  inspecting history, new rows append but don't yank you back down.
- **Footer ops row** — Audit Log, Rotate Keys, Session Rekey, **Panic
  Wipe** (red, 2-step confirm). These are the first-class CLI
  actions (`ironmesh keys rotate`, `ironmesh audit`) now exposed in
  the GUI. Panic-wipe dispatches `action: panic_wipe` over the WS
  control channel.
- **Zero outbound network calls.** Every icon is an inline SVG
  `<symbol>`. Fonts are `ui-sans-serif` + `ui-monospace` — the OS
  ships them. No Google Fonts, no Lucide CDN, no gravatar, no
  analytics. Enforced by the CSP meta.

## Headline: two backend bugs that made the dashboard lie

Two independent serialization bugs in `/api/state` were making the
dashboard show less than what the mesh actually knew.

**`PeerState.to_dict()` never emitted `agent_name`.** v0.8.1 fixed
the population of `peer_state.agent_name` from the HELLO handshake
(so `Agent.peer_by_name()` could stop returning `None`), but the
GUI serializer in `protocol.py` was never updated to include it in
the per-peer dict. Every peer in `/api/state` had `name: null`. The
dashboard fell back to short fingerprints everywhere a human name
belonged. A one-line fix in `PeerState.to_dict`: `"name": getattr(
self, "agent_name", None)`.

**`_build_full_state()` never serialized the capability registry at
all.** The dashboard's A2A dropdowns filter peers by `state.capabilities[
'llm:*']`, and the per-peer capability pills read the same structure.
Backend never set the key, so the filter silently matched zero peers
and pills were permanently empty. On a live 3-node mesh where kingpi
and gatekeeper were both announcing `llm:<model>`, the dashboard
would not let you pick either for an A2A dialogue. Fixed by emitting
an inverted dict `{capability -> [node_ids]}` — the shape every
consumer wants — from `bridge.py:_build_full_state`.

Neither bug changes the wire protocol. They were purely GUI-
serialization drift.

## Added

### v0.8.3 E2E debugging audit

Documented internally. Covers:

- **Hypothesis fuzzing on `ConvEnvelope`** — 9 properties × 400
  inputs. Round-trip, validation, reply helpers, terminal detection,
  byte-budget edge cases. Caught a dormant normalization bug in
  `make_reply` when `from_role == to_role` with empty `body`.
- **Concurrency test suite** (`tests/test_concurrency.py`) — 6 new
  tests exercising `ReplayGuard`, `TokenBucket`, `DedupCache` under
  simulated race conditions. Found + fixed a **TOCTOU race in
  `DedupCache`**: `is_duplicate()` and `add()` were separate lock
  acquisitions, leaving a window where two concurrent handlers could
  both decide a message was novel. Replaced with atomic
  `check_and_add()`.
- **Crash matrix** — four scenarios verified: SIGKILL mid-handshake,
  corrupt trust-store HMAC, corrupt `routes.json` HMAC, disk-full on
  `audit.log` append. All produce graceful degraded-mode recovery on
  next startup, not cascades.
- **Dashboard payload fuzz** — seven pathological payloads fired
  through the WS GUI control plane (oversized JSON, deeply nested,
  invalid UTF-8, null bytes, conflicting schema fields). None caused
  a server-side exception to propagate.
- **Clean scans** — `pip-audit` and `bandit` both clean. Threat
  model in `docs/THREAT_MODEL.md` re-walked against the new CONV
  envelope surface.

### Real-adapter integration tests

`tests/integration/` exercises the bundled framework adapters
(`adapters/langchain_adapter.py`, `crewai_adapter.py`,
`autogen_adapter.py`) against a `fake_ollama` stub, so the adapters
can't silently drift with upstream API changes. Run separately:
`pytest tests/integration`.

### CI expanded to macOS

The CI matrix now runs on Ubuntu + Windows + **macOS** across Python
3.10 / 3.11 / 3.12 / 3.13 — 12 jobs total, up from 8. macOS catches
the `launchd`-scheduled asyncio quirks that don't reproduce on Linux
or Windows.

### Roadmap and NAT traversal design

- [`docs/ROADMAP.md`](ROADMAP.md) — scoped to v0.9+ items we've
  talked about but haven't committed: NAT traversal, Android native
  app, Rust reference client, plugin sandbox.
- [`docs/NAT_TRAVERSAL_DESIGN.md`](NAT_TRAVERSAL_DESIGN.md) —
  accepted design, implementation deferred to v0.9. STUN-free,
  relies on Reticulum for off-grid NAT and a STUN-lite beacon
  service for conventional NAT, so the "no cloud" stance holds.

### Three new dashboard assertion tests

`tests/test_gui.py::TestGUIHTML` gains
`test_html_has_handshake_diagram`, `test_html_has_csp`, and
`test_html_has_trust_tri_state` so the identity markers (canonical
handshake diagram, offline-first CSP, TOFU tri-state) can't regress
silently on future dashboard edits.

### Dashboard hero screenshot in README

`docs/assets/dashboard.png` — live 3-node mesh (wiz · kingpi ·
gatekeeper) mid-A2A dialogue between kingpi and gatekeeper, showing
the full handshake panel, TOFU-pinned trust states, and
`[response turn N/M]` CONV frames in the feed. Replaces the
commented-out `<img>` placeholder that had been live in README with
a broken path since v0.8.0.

### `NOTICE` file

Third-party attribution (NaCl / libsodium, websockets, aiosqlite,
zeroconf, argon2-cffi, Reticulum). MIT license unchanged; `NOTICE`
is the conventional home for upstream acknowledgement.

## Fixed

Beyond the two headline serialization bugs, this release lands a
string of blind-spot fixes that came out of the audit and a pre-
launch sweep:

- **Broken README `<img>` tag** pointing at a path that didn't
  exist — fixed by both committing the screenshot and uncommenting
  the tag. GitHub no longer shows a broken-image icon above the
  intro paragraph.
- **Docker image was missing `adapters/`, `ironmesh_mcp/`,
  `examples/`** — `pyproject.toml`'s `[tool.setuptools]
  package-dir` and `packages` re-declared to include every
  subpackage. `import ironmesh.adapters.langchain_adapter` now
  works inside the container.
- **`User-Agent: Python-urllib/3.x` leak** in
  `reticulum_transport.py`'s HTTP probes — passive observers could
  fingerprint the host Python version. Replaced with `User-Agent:
  ironmesh/<version>`.
- **Stale `LICENSE`** — year + copyright holder updated; MIT
  unchanged.
- **Dashboard UX drift** carried forward into this release (from
  the unreleased v0.8.2.1 branch): CONV envelopes in the feed now
  render as `[response turn N/M] <body>` instead of raw JSON;
  peer names resolve from `state.peers` rather than node-ID hashes;
  PING/PONG/ROUTE_ANNOUNCE/CAPABILITY_ANNOUNCE filtered from the
  operator view by default with a `chatter` toggle to opt in.
- **Enter-to-send restored** on the send-message textarea. The
  redesign initially used Ctrl/Cmd+Enter (because textareas are
  multi-line), but operators immediately hit the regression when
  they cleared the feed, typed, pressed Enter, and nothing
  happened. Now Enter sends, Shift+Enter adds a newline — chat-
  input convention.
- **`ws.send` failures now surface.** The send path was wrapped in
  try/catch; a closed control channel during a click now produces a
  red `ERROR` row in the feed and an alarm statusline, not silence.
- **Empty-feed copy disambiguates** "cleared · waiting for traffic"
  (buffer empty, no filter) from "no matching events · adjust
  filter" (filter active, buffer non-empty).
- **A2A peer dropdown falls back to every peer** when no peer has
  advertised `llm:*` yet (capability announces are periodic; on
  first snapshot the set is often empty). The placeholder becomes
  `— AI peer A · no llm:* advertised —` so the operator knows the
  filter is inactive. Preserves filter semantics when capabilities
  do arrive.

## Upgrade path

`pip install -U ironmesh` — nothing else required.

No wire-protocol version bump. A v0.8.3 node will TOFU-match a
v0.8.2 known_peer without re-pinning. A v0.8.2 node will consume a
v0.8.3 `CONV` frame identically — the envelope didn't change.

If you run `examples/llm_bridge.py` on remote nodes, the new dashboard
only *shows* CONV traffic correctly when the bridge also speaks CONV
(v0.8.2+). If you deploy a dashboard screenshot-worthy setup like
ours, upgrade the remote bridges too: `pipx upgrade ironmesh`
followed by dropping the repo's current `examples/llm_bridge.py` into
place and restarting the bridge process.

## Verification

- **Tests:** 577 → 582 pass. 3 new GUI assertion tests, 9 Hypothesis
  properties, 6 concurrency tests. ruff clean, mypy clean, bandit
  clean, pip-audit clean.
- **CI matrix:** Ubuntu / Windows / **macOS** × Python 3.10 / 3.11 /
  3.12 / 3.13 = 12 jobs, all green.
- **Live 3-node mesh:** wiz (Windows) ↔ kingpi (Pi 5, Ollama
  `kingpi:latest`) ↔ gatekeeper (UGREEN NAS, Ollama `hermes3:3b`).
  End-to-end A2A dialogue verified via the dashboard's A2A panel,
  `[response turn N/M]` frames rendering in the feed, ending on
  `[END] goal-achieved` from the `[DONE]` rider.

## What's next

- **v0.8.4** — surface missing capability flags (`--mesh-routing`,
  `--rns-configdir`, custom `--capability`) on `examples/llm_bridge.py`
  so it can be a drop-in replacement for `ironmesh run` in production
  deployments. Add an `ironmesh-llm` console-script entry point.
- **v0.9** — NAT traversal (see design doc), plugin sandbox, Android
  native agent.

See [`docs/ROADMAP.md`](ROADMAP.md) for the full forward plan.
