# IronMesh Roadmap

Living document. What's actually committed is in
[CHANGELOG.md](../CHANGELOG.md); everything below is *intent*, not a
promise. Priorities get re-ordered whenever a user scenario shows up
that the current version doesn't handle well.

Ordering within each bucket is rough — "soon" means "weeks", "later"
means "quarters", "someday" means "we want to but haven't committed."

---

## Shipped

- **v0.8.2** (2026-04-16) — `MessageType.CONV` structured envelope for
  AI-to-AI dialogue, seven persona presets, byte + time budgets,
  `[DONE]` smart termination, Start A2A dashboard panel, tool-use
  registry (`echo` / `http-get` / `file-read`). Fixed GUI
  `message_event` blanking `peer_id` / `payload`. [Release notes](RELEASE_NOTES_v0.8.2.md).
- **v0.8.1** (2026-04-16) — duplicate-handshake race fix, Windows
  proactor shutdown silencer, `ironmesh demo` subcommand, SDK
  `peer_by_name()` bugfix. [Release notes](RELEASE_NOTES_v0.8.1.md).
- **v0.8.0** (2026-04-16) — Agent SDK, framework adapters
  (LangChain / CrewAI / AutoGen), federation gateway, Go reference
  client, PyPI + Docker Hub + website. [Release notes](RELEASE_NOTES_v0.8.0.md).
- **v0.7.2** — per-peer observability, backpressure + bandwidth
  throttle, peer-drop alerting, simultaneous-dial tie-breaker, MCP
  server, benchmark harness.
- **v0.7.1** — 53/62 security-audit items closed; Ed25519 mandatory
  signing; TOFU key pinning hardened.
- **v0.4 – v0.7.0** — multi-hop mesh routing, NaCl SealedBox E2E
  across hops, capability discovery, LoRa/Reticulum transport,
  audit log rotation.

## Next up (soon)

*The current focus — lock in what's shipped before building new
surfaces.*

- **Full E2E debugging audit.** Long-running soak test on a real
  3-node mesh, CONV envelope fuzzing with Hypothesis, memory-leak
  sweep, crash matrix across handshake / rekey / shutdown, concurrency
  fuzzing (~500 parallel MSGs). All findings logged with
  resolutions. Goal: prove v0.8.x is release-grade for strangers, not
  just its author.
- **Real integration tests against LangChain / CrewAI / AutoGen.**
  Today the adapters are unit-tested with `MagicMock(spec=[])`. Time
  to wire them against the real libraries + a deterministic fake
  Ollama so CI proves the toolkit, tool-invocation shape, and mesh
  communication stay green when upstream bumps.
- **macOS in the CI matrix.** Ubuntu + Windows today; Mac shakes out
  BSD-socket + `asyncio` edges that Linux and Windows hide in
  different places.
- **Performance baselines in the README.** Ship the bench harness
  output as part of every release so regressions are visible. Current
  number: 100% delivery, p50 ≈ 12 ms at 1 KB LAN payloads. We should
  have the same figures for LoRa and for 3-hop relay.
- **Dashboard polish.** Real-time transcript scroll, dark-mode toggle,
  copy-button for the GUI token, a "what's this peer?" tooltip
  showing advertised capabilities.

## Later (months out)

*Real feature work, already designed or close to it.*

- **NAT traversal (WAN support).** [Design doc already written](NAT_TRAVERSAL_DESIGN.md).
  Hybrid STUN hole-punching + relay fallback, protocol version
  `ironmesh/0.7`. Currently deferred in favor of polish work above.
  When we resume: implement relay path first, then layer STUN hole-
  punching. Single biggest feature gap in the current product.
- **Tamper-evident logging v2.** Audit log is HMAC-chained today;
  add Merkle-tree anchors so external verification doesn't need the
  full log.
- **Plugin sandbox.** Third-party handlers currently run in-process.
  Sandbox them with `resource.setrlimit` + a subprocess model so a
  bad plugin can't take down the daemon.
- **File sync example.** Extend `examples/file_transfer.py` into a
  real `ironmesh-sync` that watches a directory and replicates.
- **Binary protocol v5.** Today we carry JSON inside the outer binary
  frame. Move to CBOR or a hand-rolled binary layout to shave ~30% off
  wire size — matters for LoRa.
- **Conversation history store.** Persistent per-`conv_id` history
  for the CONV pattern so orchestrators can resume a dialogue after a
  restart.

## Someday (hopes)

*We want these but they're real engineering projects.*

- **NAT traversal hole-punching path.** After the relay path above is
  stable, ship the STUN-based direct-connection optimization.
- **Android native app.** LXMF gateway already works with Sideband;
  a first-party app would be nicer. Big scope, not near-term.
- **Rust port of the wire protocol.** Go client already proves the
  protocol is language-portable. Rust would get us `no_std`-ish
  embedded reach.
- **WebRTC data channel transport.** Optional transport for browser-
  based agents. Complements the WebSocket path.
- **Hosted relay infrastructure at `relay.ironmesh.org`.** Depends on
  NAT traversal shipping first.
- **External protocol audit.** Post the wire spec + threat model to
  r/crypto and the NaCl/libsodium list. Gets independent eyes on the
  handshake before we claim "production-ready."

## Won't do (explicit non-goals)

- **Cloud-hosted multi-tenant service.** IronMesh is local-first; if
  you want a SaaS, run it yourself.
- **DIDs or blockchain identity.** TOFU + manual revocation is the
  right trust model for this scale.
- **Built-in LLM inference.** Bring your own model (Ollama, llama.cpp,
  vLLM, OpenAI-compatible). We're the transport, not the brain.
- **UDP transport.** WebSocket on TCP is fine for agent messaging.
  Reticulum handles the LoRa case. No need for a third transport
  layer.

---

## How to propose a change

- File a GitHub issue with `roadmap-proposal` label.
- Or discuss in GitHub Discussions if it's more exploratory.
- PRs editing this file are welcome; keep the structure
  (Shipped / Next up / Later / Someday / Won't do) intact.
