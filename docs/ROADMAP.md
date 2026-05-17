# IronMesh Roadmap

Living document. What's actually committed is in
[CHANGELOG.md](../CHANGELOG.md); everything below is *intent*, not a
promise. Priorities get re-ordered whenever a user scenario shows up
that the current version doesn't handle well.

Ordering within each bucket is rough — "soon" means "weeks", "later"
means "quarters", "someday" means "we want to but haven't committed."

---

## Strategic question — who are the next 100 users?

Several roadmap priorities below depend on which audience IronMesh
serves first. The product is good for all of these, but we can't
ship the docs, install path, and example library for all of them
simultaneously. Items tagged **BLOCKED ON: next-100 decision** below
are waiting on this answer.

The four candidate audiences:

- **Developers / security researchers.** Optimize for CLI quality,
  signed releases, reproducible builds, community infrastructure.
- **Journalists / activists in hostile environments.** Optimize for
  bulletproof installation, simple GUI, threat-model-appropriate
  docs, no-ambiguity status output.
- **Preppers / sovereign-infrastructure operators.** Optimize for
  Pi images, fully offline operation, mesh resilience demos, LoRa
  integration stories.
- **Defense-adjacent / institutional users.** Optimize for audit
  reports, reproducible builds, formal crypto verification,
  compliance documentation.

The roadmap doesn't try to answer this question — it lives here as
a marker so prioritization arguments cite it explicitly rather than
re-deriving it.

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
- **CLI ergonomics (v0.9.4).** Bundled set of bounded operator-UX
  improvements. Each item below is independently shippable; together
  they reshape the day-to-day operator experience without touching
  protocol or transport.
    - **Concurrent peer operations.** `status`, `ping`, `broadcast`,
      and `health` today fan out to peers serially, which means an
      unreachable node stalls the whole command for its full timeout.
      Move these to a `ThreadPoolExecutor` (or `asyncio.gather` on the
      async path) so a 10-peer mesh status finishes in roughly the
      slowest single peer's RTT, not the sum.
    - **Short command structure.** First-class verbs: `ironmesh
      status`, `ironmesh ping`, `ironmesh peers`, `ironmesh health`.
      Today these live under longer subcommand prefixes; the short
      form matches what operators actually type. Existing forms stay
      as aliases.
    - **Structured CLI output.** Color-coded (green/yellow/red),
      icon-prefixed (✓ / ⚠ / ✗), section-broken output for the four
      verbs above. Auto-disables on non-TTY output (pipes, CI logs)
      so machine-parsing stays clean.
    - **Summary-first display with `--verbose` for details.** Default
      output is a single-screen overview; `--verbose` (or `-v`)
      reveals per-peer breakdowns, raw timings, and full envelope
      metadata. Aligns with the principle that the common case
      should fit in a glance.
- **Pre-built single-file binaries (target v1.0).** macOS, Linux,
  Windows, and Raspberry Pi binaries with no Python dependency.
  This is the largest installation barrier for non-developer
  audiences — fixing it is the single biggest accessibility win
  available. **BLOCKED ON: next-100 decision** (binary tier
  matters most for journalists/preppers; least for developers
  comfortable with `pip install`).
- **`ironmesh init` interactive setup wizard (target v0.9.x).**
  Detects the local environment, asks 3-4 essential questions,
  generates keys, writes config. Gets a new user from zero to a
  working node without manual config editing. Currently the
  config-file-and-systemd path is the documented happy-path; that
  filters out everyone who isn't already comfortable editing
  YAML.
- **`ironmesh doctor` diagnostic (target v0.9.x).** Single command
  that runs sanity checks (keys exist, ports listening, peers
  reachable, NAT detected, firewall rules, time sync) and reports
  pass/fail with suggested fixes. Probably the single most useful
  debugging tool available to add — every "it doesn't work" issue
  starts with the same five questions, and `doctor` answers them.
- **mDNS / zero-config local discovery (target v0.9.x).** Out of
  the box, two laptops on the same LAN should see each other
  without manual peer config. Currently we require explicit peer
  addresses. The "I just want my two laptops to talk" use case is
  on-ramp #1 and we're failing it.
- **Background daemon + thin CLI client (target v1.0).** Persistent
  peer connections held by a daemon process; CLI commands become
  fast (no reconnect-per-command overhead). Standard pattern in
  serious networking tools (`tailscaled`, `wg`, etc). Significant
  refactor; bundle with v1.0 GA.
- **Signed releases (target v1.0 GA).** GPG signatures on every
  artifact (PyPI wheel, sdist, Docker image, single-file binaries).
  Enables operators to verify provenance before installing. Not
  optional for institutional adoption.
- **Reproducible builds verification (target v1.0 GA).** Document
  the build process so a third party can rebuild from source and
  byte-compare to our published artifacts. Core trust signal for
  defense-adjacent / journalist audiences. **BLOCKED ON:
  next-100 decision** (priority shifts +1 if either of those
  audiences leads).
- **Public security audit report linked from homepage (target v1.0
  GA).** After the audit completes, link the report from the front
  page. Audit funded; engagement scoping in flight separately.
- **`SECURITY.md` vulnerability disclosure policy (target v1.0
  GA).** Standard receive-and-handle process for reports. Zero
  ambiguity for security researchers about how to disclose.

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
- **Tab completion for bash, zsh, fish (target v1.0).** Discoverability
  for daily users plus typing speed. Auto-generated from the
  argparse spec; not a maintenance burden.
- **Profile system for multiple meshes (target v1.x).** `ironmesh
  --profile work` vs `ironmesh --profile personal`. Most operational
  users eventually participate in more than one mesh; today the
  config-file-per-mesh juggling is friction.
- **JSON output mode for scripting (target v1.x).** `ironmesh status
  --json` for piping into `jq`, monitoring tools, CI/CD. Required
  for serious deployments. Mutually exclusive with the human-
  readable color/icon output (which is the default).
- **"Getting started in 5 minutes" guide (target v1.0).** Real test:
  a non-developer follows it and has a working 2-node mesh in 5
  minutes. Today the docs are accurate but assume operator-grade
  comfort. **BLOCKED ON: next-100 decision** (target audience
  determines what "non-developer" means).
- **Use case guides — one per audience (target v1.x).** End-to-end
  walkthroughs: emergency comms for a journalist, a small business,
  a homelab, a community of activists, disaster preparedness. Each
  is structured around an actual scenario with realistic
  constraints. **BLOCKED ON: next-100 decision** (which audience's
  guide ships first).
- **Homebrew formula for macOS (target v1.x).** Aligns with
  `tailscale` / `mosh` install conventions. Low maintenance once
  established.
- **APT / RPM packages for Debian/Ubuntu/Fedora (target v1.x).**
  `apt install ironmesh` / `dnf install ironmesh` for the
  Linux audience that prefers system packages over `pip`. Includes
  systemd unit, default config, log rotation.
- **Docker image with sane defaults (target v1.x).** Already
  publishing to Docker Hub; this item is about defaults and
  documentation polish — `docker run` should produce a useful
  daemon without 12 environment variables.
- **Official Raspberry Pi image (target v1.x).** Flash → boot → Pi
  is an IronMesh node. Targets the prepper / sovereign-
  infrastructure audience specifically. **BLOCKED ON: next-100
  decision** (high priority if this audience leads; lower
  otherwise).

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
- **Local-only web GUI.** Significant scope: HTML/CSS/JS bundle
  served by IronMesh on `127.0.0.1`, no cloud dependency. Filed as
  design exploration, not a commitment — would need a hard look at
  whether the dashboard package already in the repo can be upgraded
  in place vs. a clean new surface.
- **TUI dashboard mode.** `ironmesh dashboard` opens a `htop`-style
  full-screen interface with live peer status, message rate, audit
  events. Polish item; ranks behind binary distribution and
  zero-config discovery.
- **Connection trace debug mode.** `ironmesh trace <peer>` shows the
  full handshake + first message round trip with timing breakdown.
  Useful for advanced troubleshooting and protocol-level debugging
  by integrators. Low priority until enough operators ask for it.
- **Migration guides from adjacent tools.** "Coming from Tailscale /
  Wireguard / Reticulum / Yggdrasil — here's how IronMesh maps to
  what you already know." Helps land users who are choosing between
  options.
- **Video walkthroughs.** YouTube / asciinema captures of common
  setup flows for visual learners. Useful but the text docs need
  to be solid first.
- **Man pages for every command.** `man ironmesh-status`,
  `man ironmesh-ping`, etc. Auto-generatable from argparse;
  matters most for operators who instinctively reach for `man`
  before web docs.

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
- **Personality / flavor text modes** (naval, cyberpunk, pirate,
  etc.). Inconsistent with IronMesh's positioning as serious
  sovereign infrastructure. The audiences that lead this product
  — security researchers, journalists in hostile environments,
  defense-adjacent operators — value predictable professional
  tooling. Fun-mode UX undermines credibility. This is a
  philosophical reject, not a "maybe later."
- **Randomized fun responses on non-critical operations.** Anti-debug.
  Greppable, deterministic output is essential for log analysis
  and CI/CD integration; random responses break automated
  workflows. Same philosophical reject as above.
- **Emotional health signaling** ("the fleet is whole" / "wounded" /
  metaphorical status text). Ambiguous compared to literal status.
  High-stakes deployments need exact information ("8/8 peers
  online, 0 unreachable"), not metaphorical signals that can be
  misinterpreted under stress. Documenting this rejection
  prevents future relitigation.

---

## How to propose a change

- File a GitHub issue with `roadmap-proposal` label.
- Or discuss in GitHub Discussions if it's more exploratory.
- PRs editing this file are welcome; keep the structure
  (Shipped / Next up / Later / Someday / Won't do) intact.
