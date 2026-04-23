# IronMesh v0.9.0 — OpenClaw, ACP, and A2A interop

**Released:** 2026-04-23
**Type:** minor (no IronMesh wire-protocol or schema changes; new
optional integration surfaces)
**Compatibility:** every v0.8.x peer stays interoperable on the mesh

The v0.9.0 line opens up three new agent-interoperability surfaces:

1. **OpenClaw channel plugin** (`@wiztheagent/openclaw-ironmesh`) —
   register IronMesh as a chat channel inside an OpenClaw gateway so
   peers appear as contacts and exchange end-to-end encrypted messages.
2. **Agent Client Protocol (ACP) stdio adapter** (`ironmesh-acp`) —
   speak the JSON-RPC ACP protocol with any compatible client (acpx,
   codex, claude, droid, …) and have it prompt remote mesh peers as
   if they were local agents.
3. **Agent-to-Agent (A2A) HTTP gateway** (`ironmesh-a2a`) — expose
   each mesh node as an A2A peer with an `agent-card.json` and a
   JSON-RPC inbox, so external A2A-aware services can address the
   mesh natively.

Plus the operator-tooling and capability-persistence fixes that
surfaced during end-to-end testing of the OpenClaw integration.

## Highlights

- **Capability registry now persists learned remote capabilities.**
  Until v0.8.5.8, `~/.ironmesh/capabilities.json` only captured
  *local* capabilities at startup; remote capabilities advertised by
  peers via gossip lived in memory only and were lost on restart. The
  capability gossip loop and the `CAPABILITY_ANNOUNCE` inbound handler
  now both call `CapabilityRegistry.save()` after updating remote
  state.
- **`ironmesh-mcp --peer host:port`** for non-mDNS bootstrap. The
  embedded MCP daemon previously could only discover peers via mDNS;
  in restrictive networks (containers, VLANs, name conflicts) it
  would silently fail to join the mesh. Operators can now pass
  explicit peer hints. Repeatable; or comma-separate inside one flag.
- **`ironmesh audit verify --rotate-corrupt`** for tamper recovery.
  When a verify reports tamper, this flag archives the corrupted log
  to `<path>.corrupted-<ISO timestamp>` and lets the daemon start a
  fresh chain on the next write. Recovery for the operator-runbook
  case where two daemons collided on the same audit path before the
  v0.8.5.6 atomic-write fix.
- **TypeScript client (`@wiztheagent/ironmesh-client@0.2.0`)
  honours `opts.toNodeId` per message.** Previously the encrypted
  envelope's `destination` field was hardcoded to the handshake peer,
  so `sendMessage(payload, { toNodeId: <other-peer> })` silently
  delivered to the wrong recipient. Now the daemon's existing routing
  table relays correctly.
- **OpenClaw channel plugin
  (`@wiztheagent/openclaw-ironmesh@0.2.0`)** restructured to load
  cleanly into OpenClaw 2026.3.x:
  - Default-exported plugin definition with the
    `register(api: OpenClawPluginApi)` shape OpenClaw 2026.3.x expects
    (matches the bundled telegram channel reference). Forward-compatible
    with the newer 2026.4+ SDK.
  - Bundles its IronMesh WebSocket client into `vendor/`; no
    sibling-package install needed when the plugin tarball is dropped
    onto a target host.
  - Adds the required `package.json:openclaw.{extensions,compat,build,
    channel}` block + sibling `openclaw.plugin.json` manifest.
  - `configSchema.required` no longer blocks
    `openclaw plugins install`; validation runs at channel activation.
  - Implements the `messaging` adapter so OpenClaw's target validator
    accepts `<32-hex node id>`, `mesh:<node-id>`, or a loose
    agent-name string.
  - Renamed from `@wiztheagent/openclaw-ironmesh-channel` to match
    the manifest channel id.

## Live-mesh validation

End-to-end on a three-node mesh:

```
OpenClaw 2026.3.8 agent
  → openclaw-ironmesh channel
  → vendored ironmesh-client
  → IronMesh daemon ws://127.0.0.1:8765 (TOFU pin + ECDH)
  → mesh router (destination = remote peer)
  → remote peer's daemon
  → remote peer's llm_bridge
  → Ollama
  → reply MSG back to the originator
```

Daemon-side telemetry:
- `ironmesh_messages_relayed_total` increments correctly when
  destination is set on the envelope.
- `~/.ironmesh/capabilities.json` body shows all known remote nodes'
  capability sets within one gossip cycle (60 s default).
- Audit-tamper recovery cleanly archives the bad log and the next
  write opens a new chain anchored at GENESIS.

## Test status

- **759 Python tests collected, 757 passing + 2 skipped + 1 xpassed.**
- 61 TypeScript client tests + 29 channel-plugin tests passing.
- Live-mesh validation pass on a real ≥3-node mesh with Ollama.
- `release-smoke.sh` clean (wheel packaging gate).
- `leak-scan.sh --all` clean.

## Upgrade

PyPI:

```bash
pip install -U ironmesh==0.9.0
# or, for the LoRa transport extra:
pip install -U 'ironmesh[rns]==0.9.0'
```

Docker Hub:

```bash
docker pull wiztheagent/ironmesh:0.9.0
```

OpenClaw channel plugin (npm):

```bash
# from the release artifact
openclaw plugins install ./wiztheagent-openclaw-ironmesh-0.2.0.tgz
```

See [`OPENCLAW_CHANNEL_SETUP.md`](OPENCLAW_CHANNEL_SETUP.md) for the
full operator setup guide.

## Migration notes

- **Channel plugin renamed.** The npm package
  `@wiztheagent/openclaw-ironmesh-channel` is superseded by
  `@wiztheagent/openclaw-ironmesh`. The old package was never
  published; if you were building from source, uninstall the old
  extension dir and reinstall the new tarball.
- **Channel plugin entry shape changed.** If you were embedding the
  plugin programmatically via `defineBundledChannelEntry` (newer SDK
  shape that does not exist in OpenClaw 2026.3.x), switch to the
  default-exported `register(api)` form documented in the channel
  setup guide. The plugin's `dist/entry.js` is now suitable to drop
  into `package.json:openclaw.extensions` directly.
- **TypeScript client `opts.toNodeId`.** Existing callers that did
  not pass `toNodeId` see no behavioural change (still routes to the
  handshake peer). Callers that previously *expected* messages to
  land at the handshake peer regardless of any other option were
  relying on a bug; pass `toNodeId` explicitly when you need a
  different destination.

## Known limitations (deferred to v0.8.5.10)

- The OpenClaw channel plugin's connection is per-account (single
  daemon URL). Multi-account configurations are supported via the
  config tree but not yet through the `openclaw config set`
  shortcuts.
- The plugin id mismatch warning ("manifest uses 'ironmesh', entry
  hints 'openclaw-ironmesh'") is cosmetic — the channel still loads
  and operates correctly. A package rename to
  `@wiztheagent/ironmesh` would unify the strings, deferred so the
  v0.2.0 tarball name is stable.
- The MCP server's `peer_cap_baseline_total` Prometheus counter
  reads zero on a freshly-restarted daemon even when peers are
  observed; the underlying baseline event is firing — this is a
  counter-wiring follow-up for the next patch.

## Reference

- [`CHANGELOG.md`](../CHANGELOG.md) — full change list.
- [`docs/OPENCLAW_CHANNEL_SETUP.md`](OPENCLAW_CHANNEL_SETUP.md) — channel plugin setup.
- [`docs/OPENCLAW_MCP_SETUP.md`](OPENCLAW_MCP_SETUP.md) — MCP bridge setup.
- [`docs/OPERATOR_TRUST_RUNBOOK.md`](OPERATOR_TRUST_RUNBOOK.md) — pending-trust gate operations.
- [`docs/PROTOCOL.md`](PROTOCOL.md) — wire-protocol reference.

## Acknowledgements

This release is the product of a methodical end-to-end live-mesh
debug session: install on a real OpenClaw gateway, surface every
error, root-cause each one, fix in code, re-verify on the live mesh.
Eleven distinct issues were identified and triaged; this release
ships the seven that affect correctness or operability of the
OpenClaw integration path. The remainder are tracked publicly in the
"Known limitations" section above.
