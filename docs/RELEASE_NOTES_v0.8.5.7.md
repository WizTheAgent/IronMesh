# IronMesh v0.8.5.7 — Release Notes

## Headline

Patch release on top of v0.8.5.6. Polishes the capability-set binding
feature end-to-end: dashboard panel, Prometheus counters, OpenTelemetry
spans, operator CLI surface, and MCP tool parity. No protocol or schema
changes. Every v0.8.x peer stays interoperable with every other v0.8.x
peer.

Where v0.8.5.6 made the feature work, v0.8.5.7 makes it pleasant to
operate.

## Highlights

### Dashboard: PENDING CAP CHANGE panel

The operator console now includes a panel parallel to the existing
PENDING TRUST panel, showing one row per peer whose currently-advertised
capability set differs from its pinned baseline. Each row includes the
added / removed tokens and an ACCEPT button. A new
`cap_change_detected` WebSocket push from the daemon keeps the panel
current without manual refresh.

Operators no longer need to drop to the CLI to use cap-binding.

### Observability: nine new Prometheus counters

One counter per cap-binding / cross-transport / trust-state audit
event type. Every event the daemon emits — and every event the CLI or
MCP emits in a separate process — bumps the matching counter. Grafana
alerts can fire on the underlying conditions without scraping the audit
log.

| Counter | Fires on |
|---|---|
| `ironmesh_peer_cap_set_changed_total` | Peer demoted to `pending-cap-change` because advertised caps differ from baseline |
| `ironmesh_peer_cap_baseline_total` | First-time cap observation recorded as baseline (TOFU-for-capabilities) |
| `ironmesh_peer_cap_accepted_total` | Operator accepted a cap change; pending set becomes new baseline |
| `ironmesh_peer_cap_binding_partial_total` | Cap change detected but stash / demote did NOT fully persist — investigate |
| `ironmesh_msg_replay_cross_transport_total` | Duplicate frame arrived on a different transport than original |
| `ironmesh_peer_promoted_total` | Operator promoted a pending peer to trusted |
| `ironmesh_peer_blocked_total` | Operator locally blocked a peer |
| `ironmesh_peer_revoked_local_total` | Operator revoked a peer locally (no network propagation) |
| `ironmesh_peer_state_changed_total` | Trust-state transitions other than promoted / blocked |

### Observability: OpenTelemetry spans

Matching OTel events fire via the existing `ironmesh[otel]` extra
(`pip install ironmesh[otel]` + `OTEL_EXPORTER_OTLP_ENDPOINT=...`).
Event names follow `peer.cap.*` and `msg.replay.*` conventions. Zero
overhead on vanilla installs — the tracer stays a no-op shim when the
SDK is absent or unconfigured.

### Operator CLI — five new / improved subcommands

| Command | What it does |
|---|---|
| `ironmesh trust cap-reject <node_id>` | Reject a pending cap change; keep the existing baseline. `--block` flag also sets state to `blocked` in one shot |
| `ironmesh trust cap-status <node_id>` | Single-peer deep dive — baseline hash, pending hash, timestamps, diff |
| `ironmesh trust list --show-caps` | Adds a `Caps` column to the peers list: `baseline` / `pending` / `unknown` |
| `ironmesh audit tail --event X --since 1h` | Filtered newest-first audit log output. Multiple event types allowed comma-separated |
| `ironmesh audit stats --since 1h` | Histogram of event types over a recent window — at-a-glance triage |

Relative windows accept short forms: `30s`, `5m`, `2h`, `7d`. Absolute
ISO-8601 timestamps also accepted. Both commands can emit JSON via
`--json` for scripts.

### MCP surface: 23 → 25 tools

Two new tools bring the MCP server to 25 tools total for Claude Desktop
and Claude Code integration:

- **`ironmesh_cap_diff`** — read-only cap diff for a single peer.
  Non-destructive; safe to poll.
- **`ironmesh_cap_reject_peer`** — reject the pending change. Optional
  `block: true` argument sets state to blocked in one shot.

### New runbook + structured docs

- **`docs/OPERATOR_RUNBOOK.md`** — one-page playbook for seven common
  cap-binding and audit-log triage scenarios: peer auto-demoted,
  peer keeps demoting itself, `PEER_CAP_BINDING_PARTIAL` fired, audit
  verify reports tamper, pending-trust queue filling, cross-transport
  replay fired, daemon won't start after key rotation.
- **`AGENTS.md`** at the repo root — convention-aligned guide for AI
  coding assistants (Claude Code, Cursor, Aider, Zed, Codex). Covers
  operating rules, workflow, common tasks.
- **`examples/cap_binding_workflow.py`** — runnable in-process walkthrough
  of the full cap-change → review → accept cycle. No network, no LLM
  calls; exercises the same TrustStore paths the live daemon uses.

### Stress harness + CI nightly

`scripts/stress_concurrent.py` — promoted from an ad-hoc v0.8.5.6 audit
script to a standalone tool. 2000 threads × 20 peers completes in under
3 seconds. Asserts exactly one winner per peer + no MAC corruption +
correct final baseline. `.github/workflows/stress-nightly.yml` runs it
on Ubuntu + Windows / Python 3.11 + 3.13 every night at 04:17 UTC.

## Fixed

Eight bugs found during release hardening. Four surfaced during live
testing; four during a systematic static + fuzz audit.

**Critical:** none.

**High:** counter observability gap where the CLI and MCP paths — which
run as separate processes from the daemon — couldn't bump Prometheus
counters at all. An audit-log tail scanner now reconciles events
regardless of originating process; daemon-side reservations prevent
double-counting.

**Medium:**

- CLI `cmd_trust` had a local `import time` scoped to one branch; Python
  scoping rule made `time` function-local for every branch, breaking
  `cap-status` with `NameError`. Removed redundant locals.
- `_reserve_counter_bump` and the audit-log scanner raced on a shared
  reservation dict (mesh.py worker thread vs asyncio scanner). Added
  `threading.Lock` serializing both.
- `set-state trusted` fires `PEER_PROMOTED`, not `PEER_STATE_CHANGED`.
  Counter map didn't include it; silent undercount. Added matching
  counters + reservation bumps.
- MCP `cap_reject_peer` mutated the trust file without firing any
  audit event. Forensic review was blind to MCP-driven rejects. Now
  fires `PEER_BLOCKED` or `PEER_STATE_CHANGED` with `actor: "mcp"` +
  `reason: "cap-reject"` + `rejected_pending_hash` for traceability.
- Audit-log rotation detection used `current_size < offset`, which
  missed the case where post-rotation writes re-grew the live file
  past the pre-rotation offset. Fixed by tracking file identity via
  `st_ino` and scanning the rotated `.1` file for missed events before
  resetting.
- `Budget.from_dict(d)` crashed on non-dict input (`"0"`, `[1,2,3]`).
  Added `isinstance` guard.
- MCP `_resolve_node_id(123)` crashed in `len()`. Accept-any-type now;
  non-strings cleanly return None.

Full list with commit references in `CHANGELOG.md`.

## Scope note: no wire changes

v0.8.x remains a patch-level-backwards-compatible line. The two
wire-protocol security extensions designed in
`docs/TRUST_BINDING_WIRE_v0.9.md` (rolling transcript hash + reconnect
continuity challenge) remain queued for v0.9, where HELLO feature
negotiation can land without breaking older peers.

## Migration

Drop-in upgrade from v0.8.5.6. No operator action required. The new
counters start at zero on each daemon run (same as every other counter
in the `Metrics` dataclass). Existing `known_peers.json`, `audit.log`,
`keys.json`, `routes.json`, and `capabilities.json` files load cleanly.

## Upgrade guidance

```bash
pip install -U ironmesh                            # PyPI
# or
docker pull wiztheagent/ironmesh:0.8.5.7           # Docker Hub
```

Restart the daemon to pick up the new dashboard panel + audit-log
scanner. No config changes needed.

## Verifying the release

```bash
python -m pip install ironmesh==0.8.5.7
python -c "import ironmesh; print(ironmesh.__version__)"
# → 0.8.5.7

ironmesh --help                                    # new subcommands visible
ironmesh trust cap-status --help
ironmesh audit tail --help
```

## Diff stats

| Metric | v0.8.5.6 | v0.8.5.7 |
|---|---|---|
| Total tests | 722 | 726 |
| MCP tools | 23 | 25 |
| Prometheus counters (cap / replay / state) | 5 | 9 |
| CLI subcommands | 39 | 44 |
| Public docs pages | 12 | 14 |
