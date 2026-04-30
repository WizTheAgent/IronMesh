# IronMesh v0.8.5.8 — Release Notes

## Headline

Patch release on top of v0.8.5.7. Focus is on making the v0.8.5.7
observability layer robust under real operational pressure:
audit-log write failures, daemon restarts, out-of-process trust
mutations, and chain tamper discovered mid-startup. No protocol or
schema changes. Every v0.8.x peer stays interoperable.

Where v0.8.5.7 shipped the counters, v0.8.5.8 makes them trustworthy.

## Highlights

### Counters survive daemon restart

Mirrored Prometheus counters (`ironmesh_peer_cap_*_total`,
`ironmesh_peer_promoted_total`, `ironmesh_peer_blocked_total`,
`ironmesh_msg_replay_cross_transport_total`, and the trust-state
family) used to start at zero on every daemon restart. Prometheus
reports the zero-reset as a negative delta, which broke `rate()` and
`increase()` queries across restart boundaries and triggered false
negatives in any Grafana alert that assumed monotonic counters.

The daemon now reads the last 10,000 audit log entries on startup
and seeds each mirrored counter to match. Counter values pick up
where they left off; the restart is invisible to Prometheus. Bounded
at 10k entries so startup stays fast on hosts with very large audit
logs.

### CLI trust-mutation audit events now reach the target daemon

Operators running a daemon with a custom `--db-path` hit a silent
observability gap: `ironmesh trust cap-promote` / `cap-reject` /
`revoke` / `set-state` wrote their audit events to the default
`~/.ironmesh/audit.log`, but the daemon's audit log lived next to its
db. The daemon's counter-sync loop only tailed its own log — so every
operator mutation left the mirrored Prometheus counters
(`ironmesh_peer_cap_accepted_total`, `ironmesh_peer_promoted_total`,
`ironmesh_peer_blocked_total`, `ironmesh_peer_revoked_local_total`,
`ironmesh_peer_state_changed_total`) stuck at their pre-mutation
values, and trust-store baseline updates couldn't fully converge on
the running daemon, producing a persistent "pending-cap-change"
flap for peers that should have been trusted.

The CLI now derives the audit log path from `--trust-path` when
present (`<trust-path-dir>/audit.log`, matching the daemon's own
path-derivation rule), and accepts an explicit `--audit-path`
override when operators have unusual layouts. Default behavior is
unchanged for stock-path deployments.

### Counter-drift fix: audit emit failures no longer corrupt counters

The counter reservation mechanism introduced in v0.8.5.7 bumps the
metric BEFORE the paired audit event reaches disk, then reserves the
bump against the audit-log scanner's dedup window so the scanner
doesn't also count the event. If the audit emit failed (disk
pressure, flock timeout, rotation mid-write), the reservation was
silently orphaned — either leaving the counter +1 above truth, or
silently absorbing the next real event of that type.

Seven call sites across `bridge.py` and `mesh.py` now release the
reservation when an emit fails, and every reserve+emit pair goes
through one structured helper (`BridgeDaemon._emit_audit_with_reservation`).
A static-analysis test (`tests/test_bridge.py::TestCounterDriftOnAuditFailure::test_no_bare_reserve_counter_bump_outside_helper`)
fails CI if a new call site spells out the pattern by hand.

Drift accumulated in long-running v0.8.5.7 daemons clears on next
restart; this release prevents future drift.

### Audit-chain verification on daemon start

The daemon now runs `audit.verify()` once after opening the audit log.
If the chain reports TAMPER, a WARNING log line surfaces the entry
number and scan depth. Pre-existing corruption (from multi-writer
races pre-v0.8.5.6, or filesystem damage) now shows up immediately
instead of waiting for someone to run `ironmesh audit verify` by
hand. Startup itself is never blocked — operators decide whether to
investigate.

### CLI audit-emit failures surface at WARNING

`ironmesh trust revoke`, `trust set-state`, `trust cap-promote`, and
`trust cap-reject` previously swallowed audit-log write failures
silently: the trust mutation applied, no audit record was written,
and the operator had no idea. Failures now print a WARNING to stderr
identifying the event, the underlying error, and the audit log path
so operators can investigate. The mutation itself is still applied —
the audit emit is separate from the state change.

### Grafana dashboard: two new panels

`docs/grafana/ironmesh-dashboard.json` grows from 5 panels to 7:

- **Cap-binding activity (5m rate)** — cap-set changed, baselines
  pinned, operator-accepted, binding partial.
- **Operator trust actions + cross-transport replay (5m rate)** —
  revokes, promotions, blocks, state changes, replay alerts.

Existing imports continue to work; the new panels append to the
bottom of the dashboard so existing panel positions are unchanged.

### OPERATOR_RUNBOOK: trust-store corruption recovery playbook

New section 7 in `docs/OPERATOR_RUNBOOK.md` covers the
`Trust store integrity check FAILED` log line (v0.8.5.6 read-only
latch trip). Most common cause is a test-infra or second development
daemon colliding with production on the default trust path.

### Dashboard version badge no longer lies

The version pill in the operator console was a hardcoded string
literal (`v0.8.5 · PRE-1.0`) that never got bumped alongside
`__version__`. Dashboards served by v0.8.5.6 and v0.8.5.7 rendered
"v0.8.5" even though the package and wire handshake were correct.
Replaced the literal with a `{{IRONMESH_VERSION}}` placeholder and
a render-time substitution driven by `ironmesh.__version__`. Two
regression tests in `test_gui.py` lock in the fix.

## Operator-visible behavior change

After upgrade, mirrored Prometheus counters no longer start at zero
on daemon restart — they pick up from the last 10,000 audit entries.
Any existing Prometheus recording rule or Grafana panel that assumed
zero-reset behavior across restart will see a different pattern (no
more negative delta). Counter-type semantics are preserved; `rate()`
and `increase()` continue to produce the expected values.

No action required unless you have a recording rule keyed on the
zero-reset, in which case remove the assumption.

## Upgrade

```bash
pip install --upgrade ironmesh
# or
docker pull wiztheagent/ironmesh:0.8.5.8
```

Rolling upgrade across a mesh is safe — no protocol changes. Restart
peers one at a time and observe:

- `Audit chain verified clean (N entries).` in each daemon's startup
  log (or the TAMPER warning, which means the chain was already
  broken before the upgrade — see OPERATOR_RUNBOOK section 4).
- `Reconciled N audit-mirror counter bump(s) from the last 10000
  audit entries.` in the startup log, confirming the restart
  continuity path ran.
- No negative counter deltas in Prometheus across the restart
  boundary.

## Testing

- Unit and integration test suites green (N test files exercised).
- Live-mesh validation against the production 3-node mesh: fresh
  cap-baseline pin, cap-set change + cap-promote flow,
  cross-transport replay, audit chain verify, `/metrics` scrape.

## Thanks

To everyone using IronMesh in production and surfacing the operational
rough edges that motivate these hardening releases.
