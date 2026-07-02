# Agent guide for this repository

This file tells AI coding assistants (Claude Code, Cursor, Aider, Zed,
Codex, and similar) how to operate productively in the IronMesh
codebase. It is the emerging community convention for
repo-level AI guidance. Human contributors should read `CONTRIBUTING.md`.

## What IronMesh is

A local-first, end-to-end encrypted agent-to-agent mesh protocol.
Python daemon + TypeScript client + 25 MCP tools. No cloud
dependencies. See `README.md` for the product-level summary.

## Quick repo orientation

```
ironmesh/                  # main Python package
├── bridge.py              # daemon core — server + lifecycle (composes the mixins below)
├── handshake.py           # client handshake + outbound connect + rekey
├── routing.py             # inbound dispatch + outbound send pipeline
├── trust_ops.py           # revocation + pending-trust gate + TOFU check
├── ratelimit.py           # auth-failure lockout + bandwidth throttle
├── metrics.py             # counters + Prometheus/JSON exposition
├── dashboard.py           # GUI HTTP/WebSocket server + operator commands
├── dashboard_html.py      # embedded dashboard page (GUI_HTML)
├── trust.py               # TOFU pin store + capability-set binding
├── audit.py               # HMAC-chained audit log + cross-process flock
├── mesh.py                # distance-vector router + DedupCache
├── crypto.py              # thin wrapper over PyNaCl primitives
├── protocol.py            # binary frame + JSON-dispatch decoders
├── capabilities.py        # local + remote capability registries
├── cli.py                 # `ironmesh` command surface
├── telemetry.py           # OpenTelemetry shim (lazy, no-op on vanilla)
└── keys.py                # Ed25519 identity: generate / save / load

ironmesh_mcp/              # MCP server (Claude Desktop / Claude Code)
clients/ts/                # TypeScript client — `@wiztheagent/ironmesh-client`
tests/                     # pytest suite — unit + property + concurrency
docs/                      # public-facing docs (shipped with the release)
scripts/                   # release-smoke, leak-scan, stress harness
examples/                  # runnable walkthroughs (cap_binding_workflow etc.)
```

## Non-negotiable operating rules

1. **Do not push to any remote without explicit human instruction.**
   This covers `git push`, `twine upload`, `docker push`, `gh release`,
   Netlify deploys, and npm publishes. Local commits are fine; pushes
   require a human to type "push" or equivalent. No exceptions.

2. **Every public-facing document reads as public documentation.**
   No internal plan milestone codes (M0/M1), audit severity codes
   (C1/H1), "RAZOR #N", personal absolute paths, personal IPs, or
   first-person pronouns in commit messages / changelogs / release
   notes / public docs. `scripts/leak-scan.sh` enforces this and runs
   on every push.

3. **Live infrastructure only for mesh testing.** Run integration
   tests against a real multi-node production mesh rather than
   synthesizing alice/bob localhost daemons. pytest already isolates
   trust paths via `tests/conftest.py` so unit tests don't need live
   infra; the rule is about mesh-behavior testing specifically.

4. **Root-cause fixes over log-level patches.** If an error is
   visible, find why it's happening. Don't silence a warning to make
   the log cleaner — fix the underlying bug.

5. **Patch-level releases (v0.8.x.Y) MUST NOT change wire format
   or schema.** Every v0.8.x peer must stay interoperable with every
   other v0.8.x peer. Wire-protocol work lands in v0.9, not a patch.

## Workflow for changes

1. Read the existing code near what you're changing. Match the
   prevailing pattern even if you'd have written it differently
   greenfield.
2. Write / update tests first when possible. The suite is fast
   (~30s full); no reason to delay.
3. Run the relevant test module locally: `python -m pytest
   tests/test_trust_binding.py -q`.
4. Before any commit or push, run `scripts/leak-scan.sh --all`.
5. Before any release tag, run `scripts/release-smoke.sh` — it
   builds the wheel, imports every module in a throwaway venv, and
   invokes the CLI entry point. Release is gated on PASS.

## Common tasks

### Adding a new audit event type

1. Add the `EVENT_*` constant to `ironmesh/audit.py`.
2. Import it wherever you emit it (typically `bridge.py` or `mesh.py`).
3. Add a matching `Metrics` counter attribute so it surfaces through
   `/metrics`. Mirror in `Metrics.to_dict()` and in `_format_metrics_prometheus`.
4. Emit an OTel event via `telemetry.emit_event(...)` at the same point.
5. Add a unit test that the counter increments when the event fires.

### Adding a new CLI subcommand

1. Add the subparser in `ironmesh/cli.py` near related commands.
2. Add the handler as an `elif` branch in the appropriate `cmd_*`
   function.
3. If the command mutates trust-state, it MUST emit an audit event via
   `_audit_log_event(EVENT_*, {...actor: "cli"})`.
4. Add help text and an example to `docs/CONFIGURATION.md`.

### Adding a new MCP tool

1. Add the `tool_*` method to `IronMeshMCP` in `ironmesh_mcp/server.py`.
2. Append a spec entry to `TOOL_SPECS` — name, description, JSON Schema.
3. Update `tests/test_mcp.py::test_total_tool_count` assertion.
4. Update the "25 MCP tools" callouts in the module docstring of
   `ironmesh_mcp/server.py`, `WHATS_NEW.md`, and the website.

## Where internal-only docs live

Internal audits, bug reports, plans, gap analyses, and roadmap docs
live in the operator's private secure directory (outside the repo),
**never** in the public repo. `scripts/leak-scan.sh` and the
pre-push hook catch leaks. If you generate a forensic postmortem,
write it to the private directory, not `docs/`.

## Conventions that aren't enforced but should be followed

- Docstrings reference the bug ID or feature version when fixing
  something non-obvious (e.g. a version anchor like "v0.8.5.6:").
- Commit messages lead with `release(vX.Y.Z):` or `fix(...):` /
  `feat(...):` / `chore(...):` / `docs(...):`.
- Never write multi-paragraph docstrings; a single clear line is
  better than a wall of text.
- Comments explain WHY. The code shows WHAT.

## Getting unstuck

- Production mesh access (SSH, passphrases, IPs) lives in the
  operator's private notes outside the repo. Don't assume credentials
  are anywhere in the tree.
- `docs/TRUST_BINDING.md` — design and threat model for cap-binding.
- `docs/PROTOCOL_SPEC.md` — wire format reference.
- `docs/OBSERVABILITY.md` — Prometheus metrics + OpenTelemetry setup.
- `docs/OPERATOR_RUNBOOK.md` — playbook for common operator scenarios.
