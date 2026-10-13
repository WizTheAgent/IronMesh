# IronMesh 0.9.6 — Interop & Evidence

This page defines what the 0.9.6 release has to deliver, what counts as
evidence that each item is done, and what is explicitly left for later. A
deliverable is marked done only when the evidence named in its row exists
and is linked from here.

## Why this release

0.9.5 shipped the `ironmesh/0.9` protocol line. The next question is whether
other software can actually work with IronMesh — through the agent protocols
people already run, and through clients that are not written in Python — and
whether every public claim about IronMesh is backed by something a reader can
check. 0.9.6 answers both before anything new is added.

## Deliverables

Worked in this order; deliverable 7 runs alongside all of them.

| # | Deliverable | Done when | Status |
|---|---|---|---|
| 1 | **Tokenless PyPI publishing** | `release.yml` publishes from a dedicated job bound to the `pypi` environment through PyPI Trusted Publishing (OIDC, no stored API token), and the same flow has completed end to end against TestPyPI before the production release. | Not started |
| 2 | **A2A 1.0.1 interoperability** | The `ironmesh-a2a` gateway (A2A 0.3.0 today) conforms to A2A 1.0.1, conformance results are published, and an exchange between an independent A2A client on one host and an IronMesh node on another is recorded. | Not started |
| 3 | **MCP compatibility matrix** | A published matrix of the MCP hosts and protocol revisions `ironmesh-mcp` has been tested with (it speaks `2024-11-05` today), every cell backed by a test or a recorded session. | Not started |
| 4 | **Go and TypeScript clients at the `ironmesh/0.9` floor, in CI** | Both clients advertise and implement `ironmesh/0.9`, build and run their own tests in the CI matrix, and complete a handshake against the current Python daemon in CI. Until then they stay reference implementations (see `clients/go/STATUS.md`, `clients/ts/STATUS.md`). | Not started |
| 5 | **Pilot evidence packets** | Each pilot deployment is written up: what ran, on which hardware and transports, for how long, and what failed. | Not started |
| 6 | **External audit scope and funding** | A written scope for an external review of the protocol and implementation, and a funding plan for it. 0.9.6 does not claim an audit. | Not started |
| 7 | **Claims backed by evidence** | Every capability claim in `README.md`, `WHATS_NEW.md` and on the website points to a test, a CI job or a dated recorded run; claims without one are removed or dated. | In progress |

## Not in 0.9.6

- **Argon2id stretching of the mesh passphrase** — 0.10.0.
- **Networked revocation** (revocations that propagate across the mesh as a
  guarantee rather than a best-effort broadcast) — 0.10.0.
- **Clearing the mypy backlog** — not a release gate. The gate is that the
  error count never rises above the recorded baseline (`.mypy-baseline`).
- **Nested-value mutation through the hook context proxy** — tracked
  separately, with its own acceptance criteria.
- **Announcements and outreach** — they follow the evidence above, not the
  other way round.

## Already on the 0.9.6 branch

- `ironmesh-mcp` reads its identity, port and storage paths from the
  environment, answers `initialize` before the mesh is up, and exits instead of
  lingering when its host never speaks.
- `IronMeshConfig.from_env()` warns and keeps defaults on malformed numeric
  overrides instead of raising.
- The hook circuit breaker counts failures per hook point.
- The cross-version tests against real `0.9.4.2` on-disk state run again (their
  fixture had never been committed, so they were skipping everywhere).

See the `[Unreleased]` section of `CHANGELOG.md` for the details.
