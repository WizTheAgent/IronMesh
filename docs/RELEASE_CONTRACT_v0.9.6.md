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
| 2 | **A2A 1.0.1 interoperability** | The `ironmesh-a2a` gateway (A2A 0.3.0 today) passes the official A2A 1.0.1 conformance tests with the results published, and a cross-host exchange — an independent A2A client on one host, an IronMesh node on another — is recorded as evidence. | Not started |
| 3 | **MCP compatibility matrix** | `ironmesh-mcp` is tested across MCP protocol revisions `2024-11-05` and `2026-07-28`, each over stdio and over a networked transport, and the resulting matrix is published with every cell backed by a test or a recorded session. Today it speaks `2024-11-05` over stdio only. | Not started |
| 4 | **Go and TypeScript clients at the `ironmesh/0.9` floor, in CI** | Both clients advertise and implement `ironmesh/0.9`, build cleanly, run their own tests in the CI matrix, and complete a handshake against the current Python daemon in CI. Until then they stay reference implementations (see `clients/go/STATUS.md`, `clients/ts/STATUS.md`). | Not started |
| 5 | **Pilot evidence packets** | At least three pilot deployments are documented (the internal milestone for this release is 3–5 pilots), each written up with what ran, on which hardware and transports, for how long, and what failed. This is separate from, and does not count towards, the 1.0 gate below. | Not started |
| 6 | **Independent audit: scope and funding** | A written scope for an independent, paid third-party audit of the protocol and implementation, and a funding plan for it. 0.9.6 does not claim an audit. | Not started |
| 7 | **Claims backed by evidence** | Every capability claim in `README.md`, `WHATS_NEW.md` and on the website points to a test, a CI job or a dated recorded run; claims without one are removed or dated. | In progress |

## Evidence rule for the GUI

Advanced GUI panels must remain explicitly labelled DEMO DATA until their
displayed values come from the daemon as the authoritative source. Mock panels
and recorded screenshots do not count as release-readiness evidence.

## Before 1.0 (not 0.9.6)

1.0 requires an **independent, paid third-party audit** with its report
published, and **10–20 deployments with evidence** of how they ran. These are
separate gates from the 3–5 documented pilots of deliverable 5. 0.9.6 prepares
for both (deliverables 5 and 6) but does not claim either.

## Not in 0.9.6

- **Argon2id mesh-passphrase derivation** (replacing the unstretched HMAC key) — 0.10.0.
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
- An unparseable `IRONMESH_PORT` in `IronMeshConfig.from_env()` is logged as a
  warning and the default port is used instead of raising. This fallback is
  limited to the port and is not harmless (the node may listen on an
  unintended endpoint or collide with another node); security-relevant
  numeric limits reject malformed values instead (see below).
- The hook circuit breaker counts failures per hook point.
- The cross-version tests against real `0.9.4.2` on-disk state run again (their
  fixture had never been committed, so they were skipping everywhere), and CI
  and the release gate now fail if that fixture is missing.
- A mistyped security setting (for example
  `IRONMESH_REQUIRE_MSG_PROMOTION=ture`) refuses to start instead of silently
  meaning "off"; security limits reject values that would loosen them.
- The development lockfile clears two published advisories (`cryptography`,
  `pytest`).

See the `[Unreleased]` section of `CHANGELOG.md` for the details.
