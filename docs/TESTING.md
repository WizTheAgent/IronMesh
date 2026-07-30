# IronMesh Testing Philosophy

A short walkthrough of how IronMesh is tested and why each layer
exists. Useful for evaluating the project, contributing your first
PR, or extending the test suite.

## What gets run

A full test pass collects **1382 tests** across four layers:

| Layer | Count (approx) | Purpose |
|---|---|---|
| Unit tests | ~960 | Per-module behavior, edge cases, regression locks |
| Property-based / fuzz tests | ~30 | Hypothesis-driven invariant checks on the wire protocol, conversation envelope, and trust gate |
| Concurrency tests | ~20 | Race conditions, simultaneous-dial, queue draining under load, lock orderings |
| Integration tests | ~30 | Real framework adapters (LangChain, CrewAI, AutoGen) against live in-process mesh |

All four layers run in CI on every push and PR. The integration layer
runs on Ubuntu only because mDNS-over-localhost is more reliable on
Linux than on the Windows CI runner.

## Layer 1 — unit tests (`tests/test_*.py`)

One test file per code module, structured around the public API of
that module. Examples:

- `test_protocol.py` — frame serialization, message types, replay
  guard, token bucket, handshake state machine
- `test_crypto.py` — NaCl ECDH, SecretBox round-trip, Ed25519 sign /
  verify, secure-wipe behavior
- `test_mesh.py` — distance-vector convergence, split horizon, dedup
  cache atomicity (the v0.8.3 audit fixed a TOCTOU race here)
- `test_trust_gate.py` — pending-trust state transitions, promotion,
  block, queue eviction
- `test_mcp.py` — every MCP tool's argument validation, error paths,
  and bounds

Run them all:

```bash
pytest -q --ignore=tests/integration
```

Run one module:

```bash
pytest tests/test_protocol.py -v
```

## Layer 2 — property-based / fuzz tests (Hypothesis)

Three Hypothesis-driven test files exercise invariants that are too
broad to enumerate by hand:

- **`test_fuzz_protocol.py`** — random byte strings into the frame
  decoder must either decode to a structurally valid `Frame` or raise
  a clear typed error. No silent acceptance, no crashes, no infinite
  loops.
- **`test_conv_fuzz.py`** — random `ConvEnvelope` shapes round-trip
  through `encode`/`decode` losslessly. Termination flags
  (`is_terminal`, `KIND_END`, `KIND_ERROR`) preserve their semantics
  through the round-trip.
- **`test_fuzz_v0852.py`** — adversarial inputs into the v0.8.5.2
  hardened paths: trust-store load with corrupted MAC, MCP tool
  arguments at the boundary of size caps, audit-log rotation under
  concurrent writes.

Hypothesis stores its database under `.hypothesis/` (gitignored) and
will replay any failing example on subsequent runs until the case is
fixed.

## Layer 3 — concurrency tests (`test_concurrency_audit.py`)

The most subtle bugs in a mesh protocol are race conditions that
appear under load and disappear under a debugger. This file uses
`pytest-asyncio` with deliberate timing manipulation to exercise:

- Simultaneous-dial collisions (both peers dial each other on the
  same tick — the v0.8.0 dedup tie-breaker is verified here)
- Concurrent trust-store mutations (atomic write via
  `path.tmp` + `fsync` + `os.replace` — the v0.8.5.2 hardening)
- Queue draining while new messages arrive (priority-aware eviction
  doesn't drop a high-priority message when the queue overflows)
- Audit-log rotation while concurrent writers append (HMAC chain
  continuity is preserved across the rotation boundary)

These tests are slow (a single race might require thousands of
iterations to surface). They run in CI but not on every developer
save.

## Layer 4 — integration tests (`tests/integration/`)

Stand up real third-party packages (`langchain-core`, `crewai`,
`autogen-agentchat`) and live two-node IronMesh meshes in-process. Verify
that the framework adapters under `adapters/` actually carry messages
end-to-end.

- `test_langchain_integration.py` — a LangChain agent receives a
  message via the IronMesh adapter and produces a reply that round-
  trips back to the sender
- `test_crewai_integration.py` — same for CrewAI
- `test_autogen_integration.py` — same for AutoGen
- `fake_ollama.py` — a stub LLM responder so tests don't depend on a
  real Ollama install

Run them separately (they pull in the heavier framework deps):

```bash
pip install -e ".[dev,integrations]"
pytest tests/integration -v
```

## What's intentionally not tested in CI

- **Live LoRa / Reticulum end-to-end.** Requires actual RNode
  hardware paired with another RNode peer in radio range. Validated
  manually before each release per `docs/LORA_VALIDATION.md`. Tracked
  in the release checklist (`.github/RELEASE_CHECKLIST.md` Section 5).
- **Live multi-node mesh on real hardware.** Same — validated
  manually on a 3-node mesh (Pi 5 + NAS + desktop with Ollama)
  before each release.
- **Long-running stability.** A 24-hour soak test is part of the
  release-engineering ritual but is not run in CI on every push.

## Coverage

Coverage is measured on every CI run with `pytest --cov=. --cov-report=xml`
and uploaded to Codecov. The current floor enforced in CI is
**60%** (`--cov-fail-under=60`); the actual measured coverage is
typically much higher. The badge at the top of the README is live.

The 60% floor is intentional — chasing 100% coverage on a protocol
project rewards ceremony tests over correctness tests. Hypothesis
fuzzing and concurrency tests catch a category of bugs that line
coverage cannot reach.

## Adding a test

For a bug fix:

1. Write the test that reproduces the bug. Confirm it fails on
   `main`.
2. Apply the fix. Confirm the test passes.
3. Submit both in the same PR. The test name should describe the
   invariant, not the audit code that surfaced it (e.g.
   `test_dedup_cache_is_atomic_under_concurrent_check`, not
   `test_audit_h12`).

For a new feature:

1. Decide the layer first. New behavior of one module = unit test.
   New behavior at module boundaries = integration test. New
   adversarial-input surface = Hypothesis test.
2. Write the test before or alongside the feature. PRs that add
   feature code without a test get held for a follow-up.

For a concurrency fix:

1. Reproduce the race deterministically — usually via
   `asyncio.sleep(0)` cooperative-yield placement or
   `pytest-asyncio` event-loop manipulation. A "sometimes fails"
   test is worse than no test.
2. Once deterministic, the fix can be reviewed with confidence.

## What good looks like

- Every PR keeps the suite green on Ubuntu + Windows + macOS
  across Python 3.10 – 3.13.
- New features carry tests in the appropriate layer.
- Bug fixes carry the regression test.
- No test is named after an internal audit code or hardening
  identifier; test names describe behavior.
- Concurrency tests are deterministic.
