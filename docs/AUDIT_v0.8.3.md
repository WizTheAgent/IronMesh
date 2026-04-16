# IronMesh v0.8.3 — Full E2E Debugging Audit

**Date:** 2026-04-16 / 2026-04-17
**Branch:** `main` (post-`f05ee7c`)
**Scope:** Hunt for bugs across every surface of the current
v0.8.2 codebase before shipping v0.8.3. "Perfect what we have."

Each section below is one pass of the audit. Findings are listed in
the order they were discovered. Every finding has a **status**
(`fixed` / `accepted risk` / `tracked`) and, when fixed, the commit
hash that landed the fix.

---

## Summary

| Area | Findings | Fixed | Accepted risk | Tracked (future) |
|---|---|---|---|---|
| CONV envelope fuzzing | _tbd_ | 0 | 0 | 0 |
| Concurrency (parallel MSGs) | _tbd_ | 0 | 0 | 0 |
| Crash matrix | _tbd_ | 0 | 0 | 0 |
| Memory / resource leak | _tbd_ | 0 | 0 | 0 |
| Dashboard + GUI WS fuzz | _tbd_ | 0 | 0 | 0 |
| Dependency + security audit | _tbd_ | 0 | 0 | 0 |
| Threat model re-walk | _tbd_ | 0 | 0 | 0 |
| Cross-platform CI | _tbd_ | 0 | 0 | 0 |

(Final counts will be filled in when the audit closes.)

---

## 1. CONV envelope fuzzing

Hypothesis-based property tests, 9 properties × ~400 generated inputs
each. New suite: `tests/test_conv_fuzz.py`.

### Findings

- **CONV-01** *(test infra)* — An empty `Budget(None, None, None)` is
  semantically equivalent to `budget=None` because `to_dict()` drops
  all-None fields, so the encoder omits it. The round-trip test was
  asserting strict object equality; fixed by comparing
  `.to_dict()` on both sides. No behavior change, test tightened.
  **Status:** fixed (test-only).

### Invariants verified

| # | Property | Result |
|---|---|---|
| 1 | `encode` then `decode` preserves all required + optional fields | ✓ |
| 2 | Encoded output is always valid UTF-8 JSON with `v == 1` | ✓ |
| 3 | `body` can hold arbitrary Unicode (including emoji, CJK, RTL) | ✓ |
| 4 | `make_reply` increments turn and swaps roles correctly | ✓ |
| 5 | `is_terminal` agrees with the kind enum | ✓ |
| 6 | Arbitrary binary inputs never raise anything except `ValueError` on decode | ✓ |
| 7 | Unknown top-level keys survive round-trip via `.extra` | ✓ |
| 8 | Dataclass construction with basic types never raises | ✓ |
| 9 | Decode of partially-valid dicts either works or raises `ValueError` cleanly | ✓ |

**Verdict:** CONV envelope is robust against random input. No protocol
bug found.

## 2. Concurrency

_Pending._

## 3. Crash matrix

_Pending._

## 4. Memory / resource leaks

_Pending._

## 5. Dashboard + GUI WS fuzz

_Pending._

## 6. Dependency + security audit

_Pending._

## 7. Threat model re-walk

_Pending._

## 8. Cross-platform CI

_Pending._

---

## Closing verdict

_To be filled in when every section above is complete._
