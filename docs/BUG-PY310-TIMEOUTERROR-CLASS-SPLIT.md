# BUG: Python 3.10 — `concurrent.futures.TimeoutError` class split

**Status:** Fixed
**Severity:** Medium — CI-only symptom, but the pattern leaks through
any `except TimeoutError` that might see a `concurrent.futures.Future`
result timeout. Not exploitable; not a runtime data hazard.
**Affected versions:** any IronMesh version running on Python 3.10 with
a slow enough environment to trip a 5-second shutdown deadline.
**Fixed in:** commit `3a90c37` (in v0.9.0-dev).
**Files:** `agent.py` (primary), `bridge.py` (defensive widening).

---

## Symptom

`tests/test_concurrency_audit.py::TestParallelMessaging::test_100_parallel_sends_no_drops`
was the only failing test in CI, and it failed only on **Python 3.10**
(both `ubuntu-latest` and `windows-latest`). Every other Python in the
matrix (3.11, 3.12, 3.13) passed the same test on the same runner class.

Captured pytest log from a failing Ubuntu 3.10 job:

```
tests/test_concurrency_audit.py::TestParallelMessaging::test_100_parallel_sends_no_drops FAILED
    asyncio.run_coroutine_threadsafe(
/opt/hostedtoolcache/Python/3.10.20/x64/lib/python3.10/concurrent/futures/_base.py:460: in result
    raise TimeoutError()
E   concurrent.futures._base.TimeoutError
----------------------------- Captured stdout call -----------------------------
[concurrency-audit] 100 msgs in 0.35s = 288.8 msgs/s
```

The `Captured stdout` block is the tell: the test body **completed
successfully**. The `100 msgs in 0.35s = 288.8 msgs/s` line runs at
the very end of the `try:` block, *after* every assertion in the test.
The exception was raised in `finally:`, not in the body.

---

## Root cause

### The class hierarchy changed in Python 3.11

Python 3.10:

```python
>>> import concurrent.futures
>>> concurrent.futures.TimeoutError is TimeoutError
False
```

Python 3.11+:

```python
>>> import concurrent.futures
>>> concurrent.futures.TimeoutError is TimeoutError
True
```

This is [PEP 616](https://peps.python.org/pep-0616/) — **unified
timeout exceptions** — shipped in Python 3.11. Before 3.11,
`concurrent.futures.TimeoutError` was its own class, subclassing
nothing noteworthy. From 3.11 onward it is a direct alias for
`builtins.TimeoutError`. `asyncio.TimeoutError` got the same treatment.

### The affected code path

`agent.py` had this shutdown handler (pre-fix):

```python
def stop(self) -> None:
    ...
    if self._loop is not None:
        try:
            asyncio.run_coroutine_threadsafe(
                self.daemon.shutdown(), self._loop,
            ).result(timeout=5)
        except (TimeoutError, RuntimeError) as e:
            logger.debug("Shutdown wait: %s", e)
```

`fut.result(timeout=5)` raises `concurrent.futures.TimeoutError` when
the 5-second deadline passes without the future resolving. On
**Python 3.11+** the bare `except TimeoutError` catches it (because the
two classes are the same). On **Python 3.10** it does not — the
exception propagates up through `Agent.stop()`, out of the test's
`finally:` block, and fails the test even though the body passed.

### Why shutdown took longer than 5 seconds

`test_100_parallel_sends_no_drops` stands up two real agents on ports
`41000` / `41002`, opens a WebSocket mesh between them, sends 100
messages in parallel, asserts they all arrive, then calls `alice.stop()`
and `bob.stop()` in `finally:`. On a dev laptop, daemon shutdown
completes in tens of milliseconds. On a shared GitHub Actions runner
after 100 in-flight WebSocket frames, it occasionally exceeds 5 s —
especially on `ubuntu-latest` / Python 3.10, which is the oldest and
slowest combination in our matrix.

So the latent bug (wrong exception class in the except tuple) + the
environmental slowness (hosted runner + older Python) combined to
produce a reliable, 3.10-only failure.

---

## Fix

`agent.py:276`:

```python
except (TimeoutError, concurrent.futures.TimeoutError, RuntimeError) as e:
    logger.debug("Shutdown wait: %s", e)
```

Same widening applied defensively at `bridge.py:1810` for
`asyncio.TimeoutError` — same class-split hazard, same mitigation:

```python
except (TimeoutError, asyncio.TimeoutError, json.JSONDecodeError) as e:
```

Local repro after fix:

```
tests/test_concurrency_audit.py::TestParallelMessaging::test_100_parallel_sends_no_drops PASSED
============================= 1 passed in 20.16s ==============================
```

---

## How we found it

A false-start audit trail worth recording, because the wrong fix was
shipped twice before the real one:

1. **First hypothesis: `_wait(…, timeout=30)` in the test body was too
   tight.** Bumped to 60 s. Still failed.
2. **Second hypothesis: `send_sync`'s default `timeout=10`.** Passed
   `timeout=30` explicitly in the test. Still failed.
3. **Captured the full CI log** and noticed the `[concurrency-audit]
   100 msgs in 0.35s` line. If that line printed, the test body had
   already succeeded — the failure had to be in teardown.
4. **Grepped `def stop` in `agent.py`**; found the `run_coroutine_threadsafe(...)
   .result(timeout=5)` wrapped in `except (TimeoutError, RuntimeError)`.
5. **Verified with a one-liner**: `python -c "import concurrent.futures;
   print(concurrent.futures.TimeoutError is TimeoutError)"` — `True`
   on 3.13, `False` on 3.10. That nailed it.

The recurring mistake: **stopping at the first class in the stack
trace** (`concurrent.futures._base.TimeoutError`) instead of reading
the stdout captured immediately before the trace.

---

## Where else this hazard can lurk

Any code that:

1. Uses `fut.result(timeout=…)` on a `concurrent.futures.Future`,
   **and**
2. Catches the resulting timeout with a bare `except TimeoutError`.

Also applies to `asyncio.wait_for(..., timeout=...)` — which raises
`asyncio.TimeoutError`, itself a separate class from
`builtins.TimeoutError` on Python ≤3.10 and an alias from 3.11 on.

Guidelines:

- **Never use a bare `except TimeoutError`** around a
  `Future.result(timeout=…)` or `asyncio.wait_for` call if the code is
  expected to run on Python 3.10. Always spell both classes:

  ```python
  except (TimeoutError, concurrent.futures.TimeoutError):
      ...
  # or
  except (TimeoutError, asyncio.TimeoutError):
      ...
  ```

- Once we drop Python 3.10 support, these double-spellings become
  redundant and can be collapsed to `except TimeoutError` safely.
- New code: prefer `asyncio.wait_for` over `Future.result(timeout=…)`
  when possible — the asyncio version has a clearer raise semantic
  and the same class-split mitigation applies uniformly.

---

## Related

- PEP 616 — https://peps.python.org/pep-0616/ (though the actual
  unification lives in the [What's New in 3.11](https://docs.python.org/3/whatsnew/3.11.html#asyncio)
  asyncio section; the PEP predates and framed the change)
- `docs/BUG-RNS-HANDSHAKE-RACE.md` — similar "only-under-specific-
  conditions" CI flake, fixed in v0.5.1.
