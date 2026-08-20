#!/usr/bin/env bash
# CI pytest wrapper — runs pytest, treats "all tests passed" as success even
# if the Python interpreter hangs in atexit cleanup afterwards.
#
# Background: on hosted Ubuntu+Windows runners the pytest process completes
# the test summary line ("577 passed in 54.67s") + writes coverage XML +
# prints the coverage threshold ack — and then hangs for 18+ minutes
# inside atexit, eating the job timeout silently. Locally on a developer
# laptop the same command exits in 55s. Most likely culprit: a non-daemon
# thread (or asyncio task) that pytest-asyncio + pytest-cov are waiting
# on during their teardown sequences. Tracking that down is a separate
# investigation; this wrapper unblocks CI in the meantime.
#
# Strategy: run pytest in the background, tee its output, watch for the
# "passed in" terminator. When seen, give pytest 10 s to exit on its own;
# if it hasn't, SIGKILL it and exit 0 — the actual test work succeeded,
# CI just shouldn't wait on a broken interpreter shutdown.
#
# If pytest exits on its own with non-zero, we propagate that exit code.
# If pytest never reaches the success line within HARD_TIMEOUT, we fail.
# CI_PYTEST_MIN_PASSED / CI_PYTEST_MAX_SKIPPED (see below) additionally
# assert the run actually executed the suite rather than skipping it.

set -u
HARD_TIMEOUT="${HARD_TIMEOUT:-1200}"  # absolute ceiling; 20 min (macOS runners
                                      # need the headroom under coverage)
LOG_FILE="$(mktemp -t pytest-ci-log.XXXXXX)"

# Optional result floors — guard against the "green CI, but the check never
# ran" failure mode. pytest exits 0 when tests are skipped or deselected en
# masse (a conftest regression, a broken optional-dependency install feeding
# importorskip, an over-broad marker expression), so a green job does not by
# itself prove the suite executed. Callers set:
#
#   CI_PYTEST_MIN_PASSED   fail unless the summary reports at least this
#                          many passed tests
#   CI_PYTEST_MAX_SKIPPED  fail if the summary reports more than this many
#                          skipped tests
#
# Both unset = no floor (local runs are unaffected). CI sets floors at
# roughly 70% of the current suite size so routine test additions and
# removals never false-alarm, while a structural no-op trips immediately.
# A "no tests ran" summary is always a failure, floors or not.
CI_PYTEST_MIN_PASSED="${CI_PYTEST_MIN_PASSED:-}"
CI_PYTEST_MAX_SKIPPED="${CI_PYTEST_MAX_SKIPPED:-}"

enforce_result_floors() {
  # $1 = pytest's final summary line. Returns non-zero (with a message) if
  # the run was a structural no-op or breaches a configured floor.
  local summary="$1" n_passed n_skipped
  if echo "$summary" | grep -qE "no tests ran"; then
    echo "ci-pytest: FAIL — pytest ran zero tests: $summary"
    return 1
  fi
  n_passed=$(echo "$summary" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | head -1)
  n_skipped=$(echo "$summary" | grep -oE '[0-9]+ skipped' | grep -oE '[0-9]+' | head -1)
  n_passed="${n_passed:-0}"
  n_skipped="${n_skipped:-0}"
  if [ -n "$CI_PYTEST_MIN_PASSED" ] && [ "$n_passed" -lt "$CI_PYTEST_MIN_PASSED" ]; then
    echo "ci-pytest: FAIL — $n_passed tests passed but the floor is $CI_PYTEST_MIN_PASSED."
    echo "           A pass count this far below the known suite size means part of the"
    echo "           suite silently did not run (mass skip / deselect / empty collection)."
    echo "           If the suite genuinely shrank, lower CI_PYTEST_MIN_PASSED in the"
    echo "           workflow as a deliberate, reviewed change."
    return 1
  fi
  if [ -n "$CI_PYTEST_MAX_SKIPPED" ] && [ "$n_skipped" -gt "$CI_PYTEST_MAX_SKIPPED" ]; then
    echo "ci-pytest: FAIL — $n_skipped tests skipped but the ceiling is $CI_PYTEST_MAX_SKIPPED."
    echo "           Extra skips usually mean an optional dependency stopped importing,"
    echo "           so tests that used to run are now silently bypassed. Re-run with"
    echo "           pytest -rs to list the skips; raise CI_PYTEST_MAX_SKIPPED only as a"
    echo "           deliberate, reviewed change."
    return 1
  fi
  return 0
}

trap 'rm -f "$LOG_FILE"' EXIT

# Run pytest in the background with output teed to both the console and
# the log file so we can grep the log without losing live progress.
("$@" 2>&1; echo "__pytest_exit__=$?") | tee "$LOG_FILE" &
WRAPPER_PID=$!

START=$(date +%s)
PYTEST_OK=""
while true; do
  # Did pytest emit a final summary line? Three shapes seen in the wild:
  #   "===== 577 passed, 4 skipped, 1 xpassed in 54.67s ====="           (<60 s, green)
  #   "===== 1 failed, 598 passed, 4 skipped in 46.80s ====="            (<60 s, fail)
  #   "===== 599 passed in 74.52s (0:01:14) ====="                       (≥60 s — pytest
  #                                                                       appends H:MM:SS)
  # Anchor on the "in <N>.<N>s" core; tolerate an optional " (h:mm:ss)"
  # suffix before the trailing "=====" run.
  SUMMARY_LINE=$(
    grep -E "^=+ .* in [0-9]+(\.[0-9]+)?s( \([0-9:]+\))? =+$" "$LOG_FILE" 2>/dev/null \
      | tail -1
  )
  if [ -n "$SUMMARY_LINE" ]; then
    # Word-boundary on `failed` / `error` — otherwise `xfailed`
    # (pytest's "expected failure" marker, which is a PASS for our
    # purposes) matches the failure branch and fails CI on a
    # clean run.
    if echo "$SUMMARY_LINE" | grep -qE "\b(failed|error)\b"; then
      echo ""
      echo "ci-pytest: pytest summary reported failures — $SUMMARY_LINE"
      pkill -KILL -P "$WRAPPER_PID" 2>/dev/null
      kill -KILL "$WRAPPER_PID" 2>/dev/null
      exit 1
    fi
    if ! enforce_result_floors "$SUMMARY_LINE"; then
      pkill -KILL -P "$WRAPPER_PID" 2>/dev/null
      kill -KILL "$WRAPPER_PID" 2>/dev/null
      exit 1
    fi
    PYTEST_OK="yes"
    break
  fi
  # Did pytest itself exit (success or failure marker written by subshell)?
  if grep -Eq "^__pytest_exit__=" "$LOG_FILE" 2>/dev/null; then
    EXIT_CODE=$(grep -E "^__pytest_exit__=" "$LOG_FILE" | tail -1 | cut -d= -f2)
    echo ""
    echo "ci-pytest: pytest exited (code=$EXIT_CODE)"
    wait "$WRAPPER_PID" 2>/dev/null
    # A clean exit must still clear the result floors — pytest exits 0 on
    # a mass-skipped run, which is exactly the case the floors exist for.
    if [ "$EXIT_CODE" = "0" ] && { [ -n "$CI_PYTEST_MIN_PASSED" ] || [ -n "$CI_PYTEST_MAX_SKIPPED" ]; }; then
      FINAL_SUMMARY=$(
        grep -E "^=+ .* in [0-9]+(\.[0-9]+)?s( \([0-9:]+\))? =+$" "$LOG_FILE" 2>/dev/null \
          | tail -1
      )
      if [ -z "$FINAL_SUMMARY" ]; then
        echo "ci-pytest: FAIL — result floors are configured but pytest produced no summary line."
        exit 1
      fi
      enforce_result_floors "$FINAL_SUMMARY" || exit 1
    fi
    exit "$EXIT_CODE"
  fi
  # Hard cap: pytest hasn't even reported success in HARD_TIMEOUT s.
  NOW=$(date +%s)
  if [ $((NOW - START)) -gt "$HARD_TIMEOUT" ]; then
    echo ""
    echo "ci-pytest: hard timeout ($HARD_TIMEOUT s) reached without a passing summary line"
    kill -KILL "$WRAPPER_PID" 2>/dev/null
    pkill -KILL -P "$WRAPPER_PID" 2>/dev/null
    exit 124
  fi
  sleep 2
done

if [ "$PYTEST_OK" = "yes" ]; then
  echo ""
  echo "ci-pytest: pytest reported all tests passed; allowing 10 s for clean shutdown"
  GRACE_DEADLINE=$(( $(date +%s) + 10 ))
  while [ "$(date +%s)" -lt "$GRACE_DEADLINE" ]; do
    if ! kill -0 "$WRAPPER_PID" 2>/dev/null; then
      echo "ci-pytest: pytest exited on its own"
      wait "$WRAPPER_PID" 2>/dev/null
      exit 0
    fi
    sleep 1
  done
  echo "ci-pytest: pytest still alive after grace; forcing exit 0 (tests passed)"
  pkill -KILL -P "$WRAPPER_PID" 2>/dev/null
  kill -KILL "$WRAPPER_PID" 2>/dev/null
  exit 0
fi
