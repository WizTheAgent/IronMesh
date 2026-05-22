#!/usr/bin/env bash
# start-daemon-detached.sh — reliably detach an ironmesh daemon over SSH.
#
# Why this script exists:
#   ``nohup ironmesh run ... & disown`` LOOKS like it detaches the
#   daemon from the SSH session, but the shell's session group is
#   kept alive until every child exits. When the SSH connection
#   closes, the controlling terminal goes away and the daemon
#   receives SIGHUP. ``setsid`` puts the daemon in its own session +
#   process group, which is what actually survives logout.
#
# Usage:
#   ssh peer "bash -s" < tools/start-daemon-detached.sh -- \
#       --name my-node --port 8765 --passphrase-file ~/.ironmesh/passphrase
#
# The argument list after ``--`` is forwarded verbatim to ``ironmesh run``.
# Stdout/stderr from the daemon land in ``~/.ironmesh/daemon.log``.
set -euo pipefail

LOG="${IRONMESH_LOG:-$HOME/.ironmesh/daemon.log}"
mkdir -p "$(dirname "$LOG")"

# Use the user-installed ironmesh binary; fall back to module form
# for venv-only setups that didn't put the entry-point on PATH.
if command -v ironmesh >/dev/null 2>&1; then
    CMD=(ironmesh run "$@")
else
    CMD=(python -m ironmesh.cli run "$@")
fi

# setsid puts the daemon in its own session — SSH logout cannot
# SIGHUP it. </dev/null detaches stdin so a closed terminal can't
# block the process on a read.
setsid "${CMD[@]}" </dev/null >>"$LOG" 2>&1 &
DAEMON_PID=$!
disown "$DAEMON_PID" 2>/dev/null || true

echo "started ironmesh daemon (pid=$DAEMON_PID, log=$LOG)"
echo "tail -f $LOG  # to watch startup"
