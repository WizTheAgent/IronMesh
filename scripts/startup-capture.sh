#!/usr/bin/env bash
# startup-capture.sh — launch IronMesh, log the GUI token to disk and stdout,
# then tail the daemon log. Designed for systemd ExecStart= on headless
# nodes where operators need the token for remote dashboard access.
#
# Usage:
#   IRONMESH_HOME=/var/lib/ironmesh ./startup-capture.sh [extra args...]
#
# Environment:
#   IRONMESH_HOME         — base dir (default: $HOME/.ironmesh)
#   IRONMESH_NAME         — node name (default: hostname)
#   IRONMESH_PORT         — WebSocket port (default: 8765)
#   IRONMESH_PASSPHRASE_FILE — path to passphrase file (default: $IRONMESH_HOME/passphrase)
#   IRONMESH_TOKEN_LOG    — where to append GUI tokens (default: /var/log/ironmesh-token.log)
#
# Rationale: GUI tokens rotate on every startup. When the daemon boots
# headless, there's no easy way to grab the token later.  Writing it to a
# known location (with 0600 perms) lets "ironmesh dashboard" on an operator
# workstation retrieve the latest token via SSH without needing to grep
# systemd journal.

set -euo pipefail

IRONMESH_HOME="${IRONMESH_HOME:-$HOME/.ironmesh}"
IRONMESH_NAME="${IRONMESH_NAME:-$(hostname -s)}"
IRONMESH_PORT="${IRONMESH_PORT:-8765}"
IRONMESH_PASSPHRASE_FILE="${IRONMESH_PASSPHRASE_FILE:-$IRONMESH_HOME/passphrase}"
IRONMESH_TOKEN_LOG="${IRONMESH_TOKEN_LOG:-/var/log/ironmesh-token.log}"

mkdir -p "$IRONMESH_HOME"
if [ ! -f "$IRONMESH_PASSPHRASE_FILE" ]; then
    echo "ERROR: passphrase file not found: $IRONMESH_PASSPHRASE_FILE" >&2
    exit 2
fi

# Start the daemon, capturing stdout+stderr. Extract the GUI token line as
# soon as it appears, append to the token log, print to stdout, continue
# tailing. tee lets systemd journal capture everything too.
LOG_FIFO=$(mktemp -u --suffix=.fifo)
mkfifo "$LOG_FIFO"
trap 'rm -f "$LOG_FIFO"' EXIT

# Token extractor runs in the background reading from the FIFO
(
    while IFS= read -r line; do
        echo "$line"
        if [[ "$line" == *"GUI token:"* ]]; then
            token="${line##*GUI token: }"
            token="${token%% *}"
            ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
            entry="$ts $IRONMESH_NAME port=$IRONMESH_PORT token=$token"
            echo "[startup-capture] $entry"
            umask 077
            echo "$entry" >> "$IRONMESH_TOKEN_LOG" 2>/dev/null || true
        fi
    done < "$LOG_FIFO"
) &

exec ironmesh run \
    --name "$IRONMESH_NAME" \
    --port "$IRONMESH_PORT" \
    --passphrase-file "$IRONMESH_PASSPHRASE_FILE" \
    --gui \
    "$@" 2>&1 | tee "$LOG_FIFO"
