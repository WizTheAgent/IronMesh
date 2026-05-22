#!/usr/bin/env bash
# transfer-wheel.sh — copy an ironmesh wheel to a remote host with a
# SHA256 verification step.
#
# Why this script exists:
#   Plain ``scp wheel host:~/`` has been observed to complete with
#   exit code 0 while transferring a truncated or zero-byte file
#   over a flaky home WAN. ``rsync --checksum`` would catch it but
#   isn't installed everywhere. Streaming the wheel through ``ssh``
#   to ``cat > path`` plus a remote ``sha256sum`` comparison is the
#   most portable belt-and-suspenders option.
#
# Usage:
#   tools/transfer-wheel.sh dist/ironmesh-0.9.4.2-py3-none-any.whl peer:/tmp/
#
# Exit codes:
#   0  — wheel transferred and checksum matches
#   1  — local file missing
#   2  — transfer failed
#   3  — checksum mismatch after transfer
set -euo pipefail

LOCAL="${1:?usage: $0 <local-wheel> <host>:<remote-dir>}"
DEST="${2:?usage: $0 <local-wheel> <host>:<remote-dir>}"

if [ ! -f "$LOCAL" ]; then
    echo "error: local wheel not found: $LOCAL" >&2
    exit 1
fi

HOST="${DEST%%:*}"
REMOTE_DIR="${DEST#*:}"
WHEEL_NAME="$(basename "$LOCAL")"
REMOTE_PATH="${REMOTE_DIR%/}/$WHEEL_NAME"

# Portable SHA256 helper — Linux has ``sha256sum``, macOS uses
# ``shasum -a 256``. Try both so a macOS remote target works
# without forcing coreutils onto it.
sha256_local() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

LOCAL_SHA="$(sha256_local "$LOCAL")"
echo "local  sha256: $LOCAL_SHA  $LOCAL"

# Stream through ssh + cat rather than scp. cat closes the destination
# on EOF, so a truncated stream is detectable (the remote file ends
# up at the bytes received, NOT padded to the expected size).
if ! cat "$LOCAL" | ssh "$HOST" "cat > '$REMOTE_PATH'"; then
    echo "error: ssh+cat transfer failed" >&2
    exit 2
fi

# Run the same portability dance on the remote end. The single-quoted
# script means $REMOTE_PATH (expanded locally) is the only thing
# interpolated; everything else stays literal for the remote shell.
REMOTE_SHA="$(ssh "$HOST" "
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum '$REMOTE_PATH' | awk '{print \$1}'
    else
        shasum -a 256 '$REMOTE_PATH' | awk '{print \$1}'
    fi
" | tr -d '[:space:]')"
echo "remote sha256: $REMOTE_SHA  $HOST:$REMOTE_PATH"

if [ "$LOCAL_SHA" != "$REMOTE_SHA" ]; then
    echo "error: checksum mismatch after transfer" >&2
    echo "  remote file may be truncated; do not install it" >&2
    exit 3
fi

echo "OK — wheel transferred and verified"
