#!/usr/bin/env bash
# chaos-netem.sh — inject link chaos on a Linux host using tc netem.
#
# Applies packet loss, delay, jitter, or corruption to the IronMesh
# WebSocket port so the harness can exercise the protocol under a lossy
# link without needing real LoRa/radio interference.
#
# Usage:
#   sudo ./chaos-netem.sh apply  --iface eth0 --loss 10% --delay 50ms
#   sudo ./chaos-netem.sh clear  --iface eth0
#
# SAFETY NOTES:
#   - tc rules apply to ALL traffic on the interface, not just IronMesh.
#     Don't run this on an interface carrying SSH from the box you're
#     using to administer the host. Use a secondary interface or console.
#   - `clear` removes ALL qdiscs added by this script; if you've added
#     other netem rules manually they'll also be removed.
#   - Requires root (for tc) and the `iproute2` package.

set -euo pipefail

CMD="${1:-}"
shift || true

IFACE=""
LOSS=""
DELAY=""
JITTER=""
CORRUPT=""
PORT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --iface)   IFACE="$2"; shift 2 ;;
        --loss)    LOSS="$2"; shift 2 ;;
        --delay)   DELAY="$2"; shift 2 ;;
        --jitter)  JITTER="$2"; shift 2 ;;
        --corrupt) CORRUPT="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ -z "$IFACE" ] && { echo "missing --iface" >&2; exit 2; }

case "$CMD" in
    apply)
        args=""
        [ -n "$LOSS" ]    && args="$args loss $LOSS"
        [ -n "$DELAY" ]   && args="$args delay $DELAY ${JITTER:-}"
        [ -n "$CORRUPT" ] && args="$args corrupt $CORRUPT"
        if [ -z "$args" ]; then
            echo "provide at least one of --loss --delay --corrupt" >&2
            exit 2
        fi
        # Drop any existing qdisc first (idempotent)
        tc qdisc del dev "$IFACE" root 2>/dev/null || true
        tc qdisc add dev "$IFACE" root netem $args
        echo "applied netem on $IFACE:$args"
        tc qdisc show dev "$IFACE"
        ;;
    clear)
        tc qdisc del dev "$IFACE" root 2>/dev/null || true
        echo "cleared qdisc on $IFACE"
        ;;
    show)
        tc qdisc show dev "$IFACE"
        ;;
    *)
        cat >&2 <<EOF
Usage:
  sudo $0 apply --iface <name> [--loss <pct>] [--delay <ms>] [--jitter <ms>] [--corrupt <pct>]
  sudo $0 clear --iface <name>
  sudo $0 show  --iface <name>

Examples:
  # 10% random packet loss on eth0
  sudo $0 apply --iface eth0 --loss 10%

  # 50ms ± 10ms jitter
  sudo $0 apply --iface eth0 --delay 50ms --jitter 10ms

  # 1% corruption + 5% loss
  sudo $0 apply --iface eth0 --corrupt 1% --loss 5%

  # Clear everything
  sudo $0 clear --iface eth0
EOF
        exit 2
        ;;
esac
