---
name: ironmesh-audit
description: Tail the tamper-evident IronMesh audit log for security events. Use when investigating a TOFU mismatch, auth failure, peer dropping out, or a suspected attack.
allowed-tools: [Bash]
---

# IronMesh audit log

Reads the last N entries from the HMAC-chained audit log. Used for
security investigations — every entry is chained to the previous via
HMAC-SHA256, so tampering breaks the chain and `ironmesh audit verify`
will flag it.

## When to use

- User reports "can't connect to X" — look for `TOFU_MISMATCH` or `AUTH_BLOCKED`
- Investigating a peer that went offline — look for `PEER_DROPPED_LONG`
- Security review — look for any unexpected `KEY_ROTATION`, `REPLAY_DETECTED`, or `DECRYPT_FAILURE`

## How to run

```bash
: "${IRONMESH_AUDIT_LOG:=$HOME/.ironmesh/audit.log}"

LIMIT="${1:-50}"
FILTER="${2:-}"   # optional: grep filter (e.g. TOFU_MISMATCH)

if [ ! -f "$IRONMESH_AUDIT_LOG" ]; then
    echo "No audit log at $IRONMESH_AUDIT_LOG"
    exit 1
fi

tail -n "$LIMIT" "$IRONMESH_AUDIT_LOG" \
  | ( [ -n "$FILTER" ] && grep -i "$FILTER" || cat ) \
  | python3 -c "
import json, sys, datetime
for line in sys.stdin:
    try:
        e = json.loads(line)
        ts = datetime.datetime.fromtimestamp(e['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        event = e.get('event', '?')
        data = e.get('data', {})
        print(f'{ts} {event:<22} {json.dumps(data)}')
    except Exception:
        print(f'(unparseable) {line.rstrip()}')
"
```

## Known events

| Event | Meaning |
|---|---|
| `STARTUP` / `SHUTDOWN` | Daemon lifecycle |
| `PEER_CONNECT` / `PEER_DISCONNECT` | Normal peer state changes |
| `PEER_DROPPED_LONG` | Peer offline past threshold (default 5 min) — **investigate** |
| `TOFU_NEW_PEER` | First time we saw this peer identity — normal at init |
| `TOFU_MISMATCH` | **MITM candidate** — peer presented a different key than pinned |
| `AUTH_FAILURE` | Wrong passphrase or malformed challenge |
| `AUTH_IP_BLOCKED` | 3 auth failures in 5 min → IP blocked for 5 min |
| `DECRYPT_FAILURE` / `E2E_DECRYPT_FAILURE` | Ciphertext failed verification — protocol bug or attacker |
| `SIGNATURE_FAILURE` | Ed25519 signature didn't verify |
| `REPLAY_DETECTED` | Replayed sequence number or timestamp |
| `KEY_ROTATION` | Session key rotated (expected periodically) |
| `ROUTE_ANNOUNCED` / `ROUTE_LEARNED` / `ROUTE_EXPIRED` | Mesh routing table changes |

## Verifying chain integrity

```bash
ironmesh audit verify
```

Fails loudly if any entry was modified or deleted. Run this as part of
regular ops sanity checks.
