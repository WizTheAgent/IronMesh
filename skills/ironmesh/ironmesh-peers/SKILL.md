---
name: ironmesh-peers
description: Drill into per-peer IronMesh metrics — retry reasons, session rekeys, offline-since, transport type. Use when `ironmesh-status` shows a problem on a specific peer and you need detail.
allowed-tools: [Bash]
---

# IronMesh peer detail

Show every known peer with full metrics, including retry breakdown by
reason and session rekey history. Useful for diagnosing a flaky peer.

## When to use

- After `ironmesh-status` shows a peer offline or with a high retry count
- When tracking down why bandwidth to a specific peer is low
- Before a rekey investigation — confirm `session_rekey_count` is what you expect

## How to run

```bash
: "${IRONMESH_GUI_PORT:=8766}"
: "${IRONMESH_GUI_TOKEN:?set IRONMESH_GUI_TOKEN}"

# Optional filter: first arg = peer name or node_id fragment
FILTER="${1:-}"

curl -sS "http://127.0.0.1:${IRONMESH_GUI_PORT}/api/mesh_stats?token=${IRONMESH_GUI_TOKEN}" \
  | python3 -c '
import json, sys, datetime
d = json.load(sys.stdin)
flt = sys.argv[1] if len(sys.argv) > 1 else None
for p in d["peers"]:
    if flt and flt not in (p["name"] or "") and flt not in p["node_id"]:
        continue
    print(f"--- {p[\"name\"] or p[\"node_id\"][:16]} ---")
    print(f"  node_id:             {p[\"node_id\"]}")
    print(f"  status:              {\"online\" if p[\"online\"] else \"offline\"}")
    print(f"  transport:           {p[\"transport\"]}")
    print(f"  rtt_ms:              {p[\"rtt_ms\"]}")
    print(f"  messages sent/recv:  {p[\"messages_sent\"]}/{p[\"messages_received\"]}")
    print(f"  bytes sent/recv:     {p[\"bytes_sent_total\"]}/{p[\"bytes_received_total\"]}")
    print(f"  retries_total:       {p[\"retries_total\"]}")
    if p["retries_by_reason"]:
        for reason, count in sorted(p["retries_by_reason"].items(), key=lambda x: -x[1]):
            print(f"    {reason}: {count}")
    print(f"  session_rekeys:      {p[\"session_rekey_count\"]}")
    if p["last_seen"]:
        ago = datetime.datetime.fromtimestamp(p["last_seen"]).strftime("%H:%M:%S")
        print(f"  last_seen:           {ago}")
    print()
' -- "$FILTER"
```

## Common retry reasons

| Reason | Meaning | What to check |
|---|---|---|
| `direct_send_failed` | WS send raised before reaching peer | Peer WS session died; usually recovers via reconnect |
| `routed_send_failed` | Mesh relay next-hop was unreachable | Routing table stale; wait for next announce |
| `queued_offline` | Peer was offline → went to pending store | Normal; will flush when peer returns |
| `queue_full_dropped` | Pending store at cap, this msg was lower priority than all queued | Raise cap or drain the queue |
| `bandwidth_throttled` | Per-peer bytes/sec budget exhausted | Peer is being flooded; budget needs tuning |
| `rekey_failed` | Session key rotation errored | Check daemon log; session is still usable pre-rekey |
