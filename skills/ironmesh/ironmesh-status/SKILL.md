---
name: ironmesh-status
description: Report IronMesh mesh health — uptime, active peer count, message lifetime percentiles, queue pressure. Use when the user asks "is the mesh ok", "how's ironmesh", or before taking actions that depend on a peer being reachable.
allowed-tools: [Bash]
---

# IronMesh status

Query the local daemon's `/api/mesh_stats` endpoint and summarize the
mesh's health in one screen.

## When to use this

- User asks for mesh health ("status", "is ironmesh up", "peers online")
- Before attempting `ironmesh-send` to a specific peer — verify they're online
- As a sanity check after restarting the daemon

## How to run

```bash
: "${IRONMESH_GUI_PORT:=8766}"
: "${IRONMESH_GUI_TOKEN:?set IRONMESH_GUI_TOKEN from the startup log}"

curl -sS "http://127.0.0.1:${IRONMESH_GUI_PORT}/api/mesh_stats?token=${IRONMESH_GUI_TOKEN}" \
  | python3 -c '
import json, sys, datetime
d = json.load(sys.stdin)
print(f"Node: {d[\"name\"]} ({d[\"node_id\"][:12]}...)")
print(f"Uptime: {int(d[\"uptime_seconds\"])}s")
print(f"Peers: {d[\"active_peers\"]}/{d[\"total_peers\"]} online")
lt = d["message_lifetime"]
if lt["count"] > 0:
    print(f"Lifetime (n={lt[\"count\"]}): p50={lt[\"p50\"]*1000:.1f}ms  p90={lt[\"p90\"]*1000:.1f}ms  p99={lt[\"p99\"]*1000:.1f}ms")
else:
    print("Lifetime: no samples yet")
print()
print(f"{\"peer\":<16} {\"status\":<9} {\"rtt\":>8} {\"retries\":>8}  {\"bytes s/r\":<20}")
for p in d["peers"]:
    nid = (p["name"] or p["node_id"])[:16]
    online = "online" if p["online"] else "offline"
    rtt = f"{p[\"rtt_ms\"]:.1f}ms" if p["rtt_ms"] is not None else "-"
    retries = p["retries_total"]
    bs = p["bytes_sent_total"]
    br = p["bytes_received_total"]
    print(f"{nid:<16} {online:<9} {rtt:>8} {retries:>8}  {bs:>9}/{br:<9}")
'
```

## Interpreting

- **0 online peers** → either you're the only node, or dial is failing. Check the
  daemon log for `mDNS tie-breaker` / `TLS connection failed` lines.
- **retries_total grows** on a peer → intermittent link. Check `ironmesh-audit`
  for `PEER_DROPPED_LONG` events.
- **Lifetime p99 > 1s** → mesh is congested or a peer is slow to respond.
  Check per-peer RTT to pinpoint.
- **No lifetime samples** → no application traffic yet; PING/PONG doesn't count.
  Send a real MSG through the mesh to populate.

## Expected output (healthy 3-node mesh)

```
Node: alice (abc123def456...)
Uptime: 429s
Peers: 3/3 online
Lifetime (n=14): p50=165.8ms  p90=167.5ms  p99=168.5ms

peer             status       rtt  retries  bytes s/r
611979d276ae2c4  online     7.4ms        0          0/0
93dba8f3a5edefc  online    13.2ms        0       1234/567
65939b76915e702  online    11.9ms        0       456/789
```
