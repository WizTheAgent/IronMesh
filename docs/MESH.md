# IronMesh — Multi-Hop Mesh Routing

IronMesh v0.4 makes the mesh real. Messages can now traverse intermediate
nodes to reach destinations that are not directly connected. This document
describes how routing works, what the trust model is, and how to operate a
multi-hop mesh.

---

## TL;DR

- Distance-vector routing with split horizon + poisoned reverse.
- Default mode: `--mesh-routing=relay` — every node forwards.
- Each hop re-encrypts with its outbound session key.
- Message bodies are also wrapped in NaCl `SealedBox` end-to-end so relays
  cannot read them.
- Inner Ed25519 signature over the plaintext provides end-to-end source
  authenticity even after per-hop re-encryption.
- v0.3 peers remain interoperable as direct-only nodes; mesh forwarding is
  refused for them.

---

## Routing model

IronMesh uses **proactive distance-vector routing** with two well-known
loop-prevention tricks:

| Mechanism | What it prevents |
|-----------|------------------|
| TTL counter (default 5) | Bounded message lifetime |
| Hop list inspection | Per-message loop detection |
| Split horizon | Don't advertise a route back to the peer it came from |
| Poisoned reverse | When you do, advertise it as cost ∞ |
| Per-source dedup cache | Drop duplicates (replays, broadcast storms) |

Every node periodically (`--route-announce-interval`, default 30 s) sends a
`ROUTE_ANNOUNCE` message to each direct neighbor containing its known
routing table, filtered through split horizon + poisoned reverse.

When a node receives a `ROUTE_ANNOUNCE` it learns or refreshes routes, each
tagged with `(next_hop, cost, learned_from, learned_at)`. Routes that have
not been refreshed within `--route-ttl` (default 90 s) are evicted by the
cleanup loop. Routes are persisted to `~/.ironmesh/routes.json` (HMAC-
protected) and reloaded on startup with a shortened TTL so a Pi reboot
doesn't black-hole the mesh for 90 seconds.

If every destination becomes unreachable for longer than `2 × route_ttl`
the daemon emits an `EVENT_MESH_PARTITION_SUSPECTED` audit event.

---

## Three modes

| Mode | Forwards | Learns | Sends own routes | Use case |
|------|----------|--------|------------------|----------|
| `off` | No | No | No | Pure point-to-point, paranoid mode |
| `passive` | No | Yes | Yes | Listen-only relay (still discovers peers) |
| `relay` (default) | Yes | Yes | Yes | Full mesh participation |

```bash
ironmesh run --mesh-routing=relay --max-hops=5
```

---

## Trust model

**Read this before deploying a relay-by-default mesh.**

When your node is a relay, you are forwarding messages on behalf of other
agents. The end-to-end encryption (NaCl `SealedBox`) means **you cannot read
the message bodies**, but there is still metadata you can see and metadata
that other nodes can see about you:

| What relays can see | What relays cannot see |
|---|---|
| `frame.source` (the originator's node id) | The plaintext payload |
| `frame.destination` (the final recipient) | The inner Ed25519 source signature contents |
| `frame.msg_id` and timestamp | The original `MessageType` payload schema (only the wire MessageType is visible — the body is opaque) |
| The wire `MessageType` (e.g. `MSG`, `CONTROL`) | |
| The encrypted `e2e_payload` ciphertext | |

**Threats this mitigates:**

- A compromised or malicious relay cannot read message bodies.
- A relay cannot forge messages from another node — the inner Ed25519
  signature would fail at the destination.
- A flooding attacker cannot bloat your dedup cache: it is sharded per
  source with a hard cap.
- A route announcement attacker cannot poison your table forever:
  routes expire after `route_ttl`.

**Threats this does NOT mitigate:**

- Traffic analysis. A relay can see who is talking to whom, when, and how
  often. If anonymity matters to your use case, do not use IronMesh in
  relay mode — the goal is *confidentiality*, not anonymity.
- Active denial of service. A relay can simply drop your messages.
  IronMesh tracks per-peer failures with a circuit breaker and audit logs,
  but cannot route around an adversarial neighbor without an alternate
  topology.
- Compromise of the destination key. End-to-end confidentiality only holds
  if the destination's long-term Ed25519 key has not been exfiltrated.

If your operational threat model includes "I do not trust my mesh peers
not to drop or analyze my traffic", run with `--mesh-routing=off` and
build a closed clique of trusted peers using `--allowed-peers`.

---

## End-to-end encryption (e2e)

When `BridgeDaemon.send_message(to_node, payload)` is called and the
destination's identity key is known (either via the live peer registry or
the TOFU pinned store), IronMesh wraps the plaintext in a NaCl `SealedBox`
keyed to the destination's X25519 public key (derived from its Ed25519
identity key via libsodium's blessed `crypto_sign_ed25519_pk_to_curve25519`
helper).

The sealed ciphertext is carried in `Frame.e2e_payload` and is opaque to
every relay along the path. Only the destination — which holds the matching
secret key — can decrypt it.

**Forward secrecy.** `SealedBox` generates a fresh ephemeral X25519 keypair
for every call, so even if the destination's long-term identity key were
later compromised, past sealed messages remain unrecoverable (as long as the
ephemeral keys, which are never persisted, were also discarded).

**Inner source signature.** Because each relay re-encrypts the outer wrap
with the next-hop session key, the existing per-hop Ed25519 signature
cannot be used to authenticate the original source past the first hop.
v0.4 adds an *inner* Ed25519 detached signature computed over the plaintext
payload by the source's long-term key. This signature lives inside the
encrypted body, survives every re-encryption, and is verified by the
destination using the source's identity key.

If e2e cannot be used (destination key unknown), IronMesh falls back to
per-hop encryption only and logs a warning.

---

## Three-node quick start

This walks you through the simplest non-trivial topology: `node-a — node-b —
node-c`, where `a` and `c` cannot connect directly but can talk through `b`.

```bash
# Terminal 1: node-a
ironmesh run \
  --name node-a \
  --port 8765 \
  --keys-path ~/.ironmesh/a.keys \
  --passphrase-file ~/.ironmesh/a.pass \
  --allowed-peers node-b

# Terminal 2: node-b (the relay)
ironmesh run \
  --name node-b \
  --port 8766 \
  --keys-path ~/.ironmesh/b.keys \
  --passphrase-file ~/.ironmesh/b.pass

# Terminal 3: node-c
ironmesh run \
  --name node-c \
  --port 8767 \
  --keys-path ~/.ironmesh/c.keys \
  --passphrase-file ~/.ironmesh/c.pass \
  --allowed-peers node-b
```

Within `2 × route_announce_interval` (default 60 s) seconds, `node-a` will
have learned a route to `node-c` via `node-b`. From `node-a`'s GUI you can
send a message to `node-c`'s fingerprint and it will arrive — `node-b`'s
audit log will contain an `EVENT_MESSAGE_RELAYED` entry, and the relayed
ciphertext on `node-b` will be opaque.

---

## Operational metrics

All mesh-related counters are exported in Prometheus format at
`http://127.0.0.1:<gui-port>/metrics?token=<gui-token>`:

```
# HELP ironmesh_routes_known Number of routes in the routing table.
# TYPE ironmesh_routes_known gauge
ironmesh_routes_known 4

# HELP ironmesh_messages_relayed_total Total messages forwarded for other peers.
# TYPE ironmesh_messages_relayed_total counter
ironmesh_messages_relayed_total 178

# HELP ironmesh_route_lookup_failures_total Failed next-hop lookups.
# TYPE ironmesh_route_lookup_failures_total counter
ironmesh_route_lookup_failures_total 2

# HELP ironmesh_dedup_cache_size Total entries currently in the dedup cache.
# TYPE ironmesh_dedup_cache_size gauge
ironmesh_dedup_cache_size 47

# HELP ironmesh_circuit_breakers_open Peers with open circuit breakers.
# TYPE ironmesh_circuit_breakers_open gauge
ironmesh_circuit_breakers_open 0
```

---

## Configuration reference

| Flag | Default | Meaning |
|---|---|---|
| `--mesh-routing` | `relay` | `off` / `passive` / `relay` |
| `--max-hops` | `5` | Initial TTL applied to outbound frames |
| `--route-announce-interval` | `30.0` | Seconds between `ROUTE_ANNOUNCE` broadcasts |
| `--route-ttl` | `90.0` | Seconds before a learned route is evicted |
| `--routes-path` | `~/.ironmesh/routes.json` | Persistence file (HMAC-protected) |
| `--metrics-format` | `prometheus` | `prometheus` or `json` for `/metrics` |
| `--log-format` | `text` | `text` or `json` for stderr logs |

---

## Further reading

- `docs/PROTOCOL.md` — wire format, message schemas, frame layout.
- `docs/SECURITY.md` — full threat model and crypto rationale.
- `docs/CAPABILITIES.md` — capability advertisement and discovery.
