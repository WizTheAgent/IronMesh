# IronMesh Metrics Reference

Catalog of every metric IronMesh exports. Stable under the v1.0
stability promise (see `STABILITY_PROMISE.md §1`): new counters may be
added, existing names + label keys will not be renamed or removed.

All counters are monotonic `_total`-suffixed series. Gauges are
instantaneous snapshots sampled each scrape.

## Base endpoint

The Prometheus text format is served at `/metrics` on the daemon's
control port when `--metrics-format prometheus` (the default) is set.
A JSON shape is available at `/api/metrics` on the GUI endpoint for
dashboards that can't consume Prometheus directly.

## Transport + handshake

| Metric | Type | Meaning |
|---|---|---|
| `ironmesh_connections_total` | counter | WebSocket + RNS Link connections accepted |
| `ironmesh_handshake_successes_total` | counter | Full handshakes that produced a peer_id |
| `ironmesh_handshake_failures_total` | counter | Handshake rejections (bad passphrase, version mismatch, timeout) |
| `ironmesh_rate_limits_triggered_total` | counter | Connect / message rate limits hit |
| `ironmesh_handshake_skips_offered_total` | counter | v0.9.2: server emitted SKIP_OFFER on an identified RNS Link |
| `ironmesh_handshake_skips_activated_total` | counter | v0.9.2: client accepted a SKIP_OFFER (skip is fully on). Healthy fleet sums of `offered` and `activated` should match — divergence reveals send failures or downgrade-rejects. |
| `ironmesh_handshake_skips_rejected_total` | counter | v0.9.2: client rejected a SKIP_OFFER (missing/non-hex/wrong channel_binding). Should be ~0 on healthy meshes; a spike is alert-worthy — buggy peer or downgrade attempt. |
| `ironmesh_peer_long_drops_total` | counter | Peer offline > long-drop threshold |
| `ironmesh_peer_bandwidth_drops_total` | counter | Peer dropped due to sustained low throughput |

## Messages

| Metric | Type | Meaning |
|---|---|---|
| `ironmesh_messages_sent_total` | counter | Application-layer messages sent (post-encryption) |
| `ironmesh_messages_received_total` | counter | Application-layer messages received |
| `ironmesh_messages_delivered_total` | counter | Messages that reached a terminal peer (direct or relay-tail) |
| `ironmesh_messages_failed_total` | counter | Messages that never reached their destination |
| `ironmesh_messages_relayed_total` | counter | Frames forwarded as a mesh hop |
| `ironmesh_messages_received_blocked_total` | counter | Inbound messages blocked by pending-trust gate |
| `ironmesh_bytes_sent_total` | counter | Total bytes sent across all transports |
| `ironmesh_bytes_received_total` | counter | Total bytes received |

## Mesh routing

| Metric | Type | Meaning |
|---|---|---|
| `ironmesh_route_lookup_failures_total` | counter | `get_route` returned None for a destination |
| `ironmesh_dedup_cache_size` | gauge | Current dedup-cache entry count |
| `ironmesh_e2e_decrypt_failures_total` | counter | Tampered or wrong-key sealed envelopes |

## v0.9.2 agent-interop surfaces

| Metric | Type | Meaning |
|---|---|---|
| `ironmesh_capability_routes_attempted_total` | counter | `send_to_capability()` calls regardless of outcome |
| `ironmesh_capability_routes_succeeded_total` | counter | Calls that reached at least one peer |
| `ironmesh_capability_routes_no_match_total` | counter | Calls that found no online candidate |
| `ironmesh_group_broadcasts_sent_total` | counter | Outbound packets on RNS GROUP destination |
| `ironmesh_group_broadcasts_received_total` | counter | Inbound packets from GROUP (post-dedup) |
| `ironmesh_group_broadcasts_deduped_total` | counter | GROUP packets suppressed by payload-hash dedup |

## Trust + capability lifecycle

| Metric | Type | Meaning |
|---|---|---|
| `ironmesh_peer_promoted_total` | counter | Operator promoted a pending peer |
| `ironmesh_peer_blocked_total` | counter | Operator blocked a peer (local-only) |
| `ironmesh_peer_revoked_local_total` | counter | Local revocation of a pinned peer |
| `ironmesh_peer_state_changed_total` | counter | Any other trust-state transition |
| `ironmesh_peer_cap_set_changed_total` | counter | A peer's capability set changed vs. baseline |
| `ironmesh_peer_cap_baseline_total` | counter | First capability set seen for a peer (baselined) |
| `ironmesh_peer_cap_accepted_total` | counter | Operator accepted a capability change |
| `ironmesh_peer_cap_binding_partial_total` | counter | Capability binding partially verified |
| `ironmesh_msg_replay_cross_transport_total` | counter | Same message seen across two transports |

## Pending-trust queue

| Metric | Type | Meaning |
|---|---|---|
| `ironmesh_pending_queue_dropped_total` | counter | Messages dropped when the queue was full |
| `ironmesh_pending_queue_evicted_total` | counter | Oldest message evicted to make room |
| `ironmesh_pending_trust_dropped_total` | counter | Pending-trust gate rejected a message |
| `ironmesh_pending_trust_evicted_total` | counter | Trust-gate eviction due to queue cap |

## Sessions + LoRa

| Metric | Type | Meaning |
|---|---|---|
| `ironmesh_session_rekeys_total` | counter | Session-key rotations completed |
| `ironmesh_lora_oversized_messages_total` | counter | Frames that exceeded the LoRa payload cap |

## Per-peer labelled metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ironmesh_peer_online` | gauge | `peer`, `name` | 1 if connected, 0 otherwise |
| `ironmesh_peer_rtt_ms` | gauge | `peer`, `name` | Most recent round-trip measurement |
| `ironmesh_peer_retries_total` | counter | `peer`, `name` | Send retries for this peer |
| `ironmesh_peer_bytes_sent_total` | counter | `peer`, `name` | Bytes sent to this peer |
| `ironmesh_peer_bytes_received_total` | counter | `peer`, `name` | Bytes received from this peer |

## Audit + security

| Metric | Type | Meaning |
|---|---|---|
| `ironmesh_audit_tamper_detected_total` | counter | HMAC-chain verification failed |

## OpenTelemetry spans

When the `otel` extra is installed, the following span names are
emitted on the public Agent surfaces. Names are stable under §1.

| Span / event | Layer | Kind | Triggered by |
|---|---|---|---|
| `ironmesh.send_to_name` | agent | span | `Agent.send_to_name` |
| `ironmesh.send_to_capability` | agent | span | `Agent.send_to_capability` |
| `ironmesh.send_message` | bridge | span | Daemon-level outbound dispatch (parent of the two agent spans) |
| `handshake.skip.offered` | transport | event | Server emitted `SKIP_OFFER` on an identified RNS Link |
| `handshake.skip.activated` | transport | event | Client accepted a `SKIP_OFFER` (skip is fully on) |
| `peer.cap.baseline` | bridge | event | First capability set received from a newly-pinned peer |
| `peer.cap.accepted` | bridge | event | Peer-advertised capability set was accepted into the local registry |
| `peer.cap.set_changed` | bridge | event | A previously-known peer's capability set changed |

### Attribute keys

Span and event attributes follow the `ironmesh.<surface>.<field>`
convention so they don't collide with attributes from other libraries
in shared OTel exporters. Names are stable under §1 of the stability
promise.

| Attribute | Type | Where | Meaning |
|---|---|---|---|
| `ironmesh.peer.node_id` | string | `ironmesh.send_message` | Destination node_id (32-hex Ed25519 fingerprint) |
| `ironmesh.peer.name` | string | `ironmesh.send_to_name` | Destination agent name (human-friendly) |
| `ironmesh.peer.label` | string | `handshake.skip.activated` | Free-form peer label used in handshake-completion logging |
| `ironmesh.message.priority` | string | `ironmesh.send_*` | `CRITICAL` / `HIGH` / `NORMAL` / `LOW` |
| `ironmesh.message.size_bytes` | int | `ironmesh.send_message`, `send_to_name` | Payload byte length |
| `ironmesh.message.type` | string | `ironmesh.send_*` | MessageType enum value (`MSG`, `CONV`, `GROUP_BROADCAST`, …) |
| `ironmesh.cap.pattern` | string | `ironmesh.send_to_capability` | The fnmatch glob the caller passed |
| `ironmesh.cap.strategy` | string | `ironmesh.send_to_capability` | `first` / `random` / `all` |
| `ironmesh.skip.side` | string | `handshake.skip.{offered,activated}` | `server` (offered) or `client` (activated) |
| `ironmesh.transport` | string | `handshake.skip.{offered,activated}` | Transport carrying the handshake (`rns`, `ws`, `lxmf`) |

**Legacy attribute keys (peer.cap.* events).** The events
`peer.cap.{baseline,accepted,set_changed}` shipped in v0.8.5.7
predating the namespace convention and use bare attribute keys
(`capability_count`, `capability_hash`, `new_hash`, `added`,
`removed`, `demoted`, `stashed`). These are frozen for v1.0
backwards compatibility; renaming would break any operator
already consuming them. New events MUST use the
`ironmesh.<surface>.<field>` convention.

## Alert rules pack

Canonical alert rules live at `scripts/observability/prometheus-alerts.yml`.
Drop into your Prometheus `rule_files:`. The rules cover:

* handshake failure spikes + stalled handshakes
* audit-chain tamper
* mesh route unreachable (convergence broken)
* peer long-drop
* RNS Resource transfer stalls
* handshake-skip failure rate
* capability registry unexpected growth
* LXMF backlog
* v0.9.2: capability-route no-match spike
* v0.9.2: GROUP broadcast dedup storm (echo loop detection)

## Grafana dashboard

A pre-canned dashboard JSON lives at
`scripts/observability/grafana-dashboard.json` — 10 panels covering
the above series. Import via Grafana's "Upload JSON file" workflow.
