# Observability — OpenTelemetry + Prometheus + Grafana

IronMesh ships three observability surfaces:

1. **Prometheus metrics** — counters, gauges, and histograms exposed on
   the dashboard's `/metrics` endpoint (since v0.7.2). Per-peer
   labels for RTT, retries, bytes, queue depth, gate decisions.
2. **Structured JSON logs** — set `--log-format=json` for newline-
   delimited JSON, ingestable by Loki / Elasticsearch / any aggregator.
3. **OpenTelemetry traces** (NEW in v0.8.5.5) — distributed-tracing
   spans on the message dispatch path. Optional, off by default.

This doc covers all three plus a reference Grafana dashboard you can
import in 30 seconds.

## OpenTelemetry — quick start

```bash
# Install the optional extra
pip install ironmesh[otel]

# Point at any OTLP-compatible collector. Example: Jaeger all-in-one
docker run -d --name jaeger -p 4318:4318 -p 16686:16686 \
    jaegertracing/all-in-one:latest

# Run the daemon with telemetry on
export OTEL_SERVICE_NAME=ironmesh-alice
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_RESOURCE_ATTRIBUTES=node.name=alice,deployment.env=homelab
ironmesh run --name alice --port 8765 --passphrase-file ~/.ironmesh/passphrase
```

Then send a few messages. Open the Jaeger UI at
[http://localhost:16686](http://localhost:16686), pick `ironmesh-alice`
from the service dropdown, click "Find Traces." You'll see one span
per `send_message` call, decorated with peer node id, message type,
priority, and payload size.

## Configuration

All standard OTel env vars work. The most useful:

| Variable | Default | Notes |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | **Required to enable.** No endpoint = no-op telemetry. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | The IronMesh extra installs the HTTP/protobuf exporter. |
| `OTEL_SERVICE_NAME` | `ironmesh` | Set per-node so traces are distinguishable. |
| `OTEL_RESOURCE_ATTRIBUTES` | empty | Comma-separated `key=value` pairs added to every span. |
| `OTEL_TRACES_SAMPLER` | parent-based | Set to `traceidratio` + `OTEL_TRACES_SAMPLER_ARG=0.1` for 10% sampling under load. |
| `OTEL_BSP_MAX_QUEUE_SIZE` | `2048` | Bump if you see "BatchSpanProcessor: queue is full" warnings. |

## What's instrumented (v0.8.5.5)

- **`ironmesh.send_message`** — top-level outbound dispatch. Attributes:
  `ironmesh.peer.node_id`, `ironmesh.message.type`,
  `ironmesh.message.priority`, `ironmesh.message.size_bytes`.

Coming in subsequent patch / minor releases:

- `ironmesh.handshake.passphrase` / `.ecdh` / `.hello` — per-stage
  handshake spans
- `ironmesh.mesh.route` — multi-hop routing decisions
- `ironmesh.mcp.tool_call` — every MCP tool invocation
- `ironmesh.audit.append` — audit-log append latency

The wrapper module (`ironmesh/telemetry.py`) is a thin no-op shim by
default: importing it on a vanilla install is safe and free. Telemetry
only activates when both the extra is installed AND
`OTEL_EXPORTER_OTLP_ENDPOINT` is set.

## Prometheus metrics

Always-on (no extras required). Scrape with:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: ironmesh
    static_configs:
      - targets: ['127.0.0.1:8766']
        labels:
          instance: alice
    params:
      token: ['<dashboard-bearer-token>']
    metrics_path: /metrics
```

The dashboard's `/metrics` endpoint is bearer-token-gated using the
same token printed at daemon startup. Pass it via the `?token=`
query param as shown above (Prometheus's URL-rewrite-style auth).

Notable series:

```
ironmesh_peer_online{peer,name}                 0 or 1
ironmesh_peer_rtt_ms{peer,name}                  latest PING RTT
ironmesh_peer_retries_total{peer,name}           cumulative retries
ironmesh_peer_bytes_sent_total{peer,name}        outbound bytes
ironmesh_peer_bytes_received_total{peer,name}    inbound bytes
ironmesh_message_lifetime_seconds{quantile}      end-to-end histogram
ironmesh_pending_queue_dropped_total              queue cap hits
ironmesh_peer_bandwidth_drops_total              bandwidth cap hits
ironmesh_peer_long_drops_total                    long-drop alerts
ironmesh_gate_enabled                             0 or 1
ironmesh_pending_trust_evicted                   v0.8.5.2+
ironmesh_pending_trust_dropped                   v0.8.5.2+
ironmesh_messages_received_blocked               v0.8.5.2+
ironmesh_peer_cap_set_changed_total              v0.8.5.7+
ironmesh_peer_cap_baseline_total                 v0.8.5.7+
ironmesh_peer_cap_accepted_total                 v0.8.5.7+
ironmesh_peer_cap_binding_partial_total          v0.8.5.7+
ironmesh_msg_replay_cross_transport_total        v0.8.5.7+
ironmesh_peer_revoked_local_total                v0.8.5.7+
ironmesh_peer_state_changed_total                v0.8.5.7+
ironmesh_peer_promoted_total                     v0.8.5.7+
ironmesh_peer_blocked_total                      v0.8.5.7+
```

### Counter continuity across restart

Starting in v0.8.5.8 the daemon reconciles mirrored counters against
the tail of the audit log (last 10,000 entries) on startup. Before
this, every mirrored counter reset to zero on restart, which produced
a negative delta that Prometheus reports as a counter reset — noisy
in Grafana's `rate()` and `increase()` queries. The reconciliation
seeds each counter to match the tail so the restart is invisible to
downstream alerts. If the audit log is larger than the bound, older
events don't contribute — operators running very long
`increase(...)` windows should expect a one-time edge effect at log
rotation boundaries.

### Drift protection

Each mirrored counter is bumped BEFORE its paired audit event reaches
disk, with a reservation against the audit-log scanner's dedup window
so the scanner doesn't also count the event. If the audit emit fails
(disk pressure, filesystem error), the reservation is released so the
counter stays consistent with the durable event count. This is
handled by `BridgeDaemon._emit_audit_with_reservation` and enforced
by a static-analysis test (`tests/test_bridge.py::TestCounterDriftOnAuditFailure`)
that fails CI if a new call site spells out reserve/emit by hand.

## Structured JSON logs

```bash
ironmesh run --log-format json --log-file /var/log/ironmesh.log
```

Each log record is a JSON object with stable keys: `ts`, `level`,
`logger`, `message`, plus contextual fields (`peer_id`, `msg_id`,
`event` for security events). Parse directly with `jq`:

```bash
tail -f /var/log/ironmesh.log | jq 'select(.level=="ERROR")'
```

## Reference Grafana dashboard

A starter dashboard JSON is at
[`grafana/ironmesh-dashboard.json`](grafana/ironmesh-dashboard.json).
Import via the Grafana UI:

1. Side menu → Dashboards → Import
2. Upload JSON
3. Select your Prometheus data source
4. Click Import

Five panels:

- **Peers online** — live count by node
- **Per-peer RTT (p50, p95)** — heatmap
- **Message lifetime** — quantile lines
- **Backpressure events** — queue / bandwidth / long-drop counters
- **Pending-trust gate** — gated / dropped / blocked rates

Customize freely; the dashboard is meant as a starting point, not a
finished product.

## Audit log inspection

Outside the metrics surface, the audit log is the forensic ground
truth. Tail it as JSON for live observability:

```bash
ironmesh audit verify --path ~/.ironmesh/audit.log
tail -f ~/.ironmesh/audit.log | jq 'select(.event | startswith("MSG_GATED"))'
```

Audit events are HMAC-chained — the `verify` command recomputes the
chain and refuses corrupted history.

## Troubleshooting

- **No traces in Jaeger.** Confirm `OTEL_EXPORTER_OTLP_ENDPOINT` is
  set BEFORE the daemon starts. The env var is read once at first
  span emission; changing it post-startup has no effect (restart
  required).
- **`pip install ironmesh[otel]` fails.** The extras pull in
  `opentelemetry-exporter-otlp-proto-http`, which has a transitive
  dep on protobuf. On Alpine / musl, you may need
  `apk add gcc musl-dev linux-headers` first.
- **"BatchSpanProcessor: queue is full"** in logs means the exporter
  can't keep up. Bump `OTEL_BSP_MAX_QUEUE_SIZE=8192` and / or set
  `OTEL_TRACES_SAMPLER=traceidratio` with
  `OTEL_TRACES_SAMPLER_ARG=0.1` for 10% sampling.
- **Prometheus 401 on /metrics.** The dashboard token gates
  `/metrics`. Pass `?token=<token>` in the scrape config (see above).
