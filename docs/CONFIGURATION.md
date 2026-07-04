# IronMesh Configuration Reference

Every configurable knob in one place. This is the source of truth —
if a flag, env var, or file path is documented elsewhere, it should
also appear here.

## Precedence

For `ironmesh run`, when multiple sources set the same value, later
wins:

1. Defaults compiled into the daemon
2. Environment variable (`IRONMESH_*`)
3. CLI flag (`--name`, `--port`, etc.)

The first-run wizard does not write a config file — it prints the
full `ironmesh run` command to reuse (effectively a stored CLI
command). The JSON config file below is a library surface, not read
by `ironmesh run`. The **passphrase** has its own priority chain —
see [Passphrase sources](#passphrase-sources) below.

## JSON config file

The `IronMeshConfig` dataclass in `ironmesh/config.py` can load
`~/.ironmesh/config.json` (`IronMeshConfig.from_file()`), with field
names matching the CLI flags but with underscores instead of dashes
(e.g. CLI `--db-path` → JSON `"db_path"`). Unknown fields are ignored
and malformed JSON falls back to defaults with a warning.

**However, `ironmesh run` does not currently read this file** — the
CLI builds the daemon configuration from flags and environment
variables only. The JSON loader is a library-level surface for
embedding IronMesh in your own Python process. To persist settings
across `ironmesh run` invocations today, use a shell alias, a systemd
unit, or the command that `ironmesh setup` prints. Never inline
secrets like the passphrase in JSON config.

## CLI flags — `ironmesh run`

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--name` | str (required) | — | Agent name; advertised via mDNS, used in handshake. |
| `--port` | int | `8765` | WebSocket peer port. The dashboard binds to `--port + 1`. |
| `--bind` | str | `0.0.0.0` | Mesh WebSocket bind address. |
| `--profile` | `secure\|dev\|offline` | none | Bundled flag preset. See [Profiles](#profiles). |
| `--keys-path` | path | `~/.ironmesh/keys.json` | Encrypted identity keypair. |
| `--keys-passphrase` | str | — | Passphrase to decrypt the key file. **Discouraged** — argv is visible in the process list; prefer `--keys-passphrase-file` or `IRONMESH_KEYS_PASSPHRASE`. Usually unnecessary: when the key file was created by `ironmesh setup`, the daemon decrypts it with the mesh passphrase automatically, and otherwise prompts on a terminal. |
| `--keys-passphrase-file` | path | — | Read the key-file passphrase from a file (trailing newline stripped). `chmod 600`. Preferred headless source when the key passphrase differs from the mesh passphrase. |
| `--db-path` | path | `~/.ironmesh/data.db` | Offline message queue. |
| `--passphrase-file` | path | — | Highest-priority passphrase source. `chmod 600`. |
| `--tls-cert` / `--tls-key` | path | — | Enable WSS on the mesh port. Otherwise plaintext WS. |
| `--allowed-peers` | csv | — | mDNS allowlist. Default-deny if not set. |
| `--open-discovery` | flag | off | **INSECURE.** Auto-connect to any mDNS peer. Localhost testing only. |
| `--allow-plaintext-ws` | flag | off | **INSECURE.** Allow `ws://` fallback. Localhost testing only. |
| `--require-message-promotion` | flag | off | Enable the pending-trust message gate (opt-in). See `docs/TRUST_GATE_ARCHITECTURE.md`. |
| `--gui` | flag | off | Enable the operator dashboard on `--port + 1`. |
| `--gui-bind` | str | `127.0.0.1` | Dashboard bind address. **Anything other than loopback emits an `INSECURE BIND` warning.** See `docs/REVERSE_PROXY.md`. |
| `--rotate-keys` | flag | off | Rotate identity keypair before starting (one-shot). |
| `--strict-tls` | flag | off | Require CA-validated certs on outbound WSS (hostname check + `CERT_REQUIRED`). |
| `--pinned-ca` | path | — | Private CA bundle used as the trust anchor for `--strict-tls`. |
| `--max-msgs-per-sec` | float | off | Global daemon-wide cap on inbound message rate (defense-in-depth on top of per-peer caps). |
| `--min-protocol-version` | str | `ironmesh/0.3` | Reject peers below this protocol version. Set `ironmesh/0.9` to refuse legacy HELLO signatures. |
| `--mesh-routing` | `off\|passive\|relay` | `relay` | Multi-hop routing mode: `off` = none, `passive` = learn but don't relay, `relay` = full participation. |
| `--max-hops` | int | `5` | Max routing hops. |
| `--route-announce-interval` | float | `30.0` | Seconds between route announcements. |
| `--route-ttl` | float | `90.0` | Route lifetime before timeout. |
| `--routes-path` | path | `~/.ironmesh/routes.json` | Persisted routing table. |
| `--capability` | str (repeatable) | — | Advertise a capability (e.g. `--capability llm:llama3.2`). |
| `--capabilities-path` | path | `~/.ironmesh/capabilities.json` | Persisted capability registry. |
| `--capability-announce-interval` | float | `60.0` | Seconds between capability announcements. |
| `--pending-trust-queue-cap` | int | `100` | Per-peer cap on gated (pending-trust) messages. |
| `--trust-path` | path | `~/.ironmesh/known_peers.json` | Trust-store file override. |
| `--rekey-interval` | float | `1800.0` | Session key rotation interval in seconds (`0` disables). |
| `--metrics-format` | `prometheus\|json` | `prometheus` | Metrics exposition format. |
| `--log-level` | enum | `INFO` | `DEBUG\|INFO\|WARNING\|ERROR`. |
| `--log-file` | path | — | Redirect logs to a file. |
| `--log-format` | `text\|json` | `text` | Structured JSON logs are aggregator-friendly. |

### Reticulum / LoRa flags (`ironmesh run`, requires `ironmesh[rns]`)

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--reticulum` | flag | off | Enable the RNS / LoRa transport. |
| `--rns-configdir` | path | `~/.reticulum` | Reticulum config directory. |
| `--rns-announce-interval` | float | `300.0` | Seconds between RNS announces. |
| `--rns-connect` | csv | — | Destination hashes to connect on startup (optional — auto-discovery via announces). |
| `--rns-no-ratchets` | flag | off | Disable per-packet ratchets (only for interop with very old RNS peers). |
| `--rns-ratchet-interval` | float | `1800.0` | Ratchet key rotation interval. |
| `--rns-retained-ratchets` | int | `8` | Past ratchet keys retained for late packets. |
| `--rns-admin-identities` | csv | — | Allow-list of RNS Identity hashes for admin RPC (empty = admin RPC disabled). |
| `--rns-skip-handshake` | flag | off | Skip the stage-1 passphrase handshake on identified RNS Links (both peers must advertise `hskip`; requires the verified `ironmesh/0.9` link binding). |
| `--rns-require-link-binding` | flag | off | Reject RNS peers whose HELLO carries no `ironmesh/0.9` link binding (refuses pre-0.9 RNS peers). |
| `--rns-group-broadcast` | flag | off | Join the shared-secret mesh-wide broadcast group (`group` feature). |
| `--lora-max-payload` | int | `128` | Max payload bytes for the RNS/LoRa transport (`0` disables the cap). |
| `--lxmf`, `--lxmf-*` | — | off | LXMF listener family (storage, display name, default peer, propagation node, telemetry) — see [RETICULUM.md](RETICULUM.md) and `ironmesh run --help`. |

## CLI subcommands

| Subcommand | Purpose |
|---|---|
| `ironmesh run` | Start the daemon. (See flags above.) |
| `ironmesh setup` | Interactive first-run wizard. Writes passphrase + keypair. |
| `ironmesh demo` | Spawn two local agents, exchange a ping, print RTT. |
| `ironmesh upgrade` | Check PyPI for a newer release. |
| `ironmesh trust list \| revoke \| set-state \| list-revoked \| verify \| pin \| export \| migrate` | Trust-store management. Capability-binding subcommands (`cap-*`) are listed under the Capability-set binding section below. |
| `ironmesh keys generate \| info \| fingerprint \| migrate` | Generate / inspect / fingerprint / migrate the identity keypair. |
| `ironmesh keys keychain-store \| keychain-clear \| keychain-check` | OS keychain passphrase management (requires `pip install ironmesh[keychain]`). |
| `ironmesh backup --out <file>` | Encrypted backup of node state. |
| `ironmesh restore --in <file>` | Restore from a backup. |
| `ironmesh audit verify \| export \| verify-export \| tail \| stats` | Audit-log integrity + triage tools. |
| `ironmesh session rotate` | Force session-key rotation with a peer. |
| `ironmesh doctor [--peer HOST:PORT]` | One-shot diagnostic — keys, trust store, schema, ports, audit chain; `--peer` adds a dry-run reachability check. |

Run any subcommand with `--help` for the full list of options.

## Environment variables

### Passphrase sources

The mesh passphrase is the only configuration value that is **never**
accepted on the command line (would leak in `ps aux`). Priority:

| # | Source | Notes |
|---|---|---|
| 1 | `--passphrase-file <path>` (run flag) | Highest priority. |
| 2 | `IRONMESH_PASSPHRASE_FILE` | Path to a `chmod 600` file. |
| 3 | `IRONMESH_PASSPHRASE_KEYCHAIN=true\|1\|yes` | Query the OS keychain. Requires `ironmesh[keychain]` and a stored entry (see `ironmesh keys keychain-store`). Service ID is `ironmesh:<node-name>`. |
| 4 | `IRONMESH_PASSPHRASE` | **WARNING:** env vars are visible via `/proc/<pid>/environ` on Linux. Prefer a file. |
| 5 | Interactive `getpass` prompt | Used only when stdin is a TTY. |

If none of the above yields a passphrase, `ironmesh run` exits with
a clear error.

### Key-file passphrase sources

The identity key file (`keys.json`) has its own passphrase chain,
resolved independently of the mesh passphrase. Priority:

| # | Source | Notes |
|---|---|---|
| 1 | `--keys-passphrase <pass>` | Kept for compatibility. **Discouraged** — argv is visible in the process list. |
| 2 | `--keys-passphrase-file <path>` | Trailing newline stripped. `chmod 600`. |
| 3 | `IRONMESH_KEYS_PASSPHRASE` | Environment variable. |
| 4 | Mesh passphrase, tried silently | `ironmesh setup` encrypts the key file with the mesh passphrase, so the command it prints works with no extra flags. |
| 5 | Interactive `getpass` prompt | Used only when stdin is a TTY; names the key file. |

If the key file is encrypted and none of the above decrypts it, the
command exits with an error listing these options. Plaintext key
files need no passphrase.

### Other env vars

These are read by the CLI / daemon / gateways:

| Variable | Effect |
|---|---|
| `IRONMESH_REQUIRE_MSG_PROMOTION` | `1\|true\|yes` enables the pending-trust gate (same as `--require-message-promotion`). |
| `IRONMESH_PENDING_QUEUE_CAP` | Override the per-peer pending-trust queue cap (default `100`). |
| `IRONMESH_TRUST_PATH` | Override `~/.ironmesh/known_peers.json`. |
| `IRONMESH_ROTATE_KEYS=1` | Rotate keys before start (same as `--rotate-keys`). |
| `IRONMESH_PASSPHRASE_NEW` | Used by `ironmesh keys keychain-store --passphrase-from-env` to read the new passphrase non-interactively. |
| `IRONMESH_SETUP_PASSPHRASE` | Used by `ironmesh setup --non-interactive --passphrase-from-env`. |
| `IRONMESH_RNS_ADMIN_IDENTITIES` | Comma-separated allow-list of RNS Identity hashes for admin RPC paths. |
| `IRONMESH_SEED_RNS_CONFIG` | `1` enables the per-daemon RNS config seeder (multi-daemon-per-host without rnsd). Off by default. |
| `IRONMESH_PASSPHRASE_KEYCHAIN` | OS-keychain passphrase backend (see [Passphrase sources](#passphrase-sources)). |
| `IRONMESH_KEYS_PASSPHRASE` | Passphrase used to decrypt the identity key file when it differs from the mesh passphrase. Precedence: `--keys-passphrase` > `--keys-passphrase-file` > this variable > mesh passphrase (tried automatically) > interactive prompt. |
| `IRONMESH_A2A_TOKEN` | Bearer token enforced by the `ironmesh-a2a` HTTP gateway. |
| `IRONMESH_ACP_TIMEOUT` | Per-call timeout (seconds) for the `ironmesh-acp` server. |

A second family (`IRONMESH_NAME`, `IRONMESH_PORT`, `IRONMESH_KEYS_PATH`,
`IRONMESH_DB_PATH`, `IRONMESH_LOG_LEVEL`, `IRONMESH_LOG_FILE`,
`IRONMESH_TLS_CERT`, `IRONMESH_TLS_KEY`, `IRONMESH_RNS_ENABLED`,
`IRONMESH_RNS_CONFIGDIR`, `IRONMESH_RNS_RATCHETS`,
`IRONMESH_RNS_RATCHET_INTERVAL`, `IRONMESH_RNS_RETAINED_RATCHETS`) is
mapped by the library-level `IronMeshConfig.from_env()` for programs
that embed IronMesh, but **is not read by `ironmesh run`** — pass the
corresponding CLI flags instead. In particular, `ironmesh run` always
requires `--name` on the command line; setting `IRONMESH_NAME` alone
is not enough.

## Files written / read

All paths are tilde-expanded.

| Path | Purpose | Permissions |
|---|---|---|
| `~/.ironmesh/passphrase` | Convention path for the passphrase file. | `chmod 600` |
| `~/.ironmesh/keys.json` | Argon2id-encrypted identity keypair. | `chmod 600` |
| `~/.ironmesh/known_peers.json` | Trust store (TOFU pins). HMAC-protected. | `chmod 600` |
| `~/.ironmesh/data.db` | SQLite offline message queue + state. | `chmod 600` |
| `~/.ironmesh/audit.log` | Tamper-evident HMAC-chained audit log. | `chmod 600` |
| `~/.ironmesh/routes.json` | Persisted multi-hop routing table. | `chmod 600` |
| `~/.ironmesh/capabilities.json` | Advertised capabilities. | `chmod 600` |

## Profiles

`--profile=<name>` bundles related flags. Explicit flags always win
over the profile but emit a warning if they conflict.

| Profile | Flags applied | Use when |
|---|---|---|
| `secure` | `--require-message-promotion`. Warns if `--open-discovery` or `--allow-plaintext-ws` set. | Production hardening. |
| `dev` | `--open-discovery`, `--allow-plaintext-ws`. | Same-machine localhost testing only. |
| `offline` | `--reticulum`. | Reticulum / LoRa-only mesh. |

## Logging

- `--log-level=DEBUG` for development. Default `INFO`.
- `--log-format=json` produces newline-delimited JSON, one log line
  per record, ingestable by Loki / Elasticsearch / etc.
- `--log-file=<path>` to redirect; otherwise stderr.

The dashboard surfaces the live log feed when GUI is enabled.

## Audit log

The audit log is HMAC-chained; every entry includes the previous
entry's MAC. Verify integrity with:

```bash
ironmesh audit verify --path ~/.ironmesh/audit.log
ironmesh audit verify --archives          # also walk rotated files
```

Export a signed bundle for off-host retention:

```bash
ironmesh audit export --out audit-bundle.tar.gz
ironmesh audit verify-export audit-bundle.tar.gz
```

## Capability-set binding (v0.8.5.6+)

The pending-trust gate gained a second axis in v0.8.5.6: pinned peers
now have their **advertised capability set** recorded alongside their
identity key. A peer that reconnects with a changed capability set
auto-demotes to `pending-cap-change` until an operator reviews.

**Commands for everyday operation:**

| Command | What it does |
|---|---|
| `ironmesh trust list --show-caps` | Peers table including a `Caps` column showing `baseline` / `pending` / `unknown` |
| `ironmesh trust list-cap-pending` | Just the peers in `pending-cap-change` with their diff. `--json` for scripts. |
| `ironmesh trust cap-status <node_id>` | Single-peer deep dive (hashes, accepted_at, rejected_at, diff) |
| `ironmesh trust cap-diff <node_id>` | Just the diff, no surrounding context |
| `ironmesh trust cap-promote <node_id>` | Accept the pending change as the new baseline. `--all` for bulk accept. |
| `ironmesh trust cap-reject <node_id>` | Reject the pending change; keep the existing baseline. `--block` also sets state to `blocked`. |
| `ironmesh trust set-state <node_id> pending-cap-change` | Manually demote a peer (rare — the daemon normally does this automatically) |

**Audit events fired:** `PEER_CAP_BASELINE`, `PEER_CAP_SET_CHANGED`,
`PEER_CAP_ACCEPTED`, `PEER_CAP_BINDING_PARTIAL`. Each has a matching
Prometheus counter (`ironmesh_peer_cap_*_total`) + an OpenTelemetry
span (`peer.cap.*`). See [OBSERVABILITY.md](OBSERVABILITY.md) for
Grafana integration.

**MCP tools:** `ironmesh_pending_cap_changes`, `ironmesh_cap_diff`,
`ironmesh_cap_promote_peer`, `ironmesh_cap_reject_peer`. Total MCP
surface is now 25 tools.

## Audit log triage (v0.8.5.7+)

| Command | What it does |
|---|---|
| `ironmesh audit verify` | HMAC-chain verification of the whole log |
| `ironmesh audit verify --archives` | Verify across rotated archives too |
| `ironmesh audit tail --since 1h` | Newest-first entries from the last hour |
| `ironmesh audit tail --event PEER_CAP_SET_CHANGED,PEER_CAP_ACCEPTED` | Filter by event type (repeatable, comma-separated) |
| `ironmesh audit stats --since 24h` | Histogram of event types over a window |
| `ironmesh audit export --out snapshot.json` | Signed bundle for offline archival |
| `ironmesh audit verify-export snapshot.json` | Verify a signed export |

The `--since` argument accepts short forms (`30s`, `5m`, `2h`, `7d`)
or ISO-8601 timestamps.

## See also

- [QUICKSTART.md](QUICKSTART.md) — first-run walkthrough.
- [SECURITY.md](SECURITY.md) — threat model + hardening recommendations.
- [REVERSE_PROXY.md](REVERSE_PROXY.md) — dashboard behind nginx / Caddy / Traefik.
- [WINDOWS_SERVICE.md](WINDOWS_SERVICE.md) — running as a Windows service via NSSM.
- [NAT_TRAVERSAL.md](NAT_TRAVERSAL.md) — cross-NAT recipes.
- [OPERATOR_TRUST_RUNBOOK.md](OPERATOR_TRUST_RUNBOOK.md) — pending-trust gate operations.
- [OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md) — cap-binding + audit triage scenarios (v0.8.5.7+).
- [TRUST_BINDING.md](TRUST_BINDING.md) — cap-binding design doc.
- [migration/v0_9_default_deny.md](migration/v0_9_default_deny.md) — pending-trust default-on migration.
