# IronMesh Configuration Reference

Every configurable knob in one place. This is the source of truth —
if a flag, env var, or file path is documented elsewhere, it should
also appear here.

## Precedence

When multiple sources set the same value, later wins:

1. Defaults compiled into the daemon
2. CLI flag (`--name`, `--port`, etc.)
3. Environment variable (`IRONMESH_*`)
4. The first-run wizard's generated config (effectively a stored CLI
   command)

The only exception is the **passphrase**, which has its own priority
chain — see [Passphrase sources](#passphrase-sources) below.

## CLI flags — `ironmesh run`

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--name` | str (required) | — | Agent name; advertised via mDNS, used in handshake. |
| `--port` | int | `8765` | WebSocket peer port. The dashboard binds to `--port + 1`. |
| `--bind` | str | `0.0.0.0` | Mesh WebSocket bind address. |
| `--profile` | `secure\|dev\|offline` | none | Bundled flag preset. See [Profiles](#profiles). |
| `--keys-path` | path | `~/.ironmesh/keys.json` | Encrypted identity keypair. |
| `--keys-passphrase` | str | — | Passphrase to decrypt the key file. Prefer the env var. |
| `--db-path` | path | `~/.ironmesh/data.db` | Offline message queue. |
| `--passphrase-file` | path | — | Highest-priority passphrase source. `chmod 600`. |
| `--tls-cert` / `--tls-key` | path | — | Enable WSS on the mesh port. Otherwise plaintext WS. |
| `--allowed-peers` | csv | — | mDNS allowlist. Default-deny if not set. |
| `--open-discovery` | flag | off | **INSECURE.** Auto-connect to any mDNS peer. Localhost testing only. |
| `--allow-plaintext-ws` | flag | off | **INSECURE.** Allow `ws://` fallback. Localhost testing only. |
| `--require-message-promotion` | flag | off (v0.8.x) | Enable the pending-trust message gate. Default-on in v0.9. |
| `--gui` | flag | off | Enable the operator dashboard on `--port + 1`. |
| `--gui-bind` | str | `127.0.0.1` | Dashboard bind address. **Anything other than loopback emits an `INSECURE BIND` warning.** See `docs/REVERSE_PROXY.md`. |
| `--rotate-keys` | flag | off | Rotate identity keypair before starting (one-shot). |
| `--reticulum` | flag | off | Enable RNS / LoRa transport (requires `pip install ironmesh[rns]`). |
| `--mesh-routing` | `relay\|none` | `relay` | Multi-hop routing strategy. |
| `--max-hops` | int | `5` | Max routing hops. |
| `--route-announce-interval` | float | `30.0` | Seconds between route announcements. |
| `--route-ttl` | float | `90.0` | Route lifetime before timeout. |
| `--routes-path` | path | `~/.ironmesh/routes.json` | Persisted routing table. |
| `--capability` | str (repeatable) | — | Advertise a capability (e.g. `--capability llm:llama3.2`). |
| `--log-level` | enum | `INFO` | `DEBUG\|INFO\|WARNING\|ERROR`. |
| `--log-file` | path | — | Redirect logs to a file. |
| `--log-format` | `text\|json` | `text` | Structured JSON logs are aggregator-friendly. |

## CLI subcommands

| Subcommand | Purpose |
|---|---|
| `ironmesh run` | Start the daemon. (See flags above.) |
| `ironmesh setup` | Interactive first-run wizard. Writes passphrase + keypair. |
| `ironmesh demo` | Spawn two local agents, exchange a ping, print RTT. |
| `ironmesh upgrade` | Check PyPI for a newer release. |
| `ironmesh trust list \| revoke \| set-state \| list-revoked` | Trust-store management. |
| `ironmesh keys generate \| info` | Generate / inspect the identity keypair. |
| `ironmesh keys keychain-store \| keychain-clear \| keychain-check` | OS keychain passphrase management (requires `pip install ironmesh[keychain]`). |
| `ironmesh backup --out <file>` | Encrypted backup of node state. |
| `ironmesh restore --in <file>` | Restore from a backup. |
| `ironmesh audit verify \| export \| verify-export` | Audit-log integrity tools. |
| `ironmesh session rotate` | Force session-key rotation with a peer. |
| `ironmesh doctor` | One-shot diagnostic — keys, trust store, schema, ports, audit chain. |

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

### Other env vars

| Variable | Effect |
|---|---|
| `IRONMESH_NAME` | Default `--name`. |
| `IRONMESH_PORT` | Default `--port`. |
| `IRONMESH_REQUIRE_MSG_PROMOTION` | `1\|true\|yes` enables the pending-trust gate (same as `--require-message-promotion`). |
| `IRONMESH_PENDING_QUEUE_CAP` | Override the per-peer pending-trust queue cap (default `100`). |
| `IRONMESH_TRUST_PATH` | Override `~/.ironmesh/known_peers.json`. |
| `IRONMESH_ROTATE_KEYS=1` | Rotate keys before start (same as `--rotate-keys`). |
| `IRONMESH_PASSPHRASE_NEW` | Used by `ironmesh keys keychain-store --passphrase-from-env` to read the new passphrase non-interactively. |
| `IRONMESH_SETUP_PASSPHRASE` | Used by `ironmesh setup --non-interactive --passphrase-from-env`. |

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

## See also

- [QUICKSTART.md](QUICKSTART.md) — first-run walkthrough.
- [SECURITY.md](SECURITY.md) — threat model + hardening recommendations.
- [REVERSE_PROXY.md](REVERSE_PROXY.md) — dashboard behind nginx / Caddy / Traefik.
- [WINDOWS_SERVICE.md](WINDOWS_SERVICE.md) — running as a Windows service via NSSM.
- [NAT_TRAVERSAL.md](NAT_TRAVERSAL.md) — cross-NAT recipes.
- [OPERATOR_TRUST_RUNBOOK.md](OPERATOR_TRUST_RUNBOOK.md) — pending-trust gate operations.
- [migration/v0_9_default_deny.md](migration/v0_9_default_deny.md) — pending-trust default-on migration.
