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
| `--profile` | `lan\|lora\|homelab\|tactical\|custom` (+ aliases `secure\|dev\|offline`) | none | Bundled flag preset. See [Profiles](#profiles). |
| `--keys-path` | path | `~/.ironmesh/keys.json` | Encrypted identity keypair. |
| `--keys-passphrase` | str | — | Passphrase to decrypt the key file. **Discouraged** — argv is visible in the process list; prefer `--keys-passphrase-file` or `IRONMESH_KEYS_PASSPHRASE`. Usually unnecessary: when the key file was created by `ironmesh setup`, the daemon decrypts it with the mesh passphrase automatically, and otherwise prompts on a terminal. |
| `--keys-passphrase-file` | path | — | Read the key-file passphrase from a file (trailing newline stripped). `chmod 600`. Preferred headless source when the key passphrase differs from the mesh passphrase. |
| `--plaintext-keys` | flag | off | **INSECURE.** Store an auto-generated identity key file unencrypted. Without it, auto-generated keys are encrypted with the mesh passphrase. |
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
| `ironmesh setup` | Interactive first-run wizard. Writes passphrase + keypair. Supports `--profile`, `--generate-passphrase`, `--use-keychain`, and `--from-invite <token>` to bootstrap from an existing node (see [Bootstrap invite tokens](#bootstrap-invite-tokens)). |
| `ironmesh invite create` | Issue an ephemeral single-use bootstrap invite token for a new node (see [Bootstrap invite tokens](#bootstrap-invite-tokens)). |
| `ironmesh demo` | Spawn two local agents, exchange a ping, print RTT. |
| `ironmesh upgrade` | Check PyPI for a newer release. |
| `ironmesh trust list \| revoke \| set-state \| list-revoked \| verify \| pin \| export \| migrate` | Trust-store management. Capability-binding subcommands (`cap-*`) are listed under the Capability-set binding section below. |
| `ironmesh keys generate \| info \| fingerprint \| migrate` | Generate / inspect / fingerprint / migrate the identity keypair. |
| `ironmesh keys keychain-store \| keychain-clear \| keychain-check` | OS keychain passphrase management (requires `pip install ironmesh[keychain]`). |
| `ironmesh backup --out <file>` | Encrypted backup of node state. |
| `ironmesh restore --in <file>` | Restore from a backup. |
| `ironmesh audit verify \| export \| verify-export \| tail \| stats` | Audit-log integrity + triage tools. |
| `ironmesh session rotate` | Force session-key rotation with a peer. |
| `ironmesh doctor [--peer HOST:PORT] [--onboard] [--fix]` | One-shot diagnostic — keys, trust store, schema, ports, audit chain, passphrase-file perms, mDNS/multicast, firewall posture, Reticulum config, Ollama. `--peer` adds a dry-run reachability check. `--onboard` walks first-run failure modes; `--fix` auto-applies safe local fixes only (see [Doctor onboarding & auto-fix](#doctor-onboarding--auto-fix)). |

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
| `~/.ironmesh/invite_ledger.json` | Spent-nonce ledger for single-use invite tokens (inviter-side). Co-located with the trust store. | `chmod 600` |

## Profiles

`--profile=<name>` bundles related flags into a named deployment
posture. A profile sets **defaults only** — every value stays
individually overridable. Explicit flags always win over the profile
but emit a warning if they conflict with the posture's intent.

### Canonical postures

| Profile | Flags applied | Use when |
|---|---|---|
| `lan` | *(none — the shipped zero-config default)*. mDNS stays default-deny; pass `--allowed-peers` or `--open-discovery` to auto-connect. | Ordinary LAN mesh. Naming it just makes "the default" explicit. |
| `lora` | `--reticulum`. | Off-grid RF *is* the network. Reticulum / LoRa transport on. |
| `homelab` | *(none)* — leaves permissive LAN defaults in place; pair with `--allowed-peers` for the swarm members. | Local Ollama / agent-swarm homelab. Doctor's Ollama probe keys off this posture. |
| `tactical` | `--require-message-promotion`. Warns if `--open-discovery` or `--allow-plaintext-ws` set. | Strictest posture: pre-pinned peers only, pending-trust gate on, discovery off. Reserved to pin a group crypto suite once the keying RFC lands. |
| `custom` | *(none)* — no opinionated defaults; explicit flags only. | You want the profile machinery out of the way. |

### Back-compat aliases (pre-1.0)

These names predate the canonical set and are kept **behavior-preserving** —
an existing `--profile=secure` invocation produces exactly the same
flags and warnings it did before.

| Alias | Flags applied | Notes |
|---|---|---|
| `secure` | `--require-message-promotion`. Warns if `--open-discovery` or `--allow-plaintext-ws` set. | Production hardening. Kept **distinct** from `tactical` (their intents overlap today, but `tactical` is documented to pin a group crypto suite later — aliasing would silently change behavior once it does). |
| `dev` | `--open-discovery`, `--allow-plaintext-ws`. | **INSECURE.** Same-machine localhost testing only. |
| `offline` | `--reticulum`. | Air-gapped / no clearnet. **Distinct from `lora`**: `offline` = no network at all; `lora` = off-grid RF is the network. |

> **Reserved:** `tactical` will gain a pinned group crypto suite via the
> reserved (currently unset) `group_crypto_suite` config field once
> [`rfcs/RFC-key-hierarchy-group-messaging-v0.1-skeleton.md`](../rfcs/RFC-key-hierarchy-group-messaging-v0.1-skeleton.md)
> selects one. The field is omitted from the saved config until then, so
> no schema migration is required when it lands.

## Bootstrap invite tokens

An **invite token** lets an operator add a new node to the mesh without
retyping the shared passphrase on every machine and without any central
coordinator. It is an **ephemeral, single-use** bootstrap credential: it
gets a joining node *past first-contact identity verification* but never
past explicit operator approval, and it is useless once consumed or
expired.

```
# On an existing node — issue a token pinned to this node's endpoint:
ironmesh invite create --endpoint mesh-node-a:8765 --profile lan

# On the new node — bootstrap from it:
ironmesh setup --from-invite 'ironmesh-invite-v1:…'
```

### What the token contains

The token is a signed JSON envelope, serialized as
`ironmesh-invite-v1:<base64url(body)>`. The body carries:

| Field | Purpose |
|---|---|
| `inviter_key` | The inviter's **current Ed25519 identity public key** — the key the joiner pins. |
| `inviter_id` | The inviter's identity fingerprint (for display). |
| `endpoint` | The inviter's **bootstrap endpoint** (`host:port` or `rns:<dest-hash>`) the joiner connects to first. |
| `nonce` | A single-use random id. |
| `issued_at` / `expires_at` | The validity window. |
| `allowed_peers` | Suggested `--allowed-peers` hint for the joiner. |
| `profile` | Deployment-profile hint (also sets the default expiry). |
| `signature` | Detached Ed25519 signature over the canonical body under the domain-separation context `SIG_CTX_INVITE`. |

The token **never contains the mesh passphrase or any root secret.** A
signature captured from another IronMesh surface (HELLO, capability
announce) cannot be replayed as an invite because the domain-separation
label differs.

### Expiry — per-profile default, always overridable

Expiry reuses the protocol's existing freshness arithmetic (`issued_at` +
a per-profile max-age). Defaults:

| Profile | Default lifetime | Rationale |
|---|---|---|
| `lan`, `homelab` | 15 min | On-LAN, the joiner is nearby. |
| `lora`, `offline` | 30 min | Off-grid — you may be physically walking the token between nodes. |
| `tactical` | 5 min | Shortest window; pre-pinned peers only. |
| *(unset / other)* | 15 min | Safe fallback. |

Override with `--expires-in` (`10m`, `1h`, `900s`, or a bare number of
seconds). A joiner rejects an expired token, and the inviter re-checks
expiry when the join lands.

### Single-use — the inviting node is authoritative

The token pins the **inviter's** endpoint, so the joiner first-contacts
the inviter directly. The inviter holds a small persisted
**spent-nonce ledger** (`~/.ironmesh/invite_ledger.json`) and marks the
token spent at its TOFU pin point on a successful join. A token that is
already spent — or expired, or not issued by this node — is rejected
there. There is **no** distributed/quorum consumption and **no** mesh-wide
gossip; consumption is a single authoritative decision on the inviter.

### Identity pinning — verified-first-use, not blind TOFU

When the joiner connects to the pinned endpoint, it validates the inviter
identity presented in the handshake HELLO against the `inviter_key` in the
token. The HELLO signature already proves the server controls that key, so
a match means the joiner is talking to the exact inviter the token named.
A mismatch fails the connection closed. This is **verified-first-use**, not
blind trust-on-first-use.

> **Deferred:** SIO / FROST alignment is left to the keying RFC. The token
> pins the current Ed25519 identity now — forward-compatible, not
> forward-implemented.

### Resulting trust — `pending`, not auto-trust

An invited joiner is pinned in the **`pending`** trust state **regardless
of the global `--require-message-promotion` setting** — the token gets it
past first-contact identity verification, not past operator approval. It
lands in the pending-trust gate for explicit promotion, exactly like any
other new peer under the gate. Deny-by-default stays intact. The peer
record gets an optional `pinned_via="invite"` provenance marker (for audit
/ UX) — this is **not** a new trust state.

### The inviter must be reachable at first-contact

**Because the token is inviter-endpoint-pinned, the inviting node MUST be
reachable at its `endpoint` when the joiner bootstraps.** The join
completes by connecting to that endpoint directly; if the inviter is
offline or partitioned at that moment, the join cannot complete. **This is
by design, not a bug** — the single-use ledger and the identity pin both
live on the inviter, so the inviter has to be up to consume the token and
present its identity.

This matters most for **`lora` / off-grid** deployments: *the node that
issued the invite must be up when you join.* Plan the walk-over so the
inviting node is running and reachable on RF/LAN before you start the new
node.

### QR transport

`ironmesh invite create` can render the token as a QR code so it can be
scanned off one screen onto another without the string transiting a chat
app or clipboard sync:

- `--qr` renders an **in-terminal ASCII QR** (preferred). Requires the
  optional `[qr]` extra (`pip install ironmesh[qr]`); without it, the
  command prints the token string plus a note — the string is itself a
  complete transport.
- `--qr-png <path>` writes a **PNG**. A warning is printed because phone
  camera rolls commonly sync to the cloud. That exposure is acceptable
  **only** because the token is single-use and short-lived (useless after
  consumption / expiry).

The mesh passphrase is **never** emitted as a QR code or otherwise placed
in an invite.

## Doctor onboarding & auto-fix

`ironmesh doctor` runs a read-only diagnostic checklist (`[N/M]`) that is
safe against a live daemon. Beyond the core checks (keys, trust store,
schema, queues, port, audit chain) it also reports:

- **Passphrase-file permissions** — a dedicated line reusing the daemon's
  own permission logic (`chmod 600` recommended on POSIX).
- **mDNS / multicast reachability** — probes whether the host can join
  the mDNS multicast group. `WARN` (never `FAIL`) if blocked — pinned-peer
  and RF meshes are valid without it.
- **Firewall posture** — detect-only. Reports local port bindability and
  prints the **exact** OS-specific command to open the port (ufw /
  firewall-cmd / iptables / netsh). Doctor never runs it for you here.
- **Reticulum config presence** — for `--reticulum` / `--profile=lora`.
- **Ollama reachability** — probes `http://127.0.0.1:11434` (INFO, or
  WARN under `--profile=homelab`).

### `--onboard`

Walks the three most common first-run failures with the specific next
action for each, keyed to what the run observed:

1. Key file won't decrypt → passphrase source guidance.
2. Peers don't discover each other → mDNS/subnet guidance or `--allowed-peers`.
3. Dashboard returns 401 → the GUI token is minted per daemon start; copy
   the fresh `GUI token:` line from the startup log.

### `--fix` (safe, local, idempotent only)

`--fix` auto-applies **only** non-destructive, reversible, local fixes:

| Fix | Behavior |
|---|---|
| `chmod 600` on the passphrase file | Only changes mode bits, never contents. Allowed over SSH. |
| Regenerate a **missing** key file | Never overwrites an existing file. Encrypts with the resolved mesh passphrase; refuses to write a plaintext key file if no passphrase is available. |
| Create a **missing** config file | Writes defaults; never overwrites. Revert by deleting the file. |

**Network rules are never auto-applied.** The exact firewall command is
printed; applying it requires an explicit interactive `y/N` confirmation.
A network `--fix` is **refused over SSH** (detected via `SSH_CONNECTION`)
unless you pass `--allow-remote-network-fix` — a bad firewall rule can
lock you out of a headless box. Local file fixes are always allowed over
SSH.

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
