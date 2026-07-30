# Reference Deployment — Multi-Tenant

A working IronMesh deployment where one mesh hosts **multiple
tenants** — separate teams or projects sharing the same physical
infrastructure but isolated from each other's traffic, capabilities,
and trust state.

> **Audience:** small companies running a shared internal mesh,
> homelab operators with multiple agent stacks (one for personal,
> one for clients), researchers running multiple experiments in
> parallel, MSPs hosting per-customer agent meshes on shared
> hardware.

## What you'll build

```
                       ┌────────────────────────────────────┐
                       │      Shared host (one machine)     │
                       │                                    │
                       │  daemon-blue   daemon-green        │
                       │  port 8765     port 8865           │
                       │  ~/.iron/blue  ~/.iron/green       │
                       │     │              │               │
                       │     │              │               │
                       │  blue-passphrase  green-passphrase │
                       │  blue-trust       green-trust      │
                       │     │              │               │
                       └─────┼──────────────┼───────────────┘
                             │              │
                  blue mesh  │              │  green mesh
                             ▼              ▼
                  blue peers...   green peers...
```

Two (or more) IronMesh daemons run on the same machine:

- Different ports
- **Different passphrases** — peers on `blue` cannot decrypt `green`
  even if they overhear the WebSocket frames.
- Different trust stores — `blue`'s pinned peers don't bleed into
  `green`'s.
- Different identity keys — `blue` and `green` are cryptographically
  distinct nodes even on the same host.
- Different audit logs — separate forensic trails per tenant.

This is the simplest tenancy model that's actually secure:
**cryptographic separation by passphrase + identity per tenant.**
There's no shared component an operator could subvert to read across
tenants.

## Step 1 — Create per-tenant home directories

```bash
sudo mkdir -p /var/lib/ironmesh/{blue,green}
sudo useradd -r -s /usr/sbin/nologin ironmesh-blue
sudo useradd -r -s /usr/sbin/nologin ironmesh-green
sudo chown ironmesh-blue:ironmesh-blue /var/lib/ironmesh/blue
sudo chown ironmesh-green:ironmesh-green /var/lib/ironmesh/green
sudo chmod 700 /var/lib/ironmesh/{blue,green}
```

Per-tenant Linux user accounts give the kernel a hand enforcing
isolation: each daemon process can't read the other's files even if
something in the daemon goes wrong.

## Step 2 — Generate per-tenant passphrases

```bash
# Blue
sudo -u ironmesh-blue bash -c '
    python3 -c "import secrets; print(secrets.token_urlsafe(32))" \
        > /var/lib/ironmesh/blue/passphrase
    chmod 600 /var/lib/ironmesh/blue/passphrase
'

# Green
sudo -u ironmesh-green bash -c '
    python3 -c "import secrets; print(secrets.token_urlsafe(32))" \
        > /var/lib/ironmesh/green/passphrase
    chmod 600 /var/lib/ironmesh/green/passphrase
'
```

Distribute each tenant's passphrase only to that tenant's peers.

## Step 3 — Generate per-tenant identity keys

```bash
# Blue
sudo -u ironmesh-blue ironmesh keys generate \
    --path /var/lib/ironmesh/blue/keys.json \
    --passphrase "$(cat /var/lib/ironmesh/blue/passphrase)"

# Green
sudo -u ironmesh-green ironmesh keys generate \
    --path /var/lib/ironmesh/green/keys.json \
    --passphrase "$(cat /var/lib/ironmesh/green/passphrase)"
```

Each tenant gets a unique fingerprint; peers TOFU-pin against that
fingerprint, not against the host's identity.

## Step 4 — Run a daemon per tenant

```bash
# Blue daemon (port 8765)
sudo -u ironmesh-blue env \
    IRONMESH_PASSPHRASE_FILE=/var/lib/ironmesh/blue/passphrase \
    ironmesh run \
        --name blue-edge \
        --port 8765 \
        --keys-path /var/lib/ironmesh/blue/keys.json \
        --db-path /var/lib/ironmesh/blue/data.db \
        --trust-path /var/lib/ironmesh/blue/known_peers.json \
        --routes-path /var/lib/ironmesh/blue/routes.json \
        --capabilities-path /var/lib/ironmesh/blue/capabilities.json \
        --require-message-promotion

# Green daemon (port 8865)
sudo -u ironmesh-green env \
    IRONMESH_PASSPHRASE_FILE=/var/lib/ironmesh/green/passphrase \
    ironmesh run \
        --name green-edge \
        --port 8865 \
        --keys-path /var/lib/ironmesh/green/keys.json \
        --db-path /var/lib/ironmesh/green/data.db \
        --trust-path /var/lib/ironmesh/green/known_peers.json \
        --routes-path /var/lib/ironmesh/green/routes.json \
        --capabilities-path /var/lib/ironmesh/green/capabilities.json \
        --require-message-promotion
```

The `--trust-path`, `--routes-path`, and `--capabilities-path` flags
were added so multi-daemon hosts don't clobber each other's
`~/.ironmesh/known_peers.json`. Use them.

## Step 5 — Wrap each daemon in systemd

```ini
# /etc/systemd/system/ironmesh-blue.service
[Unit]
Description=IronMesh daemon — tenant blue
After=network.target

[Service]
Type=simple
User=ironmesh-blue
Group=ironmesh-blue
Environment=IRONMESH_PASSPHRASE_FILE=/var/lib/ironmesh/blue/passphrase
ExecStart=/usr/local/bin/ironmesh run \
    --name blue-edge --port 8765 \
    --keys-path /var/lib/ironmesh/blue/keys.json \
    --db-path /var/lib/ironmesh/blue/data.db \
    --trust-path /var/lib/ironmesh/blue/known_peers.json \
    --routes-path /var/lib/ironmesh/blue/routes.json \
    --capabilities-path /var/lib/ironmesh/blue/capabilities.json \
    --require-message-promotion
Restart=on-failure
RestartSec=5

# Sandboxing
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ironmesh/blue
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
```

Symlink and clone the unit for each tenant; enable both:

```bash
sudo systemctl enable --now ironmesh-blue ironmesh-green
sudo systemctl status ironmesh-blue ironmesh-green
```

## Capability scoping

If `blue` and `green` advertise capabilities (`--capability llm:*`,
`--capability tool:*`), each daemon only sees its own peers' caps.
Cross-tenant capability discovery is impossible without bridging.

## Optional cross-tenant federation

If two tenants on the same host **want** controlled cross-talk (e.g.
`blue`'s data analyst should be able to query `green`'s LLM but not
vice versa), bridge them with the `FederationGateway` API. It joins two
independent meshes and enforces a capability allow/deny policy at the
boundary:

```python
from ironmesh import FederationGateway

gw = FederationGateway(
    mesh_a={"name": "blue-gw",  "port": 8765, "passphrase": "blue-pass"},
    mesh_b={"name": "green-gw", "port": 8865, "passphrase": "green-pass"},
    policy={"allow": ["llm:*"], "deny": ["*"]},
)
gw.run()
```

The gateway matches each forwarded message's capability against the
policy globs (allow-list wins, deny is the default). There is no
`ironmesh-federation` console command — federation is driven through
this API. See the `FederationGateway` section in the top-level README
for the full parameter reference.

## Per-tenant operator dashboards

Each daemon binds its dashboard on `--port + 1`. Run separate
dashboards on `:8766` and `:8866`. To put both behind one nginx
reverse proxy with separate hostnames, see `docs/REVERSE_PROXY.md`
— substitute `dashboard-blue.example.com` and
`dashboard-green.example.com` and point each at the appropriate
loopback port.

## Per-tenant audit logs

Each daemon writes `~/.ironmesh/audit.log` under its own user's
home — actually `/var/lib/ironmesh/<tenant>/audit.log` if you set
`HOME` in the systemd unit. Verify each separately:

```bash
sudo -u ironmesh-blue HOME=/var/lib/ironmesh/blue \
    ironmesh audit verify

sudo -u ironmesh-green HOME=/var/lib/ironmesh/green \
    ironmesh audit verify
```

Forensics on tenant blue cannot read tenant green's events, and vice
versa.

## Threat model

This deployment is robust against:

- **Cross-tenant peer impersonation** — different identity keys.
- **Cross-tenant traffic decryption** — different passphrases.
- **Cross-tenant trust pollution** — different trust stores.
- **Cross-tenant audit-log tampering** — separate HMAC chains under
  separate user accounts.

It is **not** robust against:

- A root-level host compromise — the operator who installed both
  tenants can read both passphrase files.
- A vulnerability in the IronMesh daemon itself that escapes the
  systemd sandbox.
- Side-channel attacks (timing, RAM forensics) on a shared kernel.

For threat models that include "the host operator is hostile,"
deploy each tenant on a separate VM or hardware node.

## What you've just demonstrated

- **Cryptographic isolation between tenants on shared hardware.**
- **Per-tenant identity, trust, audit log, and capabilities** —
  every dimension that matters for forensics or compliance is
  separated.
- **Operator separation via Linux user accounts + systemd
  sandboxing** — defense in depth on top of the cryptographic
  isolation.
- **Optional controlled bridging via `FederationGateway`** for the
  cases where tenants do need to talk.

## Going further

- **Container per tenant.** Each daemon runs in its own Docker
  container with read-only mounts for the keys + passphrase file.
  Adds a kernel-namespace boundary on top of the user-account one.
- **Shared LoRa transport, separate IronMesh tenants.** Reticulum
  multiplexes naturally — multiple IronMesh meshes can ride one
  Reticulum interface as long as they use different passphrases.
- **Per-tenant rate limits.** The daemon's per-peer bandwidth budget
  applies per-process; setting cgroup CPU and memory limits per
  tenant adds resource isolation on top.
