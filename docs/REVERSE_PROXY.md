# Running the IronMesh Dashboard Behind a Reverse Proxy

The operator dashboard ships disabled (`--gui` is opt-in) and binds
to loopback (`127.0.0.1`) by default. For most deployments that's
the right answer — SSH-tunnel into the host or run a local browser
against the daemon. But sometimes you want the dashboard reachable
from a LAN, a VPN, or the internet behind TLS. This doc walks through
the recommended pattern: a reverse proxy fronts the dashboard,
terminating TLS and adding any rate-limiting or ACLs you want.

> **Two new flags in v0.8.5.5** make this safe:
>
> - `--gui-bind <addr>` configures the dashboard's bind address
>   (default `127.0.0.1`). Set it to `0.0.0.0` to expose to the host's
>   external interfaces, or to a specific interface IP.
> - The startup banner emits a loud `INSECURE BIND` warning when
>   `--gui-bind` is set to anything other than loopback, so a
>   misconfiguration cannot quietly make it into production.

## Topology

```
            ┌────────────────────────────────┐
            │  Reverse proxy                 │
internet ──►│  (nginx / Caddy / Traefik)     │
            │  · TLS termination             │
            │  · ACL / rate limit            │
            │  · WebSocket upgrade passthru  │
            └──────────────┬─────────────────┘
                           │ HTTP/WS, plaintext
                           │ on loopback or
                           │ private interface
                           ▼
            ┌────────────────────────────────┐
            │  IronMesh daemon (single host) │
            │  · WebSocket on :8765 (peers)  │
            │  · Dashboard on :8766          │
            │    bound to 127.0.0.1 or       │
            │    a private interface         │
            └────────────────────────────────┘
```

The proxy and the daemon either live on the same host (proxy
connects to `127.0.0.1:8766`) or on the same private network (proxy
connects to a private LAN IP). Never expose the dashboard's bare
HTTP port to the internet.

## Authentication model

The dashboard's only auth is a per-session **bearer token** generated
at daemon startup and printed to stderr (`GUI token: <token>`). The
browser supplies it as either:

- A `?token=<token>` query parameter on the initial page load
- An `Authorization: Bearer <token>` header on the WebSocket upgrade

Both transports are sensitive to TLS — a passive observer on a path
without TLS can see the token in the clear. **Always front the
dashboard with TLS** when binding to anything other than loopback.

## Recipe — Caddy (recommended)

Caddy handles automatic Let's Encrypt TLS, including the WebSocket
upgrade, with the smallest config:

```caddyfile
dashboard.example.com {
    # Terminate TLS, forward to the loopback dashboard.
    reverse_proxy 127.0.0.1:8766

    # Optional: restrict by IP.
    @allowed remote_ip 198.51.100.0/24
    handle_path /* {
        respond "forbidden" 403 {
            close
        }
    }
    handle @allowed {
        reverse_proxy 127.0.0.1:8766
    }

    # Optional: rate limit.
    # rate_limit { ... } — requires the caddy-ratelimit plugin
}
```

Run on the same host as the daemon, then start IronMesh with the
default `--gui-bind 127.0.0.1`.

## Recipe — nginx

```nginx
upstream ironmesh_dashboard {
    server 127.0.0.1:8766;
    # Keep the WS connection alive across reloads
    keepalive 32;
}

map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl http2;
    server_name dashboard.example.com;

    ssl_certificate     /etc/letsencrypt/live/dashboard.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dashboard.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Optional: restrict by IP
    allow 198.51.100.0/24;
    deny  all;

    location / {
        proxy_pass http://ironmesh_dashboard;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket upgrade passthrough
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        # Long-lived dashboard WebSocket needs a generous read timeout
        proxy_read_timeout 86400;
    }
}
```

## Recipe — Traefik (Docker label style)

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.ironmesh.rule=Host(`dashboard.example.com`)"
  - "traefik.http.routers.ironmesh.entrypoints=websecure"
  - "traefik.http.routers.ironmesh.tls.certresolver=letsencrypt"
  - "traefik.http.services.ironmesh.loadbalancer.server.port=8766"
  - "traefik.http.routers.ironmesh.middlewares=ipallowlist"
  - "traefik.http.middlewares.ipallowlist.ipallowlist.sourcerange=198.51.100.0/24"
```

## Hardening checklist

- [ ] **Daemon `--gui-bind 127.0.0.1`** (default) so only the proxy
      on the same host can reach it. If proxy is on a different host,
      use a specific private interface (`--gui-bind 192.0.2.10`), never
      `0.0.0.0`.
- [ ] **TLS at the proxy.** Let's Encrypt or a private CA. No
      cleartext on the wire.
- [ ] **IP allowlist or VPN.** The dashboard's bearer token is
      strong, but defense in depth means an attacker shouldn't even
      reach the auth check from the open internet.
- [ ] **Rate limit on `/auth` and `/ws`.** A naïve brute-force on
      the bearer token would take 2^256 tries; not a real risk. But
      rate limiting hides the daemon's existence from scanners.
- [ ] **Rotate the bearer token periodically.** The dashboard
      includes a "rotate token" action; or restart the daemon.
      Tokens are not persisted across restarts.
- [ ] **Keep the mesh WebSocket port (`:8765`) on the loopback or
      LAN-only interface.** That's the peer-to-peer port; it has its
      own auth (handshake), but the dashboard is the only thing a
      browser ever needs to reach.
- [ ] **Audit-log review.** Authentication failures land in
      `~/.ironmesh/audit.log` with HMAC-chained event types. Any
      unexpected failure spike from the proxy's IP indicates either
      a misconfigured client or an attempted intrusion.

## What is NOT yet implemented (as of v0.8.5.5)

The reverse-proxy story is "loud bind warning + recommended
deployment recipe" today. Still on the roadmap for a future minor:

- **CSRF synchronizer-token** for the dashboard's state-changing
  actions. Today the dashboard relies on the bearer token in the
  `Authorization` header (which already provides CSRF defense for
  cross-origin attacks because browsers don't auto-send custom
  headers). A proper CSRF token would harden against a hostile
  same-origin script if the dashboard is ever served from a domain
  that hosts other content.
- **WebSocket Origin allowlist.** The daemon does not currently
  inspect the `Origin` header on WS upgrades. Adding an
  `--allowed-origins` flag would let a reverse-proxy operator
  enforce that only their dashboard hostname can open WS sessions,
  not arbitrary third-party origins serving malicious JS.
- **Configurable base path** (e.g. `/ironmesh/` rather than `/`)
  for shared-domain deployments where the dashboard is mounted
  alongside other apps.

These are tracked for the next minor release. None block
shipping a reverse-proxy fronted dashboard today.
