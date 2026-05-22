# IronMesh v0.9.4.2 — Release Notes

## Headline

An operator-polish sweep on top of v0.9.4.1. Eight small fixes
surfaced by the v0.9.4 multi-node verification run, folded into a
focused release. No protocol changes, no wire-format changes — every
v0.8.x and v0.9.x peer remains interoperable.

**Wire protocol:** `ironmesh/0.8`, additive only. Byte-identical to
v0.9.4 and v0.9.4.1.

**Operator action:** none required. Upgrade with
`pip install --upgrade ironmesh==0.9.4.2` or pull
`wiztheagent/ironmesh:0.9.4.2`.

## Fixes

### Multi-homed peer address selection

When a peer advertises on multiple interfaces (LAN + VPN is the
common case), the mDNS discovery callback now prefers the candidate
whose `/24` matches one of the local host's interfaces. Single-homed
setups behave exactly as before — the new logic only activates when
multiple addresses are present and at least one matches a local
subnet.

### `ironmesh doctor --peer HOST:PORT`

Dry-run WebSocket handshake against a peer that reports the failure
point cleanly: unreachable host, port closed, TLS error, or
"connected but no HELLO within 3s" (the canonical fingerprint of a
passphrase mismatch). Lets an operator confirm reachability +
passphrase agreement without hitting the auth-failure-block storm
from a real daemon.

### `tools/start-daemon-detached.sh`

SSH-detached daemon launch using `setsid`. `nohup ... & disown` over
SSH does not actually survive logout — the daemon receives SIGHUP
when the controlling terminal closes. The wrapper puts the daemon
in its own session/process group so it survives. Stdout/stderr land
in `~/.ironmesh/daemon.log`.

### `tools/transfer-wheel.sh`

Wheel transfer with remote SHA256 verification. `scp` over a flaky
network has been observed to complete with exit code 0 while
transferring a truncated file. This wrapper streams via
`ssh ... 'cat > path'` and re-checks the SHA after copy.

### `examples/llm_bridge.py` — operator polish

Four targeted improvements to the Ollama bridge example:

1. `--db-path` and `--trust-path` CLI flags for parity with
   `ironmesh run`.
2. Default Ollama timeout raised 30s → 180s. The previous default
   was too tight for 14B+ models on older GPUs.
3. `query_ollama` retries connection failures and timeouts once
   with a 2-second backoff. HTTP 4xx errors (model not found,
   malformed request) bypass the retry and surface immediately.
4. Unknown-role error message lists every valid role on its own
   line and points the operator at `--system-prompt` for custom
   personas.

## What's NOT in v0.9.4.2

- No wire-protocol changes. Wire format stays at `ironmesh/0.8`.
- No new audit events, metrics, or config fields.
- External audit findings: pending the audit engagement; will land
  in v0.9.6 or v1.0-rc.

## Verification

- 1083 tests collected. ruff CI-scope clean. release-qc green.
- Wheel + sdist build clean; 30 public modules import; CLI entry
  point operational.

## Upgrade

```
pip install --upgrade ironmesh==0.9.4.2
docker pull wiztheagent/ironmesh:0.9.4.2
```

No keystore migration, no config change, no peer-mesh coordination
required. v0.9.4 and v0.9.4.1 daemons interoperate identically with
v0.9.4.2 daemons.
