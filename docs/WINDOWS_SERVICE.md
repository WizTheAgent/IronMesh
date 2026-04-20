# Running IronMesh as a Windows Service

The `ironmesh run` daemon is just a long-running Python process. On
Linux you wrap it with systemd (`scripts/ironmesh.service`). On
Windows the equivalent is the Service Control Manager + a wrapper.
The recommended wrapper is **NSSM** (the Non-Sucking Service
Manager) — a tiny, stable, externally-maintained tool that handles
stdin/stdout redirection, automatic restart, and graceful shutdown
better than any Python-side service framework.

This doc walks through installing IronMesh as a Windows service in
about 5 minutes.

## 1. Prerequisites

```powershell
# In an elevated PowerShell prompt:

# Install NSSM (use either Chocolatey or Scoop)
choco install nssm
# or:  scoop install nssm

# Install IronMesh
pip install ironmesh

# Verify both
nssm --version
ironmesh --version
```

## 2. Configure your node

Create the passphrase file and identity keypair. The `ironmesh setup`
wizard does this end-to-end:

```powershell
ironmesh setup --name alice
# answer the prompts
```

That writes `~\.ironmesh\passphrase` (chmod-equivalent on Windows
restricts to your user account) and `~\.ironmesh\keys.json` (encrypted
with the passphrase).

## 3. Install the service

```powershell
# Still in an elevated prompt
cd <your-ironmesh-checkout>

.\scripts\install-windows-service.ps1 install `
    -ServiceName IronMesh `
    -Name alice `
    -Port 8765 `
    -PassphraseFile $env:USERPROFILE\.ironmesh\passphrase `
    -KeysPath $env:USERPROFILE\.ironmesh\keys.json `
    -AllowedPeers "bob,carol" `
    -RequireMessagePromotion
```

The script:
- Asserts you are elevated and that NSSM + ironmesh are on PATH.
- Calls `nssm install` with the daemon binary + the args you supplied.
- Configures stdout / stderr redirection to `~\.ironmesh\logs\`.
- Enables automatic restart on failure with a 5-second backoff.
- Sets a 30-second graceful-shutdown timeout (matches the daemon's
  internal cleanup budget).
- Marks the service for automatic start on boot.

## 4. Start it

```powershell
Start-Service IronMesh

# Verify
Get-Service IronMesh
Get-Content $env:USERPROFILE\.ironmesh\logs\IronMesh.stderr.log -Tail 20
```

You should see the standard startup banner (handshake stages, mDNS
announcement, peer-allowlist notice).

## 5. Inspect / manage

```powershell
# Check status + tail recent logs
.\scripts\install-windows-service.ps1 status

# Stop the service
Stop-Service IronMesh

# Restart
Restart-Service IronMesh

# Remove entirely (also stops it)
.\scripts\install-windows-service.ps1 uninstall
```

## Logs

NSSM rotates stdout / stderr on a 10 MiB ceiling. Files live at:

- `~\.ironmesh\logs\IronMesh.stdout.log`
- `~\.ironmesh\logs\IronMesh.stderr.log`

Older rotations get a numeric suffix.

For production observability, prefer redirecting to Windows Event Log
or a structured-log pipeline. The IronMesh daemon itself supports
`--log-format json` (see `ironmesh run --help`); pair that with NSSM's
log redirection for a JSON-line stream that any aggregator can ingest.

## Hardening

- **Run as a dedicated service account**, not LocalSystem. Create a
  local account `IronMeshSvc` with no interactive logon rights, grant
  it read access to the passphrase file, and set the service's
  "Log On As" tab to that account.
- **Restrict the passphrase file ACL** — grant read only to the
  service account and you. Strip Everyone / Users.
- **Pair with `--require-message-promotion`** so the service will not
  silently accept messages from new TOFU peers without operator
  promotion via the dashboard / MCP / CLI.
- **Use the OS keychain backend** instead of a passphrase file if
  your deployment workflow prefers it: see
  [`keys keychain-store`](../README.md). Set
  `IRONMESH_PASSPHRASE_KEYCHAIN=true` in the service environment.

## Troubleshooting

- **Service starts then stops immediately.** Check
  `~\.ironmesh\logs\IronMesh.stderr.log` for the startup error. The
  most common cause is a missing or wrong-permission passphrase file.
- **Service won't install — "binary path not found."** The wrapper
  uses `Get-Command ironmesh.exe`. If you installed `ironmesh` into a
  virtualenv, activate that venv before running the install script,
  or pass the absolute path to the venv's `ironmesh.exe`.
- **NSSM not found.** Install via `choco install nssm` (recommended)
  or `scoop install nssm`. Manual install: download from
  https://nssm.cc and place `nssm.exe` somewhere on PATH.
- **Permission denied writing logs.** The script creates
  `~\.ironmesh\logs\` if missing; if you customize `-LogDir`, ensure
  the service account can write there.

## Why NSSM over `pywin32`?

`pywin32`'s `win32serviceutil` works but treats the service as a
Python class with `SvcDoRun()` / `SvcStop()` overrides, and stdin /
stdout / stderr redirection requires custom Python code. NSSM treats
the daemon as an opaque binary, redirects pipes at the OS level,
handles the SCM lifecycle, and survives Python upgrades without
requiring any IronMesh code change. Less coupling, fewer Windows-
specific Python edge cases.
