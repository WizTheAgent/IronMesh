# install-windows-service.ps1 — install IronMesh as a Windows service via NSSM.
#
# Why NSSM and not pywin32? NSSM (the Non-Sucking Service Manager) is a
# tiny, well-tested, externally-maintained service wrapper that handles
# stdin/stdout redirection, automatic restart, and graceful shutdown
# better than pywin32's `win32serviceutil` for Python daemons. It is
# installed once and forgotten about.
#
# Usage (in an elevated PowerShell):
#
#   # Install the service
#   .\scripts\install-windows-service.ps1 install -Name alice `
#       -PassphraseFile C:\path\to\passphrase
#
#   # Start it
#   Start-Service IronMesh
#
#   # Stop it
#   Stop-Service IronMesh
#
#   # Remove it
#   .\scripts\install-windows-service.ps1 uninstall
#
# Prerequisites:
#   - PowerShell 5.1+ (or 7+)
#   - NSSM installed and on PATH:  choco install nssm   (or scoop install nssm)
#   - ironmesh installed:          pip install ironmesh
#   - A passphrase file:           you can produce one with `ironmesh setup`

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateSet("install", "uninstall", "status")]
    [string]$Action,

    [string]$ServiceName = "IronMesh",
    [string]$Name = "ironmesh",
    [int]$Port = 8765,
    [string]$PassphraseFile = "$env:USERPROFILE\.ironmesh\passphrase",
    [string]$KeysPath = "$env:USERPROFILE\.ironmesh\keys.json",
    [string]$LogDir = "$env:USERPROFILE\.ironmesh\logs",
    [string]$AllowedPeers = "",
    [switch]$RequireMessagePromotion,
    [switch]$Gui
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script must be run from an elevated PowerShell prompt (Run as Administrator)."
        exit 1
    }
}

function Assert-Nssm {
    $nssm = Get-Command nssm.exe -ErrorAction SilentlyContinue
    if (-not $nssm) {
        Write-Error "NSSM not found on PATH. Install with one of:`n  choco install nssm`n  scoop install nssm`nThen re-run."
        exit 1
    }
    return $nssm.Source
}

function Find-Ironmesh {
    $ironmesh = Get-Command ironmesh.exe -ErrorAction SilentlyContinue
    if (-not $ironmesh) {
        $ironmesh = Get-Command ironmesh -ErrorAction SilentlyContinue
    }
    if (-not $ironmesh) {
        Write-Error "ironmesh not found on PATH. Install with: pip install ironmesh"
        exit 1
    }
    return $ironmesh.Source
}

switch ($Action) {
    "install" {
        Assert-Admin
        $nssm = Assert-Nssm
        $ironmesh = Find-Ironmesh

        if (-not (Test-Path $PassphraseFile)) {
            Write-Error "Passphrase file not found: $PassphraseFile`nGenerate one with:`n  ironmesh setup --name $Name"
            exit 1
        }

        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }

        # Build the argument list for ironmesh run
        $ironmeshArgs = @(
            "run",
            "--name", $Name,
            "--port", $Port,
            "--passphrase-file", $PassphraseFile,
            "--keys-path", $KeysPath
        )
        if ($AllowedPeers) {
            $ironmeshArgs += @("--allowed-peers", $AllowedPeers)
        }
        if ($RequireMessagePromotion) {
            $ironmeshArgs += "--require-message-promotion"
        }
        if ($Gui) {
            $ironmeshArgs += "--gui"
        }

        # Install the service. NSSM swallows the args after `install`.
        & $nssm install $ServiceName $ironmesh @ironmeshArgs

        # Stdout / stderr redirection
        & $nssm set $ServiceName AppStdout (Join-Path $LogDir "$ServiceName.stdout.log")
        & $nssm set $ServiceName AppStderr (Join-Path $LogDir "$ServiceName.stderr.log")
        & $nssm set $ServiceName AppStdoutCreationDisposition 4   # OPEN_ALWAYS
        & $nssm set $ServiceName AppStderrCreationDisposition 4
        & $nssm set $ServiceName AppRotateFiles 1
        & $nssm set $ServiceName AppRotateBytes 10485760           # 10 MiB

        # Restart on failure with backoff
        & $nssm set $ServiceName AppExit Default Restart
        & $nssm set $ServiceName AppRestartDelay 5000              # 5 s

        # Graceful shutdown — give the daemon 30 s to clean up
        & $nssm set $ServiceName AppStopMethodConsole 30000

        # Start automatically on boot
        & $nssm set $ServiceName Start SERVICE_AUTO_START

        Write-Host ""
        Write-Host "Installed Windows service '$ServiceName'." -ForegroundColor Green
        Write-Host "  Binary:        $ironmesh"
        Write-Host "  Args:          run --name $Name --port $Port --passphrase-file <hidden>"
        Write-Host "  Log directory: $LogDir"
        Write-Host ""
        Write-Host "Start with:"
        Write-Host "  Start-Service $ServiceName"
        Write-Host "Then verify:"
        Write-Host "  Get-Service $ServiceName"
        Write-Host "  Get-Content $LogDir\$ServiceName.stderr.log -Tail 20"
    }

    "uninstall" {
        Assert-Admin
        $nssm = Assert-Nssm

        # Stop first if running, ignore failure if it's already stopped
        try { Stop-Service $ServiceName -Force -ErrorAction Stop } catch { }
        & $nssm remove $ServiceName confirm
        Write-Host "Removed Windows service '$ServiceName'." -ForegroundColor Yellow
    }

    "status" {
        $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Host "Service '$ServiceName' is not installed." -ForegroundColor Yellow
            exit 0
        }
        Write-Host "Service: $ServiceName"
        Write-Host "  Status:    $($svc.Status)"
        Write-Host "  Startup:   $($svc.StartType)"
        if (Test-Path "$LogDir\$ServiceName.stderr.log") {
            Write-Host ""
            Write-Host "Last 20 lines of stderr:"
            Get-Content "$LogDir\$ServiceName.stderr.log" -Tail 20
        }
    }
}
