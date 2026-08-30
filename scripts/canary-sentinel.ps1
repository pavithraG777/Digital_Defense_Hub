[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$WatchPath,

    [ValidateRange(1, 1440)]
    [int]$RotationMinutes = 30,

    [ValidateRange(1, 60)]
    [int]$CanariesPerFolder = 1,

    [ValidateRange(1, 3600)]
    [int]$MinimumSecondsBetweenAlerts = 10,

    [bool]$IncludeSubdirectories = $true,

    [ValidateNotNullOrEmpty()]
    [string]$CanaryNotice = 'CONFIDENTIAL: This document is monitored by Digital Defense Hub. Do not copy, modify, rename, or delete it without authorization.',

    [ValidateSet('AuditOnly', 'NetworkIsolate')]
    [string]$IsolationMode = 'AuditOnly',

    [string[]]$AllowedRemoteAddress = @(),

    [string]$StateDirectory = (Join-Path $PSScriptRoot '..\storage\canary-sentinel')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This is an offline endpoint agent.  It intentionally monitors only folders
# the local user explicitly supplies; it never scans the whole drive.
$stateRoot = [IO.Path]::GetFullPath($StateDirectory)
New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
$alertLog = Join-Path $stateRoot 'alerts.jsonl'
$inventoryPath = Join-Path $stateRoot 'canary-inventory.json'
$evidenceRoot = Join-Path $stateRoot 'evidence'
New-Item -ItemType Directory -Force -Path $evidenceRoot | Out-Null
$canaries = @{}
$watchers = @()
$lastCreated = @{}
$lastAlerted = @{}
$subscriptionPrefix = 'ddh-' + [Guid]::NewGuid().ToString('N')
$rotationDue = (Get-Date).AddMinutes($RotationMinutes)

function Get-PathKey([string]$Path) {
    return [IO.Path]::GetFullPath($Path).ToUpperInvariant()
}

function Save-CanaryInventory {
    $inventory = @(
        foreach ($canary in $canaries.Values) {
            [ordered]@{
                path = $canary.path
                directory = $canary.directory
                created_at = $canary.created_at.ToUniversalTime().ToString('o')
                sha256 = if (Test-Path -LiteralPath $canary.path -PathType Leaf) {
                    (Get-FileHash -Algorithm SHA256 -LiteralPath $canary.path).Hash
                } else {
                    $null
                }
            }
        }
    )
    $inventory | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $inventoryPath -Encoding utf8
}

function New-CanaryName {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
    $token = [Guid]::NewGuid().ToString('N').Substring(0, 8).ToUpperInvariant()
    $labels = @('Quarterly_Finance', 'Employee_Salary', 'Customer_Archive', 'Backup_Credentials')
    return "$($labels | Get-Random)_$stamp`_$token.txt"
}

function Write-CanaryAlert([string]$EventType, [string]$Path) {
    $alertKey = "$(Get-PathKey $Path)|$EventType"
    $lastSent = $lastAlerted[$alertKey]
    if ($null -ne $lastSent -and ((Get-Date) - $lastSent).TotalSeconds -lt $MinimumSecondsBetweenAlerts) {
        return
    }
    $lastAlerted[$alertKey] = Get-Date
    $alert = [ordered]@{
        occurred_at = (Get-Date).ToUniversalTime().ToString('o')
        severity    = 'CRITICAL'
        source_type = 'CANARY_FILE'
        event_type  = $EventType
        file_path   = $Path
        computer    = $env:COMPUTERNAME
        username    = $env:USERNAME
    }
    ($alert | ConvertTo-Json -Compress) | Add-Content -LiteralPath $alertLog -Encoding utf8
    Write-ForensicEvidence -Alert $alert
    Write-Host "`aCANARY ALERT [$EventType] $Path" -ForegroundColor Red
    try { [Console]::Beep(1400, 350); Start-Sleep -Milliseconds 80; [Console]::Beep(1400, 350) } catch { [Media.SystemSounds]::Exclamation.Play() }
    if ($IsolationMode -eq 'NetworkIsolate') {
        & (Join-Path $PSScriptRoot 'endpoint-network-isolation.ps1') -AllowedRemoteAddress $AllowedRemoteAddress
    }
}

function Write-ForensicEvidence($Alert) {
    # FileSystemWatcher cannot reliably identify the modifying process. This
    # records an endpoint/network snapshot for later analyst correlation.
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss_fff')
    $folder = Join-Path $evidenceRoot ("canary_$stamp")
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
    $localAddresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' } | Select-Object InterfaceAlias, IPAddress, PrefixLength
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
    $processes = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path, StartTime
    $bundle = [ordered]@{
        evidence_version = '1.0'
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
        alert = $Alert
        endpoint = @{ computer = $env:COMPUTERNAME; user = $env:USERNAME; local_ipv4 = @($localAddresses) }
        network_connections = @($connections)
        process_snapshot = @($processes)
    }
    $bundlePath = Join-Path $folder 'evidence.json'
    $bundle | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $bundlePath -Encoding utf8
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $bundlePath).Hash
    [ordered]@{ sha256 = $hash; file = 'evidence.json'; collected_at = $bundle.collected_at } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'chain-of-custody.json') -Encoding utf8
}

function New-LocalCanary([string]$Directory) {
    $name = New-CanaryName
    $path = Join-Path $Directory $name
    $content = @"
$CanaryNotice
Document reference: $([Guid]::NewGuid())
Generated by Digital Defense Hub Canary Sentinel.
"@
    [IO.File]::WriteAllText($path, $content, [Text.Encoding]::UTF8)
    $pathKey = Get-PathKey $path
    $canaries[$pathKey] = @{ created_at = Get-Date; directory = $Directory; path = $path }
    $lastCreated[$pathKey] = Get-Date
    Save-CanaryInventory
    Write-Host "Canary deployed: $path" -ForegroundColor Cyan
}

function Seed-Canaries([string]$Directory) {
    for ($index = 0; $index -lt $CanariesPerFolder; $index++) { New-LocalCanary $Directory }
}

# Validate the complete configuration before creating any decoys. This avoids a
# half-started run when one requested location (for example a OneDrive Desktop)
# is not present on this endpoint.
$resolvedWatchPaths = foreach ($candidate in $WatchPath) {
    $directory = [IO.Path]::GetFullPath($candidate)
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { throw "Watch path does not exist: $directory" }
    $directory
}

foreach ($directory in $resolvedWatchPaths) {
    Seed-Canaries $directory
    $watcher = [IO.FileSystemWatcher]::new($directory, '*')
    $watcher.IncludeSubdirectories = $IncludeSubdirectories
    $watcher.NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite, Size'
    $watcher.EnableRaisingEvents = $true
    Register-ObjectEvent -InputObject $watcher -EventName Created -SourceIdentifier "$subscriptionPrefix-created-$($watchers.Count)" | Out-Null
    Register-ObjectEvent -InputObject $watcher -EventName Changed -SourceIdentifier "$subscriptionPrefix-changed-$($watchers.Count)" | Out-Null
    Register-ObjectEvent -InputObject $watcher -EventName Deleted -SourceIdentifier "$subscriptionPrefix-deleted-$($watchers.Count)" | Out-Null
    Register-ObjectEvent -InputObject $watcher -EventName Renamed -SourceIdentifier "$subscriptionPrefix-renamed-$($watchers.Count)" | Out-Null
    $watchers += $watcher
}

Write-Host "Canary Sentinel is running. Press Ctrl+C to stop." -ForegroundColor Green
try {
    while ($true) {
        $event = Wait-Event -Timeout 1
        if ($null -ne $event) {
            $args = $event.SourceEventArgs
            $path = $args.FullPath
            $eventType = ([regex]::Match($event.SourceIdentifier, '(Created|Changed|Deleted|Renamed)-\d+$', 'IgnoreCase')).Groups[1].Value.ToUpperInvariant()
            $pathKey = Get-PathKey $path
            $trackedKey = $pathKey
            $oldPathKey = $null
            # OldFullPath exists only on RenamedEventArgs; accessing it on a
            # normal file event would terminate the agent under StrictMode.
            $oldPathProperty = $args.PSObject.Properties['OldFullPath']
            if ($null -ne $oldPathProperty -and -not [string]::IsNullOrWhiteSpace($oldPathProperty.Value)) {
                $oldPathKey = Get-PathKey $oldPathProperty.Value
            }
            if (-not $canaries.ContainsKey($trackedKey) -and $null -ne $oldPathKey -and $canaries.ContainsKey($oldPathKey)) {
                $trackedKey = $oldPathKey
            }
            if ($canaries.ContainsKey($trackedKey)) {
                $age = ((Get-Date) - $lastCreated[$trackedKey]).TotalSeconds
                if ($age -gt 2) {
                    Write-CanaryAlert $eventType $canaries[$trackedKey].path
                    if ($eventType -eq 'RENAMED') {
                        $canary = $canaries[$trackedKey]
                        $canary.path = $path
                        $canaries.Remove($trackedKey)
                        $lastCreated.Remove($trackedKey)
                        $canaries[$pathKey] = $canary
                        $lastCreated[$pathKey] = Get-Date
                        Save-CanaryInventory
                    }
                }
            } elseif ($eventType -eq 'CREATED' -and [IO.Path]::GetExtension($path) -ne '') {
                # A user-created normal file causes a fresh decoy to appear in
                # that same chosen folder, without touching user content.
                New-LocalCanary ([IO.Path]::GetDirectoryName($path))
            }
            Remove-Event -EventIdentifier $event.EventIdentifier
        }
        if ((Get-Date) -ge $rotationDue) {
            foreach ($oldPathKey in @($canaries.Keys)) {
                $canary = $canaries[$oldPathKey]
                $oldPath = $canary.path
                $directory = $canary.directory
                # Suppress the watcher event produced by our own rotation.
                $lastCreated[$oldPathKey] = Get-Date
                if (Test-Path -LiteralPath $oldPath) { Remove-Item -LiteralPath $oldPath -Force }
                $canaries.Remove($oldPathKey)
                $lastCreated.Remove($oldPathKey)
                New-LocalCanary $directory
            }
            $rotationDue = (Get-Date).AddMinutes($RotationMinutes)
        }
    }
} finally {
    $watchers | ForEach-Object { $_.Dispose() }
    Get-EventSubscriber | Where-Object SourceIdentifier -like "$subscriptionPrefix-*" | Unregister-Event
}
