[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$WatchPath,

    [ValidateRange(1, 1440)]
    [int]$RotationMinutes = 30,

    [string]$TaskName = 'Digital Defense Hub Canary Sentinel'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sentinelPath = Join-Path $PSScriptRoot 'canary-sentinel.ps1'
if (-not (Test-Path -LiteralPath $sentinelPath -PathType Leaf)) {
    throw "Canary Sentinel script was not found: $sentinelPath"
}

$resolvedPaths = foreach ($path in $WatchPath) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        throw "Watch path does not exist: $path"
    }
    [IO.Path]::GetFullPath($path)
}

$quotedWatchPaths = ($resolvedPaths | ForEach-Object { "'$_'" }) -join ','
$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$sentinelPath`" -WatchPath $quotedWatchPaths -RotationMinutes $RotationMinutes"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Days 0)

if ($PSCmdlet.ShouldProcess($TaskName, 'Register logon task')) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Starts Digital Defense Hub Canary Sentinel when the user signs in.' -Force | Out-Null
    Write-Host "Installed scheduled task: $TaskName" -ForegroundColor Green
}
