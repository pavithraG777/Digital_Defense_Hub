[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$RuleGroup = 'Digital Defense Hub Endpoint Isolation',
    [string]$StatePath = (Join-Path $env:ProgramData 'DigitalDefenseHub\network-isolation-state.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Restoring endpoint networking requires an elevated Administrator PowerShell session.'
}

if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Remove Digital Defense Hub isolation rules')) {
    Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
        $state = Get-Content -Raw -LiteralPath $StatePath | ConvertFrom-Json
        foreach ($profile in $state.profiles) {
            Set-NetFirewallProfile -Profile $profile.Name -DefaultOutboundAction $profile.DefaultOutboundAction
        }
        Remove-Item -LiteralPath $StatePath -Force
    }
    Write-Host 'Endpoint network isolation rules removed.' -ForegroundColor Green
}
