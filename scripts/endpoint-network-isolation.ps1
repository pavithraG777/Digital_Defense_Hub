[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$AllowedRemoteAddress = @(),
    [string]$RuleGroup = 'Digital Defense Hub Endpoint Isolation',
    [string]$StatePath = (Join-Path $env:ProgramData 'DigitalDefenseHub\network-isolation-state.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This response isolates the local victim endpoint only. Configure backend/VPN
# responder addresses in the allow list before enabling automated isolation.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Endpoint network isolation requires an elevated Administrator PowerShell session.'
}

if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Block outbound network access for incident containment')) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $StatePath) | Out-Null
    $profiles = Get-NetFirewallProfile | Select-Object Name, DefaultOutboundAction
    @{ profiles = @($profiles); isolated_at = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding utf8
    Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Block
    foreach ($address in $AllowedRemoteAddress) {
        if (-not [string]::IsNullOrWhiteSpace($address)) {
            New-NetFirewallRule -DisplayName "DDH Incident Isolation - Allow $address" -Group $RuleGroup -Direction Outbound -Action Allow -RemoteAddress $address -Profile Any | Out-Null
        }
    }
    Write-Host 'Endpoint network isolation enabled. Restore only after analyst approval.' -ForegroundColor Red
}
