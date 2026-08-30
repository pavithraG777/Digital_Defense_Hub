[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FeatureState([string]$FeatureName) {
    try {
        return (Get-WindowsOptionalFeature -Online -FeatureName $FeatureName).State.ToString()
    } catch {
        return 'UNAVAILABLE'
    }
}

function Get-CimPropertyValue([string]$ClassName, [string]$PropertyName) {
    try {
        return (Get-CimInstance -ClassName $ClassName -ErrorAction Stop).$PropertyName
    } catch {
        return 'UNAVAILABLE'
    }
}

$deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
$report = [ordered]@{
    collected_at = (Get-Date).ToUniversalTime().ToString('o')
    computer = $env:COMPUTERNAME
    virtualization_based_security = if ($deviceGuard) { $deviceGuard.VirtualizationBasedSecurityStatus } else { 'UNAVAILABLE' }
    hypervisor_present = Get-CimPropertyValue 'Win32_ComputerSystem' 'HypervisorPresent'
    windows_sandbox = Get-FeatureState 'Containers-DisposableClientVM'
    hyper_v = Get-FeatureState 'Microsoft-Hyper-V-All'
    application_guard = Get-FeatureState 'Windows-Defender-ApplicationGuard'
}

$report | ConvertTo-Json

Write-Host 'This report is read-only. Kernel-level enforcement requires an administrator-deployed, signed Windows driver or WDAC/AppLocker policy.' -ForegroundColor Yellow
