param(
    [ValidateSet('Setup', 'Trigger', 'Reset')]
    [string]$Mode = 'Setup'
)

$demoRoot = 'E:\Cyber-Security-Platform\MyProtectedFolder\RansomwareLiveDemo'
$resolvedWorkspace = [IO.Path]::GetFullPath('E:\Cyber-Security-Platform')
$resolvedDemo = [IO.Path]::GetFullPath($demoRoot)
if (-not $resolvedDemo.StartsWith($resolvedWorkspace, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Demo path must remain inside the project workspace.'
}

if ($Mode -eq 'Setup') {
    New-Item -ItemType Directory -Path $resolvedDemo -Force | Out-Null
    1..20 | ForEach-Object {
        $path = Join-Path $resolvedDemo ("business-document-{0:D2}.txt" -f $_)
        Set-Content -LiteralPath $path -Value "Safe ransomware monitoring demo document $_"
    }
    Write-Host "Demo folder prepared: $resolvedDemo" -ForegroundColor Cyan
    Write-Host 'Select this folder in Ransomware Detection > Live Behaviour Monitor, then run Trigger.' -ForegroundColor Yellow
    exit 0
}

if (-not (Test-Path -LiteralPath $resolvedDemo -PathType Container)) {
    throw 'Run this script with -Mode Setup first.'
}

if ($Mode -eq 'Trigger') {
    Get-ChildItem -LiteralPath $resolvedDemo -File -Filter '*.txt' | ForEach-Object {
        Add-Content -LiteralPath $_.FullName -Value ("Bulk modification demo at {0:o}" -f [DateTime]::UtcNow)
        Rename-Item -LiteralPath $_.FullName -NewName ($_.Name + '.locked-demo')
    }
    Write-Host 'Safe bulk modification + extension-change activity completed.' -ForegroundColor Red
    exit 0
}

Get-ChildItem -LiteralPath $resolvedDemo -File -Filter '*.locked-demo' | ForEach-Object {
    Rename-Item -LiteralPath $_.FullName -NewName ($_.Name -replace '\.locked-demo$', '')
}
Write-Host 'Demo filenames restored.' -ForegroundColor Green
