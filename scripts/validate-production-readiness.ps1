param([switch]$AllowMissingExternalServices)
$ErrorActionPreference = 'Stop'
$failures = [Collections.Generic.List[string]]::new()
function Require-Setting([string]$Name) { if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($Name))) { $failures.Add("Missing $Name") } }
foreach ($name in 'DB_HOST','DB_PORT','DB_USER','DB_NAME','JWT_SECRET','KEY_ENCRYPTION_MASTER_KEY','METRICS_BEARER_TOKEN','EVIDENCE_SIGNING_KEY_ID','EVIDENCE_SIGNING_PUBLIC_KEY_BASE64') { Require-Setting $name }
if ($env:APP_ENV -eq 'production' -and $env:DB_SSLMODE -eq 'disable') { $failures.Add('DB_SSLMODE must not be disable in production') }
if (-not $AllowMissingExternalServices) {
    foreach ($name in 'COMMAND_SANDBOX_URL','COMMAND_SANDBOX_TOKEN','RECOVERY_RUNNER_URL','RECOVERY_RUNNER_TOKEN') { Require-Setting $name }
}
& "$PSScriptRoot\apply-platform-migrations.ps1" -ValidateOnly
if ($LASTEXITCODE -ne 0) { $failures.Add('Migration validation failed') }
if ($failures.Count -gt 0) { $failures | ForEach-Object { Write-Error $_ }; exit 1 }
Write-Host 'Production readiness configuration checks passed.'
