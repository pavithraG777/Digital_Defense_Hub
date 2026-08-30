param(
    [Parameter(Mandatory=$true)][string]$BackupFile,
    [Parameter(Mandatory=$true)][string]$TargetDatabase,
    [switch]$ConfirmRestore
)
$ErrorActionPreference = 'Stop'
if (-not $ConfirmRestore) { throw 'Restore is destructive. Re-run with -ConfirmRestore after validating the target database.' }
$backup = (Resolve-Path -LiteralPath $BackupFile).Path
if ($TargetDatabase -eq $env:DB_NAME -and $env:APP_ENV -eq 'production') { throw 'In-place production restore is blocked; restore into a separate validation database first.' }
$pgRestore = Get-Command pg_restore -ErrorAction SilentlyContinue
if (-not $pgRestore) {
    $pgRestore = Get-ChildItem -LiteralPath "$env:ProgramFiles\PostgreSQL" -Filter pg_restore.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\bin\\pg_restore\.exe$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
}
if (-not $pgRestore) { throw 'pg_restore is required' }
$hashFile = "$backup.sha256"
if (-not (Test-Path -LiteralPath $hashFile)) { throw 'Backup checksum sidecar is required' }
$expected = ((Get-Content -LiteralPath $hashFile -Raw).Trim() -split '\s+')[0]
$actual = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant()
if ($expected -ne $actual) { throw 'Backup checksum verification failed' }
$env:PGPASSWORD = $env:DB_PASSWORD
$env:PGSSLMODE = if ($env:DB_SSLMODE) { $env:DB_SSLMODE } else { 'require' }
try {
    & $pgRestore.Source --exit-on-error --clean --if-exists --no-owner --no-acl -h $env:DB_HOST -p $env:DB_PORT -U $env:DB_USER -d $TargetDatabase $backup
    if ($LASTEXITCODE -ne 0) { throw 'Database restore failed' }
} finally {
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
}
Write-Host "Restore verified and completed into $TargetDatabase"
