param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$resolvedParent = (Resolve-Path -LiteralPath $OutputDirectory -ErrorAction SilentlyContinue)
if (-not $resolvedParent) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $resolvedParent = Resolve-Path -LiteralPath $OutputDirectory
}
$pgDump = Get-Command pg_dump -ErrorAction SilentlyContinue
if (-not $pgDump) {
    $pgDump = Get-ChildItem -LiteralPath "$env:ProgramFiles\PostgreSQL" -Filter pg_dump.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\bin\\pg_dump\.exe$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
}
if (-not $pgDump) { throw 'pg_dump is required' }
foreach ($name in 'DB_HOST','DB_PORT','DB_USER','DB_NAME') { if (-not [Environment]::GetEnvironmentVariable($name)) { throw "$name is required" } }
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$backup = Join-Path $resolvedParent.Path "ddh-$stamp.dump"
$env:PGPASSWORD = $env:DB_PASSWORD
$env:PGSSLMODE = if ($env:DB_SSLMODE) { $env:DB_SSLMODE } else { 'require' }
try {
    & $pgDump.Source -Fc --no-owner --no-acl -h $env:DB_HOST -p $env:DB_PORT -U $env:DB_USER -d $env:DB_NAME -f $backup
    if ($LASTEXITCODE -ne 0) { throw 'Database backup failed' }
} finally {
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
}
$hash = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$backup.sha256" -Value "$hash  $([IO.Path]::GetFileName($backup))" -Encoding ascii
Write-Host "Backup created: $backup"
