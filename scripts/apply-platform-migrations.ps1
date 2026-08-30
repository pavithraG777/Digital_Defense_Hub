param(
    [string]$MigrationDirectory = "$PSScriptRoot\migrations\seed",
    [switch]$ValidateOnly,
    [switch]$AdoptLegacySchema
)

$ErrorActionPreference = 'Stop'
$migrationRoot = (Resolve-Path -LiteralPath $MigrationDirectory).Path
$files = @(Get-ChildItem -LiteralPath $migrationRoot -File | Where-Object { $_.Name -match '^\d{3}_[a-z0-9_]+\.sql$' -and $_.Name -notmatch '^9\d{2}_' } | Sort-Object Name)
if ($files.Count -eq 0) { throw "No numbered platform migrations found in $migrationRoot" }

$names = @{}
foreach ($file in $files) {
    if ($names.ContainsKey($file.Name)) { throw "Duplicate migration name: $($file.Name)" }
    $names[$file.Name] = $true
    $content = Get-Content -LiteralPath $file.FullName -Raw
    if ([string]::IsNullOrWhiteSpace($content)) { throw "Empty migration: $($file.Name)" }
}

$required = 24..30 | ForEach-Object { $_.ToString('000') }
foreach ($prefix in $required) {
    if (-not ($files.Name | Where-Object { $_ -like "${prefix}_*" })) { throw "Required migration $prefix is missing" }
}
Write-Host "Validated $($files.Count) ordered platform migrations, including 024-030."
if ($ValidateOnly) { exit 0 }

$requiredEnv = 'DB_HOST','DB_PORT','DB_USER','DB_NAME'
foreach ($name in $requiredEnv) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) { throw "$name is required" }
}
$psqlCommand = Get-Command psql -ErrorAction SilentlyContinue
if ($psqlCommand) {
    $psql = $psqlCommand.Source
} else {
    $psql = Get-ChildItem -LiteralPath "$env:ProgramFiles\PostgreSQL" -Filter psql.exe -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $psql) { throw 'PostgreSQL client (psql.exe) was not found. Install the PostgreSQL command-line tools or add its bin folder to PATH.' }

$env:PGPASSWORD = $env:DB_PASSWORD
$sslMode = if ($env:DB_SSLMODE) { $env:DB_SSLMODE } else { 'require' }
$env:PGSSLMODE = $sslMode
$connectionArgs = @('-X','--set','ON_ERROR_STOP=1','-h',$env:DB_HOST,'-p',$env:DB_PORT,'-U',$env:DB_USER,'-d',$env:DB_NAME)
& $psql @connectionArgs -c 'CREATE TABLE IF NOT EXISTS platform_schema_migrations(name TEXT PRIMARY KEY, sha256 TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW());'
if ($LASTEXITCODE -ne 0) { throw 'Could not initialize migration history' }

if ($AdoptLegacySchema) {
    # This is deliberately opt-in. It is only for databases that predate this
    # migration tracker but were already upgraded through the 024 cutover.
    $hasCutover = (& $psql @connectionArgs -tAc "SELECT EXISTS (SELECT 1 FROM platform_schema_migrations WHERE name LIKE '024_%') AND NOT EXISTS (SELECT 1 FROM platform_schema_migrations WHERE name LIKE '001_%')").Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect legacy migration history' }
    if ($hasCutover -ne 't') { throw 'Legacy adoption requires recorded 024 migrations and no recorded 001 migrations.' }

    $legacySchemaPresent = (& $psql @connectionArgs -tAc "SELECT to_regclass('public.file_events') IS NOT NULL AND to_regclass('public.threats') IS NOT NULL AND to_regclass('public.authentication_mfa_challenges') IS NOT NULL").Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not verify the legacy schema' }
    if ($legacySchemaPresent -ne 't') { throw 'Legacy schema sentinel tables are missing; refusing to adopt migration history.' }

    $legacyFiles = @($files | Where-Object { $_.Name -match '^(00[1-9]|01[0-9]|02[0-3])_' })
    foreach ($file in $legacyFiles) {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        & $psql @connectionArgs -c "INSERT INTO platform_schema_migrations(name,sha256) VALUES('$($file.Name.Replace("'","''"))','$hash') ON CONFLICT (name) DO NOTHING;"
        if ($LASTEXITCODE -ne 0) { throw "Could not adopt legacy migration: $($file.Name)" }
        Write-Host "ADOPTED $($file.Name)"
    }
    Write-Host 'Legacy migration history adopted. Run this script again without -AdoptLegacySchema to apply pending migrations.'
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
    exit 0
}

foreach ($file in $files) {
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    # psql emits no object for a query with no matching row; normalize that
    # expected first-run result before calling string methods on it.
    $existingOutput = & $psql @connectionArgs -tAc "SELECT sha256 FROM platform_schema_migrations WHERE name='$($file.Name.Replace("'","''"))'"
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect migration $($file.Name)" }
    $existingValue = $existingOutput | Select-Object -First 1
    $existing = if ($null -eq $existingValue) { '' } else { $existingValue.ToString().Trim() }
    if ($existing) {
        if ($existing -ne $hash) { throw "Applied migration checksum changed: $($file.Name)" }
        Write-Host "SKIP $($file.Name)"
        continue
    }
    & $psql @connectionArgs -f $file.FullName
    if ($LASTEXITCODE -ne 0) { throw "Migration failed: $($file.Name)" }
    & $psql @connectionArgs -c "INSERT INTO platform_schema_migrations(name,sha256) VALUES('$($file.Name.Replace("'","''"))','$hash');"
    if ($LASTEXITCODE -ne 0) { throw "Could not record migration: $($file.Name)" }
    Write-Host "APPLIED $($file.Name)"
}
Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
