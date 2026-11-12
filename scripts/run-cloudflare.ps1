param([switch]$SkipMigrations)
$ErrorActionPreference = "Stop"
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$backendRoot = Join-Path $projectRoot "backend-go"
$frontendRoot = Join-Path $projectRoot "frontend-react"
$aiRoot = Join-Path $projectRoot "ai-engine"

$cloudflaredCommand = Get-Command cloudflared -ErrorAction SilentlyContinue
$cloudflaredExe = if ($cloudflaredCommand) { $cloudflaredCommand.Source } else { $null }
if (-not $cloudflaredExe) {
  $standardLocations = @(
    "${env:ProgramFiles(x86)}\cloudflared\cloudflared.exe",
    "$env:ProgramFiles\cloudflared\cloudflared.exe",
    "$env:LOCALAPPDATA\Microsoft\WinGet\Links\cloudflared.exe"
  )
  $cloudflaredExe = $standardLocations | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}
if (-not $cloudflaredExe) { throw "cloudflared was installed but its executable was not found. Reopen PowerShell or locate it with: Get-ChildItem C:\ -Filter cloudflared.exe -Recurse -ErrorAction SilentlyContinue" }
if (-not $SkipMigrations) {
  Push-Location $backendRoot
  try {
    & go run .\cmd\migrate --from 45
    if ($LASTEXITCODE -ne 0) { throw "Database migration failed." }
  } finally { Pop-Location }
}

$backend = Start-Process go -ArgumentList "run .\cmd\api" -WorkingDirectory $backendRoot -PassThru -WindowStyle Hidden
$python = Join-Path $aiRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) { $python = "python" }
$ai = Start-Process $python -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8091" -WorkingDirectory $aiRoot -PassThru -WindowStyle Hidden
$frontend = Start-Process npm.cmd -ArgumentList "run dev -- --host 127.0.0.1" -WorkingDirectory $frontendRoot -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 5

Write-Host "Local frontend: http://127.0.0.1:5173"
Write-Host "Starting temporary Cloudflare URL. Copy the https://*.trycloudflare.com address shown below."
Write-Host "Keep this window open. Ctrl+C stops the public tunnel."
& $cloudflaredExe tunnel --url http://127.0.0.1:5173
