param(
    [switch]$SkipAI,
    [switch]$SkipDesktopAgent,
    [switch]$SkipInfrastructure,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$backend = Join-Path $root "backend-go"
$frontend = Join-Path $root "frontend-react"
$ai = Join-Path $root "ai-engine"
$logDirectory = Join-Path $root "runtime-logs\offline"
$startedProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

function Assert-Path([string]$Path, [string]$Description) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Description was not found: $Path"
    }
}

function Resolve-Command([string]$Name, [string]$Description) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "$Description is required but was not found in PATH ($Name)."
    }
    return $command.Source
}

function Start-LoggedProcess {
    param(
        [string]$Name,
        [string]$FilePath,
        [string]$Arguments,
        [string]$WorkingDirectory
    )

    $stdout = Join-Path $logDirectory "$Name.stdout.log"
    $stderr = Join-Path $logDirectory "$Name.stderr.log"
    $process = Start-Process -FilePath $FilePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru
    $startedProcesses.Add($process)
    return $process
}

function Test-DockerEngine([string]$DockerPath) {
    try {
        & $DockerPath info *> $null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

function Wait-DockerEngine([string]$DockerPath, [int]$TimeoutSeconds = 90) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-DockerEngine $DockerPath) {
            return
        }
        Start-Sleep -Seconds 2
    }
    throw "Docker Desktop did not become ready within $TimeoutSeconds seconds."
}

function Stop-LocalPortListener([int]$Port) {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    $processIds = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
    foreach ($processId in $processIds) {
        if (-not $processId -or $processId -eq $PID) {
            continue
        }
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "[STOP] Previous local service on port $Port ($($process.ProcessName), PID $processId)"
            Stop-Process -Id $processId -Force -ErrorAction Stop
        }
    }
}

function Wait-LocalPort {
    param(
        [string]$Name,
        [int]$Port,
        [System.Diagnostics.Process]$Process,
        [int]$TimeoutSeconds = 45
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($Process.HasExited) {
            $errorLog = Join-Path $logDirectory "$Name.stderr.log"
            $details = if (Test-Path -LiteralPath $errorLog) {
                (Get-Content -LiteralPath $errorLog -Tail 12) -join [Environment]::NewLine
            } else {
                "No error log was created."
            }
            throw "$Name stopped before port $Port became ready.`n$details"
        }

        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $result = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
            if ($result.AsyncWaitHandle.WaitOne(300) -and $client.Connected) {
                $client.EndConnect($result)
                Start-Sleep -Seconds 2
                $Process.Refresh()
                if ($Process.HasExited) {
                    $errorLog = Join-Path $logDirectory "$Name.stderr.log"
                    $details = if (Test-Path -LiteralPath $errorLog) {
                        (Get-Content -LiteralPath $errorLog -Tail 12) -join [Environment]::NewLine
                    } else {
                        "No error log was created."
                    }
                    throw "$Name could not claim port $Port. A previous local process may still be using it.`n$details"
                }
                Write-Host "[READY] $Name - http://127.0.0.1:$Port" -ForegroundColor Green
                return
            }
        } catch {
            # The service may still be starting.
        } finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 500
    }

    throw "$Name did not open port $Port within $TimeoutSeconds seconds. Check $logDirectory."
}

Assert-Path (Join-Path $backend ".env") "Backend .env"
Assert-Path (Join-Path $backend "go.mod") "Backend Go module"
Assert-Path (Join-Path $frontend "package.json") "Frontend package"
Assert-Path (Join-Path $frontend "node_modules") "Frontend dependencies (run npm install once while online)"

$go = Resolve-Command "go.exe" "Go"
$npm = Resolve-Command "npm.cmd" "Node/npm"
$python = Join-Path $ai ".venv\Scripts\python.exe"
if (-not $SkipAI) {
    Assert-Path (Join-Path $ai ".env") "AI engine .env"
    Assert-Path $python "AI engine virtual environment (install requirements once while online)"
}

New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null

Write-Host "Starting Digital Defense Hub in offline/local mode..." -ForegroundColor Cyan
Write-Host "Runtime logs: $logDirectory" -ForegroundColor DarkGray

# Ctrl+C can leave child services alive. Clear only the three ports owned by
# this local stack so every launch runs the current code.
Stop-LocalPortListener 8080
Stop-LocalPortListener 8091
Stop-LocalPortListener 5173
Start-Sleep -Milliseconds 500

if (-not $SkipInfrastructure) {
    $docker = Resolve-Command "docker.exe" "Docker Desktop"
    if (-not (Test-DockerEngine $docker)) {
        $dockerDesktop = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
        Assert-Path $dockerDesktop "Docker Desktop"
        Write-Host "[START] Docker Desktop"
        Start-Process -FilePath $dockerDesktop | Out-Null
        Wait-DockerEngine $docker
    }
    Write-Host "[START] Local object storage"
    $dockerProcess = Start-Process -FilePath $docker `
        -ArgumentList "compose -f docker-compose.local.yml up -d --pull never" `
        -WorkingDirectory $backend `
        -Wait `
        -PassThru `
        -NoNewWindow
    if ($dockerProcess.ExitCode -ne 0) {
        throw "Local Docker services failed to start. Ensure Docker Desktop is running and the images were downloaded before going offline."
    }
}

Write-Host "[START] Backend API"
$backendProcess = Start-LoggedProcess -Name "backend" -FilePath $go -Arguments "run .\cmd\api" -WorkingDirectory $backend

$aiProcess = $null
if (-not $SkipAI) {
    Write-Host "[START] AI engine"
    $aiProcess = Start-LoggedProcess -Name "ai-engine" -FilePath $python -Arguments "-m uvicorn app.main:app --host 127.0.0.1 --port 8091" -WorkingDirectory $ai
}

Write-Host "[START] Frontend"
$frontendProcess = Start-LoggedProcess -Name "frontend" -FilePath $npm -Arguments "run dev -- --host localhost" -WorkingDirectory $frontend

$desktopProcess = $null
if (-not $SkipDesktopAgent) {
    Write-Host "[START] Local desktop notification agent"
    $agent = Join-Path $PSScriptRoot "local_desktop_notification_agent.ps1"
    Assert-Path $agent "Local desktop notification agent"
    $desktopProcess = Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$agent`"" `
        -WorkingDirectory $root `
        -PassThru
    $startedProcesses.Add($desktopProcess)
}

try {
    Wait-LocalPort -Name "Backend" -Port 8080 -Process $backendProcess
    if ($aiProcess) {
        Wait-LocalPort -Name "AI engine" -Port 8091 -Process $aiProcess
    }
    Wait-LocalPort -Name "Frontend" -Port 5173 -Process $frontendProcess

    Write-Host ""
    Write-Host "Digital Defense Hub is ready for the offline demo." -ForegroundColor Green
    Write-Host "Open: http://localhost:5173" -ForegroundColor Cyan
    Write-Host "Keep this launcher window open. Press Ctrl+C when the demo is finished."

    if (-not $NoBrowser) {
        Start-Process "http://localhost:5173"
    }

    Wait-Process -Id $backendProcess.Id
} catch {
    Write-Host ""
    Write-Host "Offline startup failed: $($_.Exception.Message)" -ForegroundColor Red
    throw
}
