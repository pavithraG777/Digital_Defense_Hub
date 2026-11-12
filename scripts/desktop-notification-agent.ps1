param(
    [string]$OutboxPath = (Join-Path $PSScriptRoot "..\backend-go\storage\notification-outbox\local-desktop"),
    [int]$PollMilliseconds = 750,
    [switch]$TestSound
)

$ErrorActionPreference = "Stop"
$resolvedOutbox = [System.IO.Path]::GetFullPath($OutboxPath)
$seen = @{}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Invoke-NotificationSound {
    $sampleRate = 44100
    $durationMilliseconds = 240
    $frequency = 880
    $sampleCount = [int]($sampleRate * $durationMilliseconds / 1000)
    $dataLength = $sampleCount * 2
    $stream = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter($stream)

    try {
        $writer.Write([Text.Encoding]::ASCII.GetBytes("RIFF"))
        $writer.Write([int32](36 + $dataLength))
        $writer.Write([Text.Encoding]::ASCII.GetBytes("WAVE"))
        $writer.Write([Text.Encoding]::ASCII.GetBytes("fmt "))
        $writer.Write([int32]16)
        $writer.Write([int16]1)
        $writer.Write([int16]1)
        $writer.Write([int32]$sampleRate)
        $writer.Write([int32]($sampleRate * 2))
        $writer.Write([int16]2)
        $writer.Write([int16]16)
        $writer.Write([Text.Encoding]::ASCII.GetBytes("data"))
        $writer.Write([int32]$dataLength)

        for ($sample = 0; $sample -lt $sampleCount; $sample++) {
            $value = [int16](12000 * [Math]::Sin(2 * [Math]::PI * $frequency * $sample / $sampleRate))
            $writer.Write($value)
        }

        $writer.Flush()
        $stream.Position = 0
        $player = New-Object System.Media.SoundPlayer($stream)
        $player.PlaySync()
        $player.Dispose()
    }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

if ($TestSound) {
    Invoke-NotificationSound
    Start-Sleep -Milliseconds 180
    Invoke-NotificationSound
    exit 0
}

$notifyIcon = New-Object System.Windows.Forms.NotifyIcon
$notifyIcon.Icon = [System.Drawing.SystemIcons]::Shield
$notifyIcon.Visible = $true
$notifyIcon.Text = "Digital Defense Hub"

try {
    Write-Host "Digital Defense Hub desktop notification agent is running."
    Write-Host "Watching: $resolvedOutbox"

    while ($true) {
        if (Test-Path -LiteralPath $resolvedOutbox) {
            Get-ChildItem -LiteralPath $resolvedOutbox -Filter "*.json" -File -Recurse -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $path = $_.FullName
                    if ($seen.ContainsKey($path)) {
                        return
                    }

                    try {
                        $notification = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
                        $seen[$path] = $true

                        $severity = [string]$notification.severity
                        $title = [string]$notification.title
                        $message = [string]$notification.message
                        if ([string]::IsNullOrWhiteSpace($title)) {
                            $title = "Digital Defense Hub security alert"
                        }
                        if ([string]::IsNullOrWhiteSpace($message)) {
                            $message = "A security event requires attention."
                        }

                        $icon = [System.Windows.Forms.ToolTipIcon]::Warning
                        if ($severity -eq "CRITICAL") {
                            $icon = [System.Windows.Forms.ToolTipIcon]::Error
                        }
                        $notifyIcon.ShowBalloonTip(10000, $title, "$severity - $message", $icon)

                        if ([bool]$notification.play_sound) {
                            Invoke-NotificationSound
                            Start-Sleep -Milliseconds 180
                            Invoke-NotificationSound
                        }

                        Write-Host ("[{0}] {1}: {2}" -f (Get-Date -Format s), $severity, $title)
                    }
                    catch {
                        # The backend writes atomically; an unreadable file may
                        # still be in-flight, so retry it on the next poll.
                    }
                }
        }

        Start-Sleep -Milliseconds $PollMilliseconds
    }
}
finally {
    $notifyIcon.Visible = $false
    $notifyIcon.Dispose()
}
