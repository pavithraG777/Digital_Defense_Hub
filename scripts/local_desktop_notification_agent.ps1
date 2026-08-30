param(
    [string]$OutboxPath = "$PSScriptRoot\..\backend-go\storage\notification-outbox\local-desktop",
    [ValidateRange(1, 3)]
    [int]$AlertSoundRepeats = 2,
    [ValidateRange(37, 32767)]
    [int]$BeepFrequency = 1200,
    [ValidateRange(50, 2000)]
    [int]$BeepDuration = 220
)

if (-not ("DdhCustomAlertTone" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;

public static class DdhCustomAlertTone
{
    public static byte[] Create(int frequency, int durationMilliseconds)
    {
        const int sampleRate = 44100;
        int sampleCount = sampleRate * durationMilliseconds / 1000;
        int dataLength = sampleCount * 2;
        byte[] wave = new byte[44 + dataLength];

        using (var stream = new MemoryStream(wave))
        using (var writer = new BinaryWriter(stream))
        {
            writer.Write(new[] { 'R', 'I', 'F', 'F' });
            writer.Write(36 + dataLength);
            writer.Write(new[] { 'W', 'A', 'V', 'E' });
            writer.Write(new[] { 'f', 'm', 't', ' ' });
            writer.Write(16);
            writer.Write((short)1);
            writer.Write((short)1);
            writer.Write(sampleRate);
            writer.Write(sampleRate * 2);
            writer.Write((short)2);
            writer.Write((short)16);
            writer.Write(new[] { 'd', 'a', 't', 'a' });
            writer.Write(dataLength);

            for (int index = 0; index < sampleCount; index++)
            {
                double phase = 2.0 * Math.PI * frequency * index / sampleRate;
                writer.Write((short)(Math.Sin(phase) * short.MaxValue * 0.42));
            }
        }

        return wave;
    }
}
'@
}

function Resolve-NotificationOutboxPath {
    param([string]$path)

    $resolved = try {
        Resolve-Path -Path $path -ErrorAction Stop | Select-Object -ExpandProperty Path
    } catch {
        $null
    }

    if (-not $resolved) {
        $candidatePaths = @(
            [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\backend-go\storage\notification-outbox\local-desktop")),
            [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\storage\notification-outbox\local-desktop"))
        )

        foreach ($candidate in $candidatePaths) {
            if (Test-Path -Path $candidate) {
                return $candidate
            }
        }

        $resolved = $candidatePaths[0]
    }

    return $resolved
}

function Get-PlaySoundFromFile {
    param([string]$path)

    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        try {
            $content = Get-Content -Path $path -Raw -ErrorAction Stop
            $json = $content | ConvertFrom-Json -ErrorAction Stop
            return $json.play_sound
        } catch {
            Start-Sleep -Milliseconds 150
        }
    }

    return $null
}

function Play-AlertBeep {
    try {
        for ($soundIndex = 0; $soundIndex -lt $AlertSoundRepeats; $soundIndex++) {
            $wave = [DdhCustomAlertTone]::Create($BeepFrequency, $BeepDuration)
            $stream = [System.IO.MemoryStream]::new($wave, $false)
            $player = [System.Media.SoundPlayer]::new($stream)
            $player.Load()
            $player.PlaySync()
            $player.Dispose()
            $stream.Dispose()
            if ($soundIndex -lt ($AlertSoundRepeats - 1)) {
                Start-Sleep -Milliseconds 120
            }
        }
    } catch {
        Write-Host "[WARN] Alert beep failed: $_" -ForegroundColor DarkYellow
    }
}

function Process-NotificationFile {
    param([string]$path)

    if (-not (Test-Path -Path $path -PathType Leaf)) {
        return
    }

    if ($ProcessedFiles.Contains($path)) {
        return
    }

    $playSound = Get-PlaySoundFromFile -path $path
    if ($playSound -eq $true) {
        Write-Host "[NOTIFY] play_sound=true for $path" -ForegroundColor Yellow
        Play-AlertBeep
    } else {
        Write-Host "[SKIP] play_sound not enabled for $path" -ForegroundColor DarkGray
    }

    $ProcessedFiles.Add($path) | Out-Null
}

$OutboxPath = Resolve-NotificationOutboxPath -path $OutboxPath
if (-not (Test-Path -Path $OutboxPath)) {
    New-Item -ItemType Directory -Path $OutboxPath -Force | Out-Null
}

$ProcessedFiles = [System.Collections.Generic.HashSet[string]]::new()

# Existing outbox jobs belong to earlier events. Mark them as seen on startup
# so restarting this helper never replays an old alert tone.
Get-ChildItem -Path $OutboxPath -Recurse -Filter '*.json' -File -ErrorAction SilentlyContinue | ForEach-Object {
    $ProcessedFiles.Add($_.FullName) | Out-Null
}

Write-Host "Watching local desktop notification outbox:" -ForegroundColor Cyan
Write-Host "  $OutboxPath" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop."

while ($true) {
    Get-ChildItem -Path $OutboxPath -Recurse -Filter '*.json' -File -ErrorAction SilentlyContinue | ForEach-Object {
        Process-NotificationFile -path $_.FullName
    }

    Start-Sleep -Seconds 1
}
