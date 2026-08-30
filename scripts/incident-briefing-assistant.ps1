[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EvidenceDirectory,

    [string]$HistoricalEvidenceRoot = (Join-Path $PSScriptRoot '..\storage\canary-sentinel\evidence'),

    [switch]$Speak,

    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\storage\incident-briefings')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$evidencePath = Join-Path ([IO.Path]::GetFullPath($EvidenceDirectory)) 'evidence.json'
$custodyPath = Join-Path ([IO.Path]::GetFullPath($EvidenceDirectory)) 'chain-of-custody.json'
if (-not (Test-Path -LiteralPath $evidencePath -PathType Leaf) -or -not (Test-Path -LiteralPath $custodyPath -PathType Leaf)) {
    throw 'Valid evidence.json and chain-of-custody.json are required.'
}

$evidence = Get-Content -Raw -LiteralPath $evidencePath | ConvertFrom-Json
$custody = Get-Content -Raw -LiteralPath $custodyPath | ConvertFrom-Json
$matches = @()
if (Test-Path -LiteralPath $HistoricalEvidenceRoot -PathType Container) {
    Get-ChildItem -LiteralPath $HistoricalEvidenceRoot -Filter evidence.json -Recurse -File | ForEach-Object {
        try {
            $candidate = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
            if ($candidate.alert.event_type -eq $evidence.alert.event_type -and $candidate.alert.file_path -ne $evidence.alert.file_path) {
                $matches += [ordered]@{ evidence_file = $_.FullName; occurred_at = $candidate.alert.occurred_at; computer = $candidate.alert.computer; event_type = $candidate.alert.event_type }
            }
        } catch { Write-Warning "Skipped unreadable historical evidence: $($_.FullName)" }
    }
}

$summary = "Digital Defense Hub incident briefing. A $($evidence.alert.event_type) canary event was detected on $($evidence.alert.computer) at $($evidence.alert.occurred_at). The evidence bundle SHA-256 is $($custody.sha256)."
if ($matches.Count -gt 0) {
    $summary += " $($matches.Count) locally stored historical evidence bundle(s) have the same event pattern. Their paths and timestamps are listed in the attached proof references."
} else {
    $summary += ' No matching local historical evidence pattern was found.'
}
$summary += ' This briefing is evidence-based assistance only and does not identify an attacker or assert criminal responsibility.'

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$briefing = [ordered]@{
    briefing_type = 'OFFLINE_INCIDENT_PATTERN_BRIEFING'
    generated_at = (Get-Date).ToUniversalTime().ToString('o')
    summary = $summary
    current_evidence = @{ path = $evidencePath; sha256 = $custody.sha256; event_type = $evidence.alert.event_type; occurred_at = $evidence.alert.occurred_at }
    matching_historical_evidence = @($matches)
    limitations = @('Pattern matches are based only on locally stored evidence files.', 'A similar event pattern is not proof of attacker identity or a link between incidents.')
}
$output = Join-Path $OutputDirectory ("incident-briefing_" + (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss') + '.json')
$briefing | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $output -Encoding utf8
Write-Host $summary -ForegroundColor Cyan
Write-Host "Briefing proof record: $output" -ForegroundColor Cyan

if ($Speak) {
    Add-Type -AssemblyName System.Speech
    $voice = [System.Speech.Synthesis.SpeechSynthesizer]::new()
    $voice.Rate = -1
    $voice.Speak($summary)
    $voice.Dispose()
}
