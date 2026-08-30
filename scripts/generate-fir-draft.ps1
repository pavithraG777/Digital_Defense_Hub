[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EvidenceDirectory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ComplainantName,

    [string]$OrganizationName = 'Digital Defense Hub User',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\storage\fir-drafts')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedEvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
$evidencePath = Join-Path $resolvedEvidenceDirectory 'evidence.json'
$custodyPath = Join-Path $resolvedEvidenceDirectory 'chain-of-custody.json'
if (-not (Test-Path -LiteralPath $evidencePath -PathType Leaf) -or -not (Test-Path -LiteralPath $custodyPath -PathType Leaf)) {
    throw 'Valid evidence.json and chain-of-custody.json are required.'
}

$evidence = Get-Content -Raw -LiteralPath $evidencePath | ConvertFrom-Json
$custody = Get-Content -Raw -LiteralPath $custodyPath | ConvertFrom-Json
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$draft = [ordered]@{
    draft_type = 'CYBERCRIME_FIR_COMPLAINT_DRAFT'
    status = 'DRAFT_REQUIRES_ANALYST_AND_COMPLAINANT_APPROVAL'
    complainant_name = $ComplainantName
    organization_name = $OrganizationName
    incident_summary = "Canary file $($evidence.alert.event_type) event detected on $($evidence.alert.computer) at $($evidence.alert.occurred_at)."
    evidence = @{ bundle_sha256 = $custody.sha256; collected_at = $custody.collected_at; source_file = $custody.file }
    suspected_source = @{ local_network_observations = @($evidence.network_connections); note = 'No attacker identity or public IP is asserted without verified network/server telemetry.' }
    submission = @{ police_reference = $null; submitted_at = $null; sync_status = 'NOT_SUBMITTED'; note = 'Submit only through an authorized police/cybercrime integration or approved manual portal workflow.' }
}
$output = Join-Path $OutputDirectory ("fir-draft_" + (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss') + '.json')
$draft | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $output -Encoding utf8
Write-Host "FIR complaint draft created: $output" -ForegroundColor Cyan
