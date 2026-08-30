# Postman validation guide

Set these collection variables first:

| Variable | Value |
| --- | --- |
| `baseUrl` | `http://127.0.0.1:8080/api/v1` |
| `jwt` | JWT for a user with the listed permission |
| `mediaAssetId` | returned from the media-upload request |
| `reportId` | returned from report generation |
| `canaryId` | returned from canary creation |

Add `Authorization: Bearer {{jwt}}` to every request below except Health. The account needs `ORGANIZATION_MANAGE_SECURITY` for POST actions and `THREAT_VIEW` for GET actions.

## 4. Process isolation sandbox

Kernel/WDAC readiness is an endpoint-local security check, so it has no HTTP API and must not be exposed over Postman. Run this PowerShell command instead:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows-isolation-readiness.ps1
```

Expected result: a JSON capability report. `UNAVAILABLE` means Windows did not permit that read-only inspection; it is not a claim that a kernel control is enabled.

## 5. Advanced canary / honeytoken

### Create canary

`POST {{baseUrl}}/canary-files`

```json
{
  "file_name": "Quarterly_Finance_2026.txt",
  "canary_type": "DOCUMENT",
  "description": "Postman validation canary",
  "contains_honeytoken": false
}
```

Expected: `201 Created`, `data.id` saved as `{{canaryId}}`, and `data.status` is `DRAFT`.

### Deploy server-managed canary

`POST {{baseUrl}}/canary-files/{{canaryId}}/deploy`

```json
{
  "deployment_directory": "E:\\Cyber-Security-Platform\\storage\\canary-deployments",
  "device_name": "Z14-55N",
  "device_identifier": "postman-validation-device"
}
```

Expected: `200 OK` and `data.status` is `DEPLOYED` or `ACTIVE`.

### Validate the local offline sentinel

The offline sentinel intentionally writes only local alerts; it does not send an unauthenticated event to the API. Start it and alter one generated canary:

```powershell
# Run this once in the same terminal only if an older Sentinel run stopped
# unexpectedly and left event subscribers behind.
Get-EventSubscriber | Where-Object SourceIdentifier -like 'ddh-*' | Unregister-Event

.\scripts\canary-sentinel.ps1 `
  -WatchPath 'C:\Users\acer\Documents' `
  -CanaryNotice 'TOP SECRET — Unauthorized copy, edit, rename, or deletion is prohibited.' `
  -IncludeSubdirectories $true
```

In a **second PowerShell terminal**, create a normal file first. Expected: a
new canary is automatically created in that same folder; it should not alert.

```powershell
Set-Content -LiteralPath 'C:\Users\acer\Documents\normal-test.txt' -Value 'normal document'
Get-ChildItem 'C:\Users\acer\Documents' -Filter '*_*.txt' | Sort-Object LastWriteTime -Descending | Select-Object -First 3 Name, FullName
```

Select a newly created canary path from the output and alter **only that
canary**, for example:

```powershell
Add-Content -LiteralPath 'C:\Users\acer\Documents\Backup_Credentials_YYYYMMDD_HHMMSS_TOKEN.txt' -Value 'trigger-test'
Get-Content .\storage\canary-sentinel\alerts.jsonl -Tail 1
Get-ChildItem .\storage\canary-sentinel\evidence -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1 FullName
```

Expected: exactly two beeps, a red `CANARY ALERT`, one JSONL alert, and a new
evidence directory containing `evidence.json` plus `chain-of-custody.json`.
The SHA-256 in chain-of-custody must match this command:

```powershell
$evidenceDirectory = Get-ChildItem .\storage\canary-sentinel\evidence -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $evidenceDirectory 'evidence.json')
```

### FIR draft and offline voice briefing

After a Sentinel trigger, generate a review-required FIR complaint draft:

```powershell
.\scripts\generate-fir-draft.ps1 `
  -EvidenceDirectory $evidenceDirectory `
  -ComplainantName 'Authorized complainant' `
  -OrganizationName 'Example Organization'
```

Expected: a JSON file in `storage\fir-drafts` with
`status: DRAFT_REQUIRES_ANALYST_AND_COMPLAINANT_APPROVAL`, evidence SHA-256,
and `submission.sync_status: NOT_SUBMITTED`.

Create an offline, proof-citing police/analyst briefing and speak it through
the local Windows voice engine:

```powershell
.\scripts\incident-briefing-assistant.ps1 `
  -EvidenceDirectory $evidenceDirectory `
  -Speak
```

Expected: a local spoken briefing and one JSON proof record in
`storage\incident-briefings`. It reports only matches found in locally stored
evidence bundles and explicitly does not identify an attacker.

## 6. Production hardening

`GET {{baseUrl}}/health`

No body or authorization required.

Expected: `200 OK`, JSON `data.status: "UP"`, and these headers:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cache-Control: no-store
```

## Forensic report workflow

### Organization media policy

`GET {{baseUrl}}/deepfake-forensics/organization-policy`

Expected: `200 OK` with the effective tenant policy. Organizations without a
saved policy receive the safe defaults: all supported media categories, a
50 MiB upload limit, a 75 confidence review threshold, suspicious-media
review enabled, and 90-day retention.

`PUT {{baseUrl}}/deepfake-forensics/organization-policy`

```json
{
  "allowed_media_types": ["IMAGE", "VIDEO", "DOCUMENT"],
  "maximum_upload_bytes": 52428800,
  "review_confidence_threshold": 75,
  "require_review_for_suspicious": true,
  "retention_days": 90
}
```

Expected: `200 OK`. Subsequent uploads are checked before storage against the
allowed categories and the organization limit; the platform's global upload
limit remains an additional ceiling.

### Upload media

`POST {{baseUrl}}/deepfake-forensics/media-assets`

Body type: `form-data`.

| Key | Type | Value |
| --- | --- | --- |
| `file` | File | Select a supported `.jpg`, `.png`, `.mp4`, `.wav`, or `.pdf` |
| `source_type` | Text | `DIRECT_UPLOAD` |
| `metadata` | Text | `{"case_reference":"POSTMAN-DF-001"}` |

Expected: `201 Created`; save `data.id` as `{{mediaAssetId}}`. A type-mismatched file may return `202 Accepted` with a quarantined asset.

Each accepted upload includes a persisted `metadata.evidence_package` with
observed SHA-256 and SHA-512 hashes, a deterministic content fingerprint,
validated MIME/extension signature information, an evidence UUID, and an
initialized chain-of-custody marker. An immutable `EVIDENCE_PACKAGED` event is
available through the asset security-events endpoint. If the same original
bytes already exist in the same organization, `metadata.duplicate_media`
records the matching asset without correlating data across organizations.

### Queue deepfake, classical-forensics, and OCR analysis

`POST {{baseUrl}}/deepfake-forensics/media-assets/{{mediaAssetId}}/analyze`

```json
{
  "analysis_modes": ["DEEPFAKE", "FORENSICS", "OCR"],
  "priority": "NORMAL",
  "execution_device": "CPU",
  "force_reanalysis": false
}
```

Expected: `202 Accepted` or `200 OK` with `data.jobs`. Save each job ID. Repeating the identical request with `force_reanalysis: false` must return the reusable jobs rather than duplicate work.

For the broadest currently implemented media workflow, use the same endpoint
with all supported analysis modes:

```json
{
  "analysis_modes": ["DEEPFAKE", "FORENSICS", "OCR"],
  "priority": "HIGH",
  "execution_device": "CPU",
  "force_reanalysis": false
}
```

Expected after job completion: synthetic-media probability and confidence;
metadata/compression/noise findings; video frame counts, suspicious frames,
frame duplication/deletion and timestamp anomalies where applicable; OCR text;
and suspicious locations/regions. These are the current API outputs used as
the foundation for provenance, PRNU/CFA, temporal, cross-modal, attribution,
localization, XAI, and confidence-matrix extensions.

### Advanced forensic evidence payload

After the same job completes, inspect the result at:

`GET {{baseUrl}}/deepfake-forensics/analysis-jobs/{{analysisJobId}}/result`

Expected: the relevant `feature_data`, `forensic_feature_data`, or OCR
`metadata` includes `advanced_forensics`:

```json
{
  "advanced_forensics": {
    "media_provenance": {
      "source_sha256": "<original SHA-256>",
      "verification_status": "SOURCE_HASH_VERIFIED"
    },
    "noise_sensor_forensics": {
      "prnu_status": "REQUIRES_CAMERA_REFERENCE_SET",
      "cfa_status": "REQUIRES_RAW_OR_SENSOR_CALIBRATION_EVIDENCE"
    },
    "cross_modal_verification": {
      "status": "PENDING_CASE_FUSION"
    },
    "synthetic_media_attribution": {
      "status": "INCONCLUSIVE"
    },
    "manipulation_localization": {},
    "explainable_ai": {
      "decision_basis": []
    },
    "evidence_confidence_matrix": {
      "overall_confidence": 0,
      "human_review_required": true
    }
  }
}
```

PRNU/CFA, cross-modal verification, and attribution are deliberately marked as
pending/inconclusive until their required camera reference set, independent
modalities, or validated attribution intelligence is supplied. The API does
not fabricate a forensic conclusion from a single upload.

### Check results and trust score

`GET {{baseUrl}}/deepfake-forensics/analysis-jobs/{{analysisJobId}}/result`

Expected after completion: `200 OK`, with `data.deepfake`, `data.forensics`, or `data.ocr` as relevant. Video results may include `suspicious_frames` and `suspicious_regions`; OCR results include `extracted_text`.

`POST {{baseUrl}}/deepfake-forensics/media-assets/{{mediaAssetId}}/trust-assessment/recalculate`

No body. Expected: `200 OK` and a `data.verdict`, `trust_score`, `risk_score`, and component scores.

### Generate, approve, and download the report

`POST {{baseUrl}}/deepfake-forensics/media-assets/{{mediaAssetId}}/forensic-reports`

No body. Expected: `201 Created`; save `data.id` as `{{reportId}}`. The PDF includes asset SHA-256, custody details, deepfake summary, suspicious frame/region counts, and OCR text excerpt.

`POST {{baseUrl}}/deepfake-forensics/forensic-reports/{{reportId}}/approve`

```json
{
  "approval_note": "Reviewed trained-model, forensic, OCR and chain-of-custody signals. Escalated for analyst follow-up."
}
```

Expected: `200 OK`, `data.status: "APPROVED"`, `approved_by`, `approved_at`, a refreshed `document_sha256`, and auditable approval data. Downloaded PDFs include the analyst user-ID/time/note attestation.

`GET {{baseUrl}}/deepfake-forensics/forensic-reports/{{reportId}}/download`

Expected: `200 OK`, `Content-Type: application/pdf`, and a PDF attachment.

## Advanced trust score and threat/incident escalation

`GET {{baseUrl}}/deepfake-forensics/media-assets/{{mediaAssetId}}/trust-assessment`

Expected: `200 OK` with the combined decision fields:

```json
{
  "trust_score": 64.42,
  "risk_score": 35.58,
  "confidence_score": 65.4,
  "verdict": "SUSPICIOUS",
  "classification": "SUSPICIOUS",
  "risk_level": "MEDIUM",
  "trained_model_used": true,
  "requires_human_review": true,
  "component_scores": {
    "deepfake": {},
    "forensics": {},
    "ocr": {},
    "source_integrity": {}
  }
}
```

The score combines deepfake, classical-forensics, OCR/manual-review, metadata/source-integrity and model-confidence signals. `SUSPICIOUS`/`MEDIUM` is deliberately analyst-review evidence; automatic escalation is limited to `HIGH` or `CRITICAL` risk to prevent incident noise.

For a high/critical completed analysis, poll the same endpoint until `escalation_status` is `COMPLETED`. Expected fields then include `incident_id`, `incident_evidence_id`, and `notification_sent_at`. The backend creates the incident, preserves a media evidence link with original SHA-256, publishes a deduplicated notification, and records recommended analyst actions in the incident findings. Escalation claiming is atomic, so a retry cannot create duplicate incidents.

## Secure media storage

The current `backend-go/.env` has media encryption enabled. New uploads after an API restart must return:

```json
{
  "is_encrypted": true,
  "encryption_algorithm": "AES-256-CTR-HMAC-SHA256"
}
```

An older asset with `is_encrypted: false` was stored before encryption was enabled; it is not retroactively rewritten. Upload a new media file through the upload request above to verify the active setting. The worker verifies integrity, decrypts only into a short-lived per-job workspace during analysis, removes temporary plaintext after analysis, quarantines malformed content, and records immutable media security events.

`GET {{baseUrl}}/deepfake-forensics/media-assets/{{mediaAssetId}}/security-events?page=1&page_size=20`

Expected: `200 OK` with the asset's upload, quarantine/integrity, retention, or other security-audit events. The API never returns the physical storage path.

## Operational hardening tests

### Cancel / retry

`POST {{baseUrl}}/deepfake-forensics/analysis-jobs/{{analysisJobId}}/cancel`

No body. Expected: `200 OK`, status `CANCELLED`. It is safe to call while queued or running; the worker cooperatively stops active engine work.

`POST {{baseUrl}}/deepfake-forensics/analysis-jobs/{{analysisJobId}}/retry`

No body. Expected: `200 OK` only for `FAILED` or `CANCELLED` jobs; active or completed jobs return a conflict response, preventing duplicate work.

### Large and malformed uploads

- Upload a file above `DEEPFAKE_FORENSICS_MAXIMUM_UPLOAD_BYTES`: expected `413`.
- Upload text renamed as `.png` or a corrupt file: expected `202` with isolated/quarantined status when malformed-upload quarantine is enabled, otherwise `400`.
- Upload malformed JSON in the `metadata` form field: expected `400`.

### Cross-organization access

Use a second JWT from another organization and call:

`GET {{baseUrl}}/deepfake-forensics/media-assets/{{mediaAssetId}}`

Expected: `404 Not Found` (no resource-existence leak). Repeat for analysis jobs and reports.

### Retention and cleanup

The analysis worker runs configured retention archival and removes decrypted temporary working files after each job. Verify the worker log/metrics after an interval and confirm that original encrypted evidence remains available while temporary plaintext workspaces do not.

## Investigation case management

Cases provide the analyst workspace above incidents: they group related
incidents without copying or mutating the original evidence, SHA-256 values,
or chain-of-custody entries.

`POST {{baseUrl}}/investigation-cases`

```json
{
  "title": "Synthetic media campaign investigation",
  "description": "Cross-channel investigation for related suspicious media.",
  "priority": "HIGH"
}
```

Expected: `201 Created` and `data.case_number` beginning with `DDH-CASE-`,
with status `OPEN` and the authenticated organization/user recorded as owner.

`POST {{baseUrl}}/investigation-cases/{{caseId}}/incidents`

```json
{
  "incident_id": "{{incidentId}}"
}
```

Expected: `201 Created`. The incident must belong to the same organization.
Linking the same incident again, or trying to link it to a second case, returns
`409 Conflict` to prevent ambiguous investigation ownership.

`PATCH {{baseUrl}}/investigation-cases/{{caseId}}`

```json
{
  "status": "ACTIVE",
  "priority": "URGENT"
}
```

Expected: `200 OK` with the new lifecycle state. Setting `status` to `CLOSED`
sets `closed_at`; re-opening it clears that timestamp.

`GET {{baseUrl}}/investigation-cases/{{caseId}}/incidents`

Expected: `200 OK` with the linked organization-scoped incident records.
Using a JWT from another organization returns `404 Not Found` for the case and
must not reveal any case or incident data.
