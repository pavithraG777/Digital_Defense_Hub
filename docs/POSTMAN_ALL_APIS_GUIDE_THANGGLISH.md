# Postman-la All APIs Test Pannura Guide — Thanglish

## Exact count

Local Gin runtime scan அடிப்படையில் **362 API endpoints**:

- GET: 183
- POST: 151
- PATCH: 17
- PUT: 7
- DELETE: 4

Complete endpoint-by-endpoint list: [API_CATALOG_THANGGLISH.md](./API_CATALOG_THANGGLISH.md).

Import-ready files:

- [Postman collection](./postman/Cyber-Security-Platform.postman_collection.json)
- [Local environment](./postman/Local.postman_environment.json)

## 1. Backend ready pannunga

```powershell
cd E:\Cyber-Security-Platform\backend-go
go run .\cmd\migrate -dir ..\scripts\migrations\seed -from 24
go run .\cmd\api
```

API default base URL: `http://127.0.0.1:8080`.

## 2. Postman import

1. Postman open pannunga.
2. `Import` click pannunga.
3. Collection JSON import pannunga.
4. Environment JSON import pannunga.
5. Top-right environment selector-la `Cyber Security Platform - Local` select pannunga.
6. `base_url` value correct-aa irukka check pannunga.
7. `.env`-la irukkura metrics token-a `metrics_token` current value-la paste pannunga. Token share/commit panna koodathu.

## 3. First smoke tests

Order:

1. `GET /api/v1/health` — expected `200`, `status: UP`.
2. `GET /api/v1/ready` — expected `200`, database `UP`.
3. `GET /api/v1/metrics` — `metrics_token` correct-na `200`; missing/wrong-na `401`; server token configure illa-na `503`.

Common success envelope:

```json
{
  "success": true,
  "message": "Operation completed",
  "data": {}
}
```

Common error envelope:

```json
{
  "success": false,
  "message": "Validation or authorization error",
  "error": {}
}
```

## 4. Login and token flow

`POST /api/v1/auth/login` sample:

```json
{
  "official_email": "admin@digitaldefensehub.local",
  "password": "your-real-password",
  "device_fingerprint": "postman-device"
}
```

Possible outcomes:

- Direct success: access/refresh token வரும்; collection test environment variables save pannum.
- MFA required: `challenge_id` வரும். `POST /auth/mfa/verify` call pannunga.
- Password change required: change-password flow complete pannunga.
- `401`: credentials wrong.
- `423`/validation error: locked/inactive account or invalid request.

MFA sample:

```json
{
  "challenge_id": "{{challenge_id}}",
  "email_code": "123456",
  "totp_code": "",
  "recovery_code": ""
}
```

Configured method-க்கு தேவையான code மட்டும் fill pannunga. Successful response token variables-க்கு save ஆகும்.

## 5. Protected API test rules

Collection protected requests automatically:

```http
Authorization: Bearer {{access_token}}
Content-Type: application/json
```

Response interpretation:

- `200`: read/update success.
- `201`: resource created.
- `202`: async job accepted/queued.
- `400`: payload/path/state invalid.
- `401`: token missing/expired.
- `403`: permission missing or emergency stop active.
- `404`: tenant-scoped record இல்லை/wrong UUID.
- `409`: integrity/state/idempotency conflict.
- `422`: Gin validation failure where used.
- `500`: server/database defect; Postman generic test fail ஆகும்.

## 6. Path variables

`:id`, `:case_id`, `:incident_id`, `:evidence_id`, `:device_id` மாதிரி parameters collection environment variables-aa converted. Create API response-ல் கிடைக்கும் UUID-ஐ corresponding variable-ல் paste pannunga.

Correct testing pattern:

1. POST create.
2. Response `data.id` copy.
3. Environment relevant ID update.
4. GET verify.
5. PATCH/PUT lifecycle transition.
6. GET re-verify.

Random UUID use pannina valid format இருந்தாலும் DB record இல்லாததால் `404` expected.

## 7. Payload status in generated collection

Core auth/security APIs-க்கு runnable sample payloads included:

- Login/MFA/refresh
- Security Events
- Command Analysis
- Threat Intelligence
- Attribution
- Recovery
- Evidence verification/manifests
- Credential Abuse
- Lateral Movement
- Privilege Escalation

Some compact façade/admin/media endpoints-க்கு request DTO unique-aa இருக்கும். அவற்றில் collection body:

```json
{
  "_documentation": "Payload varies by handler DTO; API catalog handler column points to exact source. Replace this object before positive test."
}
```

இது fake payload இல்லை; intentionally non-runnable marker. Catalog-ல் handler source கொடுக்கப்பட்டுள்ளது. அந்த handler பயன்படுத்தும் DTO `json`/`binding` tags தான் exact contract.

## 8. Security Events test

```json
{
  "event_id": "{{event_id}}",
  "schema_version": 1,
  "event_type": "PROCESS_START",
  "source": "postman",
  "occurred_at": "2026-08-14T12:00:00Z",
  "entity": {"type": "PROCESS", "id": "powershell.exe"},
  "payload": {"command_line": "powershell.exe -NoProfile"}
}
```

Expected: first request create/accept; same event identity replay செய்தால் duplicate resource create ஆகக்கூடாது. Worker endpoints மூலம் outbox/DLQ/correlation verify pannunga.

## 9. Threat Intelligence test

Manual enrichment sample collection-la உள்ளது. Expected `201`, normalized IOC, reputation/confidence/severity/source list.

Provider enrichment expected `202`; external provider URL empty-na job queued-aa இருக்கலாம், worker execute ஆகாது. `/threat-intelligence/jobs` மூலம் status பார்க்கலாம்.

## 10. Attribution test

1. Observation POST.
2. Same IOC-க்கு lead POST.
3. GET leads.
4. Disposition PATCH.

Expected details: confidence level, infrastructure/association, conflicts, provenance, explanation, historical event count. Result investigative assistance மட்டும்.

## 11. Evidence Vault test

Evidence SHA-256 exactly 64 hexadecimal characters இருக்கணும். Create manifest response signature/hash தரும். Verify API-க்கு observed hash same-na success; different-na `409` integrity failure expected.

Production test object storage/WORM adapter availability-ஐ தனியாக verify செய்ய வேண்டும்.

## 12. Recovery test

Strict order:

1. Create plan.
2. Dry-run.
3. Different user approve செய்ய வேண்டும்.
4. Execute.
5. External runner result பிறகு verify அல்லது rollback.

Creator account-லேயே approve முயற்சி செய்தால் rejection expected. `RECOVERY_RUNNER_URL` empty-na execution external action complete ஆகாது. Emergency stop test செய்த பிறகு clear endpoint கண்டிப்பாக call pannunga.

## 13. File upload APIs

Deepfake/media endpoints `multipart/form-data` use செய்யலாம்:

1. Body -> `form-data`.
2. Key `file` type `File`.
3. Supported image/video/audio select.
4. Manual `Content-Type` header set panna வேண்டாம்; Postman boundary generate pannum.
5. Oversized/invalid MIME files expected-aa reject ஆகணும்.

## 14. Query/list APIs

Common query patterns module DTO-வைப் பொறுத்து:

- `limit`, `offset` அல்லது page parameters
- `status`
- time range
- severity/type
- incident/case/user/device filters

Unknown query parameter silently ignore ஆகலாம்; positive filtering test-க்கு handler query DTO reference பார்க்கவும்.

## 15. Collection Runner

All 362 APIs-ஐ blind-aa one click run panna கூடாது; lifecycle IDs/permissions/external dependencies வேறுபடும்.

Recommended folders order:

1. health
2. auth
3. organization/admin seed verification
4. protected-files/honeytokens/incidents
5. security-events
6. correlation/detection modules
7. threat-intelligence/attribution
8. evidence-vault
9. recovery
10. AI/deepfake/forensics

Read-only GET folders first run pannunga. Mutation folders separate development/test database-ல் மட்டும் run pannunga.

## 16. Regeneration

API routes change ஆன பிறகு:

1. API startup route log capture pannunga.
2. Generator run pannunga:

```powershell
.\scripts\generate-postman-api-catalog.ps1
```

Collection/catalog runtime route count match ஆகணும்.
