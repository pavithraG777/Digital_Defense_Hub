# AWS SNS selection for MFA SMS

AWS SNS is the selected SMS transport for Digital Defense Hub MFA. The generic
HTTP SMS provider must not be used for AWS SNS because SNS requires AWS
Signature Version 4 authentication.

## Required AWS setup

1. Choose the AWS Region that is approved for the deployment (for example
   `ap-south-1`).
2. Request production SMS access in Amazon SNS; sandbox accounts can only send
   to verified destination phone numbers.
3. Create a least-privilege IAM role/user for the backend with only
   `sns:Publish` for SMS. Prefer an instance/task role or an AWS profile over
   long-lived access keys.
4. Configure SMS spend limits, an India DLT sender/template where applicable,
   and CloudWatch delivery-status logging.
5. Store credentials in AWS Secrets Manager or the workload role—not in Git,
   `.env.example`, frontend code, or API responses.

## MFA security contract

- A successful password check creates a short-lived MFA challenge; it does
  not issue access or refresh tokens.
- The server stores only salted bcrypt OTP hashes, never plaintext.
- Email and AWS SNS SMS codes expire after 10 minutes, are single-use, and
  lock after five failed verification attempts. A new login challenge cancels
  any previous pending challenge for that user.
- A verified phone number must be E.164 formatted and ownership-verified.
- MFA verification creates the authenticated session with `mfa_verified=true`.
- AWS delivery acceptance is not treated as proof that a handset received the
  code; only a correct challenge response verifies the factor.

## Deployment inputs still required

The backend implementation needs these deployment-specific values:

| Input | Example | Notes |
| --- | --- | --- |
| AWS Region | `ap-south-1` | Keep data and SMS routing in an approved region. |
| Credential method | IAM role / named profile | Preferred; do not paste production keys into chat or source. |
| SMS sender/origination identity | AWS-approved sender | Must comply with destination-country registration rules. |
| SMTP sender | verified mailbox | Used for the independent email factor. |
| MFA policy | email + SMS required | Can later allow organization-specific factor policy. |

## Backend configuration

Use an IAM workload role in production. For local development, use a named AWS
profile; do not add access keys to this repository.

```dotenv
NOTIFICATION_SMS_ENABLED=true
NOTIFICATION_SMS_PROVIDER_NAME=AWS_SNS
NOTIFICATION_SMS_AWS_REGION=ap-south-1
NOTIFICATION_SMS_AWS_PROFILE=ddh-development
NOTIFICATION_SMS_AWS_SENDER_ID=DDH
NOTIFICATION_SMS_AWS_SMS_TYPE=Transactional
NOTIFICATION_SMS_DEFAULT_COUNTRY_CODE=+91
NOTIFICATION_SMS_TIMEOUT=20s

NOTIFICATION_EMAIL_ENABLED=true
NOTIFICATION_EMAIL_HOST=smtp.example.com
NOTIFICATION_EMAIL_PORT=587
NOTIFICATION_EMAIL_USERNAME=ddh-mfa@example.com
NOTIFICATION_EMAIL_PASSWORD=use-a-secret-manager-reference
NOTIFICATION_EMAIL_FROM_ADDRESS=ddh-mfa@example.com
NOTIFICATION_EMAIL_FROM_NAME=Digital Defense Hub
NOTIFICATION_EMAIL_REQUIRE_STARTTLS=true
```

`NOTIFICATION_SMS_AWS_PROFILE` is optional on AWS compute that uses an IAM
role. The dedicated provider uses the official AWS SDK default credential
chain and publishes through Amazon SNS; it does not send SNS requests through
the generic HTTP SMS gateway.

## Planned API flow

`POST /api/v1/auth/login`

```json
{ "identifier": "user@example.com", "password": "..." }
```

When MFA is enabled: `202 Accepted` with a short-lived `mfa_challenge_id`; no
JWT is returned.

`POST /api/v1/auth/mfa/verify`

```json
{
  "mfa_challenge_id": "UUID",
  "email_code": "123456",
  "sms_code": "654321"
}
```

Success: `200 OK` with the normal JWT + refresh-token response. Invalid,
expired, reused, or rate-limited challenges return no information about which
factor failed.
