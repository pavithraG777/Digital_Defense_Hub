-- Users created through the administrator workflow provide an official
-- address that is approved by an administrator. Existing active users need
-- the same trusted-email state as newly created users so MFA email delivery
-- is not skipped.
UPDATE users
SET email_verified = TRUE,
    updated_at = CURRENT_TIMESTAMP
WHERE deleted_at IS NULL
  AND account_status = 'ACTIVE'
  AND NULLIF(BTRIM(official_email), '') IS NOT NULL
  AND email_verified = FALSE;
