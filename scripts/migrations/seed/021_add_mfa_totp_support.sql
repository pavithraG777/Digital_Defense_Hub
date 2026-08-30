BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS mfa_secret_encrypted BYTEA NULL,
    ADD COLUMN IF NOT EXISTS mfa_recovery_code_hashes TEXT[] NULL;

-- Keep the existing email-OTP MFA path intact while enabling TOTP secret storage.
-- Recovery codes are stored as bcrypt hashes, which are safe to store as text.
-- Each code should be treated as a one-time-use secret when used to recover access.

CREATE INDEX IF NOT EXISTS idx_users_mfa_secret_encrypted
    ON users (id)
    WHERE mfa_secret_encrypted IS NOT NULL;

COMMIT;
