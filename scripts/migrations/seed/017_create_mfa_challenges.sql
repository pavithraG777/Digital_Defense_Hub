BEGIN;

CREATE TABLE IF NOT EXISTS authentication_mfa_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email_code_hash VARCHAR(128) NOT NULL,
    sms_code_hash VARCHAR(128) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    maximum_attempts INTEGER NOT NULL DEFAULT 5,
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITHOUT TIME ZONE NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_mfa_challenge_status CHECK (status IN ('PENDING', 'VERIFIED', 'EXPIRED', 'LOCKED', 'CANCELLED')),
    CONSTRAINT chk_mfa_challenge_attempts CHECK (attempts >= 0 AND attempts <= maximum_attempts),
    CONSTRAINT chk_mfa_challenge_expiry CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_pending
    ON authentication_mfa_challenges (user_id, expires_at DESC)
    WHERE status = 'PENDING';

COMMIT;
