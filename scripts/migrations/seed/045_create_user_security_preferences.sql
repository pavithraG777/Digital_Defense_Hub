CREATE TABLE IF NOT EXISTS user_security_preferences (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    desktop_notifications BOOLEAN NOT NULL DEFAULT TRUE,
    sound_notifications BOOLEAN NOT NULL DEFAULT TRUE,
    email_notifications BOOLEAN NOT NULL DEFAULT TRUE,
    theme VARCHAR(16) NOT NULL DEFAULT 'dark' CHECK (theme IN ('dark','light','system')),
    language VARCHAR(16) NOT NULL DEFAULT 'en',
    mfa_policy VARCHAR(24) NOT NULL DEFAULT 'USER_CHOICE' CHECK (mfa_policy IN ('USER_CHOICE','EMAIL_ONLY','TOTP_ONLY','EMAIL_OR_TOTP')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_user_security_preferences_org ON user_security_preferences(organization_id);
