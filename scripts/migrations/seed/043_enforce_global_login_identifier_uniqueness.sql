BEGIN;

-- Login accepts a username or email without a tenant identifier. Therefore
-- both identifiers must resolve to exactly one active account globally.
WITH ranked_emails AS (
    SELECT
        u.id,
        ROW_NUMBER() OVER (
            PARTITION BY LOWER(u.official_email)
            ORDER BY
                CASE
                    WHEN o.organization_code = 'DDH001' AND LOWER(u.username) = 'admin' THEN 0
                    ELSE 1
                END,
                u.created_at,
                u.id
        ) AS position
    FROM users u
    LEFT JOIN organizations o ON o.id = u.organization_id
    WHERE u.deleted_at IS NULL
), duplicate_emails AS (
    SELECT id
    FROM ranked_emails
    WHERE position > 1
)
UPDATE users u
SET
    official_email = LEFT(u.username, 180) || '+' || LEFT(REPLACE(u.id::text, '-', ''), 12) || '@identity.invalid',
    email_verified = FALSE,
    updated_at = NOW()
FROM duplicate_emails d
WHERE u.id = d.id;

WITH ranked_usernames AS (
    SELECT
        u.id,
        ROW_NUMBER() OVER (
            PARTITION BY LOWER(u.username)
            ORDER BY
                CASE WHEN o.organization_code = 'DDH001' THEN 0 ELSE 1 END,
                u.created_at,
                u.id
        ) AS position
    FROM users u
    LEFT JOIN organizations o ON o.id = u.organization_id
    WHERE u.deleted_at IS NULL
), duplicate_usernames AS (
    SELECT id
    FROM ranked_usernames
    WHERE position > 1
)
UPDATE users u
SET
    username = LEFT(u.username, 220) || '-' || LEFT(REPLACE(u.id::text, '-', ''), 8),
    updated_at = NOW()
FROM duplicate_usernames d
WHERE u.id = d.id;

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_active_username_ci
    ON users (LOWER(username))
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_active_official_email_ci
    ON users (LOWER(official_email))
    WHERE deleted_at IS NULL;

COMMIT;
