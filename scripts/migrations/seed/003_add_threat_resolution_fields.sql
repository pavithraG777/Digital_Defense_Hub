BEGIN;

ALTER TABLE threats
    ADD COLUMN IF NOT EXISTS resolution_notes TEXT;

ALTER TABLE threats
    ADD COLUMN IF NOT EXISTS resolved_by UUID;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_threat_resolved_by'
    ) THEN
        ALTER TABLE threats
            ADD CONSTRAINT fk_threat_resolved_by
            FOREIGN KEY (resolved_by)
            REFERENCES users(id)
            ON DELETE SET NULL;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_threats_resolved_by
    ON threats (resolved_by);

COMMIT;



SELECT
    column_name,
    data_type,
    is_nullable
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'threats'
  AND column_name IN (
      'resolution_notes',
      'resolved_by'
  )
ORDER BY column_name;