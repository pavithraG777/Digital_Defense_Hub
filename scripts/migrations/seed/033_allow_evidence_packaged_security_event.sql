BEGIN;

ALTER TABLE media_asset_security_events
    DROP CONSTRAINT IF EXISTS chk_media_asset_security_event_type;

ALTER TABLE media_asset_security_events
    ADD CONSTRAINT chk_media_asset_security_event_type
    CHECK (
        event_type IN (
            'QUARANTINED',
            'RELEASED',
            'INTEGRITY_FAILED',
            'RETENTION_ARCHIVED',
            'EVIDENCE_PACKAGED'
        )
    );

COMMIT;
