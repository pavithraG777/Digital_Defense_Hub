INSERT INTO media_asset_security_events (
    organization_id,
    media_asset_id,
    event_type,
    actor_user_id,
    reason,
    metadata
)
SELECT
    asset.organization_id,
    asset.id,
    'EVIDENCE_PACKAGED',
    asset.uploaded_by,
    'Secure acquisition evidence package initialized (migration backfill)',
    jsonb_build_object(
        'sha256', asset.file_hash,
        'backfilled', true
    )
FROM media_analysis_assets AS asset
WHERE NOT EXISTS (
    SELECT 1
    FROM media_asset_security_events AS event
    WHERE event.organization_id = asset.organization_id
      AND event.media_asset_id = asset.id
      AND event.event_type = 'EVIDENCE_PACKAGED'
);
