CREATE TABLE IF NOT EXISTS attribution_observations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    provider TEXT NOT NULL,
    source_reference TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    asn TEXT,
    country_code TEXT,
    network_organization TEXT,
    association TEXT,
    reputation INTEGER NOT NULL CHECK (reputation BETWEEN 0 AND 100),
    provider_confidence INTEGER NOT NULL CHECK (provider_confidence BETWEEN 0 AND 100),
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, provider, source_reference, indicator_type, indicator_value)
);

CREATE INDEX IF NOT EXISTS idx_attribution_observations_indicator
    ON attribution_observations (organization_id, indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS idx_attribution_observations_expiry
    ON attribution_observations (organization_id, expires_at);

CREATE TABLE IF NOT EXISTS attribution_leads (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    confidence_level TEXT NOT NULL CHECK (confidence_level IN ('LOW', 'MEDIUM', 'HIGH')),
    lead JSONB NOT NULL,
    model_version INTEGER NOT NULL,
    analyst_disposition TEXT CHECK (
        analyst_disposition IS NULL OR analyst_disposition IN (
            'SUPPORTED', 'INCONCLUSIVE', 'REJECTED', 'NEEDS_MORE_EVIDENCE'
        )
    ),
    analyst_note TEXT,
    disposed_by UUID,
    disposed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attribution_leads_tenant_created
    ON attribution_leads (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attribution_leads_indicator
    ON attribution_leads (organization_id, indicator_type, indicator_value);
