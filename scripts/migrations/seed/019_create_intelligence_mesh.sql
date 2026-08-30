-- Organization-scoped offline intelligence mesh. Capsules intentionally carry
-- references and checksums, not evidence binaries or credentials.
CREATE TABLE IF NOT EXISTS intelligence_mesh_nodes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    node_name varchar(120) NOT NULL,
    node_type varchar(40) NOT NULL CHECK (node_type IN ('GOVERNMENT','BUSINESS','POLICE','FORENSIC_LAB','HOSPITAL','BANK','UNIVERSITY','SOC','EDGE')),
    connectivity_status varchar(20) NOT NULL DEFAULT 'OFFLINE' CHECK (connectivity_status IN ('ONLINE','OFFLINE','DEGRADED')),
    last_seen_at timestamp without time zone,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_intelligence_mesh_node UNIQUE (organization_id, node_name)
);
CREATE INDEX IF NOT EXISTS idx_intelligence_mesh_nodes_org ON intelligence_mesh_nodes (organization_id, connectivity_status);

CREATE TABLE IF NOT EXISTS intelligence_capsules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_node_id uuid REFERENCES intelligence_mesh_nodes(id) ON DELETE SET NULL,
    target_node_id uuid REFERENCES intelligence_mesh_nodes(id) ON DELETE SET NULL,
    capsule_type varchar(40) NOT NULL CHECK (capsule_type IN ('THREAT_INTELLIGENCE','THREAT_DNA','IOC','CASE_REFERENCE','MODEL_UPDATE')),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    checksum_sha256 varchar(64),
    status varchar(20) NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED','DELIVERED','FAILED')),
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at timestamp without time zone
);
CREATE INDEX IF NOT EXISTS idx_intelligence_capsules_org ON intelligence_capsules (organization_id, status, created_at DESC);
