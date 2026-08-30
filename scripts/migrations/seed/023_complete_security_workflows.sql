BEGIN;
CREATE TABLE IF NOT EXISTS authentication_trusted_devices(id UUID PRIMARY KEY,user_id UUID NOT NULL,organization_id UUID NOT NULL,device_id TEXT NOT NULL,device_name TEXT NOT NULL,trusted BOOLEAN NOT NULL DEFAULT FALSE,last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),trusted_at TIMESTAMPTZ,revoked_at TIMESTAMPTZ,UNIQUE(user_id,device_id));
CREATE TABLE IF NOT EXISTS authentication_login_risk_events(id UUID PRIMARY KEY,user_id UUID NOT NULL,organization_id UUID NOT NULL,device_id TEXT,ip_address INET,risk_score INTEGER NOT NULL,risk_level TEXT NOT NULL,risk_flags JSONB NOT NULL DEFAULT '[]',requires_step_up BOOLEAN NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_login_risk_org_time ON authentication_login_risk_events(organization_id,created_at DESC);
ALTER TABLE credential_events ADD COLUMN IF NOT EXISTS risk_score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE credential_events ADD COLUMN IF NOT EXISTS risk_level TEXT NOT NULL DEFAULT 'LOW';
ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS organization_id UUID;
ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS retention_until TIMESTAMPTZ;
ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS integrity_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS created_by UUID;
ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
CREATE TABLE IF NOT EXISTS evidence_custody_events(id UUID PRIMARY KEY,organization_id UUID NOT NULL,job_id UUID NOT NULL,action TEXT NOT NULL,from_custodian UUID,to_custodian UUID,note TEXT NOT NULL,actor_id UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS endpoint_assets(id UUID PRIMARY KEY,organization_id UUID NOT NULL,external_id TEXT NOT NULL,hostname TEXT NOT NULL,platform TEXT NOT NULL DEFAULT 'UNKNOWN',sensor_online BOOLEAN NOT NULL DEFAULT TRUE,mfa_enforced BOOLEAN NOT NULL DEFAULT FALSE,isolation_active BOOLEAN NOT NULL DEFAULT FALSE,risk_score INTEGER NOT NULL DEFAULT 0,risk_level TEXT NOT NULL DEFAULT 'LOW',risk_flags JSONB NOT NULL DEFAULT '[]',last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(organization_id,external_id));
CREATE TABLE IF NOT EXISTS endpoint_actions(id UUID PRIMARY KEY,organization_id UUID NOT NULL,endpoint_id UUID NOT NULL,action_type TEXT NOT NULL,status TEXT NOT NULL,reason TEXT,requested_by UUID,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),completed_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS network_sensors(id UUID PRIMARY KEY,organization_id UUID NOT NULL,external_id TEXT NOT NULL,name TEXT NOT NULL,sensor_online BOOLEAN NOT NULL,visibility_healthy BOOLEAN NOT NULL,last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(organization_id,external_id));
CREATE TABLE IF NOT EXISTS network_flows(id UUID PRIMARY KEY,organization_id UUID NOT NULL,sensor_id UUID NOT NULL,source_ip INET NOT NULL,destination_ip INET NOT NULL,destination_port INTEGER NOT NULL,protocol TEXT NOT NULL,bytes_transferred BIGINT NOT NULL DEFAULT 0,quarantined BOOLEAN NOT NULL DEFAULT FALSE,risk_score INTEGER NOT NULL,risk_level TEXT NOT NULL,risk_flags JSONB NOT NULL DEFAULT '[]',observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS network_actions(id UUID PRIMARY KEY,organization_id UUID NOT NULL,host_ip INET,action_type TEXT NOT NULL,status TEXT NOT NULL,reason TEXT,requested_by UUID,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS threat_intelligence_indicators(id UUID PRIMARY KEY,organization_id UUID NOT NULL,indicator_type TEXT NOT NULL,indicator_value TEXT NOT NULL,normalized_value TEXT NOT NULL,reputation_score INTEGER NOT NULL,confidence INTEGER NOT NULL,severity TEXT NOT NULL,tags JSONB NOT NULL DEFAULT '[]',sources JSONB NOT NULL DEFAULT '[]',first_seen_at TIMESTAMPTZ NOT NULL,last_seen_at TIMESTAMPTZ NOT NULL,status TEXT NOT NULL DEFAULT 'ACTIVE',reviewed_by UUID,reviewed_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(organization_id,indicator_type,normalized_value));
INSERT INTO permissions(permission_code,permission_name,module_name,action_name,description,risk_level,requires_approval,status) VALUES
('ENDPOINT_VIEW','View Endpoints','ENDPOINT','VIEW','View endpoint telemetry and posture.','MEDIUM',FALSE,'ACTIVE'),
('ENDPOINT_SCAN','Scan Endpoints','ENDPOINT','SCAN','Ingest telemetry and request scans.','HIGH',FALSE,'ACTIVE'),
('ENDPOINT_CONTAIN','Contain Endpoints','ENDPOINT','CONTAIN','Contain or release endpoints.','CRITICAL',TRUE,'ACTIVE'),
('NETWORK_SECURITY_VIEW','View Network Security','NETWORK_SECURITY','VIEW','View sensors and network flows.','MEDIUM',FALSE,'ACTIVE'),
('NETWORK_SECURITY_SCAN','Analyze Network Telemetry','NETWORK_SECURITY','SCAN','Ingest network telemetry.','HIGH',FALSE,'ACTIVE'),
('NETWORK_SECURITY_QUARANTINE','Quarantine Network Host','NETWORK_SECURITY','QUARANTINE','Quarantine network hosts.','CRITICAL',TRUE,'ACTIVE'),
('EVIDENCE_VAULT_VIEW','View Evidence Vault','EVIDENCE_VAULT','VIEW','View preservation and custody records.','HIGH',FALSE,'ACTIVE'),
('EVIDENCE_VAULT_MANAGE','Manage Evidence Vault','EVIDENCE_VAULT','MANAGE','Manage evidence lifecycle.','CRITICAL',TRUE,'ACTIVE'),
('CREDENTIAL_ABUSE_VIEW','View Credential Abuse','CREDENTIAL_ABUSE','VIEW','View credential abuse risks.','HIGH',FALSE,'ACTIVE'),
('CREDENTIAL_ABUSE_MANAGE','Manage Credential Abuse','CREDENTIAL_ABUSE','MANAGE','Ingest credential events.','HIGH',FALSE,'ACTIVE'),
('PRIVILEGE_ESCALATION_VIEW','View Privilege Escalation','PRIVILEGE_ESCALATION','VIEW','View privilege detections.','HIGH',FALSE,'ACTIVE'),
('PRIVILEGE_ESCALATION_MANAGE','Manage Privilege Escalation','PRIVILEGE_ESCALATION','MANAGE','Review privilege detections.','CRITICAL',TRUE,'ACTIVE'),
('LATERAL_MOVEMENT_VIEW','View Lateral Movement','LATERAL_MOVEMENT','VIEW','View movement alerts and graph.','HIGH',FALSE,'ACTIVE'),
('LATERAL_MOVEMENT_MANAGE','Manage Lateral Movement','LATERAL_MOVEMENT','MANAGE','Ingest movement telemetry.','HIGH',FALSE,'ACTIVE'),
('ATTACK_STORY_VIEW','View Attack Stories','ATTACK_STORY','VIEW','View timelines and MITRE mapping.','MEDIUM',FALSE,'ACTIVE'),
('ATTACK_STORY_CREATE','Create Attack Stories','ATTACK_STORY','CREATE','Create evidence-backed stories.','HIGH',FALSE,'ACTIVE')
ON CONFLICT(permission_code) DO NOTHING;
INSERT INTO role_permissions(role_id,permission_id,granted_by,granted_at,expires_at,is_active)
SELECT r.id,p.id,NULL,NOW(),NULL,TRUE FROM roles r CROSS JOIN permissions p
WHERE r.role_code IN('SUPER_ADMIN','ORG_ADMIN','SOC_ANALYST','FORENSIC_ANALYST','INCIDENT_RESPONDER','THREAT_ANALYST')
AND p.permission_code IN('ENDPOINT_VIEW','ENDPOINT_SCAN','ENDPOINT_CONTAIN','NETWORK_SECURITY_VIEW','NETWORK_SECURITY_SCAN','NETWORK_SECURITY_QUARANTINE','EVIDENCE_VAULT_VIEW','EVIDENCE_VAULT_MANAGE','CREDENTIAL_ABUSE_VIEW','CREDENTIAL_ABUSE_MANAGE','PRIVILEGE_ESCALATION_VIEW','PRIVILEGE_ESCALATION_MANAGE','LATERAL_MOVEMENT_VIEW','LATERAL_MOVEMENT_MANAGE','ATTACK_STORY_VIEW','ATTACK_STORY_CREATE')
ON CONFLICT DO NOTHING;
COMMIT;
