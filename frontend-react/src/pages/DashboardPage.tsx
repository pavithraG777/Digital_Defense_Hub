import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { Activity, BellRing, Bot, BrainCircuit, Building2, DatabaseZap, FileSearch, FileWarning, Fingerprint, KeyRound, Network, RefreshCw, ScanSearch, ShieldAlert, ShieldCheck, Siren, Users } from "lucide-react";
import { Link } from "react-router-dom";
import { DashboardLiveBackground } from "../components/DashboardLiveBackground";
import { api } from "../lib/api";

type Organization = { id: string; organization_code?: string; code?: string; legal_name?: string; display_name?: string; organization_type?: string; status?: string; created_at?: string };
type RecordValue = Record<string, unknown>;
type OrganizationRisk = {
  organization?: { id?: string; code?: string; name?: string; status?: string };
  data_available?: boolean;
  risk_score?: number | null;
  risk_level?: string;
  factors?: Array<{ code?: string; label?: string; score?: number; weight?: number; normalized_contribution?: number; record_count?: number; available?: boolean; explanation?: string }>;
  source_counts?: { open_threats?: number; open_incidents?: number; recent_behavior_detections?: number };
  last_signal_at?: string;
};
type LoadState = { organizations: Organization[]; users: RecordValue[]; threats: RecordValue[]; incidents: RecordValue[]; health: RecordValue | null; honeytokenEvents: RecordValue[]; canaryEvents: RecordValue[]; honeytokenTotal: number; canaryTotal: number; organizationRisks: OrganizationRisk[]; riskCalculatedAt: string; operations: Record<string, unknown> };
const emptyState: LoadState = { organizations: [], users: [], threats: [], incidents: [], health: null, honeytokenEvents: [], canaryEvents: [], honeytokenTotal: 0, canaryTotal: 0, organizationRisks: [], riskCalculatedAt: "", operations: {} };

function asList(value: unknown): RecordValue[] {
  if (Array.isArray(value)) return value as RecordValue[];
  if (!value || typeof value !== "object") return [];
  const record = value as Record<string, unknown>;
  for (const key of ["items", "records", "results", "organizations", "users", "threats", "incidents", "notifications", "audit_logs", "events", "detections", "scores", "fingerprints", "jobs", "reports", "verifications", "cases", "data"]) if (Array.isArray(record[key])) return record[key] as RecordValue[];
  return [];
}
function totalFrom(value: unknown, fallback: number) { return value && typeof value === "object" && "total" in value ? Number((value as RecordValue).total || 0) : fallback; }
function orgName(org: Organization) { return org.display_name || org.legal_name || org.organization_code || org.code || "Unnamed organization"; }
function recordOrgId(record: RecordValue) { return String(record.organization_id || record.tenant_id || record.organizationId || ""); }
function statusTone(status?: string) { const value = (status || "UNKNOWN").toUpperCase(); return value === "ACTIVE" ? "good" : value === "PENDING" ? "warn" : value === "REJECTED" || value === "SUSPENDED" ? "bad" : "neutral"; }
function riskTone(level?: string) { const value = (level || "NOT_AVAILABLE").toLowerCase(); return ["critical", "high", "medium", "low"].includes(value) ? value : "neutral"; }
function sourceCount(value: unknown) { return totalFrom(value, asList(value).length); }
function normalized(value: unknown) { return String(value || "").trim().toUpperCase(); }
function matchingCount(value: unknown, fields: string[], states: string[]) {
  const accepted = new Set(states.map(normalized));
  return asList(value).filter((item) => fields.some((field) => accepted.has(normalized(item[field])))).length;
}
function operationSummary(kind: string, value: unknown) {
  const list = asList(value);
  const record = value && typeof value === "object" ? value as RecordValue : {};
  if (kind === "notifications") return { value: Number(record.unread_count ?? matchingCount(value, ["read_status", "status"], ["UNREAD", "NEW"])), meta: `${matchingCount(value, ["severity", "priority"], ["CRITICAL"])} critical · ${sourceCount(value)} total` };
  if (kind === "audit") return { value: sourceCount(value), meta: `${matchingCount(value, ["status", "outcome", "result"], ["FAILED", "DENIED", "ERROR"])} failed or denied` };
  if (kind === "files") return { value: sourceCount(value), meta: `${matchingCount(value, ["severity", "risk_level", "classification"], ["CRITICAL", "HIGH", "SUSPICIOUS"])} suspicious / high risk` };
  if (kind === "preEncryption" || kind === "aiRisk") return { value: sourceCount(value), meta: `${matchingCount(value, ["severity", "risk_level"], ["CRITICAL", "HIGH"])} high or critical` };
  if (kind === "forensicJobs") return { value: matchingCount(value, ["status"], ["QUEUED", "PENDING", "RUNNING", "PROCESSING"]), meta: `${matchingCount(value, ["status"], ["FAILED", "ERROR"])} failed · ${sourceCount(value)} total` };
  if (kind === "reports") return { value: sourceCount(value), meta: `${matchingCount(value, ["status", "review_status"], ["PENDING", "PENDING_REVIEW", "DRAFT"])} awaiting review` };
  if (kind === "model") return { value: normalized(record.status || record.integrity_status || (record.verified === true ? "VERIFIED" : "AVAILABLE")), meta: record.summary ? String(record.summary) : "Artifact integrity posture" };
  if (kind === "health") return { value: normalized(record.status || "AVAILABLE"), meta: String(record.database || record.database_status || "Platform API readiness") };
  if (kind === "sync") return { value: matchingCount(value, ["status"], ["PENDING", "IN_PROGRESS", "QUEUED"]), meta: `${matchingCount(value, ["status"], ["FAILED", "ERROR"])} failed · ${sourceCount(value)} total` };
  if (kind === "intelligence") return { value: Number(record.active_threats || 0) + Number(record.active_incidents || 0), meta: `${Number(record.offline_queue || 0)} queued · ${Number(record.media_reviews || 0)} reviews` };
  return { value: sourceCount(value), meta: `${list.length} loaded records` };
}

export function DashboardPage() {
  const [data, setData] = useState<LoadState>(emptyState);
  const [selectedOrg, setSelectedOrg] = useState("all");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [lastRefreshedAt, setLastRefreshedAt] = useState<Date | null>(null);

  async function load(background = false) {
    background ? setRefreshing(true) : setLoading(true);
    const requests = ["/admin/organizations", "/admin/users", "/threats", "/incidents", "/deepfake-forensics/health", "/file-events?source_type=HONEYTOKEN&page=1&page_size=100", "/file-events?source_type=CANARY_FILE&page=1&page_size=100", "/security-scores/organizations", "/my-notifications", "/admin/audit-activity?page=1&page_size=100", "/file-events?page=1&page_size=100", "/pre-encryption-detections", "/ai-risk/scores", "/adaptive-deception/fingerprints", "/deepfake-forensics/analysis-jobs", "/deepfake-forensics/forensic-reports?page=1&page_size=50", "/model-security/integrity", "/health", "/offline-sync/queue", "/investigation-cases", "/intelligence/dashboard"] as const;
    const results = await Promise.allSettled(requests.map((path) => api.get<unknown>(path)));
    const failed = results.flatMap((result, index) => result.status === "rejected" ? [requests[index]] : []);
    setErrors(failed);
    setData((previous) => ({
      organizations: results[0].status === "fulfilled" ? asList(results[0].value) as Organization[] : previous.organizations,
      users: results[1].status === "fulfilled" ? asList(results[1].value) : previous.users,
      threats: results[2].status === "fulfilled" ? asList(results[2].value) : previous.threats,
      incidents: results[3].status === "fulfilled" ? asList(results[3].value) : previous.incidents,
      health: results[4].status === "fulfilled" && results[4].value && typeof results[4].value === "object" ? results[4].value as RecordValue : previous.health,
      honeytokenEvents: results[5].status === "fulfilled" ? asList(results[5].value) : previous.honeytokenEvents,
      canaryEvents: results[6].status === "fulfilled" ? asList(results[6].value) : previous.canaryEvents,
      honeytokenTotal: results[5].status === "fulfilled" ? totalFrom(results[5].value, asList(results[5].value).length) : previous.honeytokenTotal,
      canaryTotal: results[6].status === "fulfilled" ? totalFrom(results[6].value, asList(results[6].value).length) : previous.canaryTotal,
      organizationRisks: results[7].status === "fulfilled" && results[7].value && typeof results[7].value === "object" && Array.isArray((results[7].value as RecordValue).organizations) ? (results[7].value as { organizations: OrganizationRisk[] }).organizations : previous.organizationRisks,
      riskCalculatedAt: results[7].status === "fulfilled" && results[7].value && typeof results[7].value === "object" ? String((results[7].value as RecordValue).calculated_at || "") : previous.riskCalculatedAt,
      operations: Object.fromEntries(requests.slice(8).map((path, index) => {
        const result = results[index + 8];
        return [path, result.status === "fulfilled" ? result.value : previous.operations[path]];
      })),
    }));
    setLastRefreshedAt(new Date());
    setLoading(false); setRefreshing(false);
  }
  useEffect(() => { void load(); }, []);

  const scoped = useMemo(() => {
    const filter = (records: RecordValue[]) => selectedOrg === "all" ? records : records.filter((record) => recordOrgId(record) === selectedOrg);
    const risks = selectedOrg === "all" ? data.organizationRisks : data.organizationRisks.filter((item) => String(item.organization?.id || "") === selectedOrg);
    return { users: filter(data.users), threats: filter(data.threats), incidents: filter(data.incidents), honeytokens: filter(data.honeytokenEvents), canaries: filter(data.canaryEvents), risks };
  }, [data, selectedOrg]);
  const currentOrg = data.organizations.find((org) => org.id === selectedOrg);
  const activeOrganizations = data.organizations.filter((org) => (org.status || "").toUpperCase() === "ACTIVE").length;
  const engineStatus = String(data.health?.status || (data.health?.runtime as RecordValue | undefined)?.status || "Unavailable");
  const scopeLabel = selectedOrg === "all" ? "All Organizations" : orgName(currentOrg!);
  const metrics = [
    { label: "Organizations", value: selectedOrg === "all" ? data.organizations.length : currentOrg ? 1 : 0, detail: selectedOrg === "all" ? `${activeOrganizations} active` : currentOrg?.status || "Unknown", icon: Building2 },
    { label: "Users", value: scoped.users.length, detail: errors.includes("/admin/users") ? "API unavailable" : "Real directory records", icon: Users },
    { label: "Threats", value: scoped.threats.length, detail: errors.includes("/threats") ? "API unavailable" : "Current records", icon: ShieldAlert },
    { label: "Incidents", value: scoped.incidents.length, detail: errors.includes("/incidents") ? "API unavailable" : "Current records", icon: Siren },
    { label: "AI Engine", value: engineStatus, detail: errors.includes("/deepfake-forensics/health") ? "Health endpoint unavailable" : "Media forensics runtime", icon: Bot },
  ];
  const overviewSources = [
    { label: "Threats", value: scoped.threats.length, tone: "critical" },
    { label: "Incidents", value: scoped.incidents.length, tone: "high" },
    { label: "Honeytoken", value: scoped.honeytokens.length, tone: "honey" },
    { label: "Canary", value: scoped.canaries.length, tone: "canary" },
  ];
  const operationCards = [
    { label: "Notifications", path: "/my-notifications", icon: BellRing, kind: "notifications", detail: "Unread requiring attention" },
    { label: "Audit activity", path: "/admin/audit-activity?page=1&page_size=100", icon: Activity, kind: "audit", detail: "Recent security timeline" },
    { label: "File monitoring", path: "/file-events?page=1&page_size=100", icon: FileSearch, kind: "files", detail: "Monitored file events" },
    { label: "Pre-encryption", path: "/pre-encryption-detections", icon: ScanSearch, kind: "preEncryption", detail: "Early ransomware detections" },
    { label: "AI risk scores", path: "/ai-risk/scores", icon: BrainCircuit, kind: "aiRisk", detail: "AI-scored security risk" },
    { label: "Deception fingerprints", path: "/adaptive-deception/fingerprints", icon: Fingerprint, kind: "fingerprints", detail: "Attacker fingerprints" },
    { label: "Forensic jobs", path: "/deepfake-forensics/analysis-jobs", icon: Bot, kind: "forensicJobs", detail: "Queued or active analyses" },
    { label: "Forensic reports", path: "/deepfake-forensics/forensic-reports?page=1&page_size=50", icon: FileWarning, kind: "reports", detail: "Generated evidence reports" },
    { label: "Model integrity", path: "/model-security/integrity", icon: ShieldCheck, kind: "model", detail: "Model artifact posture" },
    { label: "System readiness", path: "/health", icon: Activity, kind: "health", detail: "API and database health" },
    { label: "Offline sync", path: "/offline-sync/queue", icon: RefreshCw, kind: "sync", detail: "Pending synchronization" },
    { label: "Investigation cases", path: "/investigation-cases", icon: DatabaseZap, kind: "cases", detail: "Organization case load" },
    { label: "Intelligence", path: "/intelligence/dashboard", icon: Network, kind: "intelligence", detail: "Active correlated findings" },
  ];

  return <div className="page command-dashboard">
    <DashboardLiveBackground />
    <section className="dashboard-hero"><div><span className="eyebrow">Super Administrator</span><h1>{selectedOrg === "all" ? "Global Security Overview" : "Organization Security Overview"}</h1><p>Live operational records for {scopeLabel}.</p></div><div className="scope-controls"><label><span>Organization scope</span><select value={selectedOrg} onChange={(event) => setSelectedOrg(event.target.value)}><option value="all">All Organizations</option>{data.organizations.map((org) => <option key={org.id} value={org.id}>{orgName(org)}</option>)}</select></label><button type="button" onClick={() => void load(true)} disabled={refreshing}><RefreshCw size={16} className={refreshing ? "spin" : ""} /> {refreshing ? "Refreshing…" : "Refresh"}</button>{lastRefreshedAt && <small className="refresh-stamp" aria-live="polite">Updated {lastRefreshedAt.toLocaleTimeString()}</small>}</div></section>

    {errors.length > 0 && <div className="dashboard-notice">Some services did not respond: {errors.join(", ")}. Their cards show honest unavailable or zero states.</div>}
    <section className="metric-grid" aria-label="Security summary">{metrics.map(({ label, value, detail, icon: Icon }) => <article className="metric-card" key={label}><span className="metric-icon"><Icon size={21} /></span><div><p>{label}</p><strong>{loading ? "—" : value}</strong><small>{detail}</small></div></article>)}</section>
    <LiveRecordOverview sources={overviewSources} users={scoped.users.length} loading={loading} scopeLabel={scopeLabel} />
    <section className="operations-overview" aria-label="Connected platform modules"><div className="operations-heading"><div><span className="eyebrow">Connected platform modules</span><h2>Security operations overview</h2><p>Live backend summaries across detection, forensics, response, and platform health.</p></div><span>{operationCards.filter((card) => !errors.includes(card.path)).length}/{operationCards.length} live sources</span></div><div className="operations-grid">{operationCards.map(({ label, path, icon: Icon, kind, detail }) => { const unavailable = errors.includes(path); const summary = operationSummary(kind, data.operations[path]); return <article className={unavailable ? "unavailable" : ""} key={path}><span className="operation-icon"><Icon size={18}/></span><div><span>{label}</span><strong>{loading ? "—" : unavailable ? "Unavailable" : summary.value}</strong><small>{unavailable ? "Endpoint did not respond or access was denied" : summary.meta || detail}</small></div></article>; })}</div></section>

    <section className="dashboard-grid">
      <div className="dashboard-stack dashboard-primary-stack"><article className="dashboard-panel org-posture"><div className="panel-heading"><div><span className="eyebrow">Tenant posture</span><h2>Organization Overview</h2></div><span>{data.organizations.length} records</span></div>
        {loading ? <div className="panel-empty">Loading organization records…</div> : data.organizations.length === 0 ? <div className="panel-empty">No organizations were returned by the backend.</div> : <div className="table-wrap"><table><thead><tr><th>Organization</th><th>Type</th><th>Status</th><th>Code</th><th>Created</th></tr></thead><tbody>{data.organizations.filter((org) => selectedOrg === "all" || org.id === selectedOrg).map((org) => <tr key={org.id}><td><strong>{orgName(org)}</strong></td><td>{org.organization_type || "—"}</td><td><span className={`status-pill ${statusTone(org.status)}`}>{org.status || "Unknown"}</span></td><td>{org.organization_code || org.code || "—"}</td><td>{org.created_at ? new Date(org.created_at).toLocaleDateString() : "—"}</td></tr>)}</tbody></table></div>}
      </article>
      <article className="dashboard-panel risk-panel"><div className="panel-heading"><div><span className="eyebrow">Risk comparison</span><h2>Organization Risk</h2></div>{data.riskCalculatedAt && <time>{new Date(data.riskCalculatedAt).toLocaleTimeString()}</time>}</div><OrganizationRiskComparison records={scoped.risks} unavailable={errors.includes("/security-scores/organizations")} /></article>
      </div>
      <div className="dashboard-stack dashboard-secondary-stack"><article className="dashboard-panel health-panel"><div className="panel-heading"><div><span className="eyebrow">Platform</span><h2>Service Health</h2></div><Activity size={18} /></div><div className="health-list"><p><span><i className={data.health ? "good" : "neutral"} /> Media Forensics Engine</span><strong>{engineStatus}</strong></p><p><span><i className={errors.includes("/admin/organizations") ? "bad" : "good"} /> Organization API</span><strong>{errors.includes("/admin/organizations") ? "Unavailable" : "Connected"}</strong></p><p><span><i className={errors.includes("/incidents") ? "bad" : "good"} /> Incident API</span><strong>{errors.includes("/incidents") ? "Unavailable" : "Connected"}</strong></p></div></article>
      <article className="dashboard-panel deception-source-panel"><div className="panel-heading"><div><span className="eyebrow">Credential deception</span><h2>Honeytoken Activity</h2></div><KeyRound size={18} /></div><DeceptionSourceAnalytics kind="Honeytoken" events={scoped.honeytokens} total={selectedOrg === "all" ? data.honeytokenTotal : scoped.honeytokens.length} color="#ffb52e" workspace="/honeytokens" unavailable={errors.includes("/file-events?source_type=HONEYTOKEN&page=1&page_size=100")} /></article>
      <article className="dashboard-panel deception-source-panel"><div className="panel-heading"><div><span className="eyebrow">File deception</span><h2>Canary File Activity</h2></div><FileWarning size={18} /></div><DeceptionSourceAnalytics kind="Canary file" events={scoped.canaries} total={selectedOrg === "all" ? data.canaryTotal : scoped.canaries.length} color="#25bce9" workspace="/canary-files" unavailable={errors.includes("/file-events?source_type=CANARY_FILE&page=1&page_size=100")} /></article>
      </div>
    </section>
  </div>;
}

function LiveRecordOverview({ sources, users, loading, scopeLabel }: { sources: Array<{ label: string; value: number; tone: string }>; users: number; loading: boolean; scopeLabel: string }) {
  const total = sources.reduce((sum, source) => sum + source.value, 0);
  return <section className="live-record-overview" aria-label="Live record overview">
    <div className="overview-heading"><div><span className="eyebrow">Live record overview</span><h2>Current security activity</h2><p>Derived from the frontend data currently loaded for {scopeLabel}.</p></div><strong>{loading ? "—" : total}<small>tracked security records</small></strong></div>
    <div className="overview-bar" aria-label="Security record distribution">{sources.map((source) => <i className={source.tone} key={source.label} style={{ width: `${total ? (source.value / total) * 100 : 0}%` }} title={`${source.label}: ${source.value}`} />)}</div>
    <div className="overview-legend">{sources.map((source) => <article key={source.label}><i className={source.tone} /><span>{source.label}</span><strong>{loading ? "—" : source.value}</strong></article>)}<article className="overview-users"><i /><span>Directory users</span><strong>{loading ? "—" : users}</strong></article></div>
  </section>;
}

function OrganizationRiskComparison({ records, unavailable }: { records: OrganizationRisk[]; unavailable: boolean }) {
  if (unavailable) return <div className="panel-empty">Organization risk scoring API is unavailable. No score is fabricated.</div>;
  if (!records.length) return <div className="panel-empty">No organization risk records were returned for this scope.</div>;
  const ranked = [...records].sort((left, right) => Number(right.risk_score ?? -1) - Number(left.risk_score ?? -1));
  return <div className="organization-risk-list">{ranked.map((record, index) => {
    const hasScore = record.data_available !== false && typeof record.risk_score === "number";
    const score = hasScore ? Math.max(0, Math.min(100, Number(record.risk_score))) : 0;
    const level = hasScore ? String(record.risk_level || "LOW").toUpperCase() : "NOT AVAILABLE";
    const counts = record.source_counts || {};
    return <article key={record.organization?.id || `${record.organization?.code}-${index}`}>
      <div className="risk-row-header"><div className="risk-rank"><span>{index + 1}</span><div><strong>{record.organization?.name || record.organization?.code || "Unnamed organization"}</strong><small>{record.organization?.code || "No code"}</small></div></div><span className={`status-pill ${riskTone(level)}`}>{level}</span></div>
      <div className="risk-meter"><i style={{ width: hasScore ? `${score}%` : "0" }} className={riskTone(level)} /><span>{hasScore ? score.toFixed(1) : "—"}</span></div>
      <div className="risk-sources"><span>{Number(counts.open_threats || 0)} threats</span><span>{Number(counts.open_incidents || 0)} incidents</span><span>{Number(counts.recent_behavior_detections || 0)} behavior</span></div>
    </article>;
  })}</div>;
}

function DeceptionSourceAnalytics({ kind, events: sourceEvents, total, color, workspace, unavailable }: { kind: "Honeytoken" | "Canary file"; events: RecordValue[]; total: number; color: string; workspace: string; unavailable: boolean }) {
  const events = [...sourceEvents].sort((left, right) => new Date(String(right.occurred_at || right.created_at || 0)).getTime() - new Date(String(left.occurred_at || left.created_at || 0)).getTime()).slice(0, 100);
  if (unavailable && !events.length) return <div className="panel-empty">{kind} event API is unavailable for the selected scope.</div>;
  if (!events.length) return <div className="panel-empty deception-empty"><p>No {kind.toLowerCase()} trigger events were returned for the selected scope.</p><Link to={workspace}>{kind === "Honeytoken" ? "Create → place the generated value → Deploy & arm" : "Create → Deploy & arm a monitored copy"}</Link></div>;
  const severity = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => ({ level, count: events.filter((event) => String(event.severity || "").toUpperCase() === level).length }));
  const loadedTotal = Math.max(1, events.length);
  return <div className="source-analytics"><div className="source-total" style={{ "--source-color": color } as CSSProperties}><strong>{total}</strong><span>Total triggers</span><small>{events.length} loaded records</small></div><div className="severity-visual"><span className="chart-caption">Severity distribution</span><div className="severity-stack">{severity.map((item) => <i key={item.level} className={item.level.toLowerCase()} style={{ width: `${(item.count / loadedTotal) * 100}%` }} title={`${item.level}: ${item.count}`} />)}</div><div className="severity-cards">{severity.map((item) => <article className={item.level.toLowerCase()} key={item.level}><span>{item.level}</span><strong>{item.count}</strong><small>{Math.round((item.count / loadedTotal) * 100)}%</small></article>)}</div></div><div className="trigger-actions"><p>{kind} inventory and its event history remain separate from the other deception mechanism.</p><Link to={workspace}>Open {kind} workspace <strong>{total}</strong></Link><Link className="all-events" to={`/audit-activity?source=${kind === "Honeytoken" ? "HONEYTOKEN" : "CANARY_FILE"}`}>Open filtered audit activity</Link></div></div>;
}
