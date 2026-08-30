import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Activity, BarChart3, FileCheck2, Plus, RefreshCw, Search, ShieldCheck, Siren, X } from "lucide-react";
import { api } from "../lib/api";
import { DetailDrawer, EmptyState, ErrorBanner, FactGrid, LoadingState, MetricCard, StatusBadge, formatDate, humanize } from "./securityOperationsUI";
import "./securityOperations.css";

type IncidentRecord = {
  id: string;
  incident_number: string;
  incident_title: string;
  description?: string;
  incident_category: string;
  severity: string;
  priority: string;
  status: string;
  detection_source: string;
  affected_device_name?: string;
  lead_investigator_id?: string;
  data_exposure_suspected: boolean;
  ransomware_suspected: boolean;
  device_isolated: boolean;
  evidence_preserved: boolean;
  affected_record_count?: number;
  estimated_financial_impact?: number;
  initial_findings?: string;
  root_cause?: string;
  containment_summary?: string;
  resolution_summary?: string;
  detected_at: string;
  reported_at: string;
  investigation_started_at?: string;
  contained_at?: string;
  resolved_at?: string;
  closed_at?: string;
  created_at: string;
  updated_at: string;
};

type IncidentListResponse = { incidents: IncidentRecord[]; total: number; page: number; page_size: number; total_pages: number };
type IncidentThreat = { threat_id: string; threat_code: string; threat_type: string; severity: string; status: string; relation_type: string; added_at: string };
type IncidentTimeline = { id: string; event_type: string; title: string; description?: string; previous_status?: string; new_status?: string; occurred_at: string; created_at: string };
type IncidentEvidence = { id: string; evidence_code: string; evidence_type: string; evidence_name: string; description?: string; original_file_name?: string; mime_type?: string; file_size_bytes?: number; hash_algorithm: string; evidence_hash?: string; integrity_status: string; is_immutable: boolean; collected_at: string; verified_at?: string };
type IncidentThreatList = IncidentThreat[] | { threats?: IncidentThreat[] };
type TimelineList = { entries: IncidentTimeline[]; total: number };
type EvidenceList = { evidence: IncidentEvidence[]; total: number };
type IncidentFilters = { search: string; severity: string; status: string; source: string; from: string; to: string };
type Investigator = { id: string; display_name?: string; username?: string; official_email?: string; account_status?: string };

const statuses = ["OPEN", "ASSIGNED", "INVESTIGATING", "CONTAINED", "ERADICATED", "RECOVERING", "RESOLVED", "CLOSED", "REOPENED", "CANCELLED"];
const allowedTransitions: Record<string, string[]> = {
  OPEN: ["ASSIGNED", "INVESTIGATING", "CANCELLED"],
  ASSIGNED: ["INVESTIGATING", "CANCELLED"],
  INVESTIGATING: ["CONTAINED", "RESOLVED", "CANCELLED"],
  CONTAINED: ["ERADICATED", "RECOVERING", "RESOLVED"],
  ERADICATED: ["RECOVERING", "RESOLVED"],
  RECOVERING: ["CONTAINED", "RESOLVED"],
  RESOLVED: ["CLOSED", "REOPENED"],
  CLOSED: ["REOPENED"],
  REOPENED: ["ASSIGNED", "INVESTIGATING", "CANCELLED"],
  CANCELLED: ["REOPENED"],
};
const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const categories = ["UNAUTHORIZED_ACCESS", "HONEYTOKEN_TRIGGER", "CANARY_FILE_TRIGGER", "RANSOMWARE", "MALWARE", "PHISHING", "DATA_BREACH", "INSIDER_THREAT", "ACCOUNT_COMPROMISE", "API_ATTACK", "DEEPFAKE", "DIGITAL_EVIDENCE", "POLICY_VIOLATION", "SYSTEM_ANOMALY", "OTHER"];
const sources = ["SECURITY_ALERT", "HONEYTOKEN", "CANARY_FILE", "FILE_MONITORING", "AI_ANALYSIS", "USER_REPORT", "ADMIN_REPORT", "SYSTEM", "EXTERNAL_REPORT", "OTHER"];
const blankFilters: IncidentFilters = { search: "", severity: "", status: "", source: "", from: "", to: "" };

function listQuery(filters: IncidentFilters) {
  const query = new URLSearchParams({ page: "1", page_size: "100" });
  if (filters.search.trim()) query.set("search", filters.search.trim());
  if (filters.severity) query.set("severity", filters.severity);
  if (filters.status) query.set("status", filters.status);
  if (filters.source) query.set("detection_source", filters.source);
  if (filters.from) query.set("from", new Date(`${filters.from}T00:00:00`).toISOString());
  if (filters.to) query.set("to", new Date(`${filters.to}T23:59:59.999`).toISOString());
  return query.toString();
}

function getThreats(result: IncidentThreatList) {
  return Array.isArray(result) ? result : result.threats || [];
}

function shortHash(value?: string) {
  if (!value) return "Not reported";
  return value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

type CreateIncidentState = { title: string; category: string; source: string; severity: string; priority: string; description: string; device: string; ransomware: boolean; exposure: boolean };
const blankIncident: CreateIncidentState = { title: "", category: "SYSTEM_ANOMALY", source: "SECURITY_ALERT", severity: "MEDIUM", priority: "MEDIUM", description: "", device: "", ransomware: false, exposure: false };

export function IncidentResponsePage() {
  const [filters, setFilters] = useState<IncidentFilters>(blankFilters);
  const [appliedFilters, setAppliedFilters] = useState<IncidentFilters>(blankFilters);
  const [data, setData] = useState<IncidentListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<IncidentRecord | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [relatedThreats, setRelatedThreats] = useState<IncidentThreat[]>([]);
  const [timeline, setTimeline] = useState<IncidentTimeline[]>([]);
  const [evidence, setEvidence] = useState<IncidentEvidence[]>([]);
  const [nextStatus, setNextStatus] = useState("");
  const [transitionSummary, setTransitionSummary] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [createState, setCreateState] = useState<CreateIncidentState>(blankIncident);
  const [createError, setCreateError] = useState<string | null>(null);
  const [noteTitle, setNoteTitle] = useState("");
  const [noteDescription, setNoteDescription] = useState("");
  const [investigators, setInvestigators] = useState<Investigator[]>([]);
  const [investigatorID, setInvestigatorID] = useState("");

  const load = useCallback(async (refresh = false) => {
    refresh ? setRefreshing(true) : setLoading(true);
    setError(null);
    try {
      setData(await api.get<IncidentListResponse>(`/incidents?${listQuery(appliedFilters)}`));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Incident records could not be loaded.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [appliedFilters]);

  useEffect(() => { void load(); }, [load]);

  const incidents = data?.incidents || [];
  const severityCounts = useMemo(() => Object.fromEntries(severities.map((severity) => [severity, incidents.filter((item) => item.severity === severity).length])) as Record<string, number>, [incidents]);
  const statusCounts = useMemo(() => Object.fromEntries(statuses.map((status) => [status, incidents.filter((item) => item.status === status).length])) as Record<string, number>, [incidents]);
  const activeCount = incidents.filter((item) => !["RESOLVED", "CLOSED", "CANCELLED"].includes(item.status)).length;
  const unassignedCount = incidents.filter((item) => !item.lead_investigator_id).length;
  const sourceCounts = useMemo(() => {
    const counts = new Map<string, number>();
    incidents.forEach((item) => counts.set(item.detection_source || "NOT_REPORTED", (counts.get(item.detection_source || "NOT_REPORTED") || 0) + 1));
    return [...counts.entries()].sort((left, right) => right[1] - left[1]);
  }, [incidents]);

  async function openIncident(incident: IncidentRecord) {
    setSelected(incident);
    setNextStatus(incident.status);
    setTransitionSummary("");
    setRelatedThreats([]);
    setTimeline([]);
    setEvidence([]);
    setDetailLoading(true);
    setDetailError(null);
    try {
      const [record, threatResult, timelineResult, evidenceResult, userResult] = await Promise.all([
        api.get<IncidentRecord>(`/incidents/${encodeURIComponent(incident.id)}`),
        api.get<IncidentThreatList>(`/incidents/${encodeURIComponent(incident.id)}/threats`).catch(() => [] as IncidentThreat[]),
        api.get<TimelineList>(`/incidents/${encodeURIComponent(incident.id)}/timeline?page=1&page_size=100`).catch(() => ({ entries: [], total: 0 })),
        api.get<EvidenceList>(`/incidents/${encodeURIComponent(incident.id)}/evidence?page=1&page_size=100`).catch(() => ({ evidence: [], total: 0 })),
        api.get<any>("/admin/users?page=1&page_size=100").catch(() => ({ users: [] })),
      ]);
      setSelected(record);
      setNextStatus(record.status);
      setTransitionSummary("");
      setRelatedThreats(getThreats(threatResult));
      setTimeline(timelineResult.entries || []);
      setEvidence(evidenceResult.evidence || []);
      const users = Array.isArray(userResult) ? userResult : userResult?.users || userResult?.items || [];
      setInvestigators(users.filter((user: Investigator) => !user.account_status || user.account_status === "ACTIVE"));
      setInvestigatorID(record.lead_investigator_id || "");
    } catch (requestError) {
      setDetailError(requestError instanceof Error ? requestError.message : "Incident detail could not be loaded.");
    } finally {
      setDetailLoading(false);
    }
  }

  async function updateStatus() {
    if (!selected || !nextStatus || nextStatus === selected.status) return;
    const summary = transitionSummary.trim();
    if (nextStatus === "CONTAINED" && !selected.containment_summary && !summary) {
      setDetailError("A factual containment summary is required before this incident can be marked contained.");
      return;
    }
    if (nextStatus === "RESOLVED" && !selected.resolution_summary && !summary) {
      setDetailError("A factual resolution summary is required before this incident can be marked resolved.");
      return;
    }
    setActionBusy(true);
    setDetailError(null);
    try {
      const body: Record<string, string> = { status: nextStatus };
      if (nextStatus === "CONTAINED" && summary) body.containment_summary = summary;
      if (nextStatus === "RESOLVED" && summary) body.resolution_summary = summary;
      const updated = await api.patch<IncidentRecord>(`/incidents/${encodeURIComponent(selected.id)}/status`, body);
      setSelected(updated);
      setTransitionSummary("");
      await Promise.all([load(true), openIncident(updated)]);
    } catch (requestError) {
      setDetailError(requestError instanceof Error ? requestError.message : "Incident status could not be updated.");
    } finally {
      setActionBusy(false);
    }
  }

  async function assignInvestigator() {
    if (!selected || !investigatorID || investigatorID === selected.lead_investigator_id) return;
    setActionBusy(true);
    setDetailError(null);
    try {
      const updated = await api.patch<IncidentRecord>(`/incidents/${encodeURIComponent(selected.id)}/assignment`, { lead_investigator_id: investigatorID });
      setSelected(updated);
      setNextStatus(updated.status);
      await Promise.all([load(true), openIncident(updated)]);
    } catch (requestError) {
      setDetailError(requestError instanceof Error ? requestError.message : "Investigator could not be assigned.");
    } finally {
      setActionBusy(false);
    }
  }

  async function addNote(event: FormEvent) {
    event.preventDefault();
    if (!selected || !noteTitle.trim()) return;
    setActionBusy(true);
    setDetailError(null);
    try {
      await api.post(`/incidents/${encodeURIComponent(selected.id)}/timeline/notes`, { title: noteTitle.trim(), description: noteDescription.trim() || undefined });
      setNoteTitle("");
      setNoteDescription("");
      await openIncident(selected);
    } catch (requestError) {
      setDetailError(requestError instanceof Error ? requestError.message : "Investigation note could not be added.");
    } finally {
      setActionBusy(false);
    }
  }

  async function createIncident(event: FormEvent) {
    event.preventDefault();
    setActionBusy(true);
    setCreateError(null);
    try {
      await api.post("/incidents", {
        incident_title: createState.title.trim(), incident_category: createState.category, detection_source: createState.source,
        severity: createState.severity, priority: createState.priority, description: createState.description.trim() || undefined,
        affected_device_name: createState.device.trim() || undefined, ransomware_suspected: createState.ransomware,
        data_exposure_suspected: createState.exposure, device_isolated: false, evidence_preserved: false,
      });
      setCreateState(blankIncident);
      setCreateOpen(false);
      await load(true);
    } catch (requestError) {
      setCreateError(requestError instanceof Error ? requestError.message : "Incident could not be created.");
    } finally {
      setActionBusy(false);
    }
  }

  return (
    <section className="page soc-ops-page">
      <header className="soc-ops-hero"><div><p className="eyebrow">INCIDENT OPERATIONS</p><h1>Incident Response</h1><span>Security incidents, assignments, response evidence and investigation timeline.</span></div><div className="hero-actions"><button type="button" className="primary with-icon" onClick={() => setCreateOpen(true)}><Plus size={16} /> Create incident</button><button type="button" className="secondary with-icon" disabled={refreshing} onClick={() => void load(true)}><RefreshCw className={refreshing ? "spin" : ""} size={16} /> Refresh</button></div></header>

      <form className="soc-filterbar" onSubmit={(event) => { event.preventDefault(); setAppliedFilters(filters); }}>
        <label className="soc-search"><Search size={17} /><input value={filters.search} onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))} placeholder="Search incident number, title, user or device" /></label>
        <label><span>Severity</span><select value={filters.severity} onChange={(event) => setFilters((current) => ({ ...current, severity: event.target.value }))}><option value="">All severities</option>{severities.map((item) => <option key={item}>{item}</option>)}</select></label>
        <label><span>Status</span><select value={filters.status} onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))}><option value="">All statuses</option>{statuses.map((item) => <option key={item}>{item}</option>)}</select></label>
        <label><span>Source</span><select value={filters.source} onChange={(event) => setFilters((current) => ({ ...current, source: event.target.value }))}><option value="">All sources</option>{sources.map((item) => <option key={item}>{item}</option>)}</select></label>
        <label><span>From</span><input type="date" value={filters.from} onChange={(event) => setFilters((current) => ({ ...current, from: event.target.value }))} /></label>
        <label><span>To</span><input type="date" value={filters.to} onChange={(event) => setFilters((current) => ({ ...current, to: event.target.value }))} /></label>
        <button type="submit" className="primary">Apply filters</button><button type="button" className="secondary" onClick={() => { setFilters(blankFilters); setAppliedFilters(blankFilters); }}>Clear</button>
      </form>

      {error ? <ErrorBanner message={error} /> : null}
      {loading ? <LoadingState label="Loading incident operations…" /> : <>
        <div className="soc-metrics"><MetricCard label="Total incidents" value={data?.total || 0} hint={`${incidents.length} loaded for this view`} /><MetricCard label="Critical" value={severityCounts.CRITICAL || 0} accent="red" /><MetricCard label="Active" value={activeCount} accent="amber" /><MetricCard label="Investigating" value={statusCounts.INVESTIGATING || 0} accent="violet" /><MetricCard label="Unassigned" value={unassignedCount} accent="green" /></div>
        {!incidents.length ? <EmptyState title="No incidents in this scope" message="No security incidents were returned for the selected filters." /> : <>
          <div className="soc-visual-grid soc-incident-visuals">
            <article className="soc-panel soc-wide"><header><div><p>OPERATIONAL FLOW</p><h2>Incident status pipeline</h2></div><Siren size={20} /></header><div className="soc-pipeline soc-pipeline-horizontal">{statuses.filter((status) => status !== "CANCELLED").map((status) => <button type="button" key={status} className={statusCounts[status] ? "active" : ""} onClick={() => { const updated = { ...filters, status }; setFilters(updated); setAppliedFilters(updated); }}><span>{humanize(status)}</span><strong>{statusCounts[status] || 0}</strong></button>)}</div></article>
            <article className="soc-panel"><header><div><p>SEVERITY</p><h2>Incident severity</h2></div><BarChart3 size={20} /></header><div className="soc-bars">{severities.map((severity) => <div key={severity}><span>{humanize(severity)}</span><i><b style={{ width: `${incidents.length ? Math.max(4, ((severityCounts[severity] || 0) / incidents.length) * 100) : 0}%` }} /></i><strong>{severityCounts[severity] || 0}</strong></div>)}</div></article>
            <article className="soc-panel"><header><div><p>DETECTION</p><h2>Incidents by source</h2></div><Activity size={20} /></header><div className="soc-bars">{sourceCounts.map(([source, count]) => <div key={source}><span>{humanize(source)}</span><i><b style={{ width: `${Math.max(4, (count / incidents.length) * 100)}%` }} /></i><strong>{count}</strong></div>)}</div></article>
          </div>
          <article className="soc-panel soc-table-panel"><header><div><p>INCIDENT QUEUE</p><h2>Operational incident records</h2></div><ShieldCheck size={20} /></header><div className="table-wrap"><table className="soc-table"><thead><tr><th>Incident</th><th>Source</th><th>Affected resource</th><th>Severity</th><th>Priority</th><th>Status</th><th>Created</th><th /></tr></thead><tbody>{incidents.map((item) => <tr key={item.id} onClick={() => void openIncident(item)}><td><strong>{item.incident_number}</strong><small>{item.incident_title}</small></td><td>{humanize(item.detection_source)}<small>{humanize(item.incident_category)}</small></td><td>{item.affected_device_name || "Not reported"}</td><td><StatusBadge value={item.severity} /></td><td><StatusBadge value={item.priority} /></td><td><StatusBadge value={item.status} /></td><td>{formatDate(item.created_at)}</td><td><button type="button" className="icon-button" onClick={(event) => { event.stopPropagation(); void openIncident(item); }} aria-label={`Open ${item.incident_number}`}>→</button></td></tr>)}</tbody></table></div></article>
        </>}
      </>}

      {selected ? <DetailDrawer eyebrow="INCIDENT RESPONSE WORKSPACE" title={`${selected.incident_number} · ${selected.incident_title}`} onClose={() => setSelected(null)}>
        {detailError ? <ErrorBanner message={detailError} /> : null}{detailLoading ? <LoadingState label="Loading incident relationships and evidence…" /> : <>
          <section className="soc-detail-summary"><StatusBadge value={selected.severity} /><StatusBadge value={selected.status} /><StatusBadge value={selected.priority} /><strong>{humanize(selected.detection_source)}</strong></section>
          <section className="soc-detail-section"><h3>Investigator assignment</h3><p className="soc-muted">Assign an active platform user before progressing this incident through its lifecycle.</p><div className="soc-inline-action"><select value={investigatorID} onChange={(event) => setInvestigatorID(event.target.value)}><option value="">Select investigator</option>{investigators.map((user) => <option key={user.id} value={user.id}>{user.display_name || user.username || user.official_email || user.id}</option>)}</select><button className="primary" type="button" disabled={actionBusy || !investigatorID || investigatorID === selected.lead_investigator_id} onClick={() => void assignInvestigator()}>{actionBusy ? "Assigning…" : selected.lead_investigator_id ? "Reassign" : "Assign investigator"}</button></div>{!investigators.length ? <p className="soc-muted">No active users are available, or the user directory could not be loaded.</p> : null}</section>
          <section className="soc-detail-section"><h3>What happened?</h3><p>{selected.description || selected.initial_findings || "No investigation-safe narrative has been recorded yet."}</p><FactGrid facts={[{ label: "Category", value: humanize(selected.incident_category) }, { label: "Detected", value: formatDate(selected.detected_at) }, { label: "Reported", value: formatDate(selected.reported_at) }, { label: "Last updated", value: formatDate(selected.updated_at) }, { label: "Affected device", value: selected.affected_device_name || "Not reported" }, { label: "Investigator assigned", value: selected.lead_investigator_id ? "Yes" : "No" }, { label: "Affected records", value: selected.affected_record_count === undefined ? "Not reported" : String(selected.affected_record_count) }]} /></section>
          <section className="soc-detail-section"><h3>Impact and response posture</h3><div className="soc-flag-grid"><div className={selected.ransomware_suspected ? "risk" : "clear"}>Ransomware suspected<strong>{selected.ransomware_suspected ? "Yes" : "No"}</strong></div><div className={selected.data_exposure_suspected ? "risk" : "clear"}>Data exposure suspected<strong>{selected.data_exposure_suspected ? "Yes" : "No"}</strong></div><div className={selected.device_isolated ? "clear" : "pending"}>Device isolated<strong>{selected.device_isolated ? "Yes" : "No"}</strong></div><div className={selected.evidence_preserved ? "clear" : "pending"}>Evidence preserved<strong>{selected.evidence_preserved ? "Yes" : "No"}</strong></div></div></section>
          <section className="soc-detail-section"><h3>Investigation findings</h3><FactGrid facts={[{ label: "Initial findings", value: selected.initial_findings || "Not recorded" }, { label: "Root cause", value: selected.root_cause || "Not recorded" }, { label: "Containment summary", value: selected.containment_summary || "Not recorded" }, { label: "Resolution summary", value: selected.resolution_summary || "Not recorded" }, { label: "Investigation started", value: formatDate(selected.investigation_started_at) }, { label: "Contained", value: formatDate(selected.contained_at) }, { label: "Resolved", value: formatDate(selected.resolved_at) }, { label: "Closed", value: formatDate(selected.closed_at) }]} /></section>
          <section className="soc-detail-section"><h3>Attack and response timeline</h3>{timeline.length ? <ol className="soc-timeline">{timeline.map((entry) => <li key={entry.id}><time>{formatDate(entry.occurred_at)}</time><strong>{entry.title}</strong><span>{entry.description || humanize(entry.event_type)}</span>{entry.new_status ? <StatusBadge value={entry.new_status} /> : null}</li>)}</ol> : <p className="soc-muted">No timeline entries were returned.</p>}</section>
          <section className="soc-detail-section"><h3>Related threats</h3>{relatedThreats.length ? <div className="soc-related-list">{relatedThreats.map((threat) => <article key={threat.threat_id}><div><strong>{threat.threat_code}</strong><span>{humanize(threat.threat_type)} · {humanize(threat.relation_type)}</span></div><StatusBadge value={threat.severity} /><StatusBadge value={threat.status} /></article>)}</div> : <p className="soc-muted">No threats are linked to this incident.</p>}</section>
          <section className="soc-detail-section"><h3>Evidence integrity</h3>{evidence.length ? <div className="soc-evidence-grid">{evidence.map((item) => <article key={item.id}><FileCheck2 size={18} /><div><strong>{item.evidence_name}</strong><span>{humanize(item.evidence_type)} · {item.evidence_code}</span><small>{item.original_file_name || "No source filename"} · {item.hash_algorithm} {shortHash(item.evidence_hash)}</small><small>Collected {formatDate(item.collected_at)}</small></div><StatusBadge value={item.integrity_status} /></article>)}</div> : <p className="soc-muted">No evidence metadata is linked to this incident.</p>}</section>
          <section className="soc-detail-section"><h3>Lifecycle action</h3><p className="soc-muted">The assigned investigator (or authorized incident lead) records this action. <strong>CONTAINED</strong> means a real response action was completed, such as isolating the endpoint through the endpoint-management tool, blocking an account, or restricting a share. This dashboard only records and audits that outcome; it does not silently disconnect a device. <strong>RESOLVED</strong> is recorded after remediation and verification.</p>{!selected.lead_investigator_id ? <p className="soc-muted">This incident must be assigned to an investigator before it can move to Assigned or Investigating.</p> : null}<div className="soc-inline-action"><select value={nextStatus} onChange={(event) => { setNextStatus(event.target.value); setTransitionSummary(""); }}><option value={selected.status}>{selected.status} (current)</option>{(allowedTransitions[selected.status] || []).map((status) => <option key={status}>{status}</option>)}</select><button className="primary" type="button" disabled={actionBusy || nextStatus === selected.status} onClick={() => void updateStatus()}>{actionBusy ? "Updating…" : "Update status"}</button></div>{(nextStatus === "CONTAINED" && !selected.containment_summary) || (nextStatus === "RESOLVED" && !selected.resolution_summary) ? <textarea className="soc-transition-summary" value={transitionSummary} onChange={(event) => setTransitionSummary(event.target.value)} maxLength={10000} placeholder={nextStatus === "CONTAINED" ? "Record the actual containment action, system, and verification" : "Record the remediation and verification outcome"} /> : null}</section>
          <section className="soc-detail-section"><h3>Add investigation note</h3><form className="soc-note-form" onSubmit={addNote}><input value={noteTitle} onChange={(event) => setNoteTitle(event.target.value)} placeholder="Note title" minLength={3} maxLength={255} required /><textarea value={noteDescription} onChange={(event) => setNoteDescription(event.target.value)} placeholder="Investigation observation (no credentials or secrets)" maxLength={10000} /><button type="submit" className="primary" disabled={actionBusy}>Add audited note</button></form></section>
        </>}
      </DetailDrawer> : null}

      {createOpen ? <div className="soc-drawer-backdrop" role="presentation" onMouseDown={() => setCreateOpen(false)}><section className="soc-modal" role="dialog" aria-modal="true" aria-label="Create incident" onMouseDown={(event) => event.stopPropagation()}><header><div><p>MANUAL INCIDENT REPORT</p><h2>Create incident</h2></div><button type="button" className="icon-button" onClick={() => setCreateOpen(false)} aria-label="Close"><X size={19} /></button></header>{createError ? <ErrorBanner message={createError} /> : null}<form onSubmit={createIncident} className="soc-create-form"><label>Incident title *<input value={createState.title} onChange={(event) => setCreateState((current) => ({ ...current, title: event.target.value }))} minLength={3} maxLength={255} required /></label><label>Category *<select value={createState.category} onChange={(event) => setCreateState((current) => ({ ...current, category: event.target.value }))}>{categories.map((item) => <option key={item}>{item}</option>)}</select></label><label>Detection source *<select value={createState.source} onChange={(event) => setCreateState((current) => ({ ...current, source: event.target.value }))}>{sources.map((item) => <option key={item}>{item}</option>)}</select></label><label>Severity<select value={createState.severity} onChange={(event) => setCreateState((current) => ({ ...current, severity: event.target.value }))}>{severities.map((item) => <option key={item}>{item}</option>)}</select></label><label>Priority<select value={createState.priority} onChange={(event) => setCreateState((current) => ({ ...current, priority: event.target.value }))}>{["LOW", "MEDIUM", "HIGH", "URGENT"].map((item) => <option key={item}>{item}</option>)}</select></label><label>Affected device name<input value={createState.device} onChange={(event) => setCreateState((current) => ({ ...current, device: event.target.value }))} maxLength={255} /></label><label className="field-wide">Description<textarea value={createState.description} onChange={(event) => setCreateState((current) => ({ ...current, description: event.target.value }))} maxLength={5000} /></label><label className="soc-check"><input type="checkbox" checked={createState.ransomware} onChange={(event) => setCreateState((current) => ({ ...current, ransomware: event.target.checked }))} /> Ransomware suspected</label><label className="soc-check"><input type="checkbox" checked={createState.exposure} onChange={(event) => setCreateState((current) => ({ ...current, exposure: event.target.checked }))} /> Data exposure suspected</label><footer><button type="button" className="secondary" onClick={() => setCreateOpen(false)}>Cancel</button><button type="submit" className="primary" disabled={actionBusy}>{actionBusy ? "Creating…" : "Create incident"}</button></footer></form></section></div> : null}
    </section>
  );
}
