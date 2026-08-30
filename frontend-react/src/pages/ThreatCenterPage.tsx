import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Activity, RefreshCw, Search, ShieldAlert, Target, Workflow } from "lucide-react";
import { api } from "../lib/api";
import { DetailDrawer, EmptyState, ErrorBanner, FactGrid, LoadingState, MetricCard, StatusBadge, formatDate, formatScore, humanize, safeFacts, text } from "./securityOperationsUI";
import "./securityOperations.css";

type ThreatRecord = {
  id: string;
  threat_code: string;
  title: string;
  description?: string;
  threat_type: string;
  threat_category: string;
  detection_method: string;
  severity: string;
  threat_score: number;
  confidence_score: number;
  classification: string;
  status: string;
  event_count: number;
  affected_file_count: number;
  first_detected_at: string;
  last_detected_at: string;
  process_name?: string;
  device_name?: string;
  indicators?: unknown;
  risk_factors?: unknown;
  evidence_summary?: unknown;
  recommended_actions?: unknown;
  containment_actions?: unknown;
  resolution_notes?: string;
  assigned_to?: string;
  confirmed_at?: string;
  mitigated_at?: string;
  resolved_at?: string;
  file_events?: Array<{ relation_type: string; created_at: string }>;
  honeytoken_id?: string;
  canary_file_id?: string;
};

type ThreatListResponse = {
  threats: ThreatRecord[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
};

type ThreatFilters = { search: string; severity: string; status: string; from: string; to: string };

const initialFilters: ThreatFilters = { search: "", severity: "", status: "", from: "", to: "" };
const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const threatStatuses = ["DETECTED", "ANALYZING", "CONFIRMED", "FALSE_POSITIVE", "MITIGATED", "ESCALATED", "RESOLVED", "ARCHIVED"];
const allowedThreatTransitions: Record<string, string[]> = {
  DETECTED: ["ANALYZING", "CONFIRMED", "FALSE_POSITIVE", "ESCALATED", "ARCHIVED"],
  ANALYZING: ["CONFIRMED", "FALSE_POSITIVE", "ESCALATED", "ARCHIVED"],
  CONFIRMED: ["MITIGATED", "ESCALATED", "FALSE_POSITIVE"],
  MITIGATED: ["RESOLVED", "ESCALATED"],
  ESCALATED: ["ANALYZING", "CONFIRMED", "MITIGATED", "RESOLVED"],
  RESOLVED: ["ARCHIVED", "ESCALATED"],
  FALSE_POSITIVE: ["ANALYZING", "ARCHIVED"],
  ARCHIVED: [],
};

function queryFrom(filters: ThreatFilters) {
  const query = new URLSearchParams({ page: "1", page_size: "100" });
  if (filters.search.trim()) query.set("search", filters.search.trim());
  if (filters.severity) query.set("severity", filters.severity);
  if (filters.status) query.set("status", filters.status);
  if (filters.from) query.set("from", new Date(`${filters.from}T00:00:00`).toISOString());
  if (filters.to) query.set("to", new Date(`${filters.to}T23:59:59.999`).toISOString());
  return query.toString();
}

export function ThreatCenterPage() {
  const [filters, setFilters] = useState<ThreatFilters>(initialFilters);
  const [appliedFilters, setAppliedFilters] = useState<ThreatFilters>(initialFilters);
  const [data, setData] = useState<ThreatListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<ThreatRecord | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [nextStatus, setNextStatus] = useState("");
  const [resolutionNotes, setResolutionNotes] = useState("");
  const [statusBusy, setStatusBusy] = useState(false);

  const load = useCallback(async (showRefresh = false) => {
    showRefresh ? setRefreshing(true) : setLoading(true);
    setError(null);
    try {
      setData(await api.get<ThreatListResponse>(`/threats?${queryFrom(appliedFilters)}`));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Threat records could not be loaded.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [appliedFilters]);

  useEffect(() => { void load(); }, [load]);

  const threats = data?.threats || [];
  const severityCounts = useMemo(() => Object.fromEntries(severityOrder.map((severity) => [severity, threats.filter((item) => item.severity === severity).length])) as Record<(typeof severityOrder)[number], number>, [threats]);
  const activeCount = threats.filter((item) => !["RESOLVED", "ARCHIVED", "FALSE_POSITIVE"].includes(item.status)).length;
  const unassignedCount = threats.filter((item) => !item.assigned_to).length;
  const averageScore = threats.length ? threats.reduce((total, item) => total + item.threat_score, 0) / threats.length : null;
  const loadedSeverityTotal = severityOrder.reduce((total, severity) => total + severityCounts[severity], 0);
  const criticalDegrees = loadedSeverityTotal ? (severityCounts.CRITICAL / loadedSeverityTotal) * 360 : 0;
  const highDegrees = loadedSeverityTotal ? (severityCounts.HIGH / loadedSeverityTotal) * 360 : 0;
  const mediumDegrees = loadedSeverityTotal ? (severityCounts.MEDIUM / loadedSeverityTotal) * 360 : 0;
  const sourceCounts = useMemo(() => {
    const counts = new Map<string, number>();
    threats.forEach((item) => counts.set(item.threat_type || "NOT_REPORTED", (counts.get(item.threat_type || "NOT_REPORTED") || 0) + 1));
    return [...counts.entries()].sort((left, right) => right[1] - left[1]);
  }, [threats]);

  function submitFilters(event: FormEvent) {
    event.preventDefault();
    setAppliedFilters(filters);
  }

  async function openThreat(threat: ThreatRecord) {
    setSelected(threat);
    setNextStatus(threat.status);
    setResolutionNotes("");
    setDetailLoading(true);
    setDetailError(null);
    try {
      const detail = await api.get<ThreatRecord>(`/threats/${encodeURIComponent(threat.id)}`);
      setSelected(detail);
      setNextStatus(detail.status);
      setResolutionNotes("");
    } catch (requestError) {
      setDetailError(requestError instanceof Error ? requestError.message : "Threat detail could not be loaded.");
    } finally {
      setDetailLoading(false);
    }
  }

  async function updateStatus() {
    if (!selected || !nextStatus || nextStatus === selected.status) return;
    const needsResolutionNotes = ["RESOLVED", "FALSE_POSITIVE"].includes(nextStatus);
    if (needsResolutionNotes && !resolutionNotes.trim()) {
      setDetailError(`Analyst resolution notes are required before marking this threat ${humanize(nextStatus).toLowerCase()}.`);
      return;
    }
    setStatusBusy(true);
    setDetailError(null);
    try {
      const updated = await api.patch<ThreatRecord>(`/threats/${encodeURIComponent(selected.id)}/status`, {
        status: nextStatus,
        ...(resolutionNotes.trim() ? { resolution_notes: resolutionNotes.trim() } : {}),
      });
      setSelected(updated);
      setNextStatus(updated.status);
      setResolutionNotes("");
      await load(true);
    } catch (requestError) {
      setDetailError(requestError instanceof Error ? requestError.message : "Threat status could not be updated.");
    } finally {
      setStatusBusy(false);
    }
  }

  return (
    <section className="page soc-ops-page">
      <header className="soc-ops-hero">
        <div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Threat Center</h1><span>Prioritize, investigate and track real organization threat records.</span></div>
        <button type="button" className="secondary with-icon" disabled={refreshing} onClick={() => void load(true)}><RefreshCw className={refreshing ? "spin" : ""} size={16} /> Refresh</button>
      </header>

      <form className="soc-filterbar" onSubmit={submitFilters}>
        <label className="soc-search"><Search size={17} /><input value={filters.search} onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))} placeholder="Search threat code, title, device or process" /></label>
        <label><span>Severity</span><select value={filters.severity} onChange={(event) => setFilters((current) => ({ ...current, severity: event.target.value }))}><option value="">All severities</option>{severityOrder.map((item) => <option key={item}>{item}</option>)}</select></label>
        <label><span>Status</span><select value={filters.status} onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))}><option value="">All statuses</option>{threatStatuses.map((item) => <option key={item}>{item}</option>)}</select></label>
        <label><span>From</span><input type="date" value={filters.from} onChange={(event) => setFilters((current) => ({ ...current, from: event.target.value }))} /></label>
        <label><span>To</span><input type="date" value={filters.to} onChange={(event) => setFilters((current) => ({ ...current, to: event.target.value }))} /></label>
        <button className="primary" type="submit">Apply filters</button>
        <button className="secondary" type="button" onClick={() => { setFilters(initialFilters); setAppliedFilters(initialFilters); }}>Clear</button>
      </form>

      {error ? <ErrorBanner message={error} /> : null}
      {loading ? <LoadingState /> : (
        <>
          <div className="soc-metrics">
            <MetricCard label="Total threats" value={data?.total || 0} hint={`${threats.length} loaded for this view`} />
            <MetricCard label="Critical" value={severityCounts.CRITICAL} hint="Loaded records" accent="red" />
            <MetricCard label="Active" value={activeCount} hint="Not resolved, archived or dismissed" accent="amber" />
            <MetricCard label="Unassigned" value={unassignedCount} hint="No investigator assigned" accent="violet" />
            <MetricCard label="Average threat score" value={averageScore === null ? "—" : formatScore(averageScore)} hint="Calculated from loaded records" accent="green" />
          </div>

          {!threats.length ? <EmptyState title="No threats in this scope" message="The backend returned no threat records for the selected filters." /> : (
            <>
              <div className="soc-visual-grid">
                <article className="soc-panel soc-severity-panel">
                  <header><div><p>SEVERITY POSTURE</p><h2>Threats by severity</h2></div><ShieldAlert size={20} /></header>
                  <div className="soc-donut-row">
                    <div className="soc-donut" style={{ background: `conic-gradient(#ff4d64 0 ${criticalDegrees}deg,#ff9d37 ${criticalDegrees}deg ${criticalDegrees + highDegrees}deg,#ffd04d ${criticalDegrees + highDegrees}deg ${criticalDegrees + highDegrees + mediumDegrees}deg,#39d98a ${criticalDegrees + highDegrees + mediumDegrees}deg 360deg)` }}><span><strong>{loadedSeverityTotal}</strong>loaded</span></div>
                    <div className="soc-legend">{severityOrder.map((severity) => <div key={severity}><StatusBadge value={severity} /><strong>{severityCounts[severity]}</strong></div>)}</div>
                  </div>
                </article>
                <article className="soc-panel">
                  <header><div><p>DETECTION SOURCES</p><h2>Threat type distribution</h2></div><Target size={20} /></header>
                  <div className="soc-bars">{sourceCounts.length ? sourceCounts.map(([source, count]) => <div key={source}><span>{humanize(source)}</span><i><b style={{ width: `${Math.max(5, (count / threats.length) * 100)}%` }} /></i><strong>{count}</strong></div>) : <p className="soc-muted">No threat type data was returned.</p>}</div>
                </article>
                <article className="soc-panel">
                  <header><div><p>LIFECYCLE</p><h2>Investigation status</h2></div><Workflow size={20} /></header>
                  <div className="soc-pipeline">{threatStatuses.map((status) => { const count = threats.filter((item) => item.status === status).length; return <div key={status} className={count ? "active" : ""}><span>{humanize(status)}</span><strong>{count}</strong></div>; })}</div>
                </article>
              </div>

              <article className="soc-panel soc-table-panel">
                <header><div><p>LIVE THREAT QUEUE</p><h2>Backend threat records</h2></div><Activity size={20} /></header>
                <div className="table-wrap"><table className="soc-table"><thead><tr><th>Threat</th><th>Type / method</th><th>Severity</th><th>Score</th><th>Events</th><th>Status</th><th>Last detected</th><th>Action</th></tr></thead><tbody>{threats.map((item) => <tr key={item.id} onClick={() => void openThreat(item)}><td><strong>{item.threat_code}</strong><small>{item.title}</small></td><td>{humanize(item.threat_type)}<small>{humanize(item.detection_method)}</small></td><td><StatusBadge value={item.severity} /></td><td><div className="soc-score"><i><b style={{ width: `${Math.min(100, Math.max(0, item.threat_score))}%` }} /></i><strong>{item.threat_score}</strong></div></td><td>{item.event_count}<small>{item.affected_file_count} affected files</small></td><td><StatusBadge value={item.status} /></td><td>{formatDate(item.last_detected_at)}</td><td><button className="soc-review-button" type="button" onClick={(event) => { event.stopPropagation(); void openThreat(item); }} aria-label={`Review ${item.threat_code}`}>Review</button></td></tr>)}</tbody></table></div>
              </article>
            </>
          )}
        </>
      )}

      {selected ? <DetailDrawer eyebrow="NON-SENSITIVE THREAT RECORD" title={`${selected.threat_code} · ${selected.title}`} onClose={() => setSelected(null)}>
        {detailError ? <ErrorBanner message={detailError} /> : null}
        {detailLoading ? <LoadingState label="Loading complete threat record…" /> : <>
          <section className="soc-detail-summary"><StatusBadge value={selected.severity} /><StatusBadge value={selected.status} /><StatusBadge value={selected.classification} /><strong>{formatScore(selected.threat_score)} threat score</strong><span>{formatScore(selected.confidence_score, "%")} confidence</span></section>
          <section className="soc-detail-section"><h3>Executive summary</h3><p>{selected.description || "No analyst-safe description was returned for this threat."}</p><FactGrid facts={[
            { label: "Threat type", value: humanize(selected.threat_type) }, { label: "Category", value: humanize(selected.threat_category) }, { label: "Detection method", value: humanize(selected.detection_method) }, { label: "First detected", value: formatDate(selected.first_detected_at) }, { label: "Last detected", value: formatDate(selected.last_detected_at) }, { label: "Event count", value: String(selected.event_count) }, { label: "Affected files", value: String(selected.affected_file_count) }, { label: "Process", value: text(selected.process_name) }, { label: "Device", value: text(selected.device_name) }, { label: "Honeytoken evidence", value: selected.honeytoken_id ? "Linked" : "Not linked" }, { label: "Canary evidence", value: selected.canary_file_id ? "Linked" : "Not linked" },
          ]} /></section>
          <section className="soc-detail-section"><h3>Why this threat was produced</h3><div className="soc-signal-columns"><div><h4>Indicators</h4><FactGrid facts={safeFacts(selected.indicators)} /></div><div><h4>Risk factors</h4><FactGrid facts={safeFacts(selected.risk_factors)} /></div></div></section>
          <section className="soc-detail-section"><h3>Evidence summary</h3><FactGrid facts={safeFacts(selected.evidence_summary)} />{selected.file_events?.length ? <ol className="soc-timeline">{selected.file_events.map((event, index) => <li key={`${event.created_at}-${index}`}><time>{formatDate(event.created_at)}</time><strong>{humanize(event.relation_type)}</strong><span>Correlated file event</span></li>)}</ol> : null}</section>
          <section className="soc-detail-section"><h3>Recommended response</h3><div className="soc-signal-columns"><div><h4>Recommended actions</h4><FactGrid facts={safeFacts(selected.recommended_actions)} /></div><div><h4>Containment record</h4><FactGrid facts={safeFacts(selected.containment_actions)} /></div></div>{selected.resolution_notes ? <p>{selected.resolution_notes}</p> : null}</section>
          <section className="soc-detail-section"><h3>Lifecycle action</h3><p className="soc-muted">Only backend-approved transitions are offered. Every change is recorded against the authenticated analyst.</p><div className="soc-inline-action"><select value={nextStatus} onChange={(event) => { setNextStatus(event.target.value); setResolutionNotes(""); }}><option value={selected.status}>{selected.status} (current)</option>{(allowedThreatTransitions[selected.status] || []).map((status) => <option key={status}>{status}</option>)}</select><button type="button" className="primary" disabled={statusBusy || nextStatus === selected.status} onClick={() => void updateStatus()}>{statusBusy ? "Updating…" : "Update status"}</button></div>{["RESOLVED", "FALSE_POSITIVE"].includes(nextStatus) ? <label className="soc-transition-field"><span>Analyst resolution notes *</span><textarea className="soc-transition-summary" value={resolutionNotes} onChange={(event) => setResolutionNotes(event.target.value)} placeholder="Record the verified facts supporting this resolution. Do not include credentials or secrets." rows={4} /></label> : null}{selected.status === "ARCHIVED" ? <p className="soc-muted">Archived threats are terminal and cannot be moved to another status.</p> : null}</section>
        </>}
      </DetailDrawer> : null}
    </section>
  );
}
