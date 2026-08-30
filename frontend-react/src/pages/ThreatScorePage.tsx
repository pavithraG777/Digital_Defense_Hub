import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Database,
  RefreshCw,
  ShieldAlert,
  Target,
  TrendingUp,
} from "lucide-react";
import { Link } from "react-router-dom";
import { securityScores } from "../lib/securityScores";
import type { ThreatScoreData } from "../lib/securityScores";
import "./ThreatScorePage.css";

const display = (value: string) => value.replaceAll("_", " ").toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase());
const localDate = (value?: string) => value ? new Date(value).toLocaleString() : "No signal recorded";

export function ThreatScorePage() {
  const [data, setData] = useState<ThreatScoreData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setData(await securityScores.threats());
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load the threat score.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  if (loading && !data) return <ThreatState label="Calculating from security records…" spinning />;
  if (!data) return <ThreatState label={error || "No threat score is available."} retry={() => void load()} />;

  const score = data.risk.risk_score;
  const level = data.risk.risk_level.toLowerCase();

  return <section className="page threat-score-page">
    <header className="threat-score-heading">
      <div>
        <span className="eyebrow">REAL-TIME SECURITY POSTURE</span>
        <h1>Threat Score</h1>
        <p>Organization-level risk calculation. Use Threat Center to investigate and resolve individual threat records.</p>
      </div>
      <button type="button" className="secondary with-icon" onClick={() => void load()} disabled={loading}>
        <RefreshCw size={16} className={loading ? "spin" : ""} /> {loading ? "Refreshing…" : "Refresh"}
      </button>
    </header>

    {error && <div className="alert alert-error"><AlertTriangle size={17} />{error}</div>}

    <div className="threat-score-overview">
      <article className={`threat-score-primary level-${level}`}>
        <div className="threat-score-ring" style={{ background: score == null ? undefined : `conic-gradient(var(--score-color) ${score * 3.6}deg, rgba(83,120,154,.16) 0deg)` }}>
          <div><strong>{score == null ? "—" : score.toFixed(1)}</strong><span>/ 100</span></div>
        </div>
        <div>
          <span className="eyebrow">ORGANIZATION RISK</span>
          <h2>{data.risk.organization.name}</h2>
          <div className={`threat-level level-${level}`}>{display(data.risk.risk_level)}</div>
          <p>{data.risk.data_available ? `Calculated from ${data.risk.factors.filter((factor) => factor.available).length} available evidence sources.` : "No scored security record is available; the system does not fabricate a risk value."}</p>
          <small>Last signal: {localDate(data.risk.last_signal_at)}</small>
        </div>
      </article>

      <Metric icon={<ShieldAlert />} label="Threat input" value={data.inventory.open} note="Open records influencing exposure" />
      <Metric icon={<Activity />} label="Open incidents" value={data.risk.source_counts.open_incidents} note={`${data.risk.source_counts.total_incidents} total records`} />
      <Metric icon={<TrendingUp />} label="Behavior detections" value={data.risk.source_counts.recent_behavior_detections} note={`Previous ${data.methodology.behavior_window_days} days`} />
      <Metric icon={<Target />} label="Occurrences" value={data.inventory.total_occurrences} note={`${data.inventory.affected_device_count} affected devices`} />
    </div>

    <div className="threat-score-grid">
      <article className="threat-score-card factor-card">
        <CardTitle icon={<Database size={17} />} title="Why the score is high or low" note="Each available data source contributes a weighted share." />
        <div className="factor-list">
          {data.risk.factors.map((factor) => <div className={`factor-row ${factor.available ? "" : "unavailable"}`} key={factor.code}>
            <div className="factor-row-heading"><strong>{factor.label}</strong><span>{factor.score == null ? "Not available" : `${factor.score.toFixed(1)} / 100`}</span></div>
            <div className="factor-track"><span style={{ width: `${factor.score || 0}%` }} /></div>
            <div className="factor-meta"><span>{factor.record_count} record(s)</span><span>{factor.available ? `${Math.round(factor.effective_weight * 100)}% effective weight` : "Excluded from score"}</span></div>
            <p>{factor.explanation}</p>
          </div>)}
        </div>
      </article>

      <article className="threat-score-card severity-card">
        <CardTitle icon={<BarChart3 size={17} />} title="What this score means" note="Organization posture summary — not an investigation queue." />
        <div className="score-context">
          <p><strong>Current risk:</strong> <span className={`threat-level level-${level}`}>{display(data.risk.risk_level)}</span></p>
          <p><strong>Evidence used:</strong> {data.risk.factors.filter((factor) => factor.available).length} of {data.risk.factors.length} configured sources are available.</p>
          <p><strong>Scoring model:</strong> {data.methodology.version}</p>
          <p>Resolve underlying threats or incidents in their workspaces; the organization score recalculates from the stored results.</p>
        </div>
      </article>
    </div>

    <article className="threat-score-card trend-card">
      <CardTitle icon={<TrendingUp size={17} />} title="30-day threat trend" note="Daily detections based on last detected timestamps." />
      <ThreatTrend values={data.trend} />
    </article>

    <article className="threat-score-card score-actions-card">
      <CardTitle icon={<ShieldAlert size={17} />} title="What to do next" note="Resolve the underlying records; this score recalculates from stored evidence." />
      <p>Use Threat Center for triage, containment evidence and lifecycle updates. Use Incident Response when a threat has escalated into an incident.</p>
      <div><Link to="/threats">Open Threat Center</Link><Link to="/incidents">Open Incident Response</Link></div>
    </article>

    <details className="threat-methodology">
      <summary>How this score is calculated</summary>
      <div><strong>Version</strong><span>{data.methodology.version}</span></div>
      <div><strong>Formula</strong><span>{data.methodology.formula}</span></div>
      <div><strong>Missing data</strong><span>{data.methodology.missing_data_policy}</span></div>
      <div><strong>Calculated</strong><span>{localDate(data.calculated_at)}</span></div>
    </details>
  </section>;
}

function ThreatState({ label, spinning, retry }: { label: string; spinning?: boolean; retry?: () => void }) {
  return <section className="page threat-score-page"><div className="threat-score-state"><ShieldAlert size={30} /><h2>{label}</h2>{retry && <button type="button" className="primary" onClick={retry}>Try again</button>}{spinning && <RefreshCw className="spin" />}</div></section>;
}

function Metric({ icon, label, value, note }: { icon: React.ReactNode; label: string; value: number; note: string }) {
  return <article className="threat-score-metric"><div className="metric-icon">{icon}</div><div><span>{label}</span><strong>{value.toLocaleString()}</strong><small>{note}</small></div></article>;
}

function CardTitle({ icon, title, note }: { icon: React.ReactNode; title: string; note: string }) {
  return <header className="threat-card-title"><div>{icon}<h2>{title}</h2></div><span>{note}</span></header>;
}

function ThreatTrend({ values }: { values: ThreatScoreData["trend"] }) {
  const points = useMemo(() => {
    const max = Math.max(1, ...values.map((item) => item.detected));
    return values.map((item, index) => `${values.length < 2 ? 0 : index / (values.length - 1) * 600},${120 - item.detected / max * 100}`).join(" ");
  }, [values]);
  const total = values.reduce((sum, value) => sum + value.detected, 0);
  return <div className="threat-trend"><div className="trend-summary"><strong>{total}</strong><span>detections in displayed window</span></div><svg viewBox="0 0 600 130" role="img" aria-label="Threat detections over the previous 30 days"><line x1="0" y1="120" x2="600" y2="120"/><line x1="0" y1="70" x2="600" y2="70"/><line x1="0" y1="20" x2="600" y2="20"/><polyline points={points}/></svg><div className="trend-dates"><span>{values[0]?.date || ""}</span><span>{values[values.length - 1]?.date || ""}</span></div></div>;
}
