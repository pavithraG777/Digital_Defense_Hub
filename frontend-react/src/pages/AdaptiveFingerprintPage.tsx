import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, Clock3, Fingerprint, Laptop, Network, RefreshCw, Terminal, UserRound } from "lucide-react";
import { api } from "../lib/api";
import "./adaptiveFingerprint.css";

type InteractionFingerprint = {
  id: string;
  fingerprint_hash: string;
  fingerprint_version: string;
  event_type: string;
  device_identifier?: string;
  device_name?: string;
  operating_system?: string;
  operating_system_user?: string;
  process_name?: string;
  process_path?: string;
  process_id?: number;
  parent_process_name?: string;
  source_ip?: string;
  interaction_pattern?: Record<string, unknown>;
  behavioural_score: number;
  confidence_score: number;
  is_suspicious: boolean;
  ransomware_suspected: boolean;
  occurrence_count: number;
  first_observed_at: string;
  last_observed_at: string;
};

type FingerprintPage = { items: InteractionFingerprint[]; total: number };

const value = (input?: string | number) => input === undefined || input === null || input === "" ? "Not reported" : String(input);
const isSimulation = (item: InteractionFingerprint) => JSON.stringify(item).toLowerCase().includes("simulation");

export function AdaptiveFingerprintPage() {
  const [records, setRecords] = useState<InteractionFingerprint[]>([]);
  const [selected, setSelected] = useState<InteractionFingerprint | null>(null);
  const [includeSimulations, setIncludeSimulations] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true); setError("");
    try {
      const result = await api.get<FingerprintPage>("/adaptive-deception/fingerprints?page=1&page_size=100");
      setRecords(result.items || []);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load interaction fingerprints.");
    } finally { setLoading(false); }
  };

  useEffect(() => { void load(); }, []);
  const visible = useMemo(() => records.filter((item) => includeSimulations || !isSimulation(item)), [records, includeSimulations]);
  const suspicious = visible.filter((item) => item.is_suspicious).length;
  const repeated = visible.filter((item) => item.occurrence_count > 1).length;

  return <div className="fingerprint-page">
    <section className="fingerprint-hero">
      <div><span className="eyebrow">ADAPTIVE DECEPTION</span><h1>Interaction Fingerprints</h1><p>A fingerprint is a repeatable digital behaviour pattern—not a physical fingerprint. It links who or what touched a honeytoken or canary using device, network, process and action evidence.</p></div>
      <button onClick={() => void load()} disabled={loading}><RefreshCw size={17}/>{loading ? "Loading…" : "Refresh"}</button>
    </section>

    {error && <div className="fingerprint-error"><AlertTriangle size={18}/>{error}</div>}
    <section className="fingerprint-stats">
      <article><Fingerprint/><span>Unique patterns</span><strong>{visible.length}</strong></article>
      <article><AlertTriangle/><span>Suspicious patterns</span><strong>{suspicious}</strong></article>
      <article><Activity/><span>Repeated behaviour</span><strong>{repeated}</strong></article>
      <label><input type="checkbox" checked={includeSimulations} onChange={(event) => setIncludeSimulations(event.target.checked)}/><span>Include simulation/test records</span></label>
    </section>

    <section className="fingerprint-content">
      <div className="fingerprint-list">
        <div className="fingerprint-heading"><div><span className="eyebrow">DETECTED ACTORS</span><h2>Canary and honeytoken interactions</h2></div><small>{visible.length} real records</small></div>
        {!loading && visible.length === 0 ? <div className="fingerprint-empty"><Fingerprint/><h3>No real interaction fingerprint yet</h3><p>Test/simulation records are hidden. A record appears when a monitored deception resource is accessed.</p></div> : visible.map((item) => <button key={item.id} className={selected?.id === item.id ? "selected" : ""} onClick={() => setSelected(item)}>
          <span className={`fingerprint-risk ${item.ransomware_suspected ? "danger" : item.is_suspicious ? "warning" : "safe"}`}>{Math.round(item.behavioural_score)}</span>
          <span className="fingerprint-primary"><strong>{value(item.device_name || item.device_identifier)}</strong><small>{value(item.operating_system_user)} · {item.event_type || "INTERACTION"}</small><code>{item.fingerprint_hash.slice(0, 16)}…</code></span>
          <span><b>{item.occurrence_count}×</b><small>Occurrences</small></span>
          <span><b>{new Date(item.last_observed_at).toLocaleDateString()}</b><small>{new Date(item.last_observed_at).toLocaleTimeString()}</small></span>
        </button>)}
      </div>

      <aside className="fingerprint-detail">
        {!selected ? <div className="fingerprint-empty"><Fingerprint/><h3>Select a fingerprint</h3><p>Open a pattern to see attributable device, user, IP, process and timing evidence.</p></div> : <>
          <div className="detail-title"><span className={`status ${selected.ransomware_suspected ? "danger" : "warning"}`}>{selected.ransomware_suspected ? "RANSOMWARE CORRELATION" : selected.is_suspicious ? "SUSPICIOUS INTERACTION" : "OBSERVED"}</span><h2>{value(selected.device_name || selected.device_identifier)}</h2><p>Confidence {Math.round(selected.confidence_score)}% · observed {selected.occurrence_count} time(s)</p></div>
          <div className="evidence-grid">
            <article><Laptop/><span>Device and OS</span><b>{value(selected.device_identifier)}</b><small>{value(selected.operating_system)}</small></article>
            <article><UserRound/><span>Operating-system user</span><b>{value(selected.operating_system_user)}</b></article>
            <article><Network/><span>Source network</span><b>{value(selected.source_ip)}</b></article>
            <article><Terminal/><span>Process</span><b>{value(selected.process_name)}</b><small>PID {value(selected.process_id)} · parent {value(selected.parent_process_name)}</small></article>
            <article><Activity/><span>Observed action</span><b>{value(selected.event_type)}</b><small>{value(selected.process_path)}</small></article>
            <article><Clock3/><span>Observation window</span><b>{new Date(selected.first_observed_at).toLocaleString()}</b><small>Last: {new Date(selected.last_observed_at).toLocaleString()}</small></article>
          </div>
          <div className="pattern-hash"><span>Stable interaction fingerprint</span><code>{selected.fingerprint_hash}</code><small>Same device + user + process + action pattern is correlated into this identity; timestamps are not used to create a new identity.</small></div>
        </>}
      </aside>
    </section>
  </div>;
}
