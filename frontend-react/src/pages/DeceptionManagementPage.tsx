import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { AlertTriangle, Check, Copy, Eye, EyeOff, FileCheck2, KeyRound, Plus, RefreshCw, Rocket, Search, Upload, X } from "lucide-react";
import { api } from "../lib/api";

type Kind = "honeytoken" | "canary";
type Row = Record<string, unknown>;
type EventRow = Row & { id: string; source_type: string; occurred_at: string };
type InvestigationContext = { trigger_aggregate?: Row; threats?: Row[]; incidents?: Row[]; investigation_cases?: Row[] };

const tokenTypes = ["USERNAME", "PASSWORD", "EMAIL_ADDRESS", "API_KEY", "ACCESS_TOKEN", "DATABASE_RECORD", "CLOUD_CREDENTIAL", "SSH_KEY", "DOCUMENT_DATA", "URL", "CUSTOM"];
const canaryTypes = ["DOCUMENT", "SPREADSHEET", "PDF", "IMAGE", "ARCHIVE", "DATABASE_BACKUP", "CONFIGURATION", "SOURCE_CODE", "CREDENTIAL_FILE", "CUSTOM"];
const classifications = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "CRITICAL"];
const honeytokenStatuses = ["DRAFT", "ACTIVE", "TRIGGERED", "INACTIVE", "EXPIRED", "REVOKED", "ARCHIVED"];
const canaryStatuses = ["DRAFT", "DEPLOYED", "ACTIVE", "TRIGGERED", "TAMPERED", "MISSING", "INACTIVE", "EXPIRED", "ARCHIVED"];
const canaryExtensions: Record<string, string> = {
  DOCUMENT: ".txt",
  SPREADSHEET: ".csv",
  PDF: ".pdf",
  IMAGE: ".png",
  ARCHIVE: ".zip",
  DATABASE_BACKUP: ".sql",
  CONFIGURATION: ".ini",
  SOURCE_CODE: ".go",
  CREDENTIAL_FILE: ".txt",
  CUSTOM: ".txt",
};
const maxCanaryUploadBytes = 10 * 1024 * 1024;
const acceptedCanaryUploadTypes = ".txt,.docx,.csv,.xlsx,.pdf,.png,.jpg,.jpeg,.webp,.zip,.sql,.ini,.conf,.cfg,.yaml,.yml,.env,.json,.log,.go,.py,.js,.ts,.java,.c,.cpp,.h,.cs";

const str = (value: unknown) => value == null || value === "" ? "Not available" : String(value);
const date = (value: unknown) => value ? new Date(String(value)).toLocaleString() : "Never";
const idOf = (row: Row) => String(row.id || "");
const labelOf = (row: Row, kind: Kind) => str(kind === "honeytoken" ? row.honeytoken_name : row.file_name);
const fileSize = (value: number) => value < 1024 * 1024 ? `${(value / 1024).toFixed(1)} KB` : `${(value / (1024 * 1024)).toFixed(2)} MB`;

function browserAudioContext() {
  const AudioContextCtor = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  return AudioContextCtor ? new AudioContextCtor() : null;
}

async function playHoneytokenAlert(context: AudioContext | null, tokenName: string) {
  if (!context) return false;
  if (context.state !== "running") await context.resume().catch(() => undefined);
  if (context.state !== "running") return false;
  const now = context.currentTime;
  const gain = context.createGain();
  gain.gain.setValueAtTime(.0001, now);
  gain.gain.exponentialRampToValueAtTime(.32, now + .015);
  gain.gain.setValueAtTime(.32, now + .68);
  gain.gain.exponentialRampToValueAtTime(.0001, now + .82);
  gain.connect(context.destination);
  [880, 1175, 880].forEach((frequency, index) => {
    const oscillator = context.createOscillator();
    oscillator.type = "square";
    oscillator.frequency.value = frequency;
    oscillator.connect(gain);
    oscillator.start(now + index * .25);
    oscillator.stop(now + index * .25 + .18);
  });
  if ("Notification" in window && Notification.permission === "granted") {
    new Notification("Deception alert triggered", { body: `${tokenName} recorded a new security event.` });
  }
  return true;
}

type DetailField = { key: string; label: string };
type DetailSection = { title: string; fields: DetailField[] };

const honeytokenDetailSections: DetailSection[] = [
  { title: "Identity and classification", fields: [
    { key: "id", label: "Record ID" }, { key: "honeytoken_code", label: "Honeytoken code" },
    { key: "honeytoken_name", label: "Name" }, { key: "honeytoken_type", label: "Type" },
    { key: "classification", label: "Classification" }, { key: "status", label: "Lifecycle status" },
    { key: "description", label: "Description" },
  ] },
  { title: "Decoy placement", fields: [
    { key: "target_system", label: "Target system" }, { key: "decoy_username", label: "Decoy username" },
    { key: "decoy_email", label: "Decoy email" }, { key: "value_prefix", label: "Safe value prefix" },
    { key: "deployment_configured", label: "Deployment configured" },
  ] },
  { title: "Ownership and tenant context", fields: [
    { key: "organization_id", label: "Organization ID" }, { key: "department_id", label: "Department ID" },
    { key: "policy_id", label: "Policy ID" }, { key: "owner_user_id", label: "Owner user ID" },
    { key: "created_by", label: "Created by" },
  ] },
  { title: "Activity and lifecycle", fields: [
    { key: "access_count", label: "Access count" }, { key: "last_triggered_at", label: "Last triggered" },
    { key: "deployed_at", label: "Deployed" }, { key: "expires_at", label: "Expires" },
    { key: "created_at", label: "Created" }, { key: "updated_at", label: "Last updated" },
  ] },
];

const canaryDetailSections: DetailSection[] = [
  { title: "File identity", fields: [
    { key: "id", label: "Record ID" }, { key: "canary_code", label: "Canary code" },
    { key: "file_name", label: "File name" }, { key: "file_extension", label: "Extension" },
    { key: "mime_type", label: "MIME type" }, { key: "canary_type", label: "Canary type" },
    { key: "status", label: "Lifecycle status" }, { key: "description", label: "Description" },
  ] },
  { title: "Integrity and linked deception", fields: [
    { key: "original_file_hash", label: "Original file hash" }, { key: "hash_algorithm", label: "Hash algorithm" },
    { key: "file_size_bytes", label: "File size" }, { key: "contains_honeytoken", label: "Contains Honeytoken" },
    { key: "honeytoken_id", label: "Embedded Honeytoken ID" },
  ] },
  { title: "Deployment and ownership", fields: [
    { key: "deployed_file_path", label: "Monitored Canary path" },
    { key: "deployed_device_name", label: "Deployed device" },
    { key: "deployed_device_identifier", label: "Device identifier" },
    { key: "organization_id", label: "Organization ID" }, { key: "department_id", label: "Department ID" },
    { key: "policy_id", label: "Policy ID" }, { key: "owner_user_id", label: "Owner user ID" },
  ] },
  { title: "Activity and lifecycle", fields: [
    { key: "access_count", label: "Access count" }, { key: "last_triggered_at", label: "Last triggered" },
    { key: "deployed_at", label: "Deployed" }, { key: "expires_at", label: "Expires" },
    { key: "created_at", label: "Created" }, { key: "updated_at", label: "Last updated" },
  ] },
];

const honeytokenCreationFields: DetailField[] = [
  { key: "id", label: "Record ID" }, { key: "honeytoken_code", label: "Honeytoken code" },
  { key: "honeytoken_name", label: "Name" }, { key: "honeytoken_type", label: "Type" },
  { key: "value_prefix", label: "Safe value prefix" }, { key: "classification", label: "Classification" },
  { key: "status", label: "Lifecycle status" }, { key: "expires_at", label: "Expires" },
  { key: "created_at", label: "Created" },
];

const canaryCreationFields: DetailField[] = [
  { key: "id", label: "Record ID" }, { key: "canary_code", label: "Canary code" },
  { key: "file_name", label: "File name" }, { key: "file_extension", label: "Extension" },
  { key: "mime_type", label: "MIME type" }, { key: "canary_type", label: "Canary type" },
  { key: "hash_algorithm", label: "Hash algorithm" }, { key: "file_size_bytes", label: "File size" },
  { key: "contains_honeytoken", label: "Contains Honeytoken" }, { key: "honeytoken_id", label: "Embedded Honeytoken ID" },
  { key: "status", label: "Lifecycle status" }, { key: "created_at", label: "Created" },
];

function detailValue(key: string, value: unknown) {
  if (value == null || value === "") return "Not available";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (key === "file_size_bytes") return fileSize(Number(value));
  if (key.endsWith("_at")) return date(value);
  return str(value);
}

export function DeceptionManagementPage({ kind }: { kind: Kind }) {
  const isToken = kind === "honeytoken";
  const [rows, setRows] = useState<Row[]>([]);
  const [total, setTotal] = useState(0);
  const [availableTokens, setAvailableTokens] = useState<Row[]>([]);
  const [relatedEvents, setRelatedEvents] = useState<EventRow[]>([]);
  const [investigation, setInvestigation] = useState<InvestigationContext | null>(null);
  const [canaryHealth, setCanaryHealth] = useState<Row | null>(null);
  const [healthBusy, setHealthBusy] = useState(false);
  const [rotationBusy, setRotationBusy] = useState(false);
  const [lifecycleBusy, setLifecycleBusy] = useState(false);
  const [selected, setSelected] = useState<Row | null>(null);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [deploying, setDeploying] = useState<Row | null>(null);
  const [demoValue, setDemoValue] = useState("");
  const [demoVisible, setDemoVisible] = useState(false);
  const [demoBusy, setDemoBusy] = useState(false);
  const [demoResult, setDemoResult] = useState("");
  const [demoAudio, setDemoAudio] = useState<AudioContext | null>(null);
  const [soundReady, setSoundReady] = useState(false);

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setError("");
    try {
      const listPath = isToken ? "/honeytokens?page=1&limit=100" : "/canary-files?page=1&page_size=100";
      const inventory = await api.get<Row>(listPath);
      const values = (isToken ? inventory.honeytokens : inventory.items) as Row[] || [];
      setRows(Array.from(new Map(values.map((row) => [idOf(row), row])).values()));
      setTotal(Number(inventory.total ?? values.length));
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to load deception records."); }
    finally { if (!silent) setLoading(false); }
  }, [isToken]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (isToken) return;
    const timer = window.setInterval(() => {
      if (!createOpen && !deploying) void load(true);
    }, 4000);
    return () => window.clearInterval(timer);
  }, [createOpen, deploying, isToken, load]);
  useEffect(() => {
    if (isToken) { setAvailableTokens([]); return; }
    void api.get<Row>("/honeytokens?page=1&limit=100")
      .then((result) => setAvailableTokens((result.honeytokens as Row[]) || []))
      .catch(() => setAvailableTokens([]));
  }, [isToken]);
  useEffect(() => {
    if (isToken || !selected?.deployed_at) return;
    const entityID = idOf(selected);
    const timer = window.setInterval(() => {
      void api.get<Row>(`/file-events?canary_file_id=${entityID}&source_type=CANARY_FILE&page=1&page_size=100`)
        .then(async history => {
          const incoming = (history.items as EventRow[]) || [];
          const known = new Set(relatedEvents.map(event => event.id));
          if (incoming.some(event => !known.has(event.id)) && soundReady) {
            await playHoneytokenAlert(demoAudio, `Canary file ${labelOf(selected, kind)}`);
          }
          setRelatedEvents(incoming);
        })
        .catch(() => undefined);
    }, 4000);
    return () => window.clearInterval(timer);
  }, [demoAudio, isToken, kind, relatedEvents, selected, soundReady]);

  const filtered = useMemo(() => rows.filter((row) => {
    const haystack = Object.values(row).map(str).join(" ").toLowerCase();
    return (!query || haystack.includes(query.toLowerCase())) && (!status || str(row.status) === status);
  }), [rows, query, status]);
  const triggered = rows.filter((row) => Number(row.access_count || 0) > 0 || str(row.status) === "TRIGGERED").length;
  const active = rows.filter((row) => ["ACTIVE", "DEPLOYED"].includes(str(row.status))).length;

  async function inspect(row: Row) {
    setDemoValue("");
    setDemoVisible(false);
    setDemoResult("");
    try {
      const entityID = idOf(row);
      const entityFilter = isToken ? "honeytoken_id" : "canary_file_id";
      const authoritativeSource = isToken ? "HONEYTOKEN" : "CANARY_FILE";
      const [detail, history, investigationContext, health] = await Promise.all([
        api.get<Row>(`${isToken ? "/honeytokens" : "/canary-files"}/${entityID}`),
        api.get<Row>(`/file-events?${entityFilter}=${entityID}&source_type=${authoritativeSource}&page=1&page_size=100`),
        api.get<InvestigationContext>(`${isToken ? "/honeytokens" : "/canary-files"}/${entityID}/investigation`),
        isToken ? Promise.resolve(null) : api.get<Row>(`/adaptive-deception/canaries/${entityID}/health`).catch(()=>null),
      ]);
      setSelected(detail);
      setRelatedEvents((history.items as EventRow[]) || []);
      setInvestigation(investigationContext);
      setCanaryHealth(health);
    }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to load details."); }
  }

  async function checkCanaryHealth() {
    if (!selected || isToken) return;
    setHealthBusy(true);
    try { const health=await api.post<Row>(`/adaptive-deception/canaries/${idOf(selected)}/health-check`,{check_type:"MANUAL"}); setCanaryHealth(current=>({...current,...health})); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Canary health check failed."); }
    finally { setHealthBusy(false); }
  }

  async function rotateCanary() {
    if (!selected || isToken || !window.confirm(`Rotate ${labelOf(selected,kind)}? The current canary is preserved as rotation evidence.`)) return;
    setRotationBusy(true);
    try { await api.post<Row>(`/adaptive-deception/canaries/${idOf(selected)}/rotate`,{rotation_reason:"MANUAL_UI_ROTATION",rotation_strategy:"MANUAL"}); setSelected(null); await load(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Canary rotation failed."); }
    finally { setRotationBusy(false); }
  }

  async function deactivate() {
    if (!selected || !window.confirm(`Deactivate ${labelOf(selected, kind)}? Monitoring will stop, but all existing evidence is retained.`)) return;
    setLifecycleBusy(true);
    try {
      const updated = await api.patch<Row>(`${isToken ? "/honeytokens" : "/canary-files"}/${idOf(selected)}/status`, { status: "INACTIVE" });
      setSelected(updated);
      await load(true);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to deactivate this record."); }
    finally { setLifecycleBusy(false); }
  }

  async function simulateHoneytokenTrigger(event: FormEvent) {
    event.preventDefault();
    if (!selected || !isToken || !demoValue.trim()) return;
    const audioContext = demoAudio || browserAudioContext();
    if (audioContext && !demoAudio) setDemoAudio(audioContext);
    await audioContext?.resume().catch(() => undefined);
    setDemoBusy(true);
    setDemoResult("");
    setError("");
    try {
      const result = await api.post<Row>(`/honeytokens/${idOf(selected)}/validate`, { observed_value: demoValue });
      if (result.valid === true && result.triggered === true) {
        const sounded = await playHoneytokenAlert(audioContext, labelOf(selected, kind));
        window.dispatchEvent(new CustomEvent("ddh:deception-alert", { detail: {
          id: `honeytoken-${idOf(selected)}-${Date.now()}`,
          source_type: "HONEYTOKEN",
          event_type: "HONEYTOKEN_TRIGGERED",
          file_name: labelOf(selected, kind),
          device_name: str(selected.target_system || "Authorized browser demo"),
          severity: "CRITICAL",
        } }));
        setSoundReady(sounded);
        setDemoResult(`Trigger recorded successfully. Access count is now ${Number(result.access_count || 0)}.${sounded ? " Alert sound played." : " Browser audio is blocked; click Test sound first."}`);
        setDemoValue("");
        const detail = await api.get<Row>(`/honeytokens/${idOf(selected)}`);
        setSelected(detail);
        await load(true);
      } else {
        setDemoResult("The observed value did not match this Honeytoken. No trigger was recorded.");
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Honeytoken demo trigger failed.");
    } finally {
      setDemoBusy(false);
    }
  }

  async function testHoneytokenSound() {
    const context = demoAudio || browserAudioContext();
    if (context && !demoAudio) setDemoAudio(context);
    const played = await playHoneytokenAlert(context, isToken ? "Honeytoken sound test" : "Canary file sound test");
    setSoundReady(played);
    setDemoResult(played
      ? `Sound is enabled. The same alarm will play after ${isToken ? "a successful trigger" : "a new Canary filesystem event"}.`
      : "Browser audio is blocked or no audio output device is available.");
  }

  const selectedEvents = selected ? relatedEvents : [];
  const statusOptions = isToken ? honeytokenStatuses : canaryStatuses;
  const detailSections = isToken ? honeytokenDetailSections : canaryDetailSections;
  return <section className="page deception-page">
    <header className="deception-header"><div><span className="eyebrow">DECEPTION DEFENSE</span><h1>{isToken ? "Honeytoken Management" : "Canary File Management"}</h1><p>{isToken ? "Create, deploy and investigate decoy credentials and tokens." : "Create and monitor decoy files used for ransomware and unauthorized-access detection."}</p></div><div className="deception-actions"><button className="secondary with-icon" onClick={() => void load()}><RefreshCw size={16}/>Refresh</button><button className="primary with-icon" onClick={() => setCreateOpen(true)}><Plus size={17}/>Create {isToken ? "Honeytoken" : "Canary File"}</button></div></header>
    {error && <div className="alert alert-error"><AlertTriangle size={17}/>{error}</div>}
    <div className="deception-scope-guide" aria-label={`${isToken ? "Honeytoken" : "Canary file"} operating model`}>
      {isToken ? <>
        <KeyRound size={20}/>
        <div><strong>Honeytoken = a decoy value, not a file</strong><span><b>Target system</b> is the real logical service where the decoy will appear, such as Payroll API, Finance Vault or a decoy database record. Create generates the value; an authorized operator must place it there, then use <b>Deploy and arm</b> to record that placement.</span></div>
      </> : <>
        <FileCheck2 size={20}/>
        <div><strong>Canary File = a dot-prefixed monitored copy</strong><span>By default, create or import deploys a sibling-style copy such as report.pdf → .report.pdf into the approved CanaryAlerts folder and arms monitoring. The original selected file is never monitored or modified.</span></div>
      </>}
    </div>
    <div className="deception-kpis"><Kpi label={`Total ${isToken ? "Honeytokens" : "Canary Files"}`} value={total}/><Kpi label="Loaded active / deployed" value={active}/><Kpi label="Loaded triggered" value={triggered}/><Kpi label="Loaded never triggered" value={Math.max(rows.length-triggered,0)}/></div>
    <article className="deception-inventory">
      <div className="inventory-toolbar"><div><span className="eyebrow">LIVE BACKEND INVENTORY</span><h2>{isToken ? "Honeytokens" : "Canary Files"}</h2><small>{rows.length} of {total} backend records loaded</small></div><label className="inventory-search"><Search size={16}/><input value={query} onChange={(e)=>setQuery(e.target.value)} placeholder={`Search ${isToken ? "name, type, target system or code" : "file, type, deployed device or code"}`}/></label><select aria-label={`Filter ${isToken ? "Honeytokens" : "Canary Files"} by lifecycle status`} value={status} onChange={(e)=>setStatus(e.target.value)}><option value="">All loaded statuses</option>{statusOptions.map(v=><option key={v}>{v}</option>)}</select></div>
      {loading ? <div className="empty-inline">Loading real backend records…</div> : <div className="table-wrap"><table className="table deception-table"><thead><tr><th>Name</th><th>Type</th><th>{isToken ? "Target system" : "Deployed device"}</th><th>Status</th><th>Accesses</th><th>Last trigger</th><th>Created</th><th/></tr></thead><tbody>{filtered.map(row=>{const isCanaryDeployed=!isToken&&Boolean(row.deployed_at);return <tr key={idOf(row)} onClick={()=>void inspect(row)}><td><strong>{labelOf(row,kind)}</strong><small>{str(isToken?row.honeytoken_code:row.canary_code)}</small></td><td>{str(isToken?row.honeytoken_type:row.canary_type)}</td><td>{isToken ? str(row.target_system) : (isCanaryDeployed ? str(row.deployed_device_name||row.deployed_device_identifier||"This PC") : "Not deployed")}</td><td><span className={`status-chip status-${str(row.status).toLowerCase()}`}>{str(row.status)}</span></td><td>{Number(row.access_count||0)}</td><td>{date(row.last_triggered_at)}</td><td>{date(row.created_at)}</td><td><button className="icon-button" aria-label="View details"><Eye size={16}/></button></td></tr>})}</tbody></table>{!filtered.length&&<div className="empty-inline">No matching backend records.</div>}</div>}
    </article>
    {selected && ["ACTIVE","TRIGGERED","TAMPERED","MISSING"].includes(str(selected.status)) && <button type="button" className="deception-lifecycle-control" disabled={lifecycleBusy} onClick={()=>void deactivate()}>{lifecycleBusy ? "Deactivating…" : "Deactivate monitoring"}</button>}
    {selected && (isToken ? ["ACTIVE","TRIGGERED"].includes(str(selected.status)) : Boolean(selected.deployed_at)) && <button type="button" className={`secondary honeytoken-sound-test${soundReady ? " sound-ready" : ""}`} onClick={()=>void testHoneytokenSound()}>{soundReady ? "Sound ready" : "Test alert sound"}</button>}
    {selected && <><button className="drawer-backdrop" aria-label="Close secured record" onClick={()=>{setSelected(null);setInvestigation(null);}}/><aside className="deception-drawer"><div className="drawer-heading"><div><span className="eyebrow">SECURED RECORD</span><h2>{labelOf(selected,kind)}</h2></div><button onClick={()=>{setSelected(null);setInvestigation(null);}}><X size={18}/></button></div><div className="detail-summary"><Kpi label="Total accesses" value={Number(selected.access_count||0)}/><Kpi label="Loaded source events" value={selectedEvents.length}/></div>{(!isToken&&!selected.deployed_at||isToken&&["DRAFT","GENERATED"].includes(str(selected.status)))&&<div className="deployment-notice"><AlertTriangle size={17}/><div><strong>Not armed yet</strong><span>This record exists in the database, but monitoring starts only after deployment.</span></div><button className="primary with-icon" onClick={()=>setDeploying(selected)}><Rocket size={15}/>Deploy and arm</button></div>}{isToken&&["ACTIVE","TRIGGERED"].includes(str(selected.status))&&<form className="honeytoken-demo-panel" onSubmit={simulateHoneytokenTrigger}><div className="honeytoken-demo-heading"><KeyRound size={18}/><div><strong>Browser demo trigger</strong><span>Paste the one-time generated value to simulate an authorized monitoring agent observing this armed Honeytoken.</span></div></div><label>Observed Honeytoken value<div className="honeytoken-demo-control"><input required autoComplete="off" type={demoVisible?"text":"password"} value={demoValue} onChange={event=>setDemoValue(event.target.value)} placeholder="Paste the copied one-time value"/><button className="icon-button" type="button" aria-label={demoVisible?"Hide observed value":"Show observed value"} onClick={()=>setDemoVisible(value=>!value)}>{demoVisible?<EyeOff size={17}/>:<Eye size={17}/>}</button><button className="primary" type="submit" disabled={demoBusy||!demoValue.trim()}>{demoBusy?"Triggering…":"Simulate trigger"}</button></div></label>{demoResult&&<p className={demoResult.startsWith("Trigger recorded")?"demo-result success":"demo-result"}>{demoResult}</p>}</form>}{!isToken&&Boolean(selected.deployed_at)&&<div className="deployment-notice armed"><FileCheck2 size={17}/><div><strong>Monitoring CanaryAlerts / {labelOf(selected,kind)}</strong><span>Edit, rename, or delete this deployed copy. The original file selected during import is not monitored.</span></div></div>}{!isToken&&<section className="canary-health-panel"><div><h3>Canary health</h3><p>Latest verified health state: <strong>{str(canaryHealth?.latest_health_check ? (canaryHealth.latest_health_check as Row).health_status : canaryHealth?.status)}</strong></p><p className="muted">{canaryHealth?.latest_health_check ? date((canaryHealth.latest_health_check as Row).checked_at) : "No completed health check is available."}</p></div><div><button className="secondary" disabled={healthBusy} onClick={()=>void checkCanaryHealth()}>{healthBusy?"Checking…":"Verify integrity"}</button><button className="primary" disabled={rotationBusy} onClick={()=>void rotateCanary()}>{rotationBusy?"Rotating…":"Rotate"}</button></div></section>}<InvestigationSummary value={investigation}/><SafeDetailSections row={selected} sections={detailSections}/><h3>{isToken ? "Honeytoken validation history" : "Canary filesystem history"}</h3><EventList events={selectedEvents}/></aside></>}
    {createOpen && <CreateDialog kind={kind} honeytokens={availableTokens} onClose={()=>setCreateOpen(false)} onCreated={()=>{setCreateOpen(false);void load();}}/>}
    {deploying && <DeployDialog kind={kind} row={deploying} onClose={()=>setDeploying(null)} onDeployed={()=>{setDeploying(null);setSelected(null);void load();}}/>}
  </section>;
}

function Kpi({label,value}:{label:string;value:number}) { return <article><span>{label}</span><strong>{value}</strong></article>; }
function SafeDetailSections({row,sections}:{row:Row;sections:DetailSection[]}) {
  return <div className="safe-detail-sections">{sections.map(section=><section key={section.title}>
    <h3>{section.title}</h3>
    <dl className="detail-grid">{section.fields.map(field=><div key={field.key}><dt>{field.label}</dt><dd className={field.key.includes("hash") || field.key.endsWith("_id") || field.key === "id" ? "machine-value" : undefined}>{detailValue(field.key,row[field.key])}</dd></div>)}</dl>
  </section>)}</div>;
}
function EventList({events}:{events:EventRow[]}) { return <div className="event-list">{events.length?events.map(event=><article key={event.id}><span className={`severity ${str(event.severity).toLowerCase()}`}>{str(event.severity)}</span><div><strong>{str(event.event_type)} · {str(event.file_name)}</strong><small>{str(event.system_username)} · {str(event.device_name)} · {str(event.process_name)}</small></div><time>{date(event.occurred_at)}</time></article>):<div className="empty-inline">No matching event has been recorded.</div>}</div>; }
function InvestigationSummary({value}:{value:InvestigationContext|null}) { const aggregate=value?.trigger_aggregate||{}; return <section className="deception-investigation"><h3>Investigation context</h3><div className="detail-summary"><Kpi label="Triggers" value={Number(aggregate.total||0)}/><Kpi label="Suspicious" value={Number(aggregate.suspicious||0)}/><Kpi label="Critical" value={Number(aggregate.critical||0)}/></div><LinkedRecords title="Linked threats" rows={value?.threats||[]} code="threat_code" timestamp="last_detected_at"/><LinkedRecords title="Linked incidents" rows={value?.incidents||[]} code="incident_code" timestamp="updated_at"/><LinkedRecords title="Linked investigation cases" rows={value?.investigation_cases||[]} code="case_number" timestamp="updated_at"/></section>; }
function LinkedRecords({title,rows,code,timestamp}:{title:string;rows:Row[];code:string;timestamp:string}) { return <div className="linked-records"><h4>{title} <small>{rows.length}</small></h4>{rows.length?<div>{rows.map(row=><article key={idOf(row)}><strong>{str(row[code])}</strong><span>{str(row.title)}</span><small>{str(row.severity||row.priority)} · {str(row.status)} · {date(row[timestamp])}</small></article>)}</div>:<p>No linked records yet.</p>}</div>; }

function CreateDialog({kind,honeytokens,onClose,onCreated}:{kind:Kind;honeytokens:Row[];onClose:()=>void;onCreated:()=>void}) {
  const isToken = kind === "honeytoken";
  const [form, setForm] = useState<Record<string,string|boolean>>({
    classification: "CONFIDENTIAL",
    honeytoken_type: "API_KEY",
    canary_type: "DOCUMENT",
    contains_honeytoken: false,
    deploy_immediately: true,
  });
  const [creationMode, setCreationMode] = useState<"GENERATE"|"IMPORT">("GENERATE");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState("");
  const [created, setCreated] = useState<Row|null>(null);
  const [busy, setBusy] = useState(false);
  const [secretVisible, setSecretVisible] = useState(false);
  const [secretCopied, setSecretCopied] = useState(false);
  const update = (name:string,value:string|boolean) => setForm(current=>({...current,[name]:value}));

  function changeCreationMode(mode:"GENERATE"|"IMPORT") {
    setCreationMode(mode);
    setSelectedFile(null);
    setError("");
  }

  function chooseExistingFile(file:File|null) {
    setError("");
    setSelectedFile(null);
    if (!file) return;
    if (file.size === 0) { setError("The selected file is empty."); return; }
    if (file.size > maxCanaryUploadBytes) { setError("The selected file exceeds the 10 MB upload limit."); return; }
    const extension = `.${file.name.split(".").pop()?.toLowerCase() || ""}`;
    if (!acceptedCanaryUploadTypes.split(",").includes(extension)) {
      setError("This file format cannot be imported safely. Choose a supported document, spreadsheet, image, archive, configuration, SQL, JSON, YAML or source-code file.");
      return;
    }
    setSelectedFile(file);
  }

  async function submit(event:FormEvent) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      let result:Row;
      if (isToken) {
        result = await api.post<Row>("/honeytokens", {
          honeytoken_name: form.honeytoken_name,
          honeytoken_type: form.honeytoken_type,
          description: form.description || undefined,
          target_system: form.target_system || undefined,
          classification: form.classification,
        });
      } else if (creationMode === "IMPORT") {
        if (!selectedFile) throw new Error("Choose the existing file that DDH should copy into secured staging.");
        const originalPath = String(form.original_file_path || "").trim();
        const pathFileName = originalPath.split(/[\\/]/).pop()?.toLowerCase();
        if (!originalPath || !pathFileName || pathFileName !== selectedFile.name.toLowerCase()) {
          throw new Error("The exact original path is required, and its filename must match the selected file.");
        }
        const body = new FormData();
        body.append("file", selectedFile);
        if (form.description) body.append("description", String(form.description));
        result = await api.post<Row>("/canary-files/import", body);
      } else {
        result = await api.post<Row>("/canary-files", {
          file_name: form.file_name,
          canary_type: form.canary_type,
          description: form.description || undefined,
          contains_honeytoken: Boolean(form.contains_honeytoken),
          honeytoken_id: form.contains_honeytoken && form.honeytoken_id ? form.honeytoken_id : undefined,
        });
      }
      if (!isToken && Boolean(form.deploy_immediately)) {
        const deployment = await api.post<Row>(`/canary-files/${idOf(result)}/deploy`, {
          deployment_directory: "CanaryAlerts",
          original_file_path: creationMode === "IMPORT" && form.original_file_path ? String(form.original_file_path) : undefined,
        });
        result = {...result, ...deployment};
      }
      setCreated(result);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Creation failed.");
    } finally {
      setBusy(false);
    }
  }

  const generatedExtension = canaryExtensions[String(form.canary_type)] || ".txt";
  const oneTimeSecret = isToken && created ? String(created.generated_value || "") : "";
  const creationFields = isToken ? honeytokenCreationFields : canaryCreationFields;

  async function copyOneTimeSecret() {
    if (!oneTimeSecret) return;
    try {
      await navigator.clipboard.writeText(oneTimeSecret);
      setSecretCopied(true);
      window.setTimeout(() => setSecretCopied(false), 2000);
    } catch {
      setError("The browser blocked clipboard access. Reveal the value and copy it manually.");
    }
  }

  return <div className="modal-backdrop" onMouseDown={onClose}>
    <section className="modal deception-modal" onMouseDown={e=>e.stopPropagation()}>
      <div className="modal-header">
        <div><span className="eyebrow">SECURE CREATION</span><h2>Create {isToken ? "Honeytoken" : "Canary File"}</h2></div>
        <button className="icon-button" type="button" aria-label="Close creation dialog" onClick={onClose}><X size={18}/></button>
      </div>
      {error && <div className="alert alert-error"><AlertTriangle size={16}/>{error}</div>}
      {created ? <div className="created-secret">
        <div className="staging-status"><strong>{!isToken && Boolean(form.deploy_immediately) ? "Deployed and monitoring" : "Staged securely — not monitored yet"}</strong><span>{isToken ? "The backend created a DRAFT Honeytoken record. Place the one-time material in its approved logical target, then record that placement with Deploy & Arm." : Boolean(form.deploy_immediately) ? "DDH created a dot-prefixed monitored copy (for example, report.pdf → .report.pdf) in the CanaryAlerts folder. Editing, renaming or deleting that copy produces an alert." : "The backend created a DRAFT secured Canary copy in tenant staging. Select Deploy & Arm to copy it into an approved monitored directory."}</span></div>
        {oneTimeSecret && <section className="one-time-secret" aria-label="One-time generated Honeytoken material">
          <div><strong>One-time generated value</strong><span>Shown only in this creation response. Store it in the approved target before closing this dialog.</span></div>
          <div className="secret-control"><input aria-label="Generated Honeytoken value" readOnly type={secretVisible ? "text" : "password"} value={oneTimeSecret}/><button className="icon-button" type="button" aria-label={secretVisible ? "Hide generated value" : "Reveal generated value"} onClick={()=>setSecretVisible(value=>!value)}>{secretVisible?<EyeOff size={17}/>:<Eye size={17}/>}</button><button className="secondary with-icon" type="button" onClick={()=>void copyOneTimeSecret()}>{secretCopied?<Check size={16}/>:<Copy size={16}/>} {secretCopied?"Copied":"Copy"}</button></div>
        </section>}
        <div className="creation-metadata">{creationFields.map(field=><div key={field.key}><span>{field.label}</span><strong className={field.key.includes("hash") || field.key.endsWith("_id") || field.key === "id" ? "machine-value" : undefined}>{detailValue(field.key,created[field.key])}</strong></div>)}</div>
        <button className="primary" onClick={onCreated}>View inventory</button>
      </div> : <form onSubmit={submit}>
        {!isToken && <div className="canary-mode-switch" role="group" aria-label="Canary file source">
          <button type="button" className={creationMode === "GENERATE" ? "active" : ""} aria-pressed={creationMode === "GENERATE"} onClick={()=>changeCreationMode("GENERATE")}>
            <strong>Generate a decoy</strong><span>DDH creates safe decoy content</span>
          </button>
          <button type="button" className={creationMode === "IMPORT" ? "active" : ""} aria-pressed={creationMode === "IMPORT"} onClick={()=>changeCreationMode("IMPORT")}>
            <strong>Use an existing file copy</strong><span>Your original file is not modified</span>
          </button>
        </div>}
        {!isToken && <div className="canary-source-note">
          {creationMode === "GENERATE"
            ? `The name is a label. DDH generates a real ${generatedExtension} decoy in backend-managed tenant staging; its physical path stays hidden and it alerts only after deployment.`
            : "DDH uploads an unchanged secured copy into backend-managed tenant staging. The selected original stays in its current location; the staging path is hidden for security."}
        </div>}
        <div className="form-grid">
          {isToken ? <>
            <label>Honeytoken name *<input required onChange={e=>update("honeytoken_name",e.target.value)}/></label>
            <label>Type *<select value={String(form.honeytoken_type)} onChange={e=>update("honeytoken_type",e.target.value)}>{tokenTypes.map(v=><option key={v}>{v}</option>)}</select></label>
            <label>Target system<input onChange={e=>update("target_system",e.target.value)} placeholder="Example: Payroll API or Finance Vault"/><small>Name the logical application, service, vault or database that will contain the decoy. This is not a laptop name and not a file path. A Honeytoken is a decoy value, so DDH cannot physically insert it into an external API or vault without a separately configured integration.</small></label>
            <label>Classification *<select value={String(form.classification)} onChange={e=>update("classification",e.target.value)}>{classifications.map(v=><option key={v}>{v}</option>)}</select></label>
          </> : creationMode === "GENERATE" ? <>
            <label>Decoy file name *<input required onChange={e=>update("file_name",e.target.value)} placeholder="Finance_Report_2026"/><small>Do not enter an extension; selected type produces {generatedExtension}.</small></label>
            <label>Canary template *<select value={String(form.canary_type)} onChange={e=>update("canary_type",e.target.value)}>{canaryTypes.map(v=><option key={v}>{v.replaceAll("_"," ")}</option>)}</select></label>
            <label className="checkbox-field"><input type="checkbox" checked={Boolean(form.contains_honeytoken)} onChange={e=>update("contains_honeytoken",e.target.checked)}/>Embed an existing Honeytoken in generated content</label>
            {form.contains_honeytoken && <label>Honeytoken<select required value={String(form.honeytoken_id||"")} onChange={e=>update("honeytoken_id",e.target.value)}><option value="">Select token</option>{honeytokens.map(v=><option key={idOf(v)} value={idOf(v)}>{labelOf(v,"honeytoken")} ({str(v.status)})</option>)}</select>{!honeytokens.length && <small>No Honeytoken records are available. Create one first.</small>}</label>}
          </> : <>
          <label className="field-wide">Original full file path *<input required value={String(form.original_file_path||"")} onChange={e=>update("original_file_path",e.target.value)} placeholder="D:\\Documents\\report.pdf"/><small>Enter the exact path before choosing the file. Browsers hide local paths from file pickers, so DDH cannot auto-fill it. The backend verifies this path and the selected filename must match.</small></label>
          <label className="field-wide canary-upload-drop">
            <Upload size={24}/>
            <strong>{selectedFile ? selectedFile.name : "Choose an existing file"}</strong>
            <span>{selectedFile ? `${fileSize(selectedFile.size)} · ${selectedFile.type || "Type detected by backend"}` : "A secured copy is uploaded; maximum size 10 MB."}</span>
            <span className="canary-upload-action">{selectedFile ? "Choose a different file" : "Browse files"}</span>
            <input className="canary-file-input" type="file" required accept={acceptedCanaryUploadTypes} onChange={e=>chooseExistingFile(e.target.files?.[0] || null)}/>
          </label>
          </>}
          <label className="field-wide">Description<textarea onChange={e=>update("description",e.target.value)} placeholder="Purpose and intended monitored placement"/></label>
          {!isToken && <label className="field-wide checkbox-field"><input type="checkbox" checked={Boolean(form.deploy_immediately)} onChange={e=>update("deploy_immediately",e.target.checked)}/><span><strong>Automatically deploy and arm on this PC</strong><small>Create a dot-prefixed monitored copy such as .report.pdf immediately after generation or upload. Your original file remains unchanged.</small></span></label>}
        </div>
        <div className="modal-actions">
          <button className="secondary" type="button" onClick={onClose}>Cancel</button>
          <button className="primary" disabled={busy} type="submit">{busy ? "Staging…" : isToken ? "Generate securely" : creationMode === "IMPORT" ? "Upload secured copy" : "Generate decoy"}</button>
        </div>
      </form>}
    </section>
  </div>;
}

function DeployDialog({kind,row,onClose,onDeployed}:{kind:Kind;row:Row;onClose:()=>void;onDeployed:()=>void}) {
  const isToken=kind==="honeytoken";
  const [location,setLocation]=useState("");
  const [target,setTarget]=useState(String(row.target_system||""));
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  const [placementConfirmed,setPlacementConfirmed]=useState(false);

  async function submit(event:FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      if (isToken && !placementConfirmed) {
        setError("Confirm that the one-time Honeytoken value has been placed in the approved target before arming it.");
        return;
      }
      const body=isToken
        ? {deployment_location:location,target_system:target||undefined}
        : {deployment_directory:"CanaryAlerts",original_file_path:location};
      await api.post<Row>(`${isToken?"/honeytokens":"/canary-files"}/${idOf(row)}/deploy`,body);
      onDeployed();
    } catch(reason) {
      setError(reason instanceof Error?reason.message:"Deployment failed.");
    } finally { setBusy(false); }
  }

  return <div className="modal-backdrop" onMouseDown={onClose}><section className="modal deception-modal" onMouseDown={e=>e.stopPropagation()}>
    <div className="modal-header"><div><span className="eyebrow">AUTHORIZED DEPLOYMENT</span><h2>Deploy and arm {labelOf(row,kind)}</h2></div><button className="icon-button" type="button" aria-label="Close deployment dialog" onClick={onClose}><X size={18}/></button></div>
    {error&&<div className="alert alert-error">{error}</div>}
    <p className="form-guidance">{isToken
      ? "Honeytoken: this records an approved logical placement and arms validation. It does not copy a credential, API key, or secret into an external system. Place the one-time value yourself first."
      : "Canary file: enter the existing original file's absolute path. DDH verifies it and creates a dot-prefixed sibling in the same folder, then watches that sibling for edits, renames, or deletion."}</p>
    <form onSubmit={submit}><div className="form-grid">
      <label className="field-wide">{isToken?"Authorized placement or locator":"Original full file path"} *
        <input required value={location} onChange={e=>setLocation(e.target.value)} placeholder={isToken?"Payroll API / Finance Vault / approved locator":"D:\\Documents\\report.pdf"}/>
        <small>{isToken
          ? "Enter the logical service, vault, application location or approved locator where the Honeytoken material was placed."
          : "The file must already exist on the backend machine and its filename must match this Canary record. DDH creates .filename beside it without modifying the original."}</small>
      </label>
      {isToken?<label className="field-wide">Target system<input value={target} onChange={e=>setTarget(e.target.value)} placeholder="Payroll API or Finance Vault"/></label>:<div className="field-wide canary-device-detection"><Check size={17}/><div><strong>Device detected automatically</strong><small>The backend records this PC's hostname when the Canary is deployed. No device name or device ID entry is required.</small></div></div>}
    </div>{isToken && <label className="checkbox-field deployment-confirmation"><input type="checkbox" checked={placementConfirmed} onChange={e=>setPlacementConfirmed(e.target.checked)}/>I have placed the generated Honeytoken value in the approved target. Arm monitoring now.</label>}<div className="modal-actions"><button className="secondary" type="button" onClick={onClose}>Cancel</button><button className="primary with-icon" disabled={busy || (isToken && !placementConfirmed)} type="submit"><Rocket size={15}/>{busy?"Deploying…":"Deploy and arm"}</button></div></form>
  </section></div>;
}
