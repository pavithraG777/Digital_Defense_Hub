import { useCallback, useEffect, useMemo, useState } from "react";
import type { CSSProperties, FormEvent } from "react";
import { Link, Navigate, useParams } from "react-router-dom";
import { AlertCircle, Check, ChevronRight, CircleOff, Download, Eye, Files, Gauge, LoaderCircle, Monitor, Network, Plus, RefreshCw, Search, ShieldAlert, X, Zap } from "lucide-react";
import type { ApiSource, ScreenAction } from "../types";
import { api, apiBlob, apiRequest, session } from "../lib/api";
import { displayValue, getRecordId, getRecordLabel, getRecordStatus, isRecord, recordTimestamp, toCollection, type UnknownRecord } from "../lib/records";
import { canAccessModule, getModule, getScreen } from "../lib/modules";
import "./moduleWorkspaceVisuals.css";
import "./healthFocus.css";
import "./preEncryptionVisual.css";

type ResourceStatus = "loading" | "success" | "error";

type ResourceState = {
  source: ApiSource;
  status: ResourceStatus;
  data?: unknown;
  error?: string;
};

type DetailState = {
  title: string;
  status: ResourceStatus;
  data?: unknown;
  error?: string;
} | null;

function modulePath(moduleId: string, screenId: string) {
  return `/module/${moduleId}/${screenId}`;
}

function interpolatePath(path: string, id: string) {
  return path.replace(/:[a-zA-Z_][a-zA-Z0-9_]*/, encodeURIComponent(id));
}

function dataFields(value: UnknownRecord) {
  return Object.entries(value).filter(([fieldName, fieldValue]) => fieldValue !== undefined && fieldValue !== null && !/(password|secret|token|authorization|cookie|private.?key|storage.?path|file.?path|model.?file|visualization.?file|raw.?content|extracted.?text)/i.test(fieldName));
}

function JSONDetail({ value }: { value: unknown }) {
  if (isRecord(value)) {
    const fields = dataFields(value);
    return (
      <dl className="detail-grid">
        {fields.map(([key, fieldValue]) => (
          <div key={key}>
            <dt>{key.replace(/_/g, " ")}</dt>
            <dd>{displayValue(fieldValue)}</dd>
          </div>
        ))}
      </dl>
    );
  }

  return <pre className="json-view">{JSON.stringify(value, null, 2)}</pre>;
}

function objectValue(value:unknown):UnknownRecord { if(isRecord(value))return value;if(typeof value==="string"){try{const parsed=JSON.parse(value);return isRecord(parsed)?parsed:{};}catch{return {};}}return {}; }
function arrayValue(value:unknown):UnknownRecord[]{if(Array.isArray(value))return value.filter(isRecord);if(typeof value==="string"){try{return arrayValue(JSON.parse(value));}catch{return [];}}if(isRecord(value)){for(const key of ["items","factors","risk_factors","actions","recommended_actions","signals"]){const nested=arrayValue(value[key]);if(nested.length)return nested;}}return [];}
function numeric(value:unknown){const result=Number(value);return Number.isFinite(result)?result:0;}
function ScoreRing({value,label,danger=false}:{value:number;label:string;danger?:boolean}){const score=Math.max(0,Math.min(100,value));return <div className={`visual-score-ring${danger?" danger":""}`} style={{"--score":`${score*3.6}deg`} as CSSProperties}><div><strong>{Math.round(score)}</strong><span>{label}</span></div></div>}
function Meter({label,value,tone="blue"}:{label:string;value:number;tone?:string}){const score=Math.max(0,Math.min(100,value));return <div className="visual-meter"><header><span>{label}</span><strong>{Math.round(value)}</strong></header><i><b className={tone} style={{width:`${score}%`}}/></i></div>}

function FingerprintVisual({value}:{value:unknown}){
 const item=objectValue(value),pattern=objectValue(item.interaction_pattern),rawSignals=Array.isArray(pattern.behavioural_signals)?pattern.behavioural_signals:[],signals=rawSignals.length?rawSignals.map(String):[item.is_suspicious&&"Suspicious interaction",item.ransomware_suspected&&"Ransomware suspected",item.event_type&&`${String(item.event_type)} canary event`,item.occurrence_count&&`Observed ${String(item.occurrence_count)} time(s)`].filter(Boolean).map(String);
 const behavioural=numeric(item.behavioural_score),behaviour=behavioural,confidence=numeric(item.confidence_score);
 return <div className="security-visual"><section className="visual-hero"><ScoreRing value={behavioural} label="Behaviour risk" danger={Boolean(item.is_suspicious)}/><div><p>INTERACTION VERDICT</p><h3>{item.is_suspicious?"Suspicious canary interaction":"Recognized interaction"}</h3><span>{String(item.event_type||"Interaction")} from {String(item.source_ip||"unknown network")}</span><div className="visual-tags"><b className={item.is_suspicious?"bad":"good"}>{item.is_suspicious?"SUSPICIOUS":"NORMAL"}</b><b className={item.ransomware_suspected?"bad":"neutral"}>{item.ransomware_suspected?"RANSOMWARE SIGNAL":"NO RANSOMWARE SIGNAL"}</b></div></div></section><section className="visual-path"><article><Network/><small>Source</small><strong>{displayValue(item.source_ip)}</strong></article><i>→</i><article><Monitor/><small>Device</small><strong>{displayValue(item.device_name||item.device_identifier)}</strong></article><i>→</i><article><Files/><small>Canary event</small><strong>{displayValue(item.event_type)}</strong></article></section><section className="visual-grid"><article><h4><Gauge/> Detection confidence</h4><Meter label="Confidence" value={confidence} tone="cyan"/><Meter label="Behaviour anomaly" value={behaviour} tone={item.is_suspicious?"red":"green"}/></article><article><h4><Monitor/> Actor fingerprint</h4><dl><div><dt>Process</dt><dd>{displayValue(item.process_name)}</dd></div><div><dt>OS user</dt><dd>{displayValue(item.operating_system_user)}</dd></div><div><dt>Occurrences</dt><dd>{displayValue(item.occurrence_count)}</dd></div><div><dt>First seen</dt><dd>{recordTimestamp(item)}</dd></div></dl></article></section><section className="visual-signals"><h4><Zap/> Behaviour signals</h4><div>{signals.length?signals.map(signal=><span key={signal}>{humanizeLabel(signal)}</span>):<span>No additional behavioural signals</span>}</div></section></div>;
}

function CanaryHealthVisual({value}:{value:unknown}){const root=objectValue(value),item=isRecord(root.latest_health_check)?root.latest_health_check:root,canary=objectValue(root.canary_file),score=numeric(item.health_score);const checks=[["File exists",item.file_exists],["Path matches",item.path_matches],["Hash matches",item.hash_matches],["Size matches",item.size_matches],["Permissions valid",item.permissions_valid]] as const;return <div className="security-visual"><section className="visual-hero"><ScoreRing value={score} label="Canary health" danger={!item.is_healthy}/><div><p>DECOY READINESS</p><h3>{item.is_healthy?"Canary is healthy and armed":"Canary requires attention"}</h3><span>{displayValue(canary.file_name||canary.canary_code)} · checked {recordTimestamp(item)}</span><div className="visual-tags"><b className={item.is_healthy?"good":"bad"}>{item.is_healthy?"READY":"DEGRADED"}</b><b>{displayValue(item.check_type)}</b></div></div></section><section className="health-check-grid">{checks.map(([label,passed])=><article className={passed?"passed":"failed"} key={label}><i>{passed?"✓":"!"}</i><span>{label}</span><strong>{passed?"PASS":"FAIL"}</strong></article>)}</section>{Boolean(item.failure_reason)&&<section className="score-story"><strong>Failure reason</strong><p>{displayValue(item.failure_reason)}</p></section>}</div>}
function CanaryRotationVisual({value}:{value:unknown}){const item=objectValue(value),completed=String(item.status||"").toUpperCase()==="COMPLETED";return <div className="security-visual"><section className="visual-hero"><ScoreRing value={completed?100:50} label="Rotation progress" danger={!completed}/><div><p>DECOY IDENTITY ROTATION</p><h3>{completed?"Canary identity rotated successfully":"Rotation is in progress"}</h3><span>Rotation replaces the decoy identity so an attacker cannot learn and avoid an old canary.</span><div className="visual-tags"><b className={completed?"good":"warn"}>{displayValue(item.status)}</b><b>{humanizeLabel(String(item.rotation_reason||"Scheduled rotation"))}</b></div></div></section><section className="rotation-flow"><article><small>Previous decoy</small><strong>{displayValue(item.old_file_name)}</strong><span>Tracking ID: {displayValue(item.old_tracking_identifier)}</span></article><i>→</i><article className="rotated"><small>New active decoy</small><strong>{displayValue(item.new_file_name)}</strong><span>Tracking ID: {displayValue(item.new_tracking_identifier)}</span></article></section><section className="visual-grid"><article><h4><ShieldAlert/> Protection outcome</h4><p>Filename, tracking identity and integrity hash were renewed. The rotation is recorded in the audit trail.</p></article><article><h4><Gauge/> Rotation details</h4><dl><div><dt>Strategy</dt><dd>{humanizeLabel(String(item.rotation_strategy||"Not supplied"))}</dd></div><div><dt>Requested</dt><dd>{displayValue(item.requested_at)}</dd></div><div><dt>Completed</dt><dd>{displayValue(item.completed_at)}</dd></div></dl></article></section></div>}
function AdaptiveDeceptionGuide({screenId}:{screenId:string}){const steps=[{id:"health",title:"1. Canary health",question:"Is the decoy still intact?",detail:"Checks whether the file exists and its path, hash, size and permissions still match."},{id:"fingerprints",title:"2. Interaction fingerprints",question:"Who touched the decoy?",detail:"Groups access, edit, rename or delete activity by IP, device, user and process."},{id:"rotation",title:"3. Canary rotation",question:"Should the decoy identity change?",detail:"Replaces the filename, hash and tracking identity so the decoy does not become predictable."}];return <section className="deception-guide"><header><div><p>HOW ADAPTIVE DECEPTION WORKS</p><h2>One canary, three different security views</h2></div><span>Canary file → integrity check → attacker interaction → incident / rotation</span></header><div>{steps.map((step,index)=><article className={screenId===step.id?"active":""} key={step.id}><i>{index+1}</i><div><strong>{step.title}</strong><b>{step.question}</b><span>{step.detail}</span></div></article>)}</div><footer><ShieldAlert size={16}/><span><b>Connection:</b> all three records share the same <code>canary_file_id</code>. Health describes the file, fingerprint describes the actor/event, and rotation describes the decoy identity change.</span></footer></section>}
function AdaptiveSummary({screenId,resources}:{screenId:string;resources:ResourceState[]}){const records=(id:string)=>resources.find(resource=>resource.source.id===id)?.status==="success"?toCollection(resources.find(resource=>resource.source.id===id)?.data):[];if(screenId==="fingerprints"){const items=records("fingerprints").filter(isRecord);return <div className="iam-summary-grid"><article><span>Observed actor patterns</span><strong>{items.length}</strong><small>Grouped canary interactions</small></article><article><span>Suspicious</span><strong>{items.filter(item=>item.is_suspicious).length}</strong><small>Needs analyst review</small></article><article><span>Ransomware signals</span><strong>{items.filter(item=>item.ransomware_suspected).length}</strong><small>High-risk behaviour</small></article></div>}if(screenId==="health"){const items=records("canaries").filter(isRecord);return <div className="iam-summary-grid"><article><span>Health records</span><strong>{items.length}</strong><small>Latest integrity results</small></article><article><span>Healthy</span><strong>{items.filter(item=>item.is_healthy||String(item.health_status).toUpperCase()==="HEALTHY").length}</strong><small>All integrity checks passed</small></article><article><span>Attention required</span><strong>{items.filter(item=>!item.is_healthy).length}</strong><small>Failed or not yet checked</small></article></div>}const canaries=records("canaries").filter(isRecord),history=records("history").filter(isRecord);return <div className="iam-summary-grid"><article><span>Available canaries</span><strong>{canaries.length}</strong><small>Select one to rotate</small></article><article><span>Rotation operations</span><strong>{history.length}</strong><small>Audited identity changes</small></article><article><span>Completed</span><strong>{history.filter(item=>String(item.status).toUpperCase()==="COMPLETED").length}</strong><small>New identity activated</small></article></div>}
function humanizeLabel(value:string){return value.replaceAll("_"," ").replace(/\b\w/g,char=>char.toUpperCase());}
function PreEncryptionVisual({value}:{value:unknown}){
 const root=objectValue(value),d:any=isRecord(root.detection)?root.detection:root,storedFactors=arrayValue(d.risk_factors),actions=arrayValue(d.recommended_actions),score=numeric(d.combined_risk_score);
 const storedActiveFactors=storedFactors.filter(f=>numeric(f.signal_count)>0||numeric(f.score)>0);
 const derivedFactors=[{code:"MODIFIED",name:`Modified events (${numeric(d.modified_event_count)})`,score:Math.min(100,numeric(d.modified_event_count)*25)},{code:"RENAMED",name:`Rename events (${numeric(d.renamed_event_count)})`,score:Math.min(100,numeric(d.renamed_event_count)*35)},{code:"DELETED",name:`Delete events (${numeric(d.deleted_event_count)})`,score:Math.min(100,numeric(d.deleted_event_count)*40)},{code:"EXTENSION",name:`Extension changes (${numeric(d.extension_changed_event_count)})`,score:Math.min(100,numeric(d.extension_changed_event_count)*45)},{code:"ENTROPY",name:`High-entropy writes (${numeric(d.high_entropy_write_count)})`,score:Math.min(100,numeric(d.high_entropy_write_count)*55)},{code:"DECEPTION",name:`Canary / honeytoken events (${numeric(d.canary_event_count)+numeric(d.honeytoken_event_count)})`,score:(numeric(d.canary_event_count)+numeric(d.honeytoken_event_count))>0?100:0},{code:"RATE",name:`Event rate (${numeric(d.event_rate_per_minute).toFixed(1)}/min)`,score:Math.min(100,numeric(d.event_rate_per_minute))}].filter(f=>f.score>0);
 const factors=storedActiveFactors.length?storedActiveFactors:derivedFactors;
 const applicableActions=actions.filter(action=>{const code=String(action.code||"");if(code==="RESTRICT_WRITE_ACTIVITY")return numeric(d.modified_event_count)+numeric(d.renamed_event_count)+numeric(d.deleted_event_count)+numeric(d.extension_changed_event_count)>0;if(code==="INVESTIGATE_DECEPTION_TRIGGER")return numeric(d.canary_event_count)+numeric(d.honeytoken_event_count)>0;if(code==="SUSPEND_SUSPICIOUS_PROCESS")return numeric(d.suspicious_process_count)>0;if(code==="ISOLATE_ENDPOINT")return Boolean(d.requires_endpoint_isolation);return true;});
 const activitySummary=[["Modified",numeric(d.modified_event_count)],["Renamed",numeric(d.renamed_event_count)],["Deleted",numeric(d.deleted_event_count)],["Extension changed",numeric(d.extension_changed_event_count)],["Encrypted",numeric(d.encrypted_event_count)],["Canary",numeric(d.canary_event_count)],["Honeytoken",numeric(d.honeytoken_event_count)]].filter(([,count])=>Number(count)>0);
 const stages=[{label:"File activity",active:numeric(d.total_event_count)>0},{label:"Pattern detected",active:score>0},{label:"Pre-encryption warning",active:String(d.detection_stage||"").includes("PRE")},{label:"Endpoint isolation",active:Boolean(d.requires_endpoint_isolation)}];
 return <div className="security-visual"><section className="visual-hero"><ScoreRing value={score} label="Ransomware risk" danger={score>=70}/><div><p>PRE-ENCRYPTION VERDICT</p><h3>{humanizeLabel(String(d.classification||"Assessment pending"))}</h3><span>{displayValue(d.device_name||d.device_identifier)} · {displayValue(d.process_name)}</span><div className="visual-tags"><b className={score>=70?"bad":"neutral"}>{displayValue(d.risk_level)}</b><b className={d.requires_human_review?"warn":"good"}>{d.requires_human_review?"REVIEW REQUIRED":"AUTO-ASSESSED"}</b></div></div></section><section className="attack-progress">{stages.map((stage,index)=><article className={stage.active?"active":""} key={stage.label}><i>{index+1}</i><span>{stage.label}</span></article>)}</section><section className="visual-stats"><article><Files/><strong>{numeric(d.unique_file_count)}</strong><span>Files touched</span></article><article><Zap/><strong>{numeric(d.event_rate_per_minute).toFixed(1)}</strong><span>Events / minute</span></article><article><ShieldAlert/><strong>{numeric(d.encrypted_event_count)}</strong><span>Encrypted events</span></article><article><Monitor/><strong>{numeric(d.unique_process_count)}</strong><span>Processes</span></article></section><section className="detection-inputs"><strong>Signals in this detection</strong><div>{activitySummary.length?activitySummary.map(([label,count])=><span key={String(label)}><b>{count}</b> {label}</span>):<span>No operation-specific counters were stored.</span>}</div><small>Identical input signals produce identical scores and responses; values are not randomized by file name.</small></section><section className="visual-grid"><article><h4><Gauge/> Why this score?</h4>{factors.length?factors.slice(0,7).map(f=><Meter key={String(f.code||f.name)} label={String(f.name||humanizeLabel(String(f.code)))} value={numeric(f.score)} tone={numeric(f.score)>=70?"red":"cyan"}/>):<p>No contributing factors returned.</p>}</article><article><h4><ShieldAlert/> Responses applicable to this detection</h4><div className="action-cards">{applicableActions.length?applicableActions.map(a=><div key={String(a.code||a.title)}><b>{displayValue(a.priority)}</b><strong>{displayValue(a.title)}</strong><span>{displayValue(a.description)}</span></div>):<p>No response action is required for the recorded signals.</p>}</div></article></section>{d.score_explanation&&<section className="score-story"><strong>Analyst explanation</strong><p>{displayValue(d.score_explanation)}</p></section>}</div>;
}

function matchesQuery(record: unknown, query: string) {
  return !query || JSON.stringify(record).toLowerCase().includes(query.toLowerCase());
}

function csvValue(value: unknown) { return `"${displayValue(value).replaceAll('"', '""')}"`; }

function exportRecords(label: string, records: unknown[]) {
  const objects = records.filter(isRecord);
  if (!objects.length) return;
  const keys = [...new Set(objects.flatMap((item) => Object.keys(item)).filter((key) => !/(password|secret|token|path|raw)/i.test(key)))];
  const csv = [keys.map(csvValue).join(","), ...objects.map((item) => keys.map((key) => csvValue(item[key])).join(","))].join("\r\n");
  const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  link.download = `${label.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${new Date().toISOString().slice(0, 10)}.csv`; link.click(); URL.revokeObjectURL(link.href);
}

function ResourceContents({ resource, onInspect, onSelect, selectedId, query, moduleId, screenId }: { resource: ResourceState; onInspect: (source: ApiSource, value: unknown) => void; onSelect:(record:unknown)=>void; selectedId?:string; query: string; moduleId:string; screenId:string }) {
  if (resource.status === "loading") {
    return <div className="resource-loading"><LoaderCircle size={18} className="spin" /> Loading live data…</div>;
  }
  if (resource.status === "error") {
    return <div className="resource-error"><AlertCircle size={17} /><div><strong>Could not load this source</strong><span>{resource.error}</span></div></div>;
  }

  const allRecords = toCollection(resource.data);
  const records = allRecords.filter((record) => matchesQuery(record, query));
  if (records.length) {
    return (
      <div className="table-wrap">
        <div className="connection-strip"><strong>{records.length}</strong> matching record{records.length === 1 ? "" : "s"}<span>·</span><button className="secondary with-icon" type="button" onClick={() => exportRecords(resource.source.label, records)}><Download size={14}/> Export CSV</button></div>
        <table className="table">
          <thead><tr><th>Record</th><th>Status / severity</th><th>Last activity</th><th aria-label="Open details" /></tr></thead>
          <tbody>
            {records.slice(0, 50).map((record, index) => {
              const canInspect = Boolean(getRecordId(record));
              const selectableCanary=moduleId==="adaptive-deception"&&resource.source.id==="canaries"&&(screenId==="health"||screenId==="rotation");
              const selected=selectableCanary&&getRecordId(record)===selectedId;
              return (
                <tr key={getRecordId(record) || `${resource.source.id}-${index}`} className={`${canInspect ? "table-row-action" : ""} ${selected?"selected-record":""}`} onClick={() => canInspect && onInspect(resource.source, record)}>
                  <td><strong>{isRecord(record)&&moduleId==="adaptive-deception"&&screenId==="fingerprints"?`${displayValue(record.device_name||record.device_identifier)} · ${displayValue(record.event_type)}`:isRecord(record)&&moduleId==="pre-encryption"?displayValue(record.detection_code||record.device_name||record.id):getRecordLabel(record)}</strong>{isRecord(record)&&(record.description||record.process_name||record.source_ip)?<small>{displayValue(record.description||record.process_name||record.source_ip)}</small>:null}</td>
                  <td>{isRecord(record)&&moduleId==="adaptive-deception"&&screenId==="fingerprints"?<span className={`status-chip ${record.is_suspicious?"status-critical":"status-active"}`}>{record.is_suspicious?"SUSPICIOUS":"NORMAL"}</span>:isRecord(record)&&moduleId==="pre-encryption"?<span className={`status-chip status-${String(record.risk_level||"unknown").toLowerCase()}`}>{displayValue(record.risk_level||record.classification)}</span>:<span className={`status-chip status-${getRecordStatus(record).toLowerCase().replace(/[^a-z0-9]+/g,"-")}`}>{getRecordStatus(record)}</span>}</td>
                  <td>{recordTimestamp(record)}</td>
                  <td><div className="record-actions">{selectableCanary?<button className={selected?"selected":""} type="button" onClick={(event)=>{event.stopPropagation();onSelect(record)}}>{selected?<><Check size={14}/> Selected</>:"Select"}</button>:null}{canInspect ? <button className="icon-button" type="button" aria-label="View details" onClick={(event) => { event.stopPropagation(); onInspect(resource.source, record); }}><Eye size={16} /></button> : null}</div></td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {records.length > 50 && <p className="table-note">Showing the first 50 of {records.length} records returned by this API.</p>}
      </div>
    );
  }

  if (isRecord(resource.data) && Object.keys(resource.data).length) return <JSONDetail value={resource.data} />;

  return <div className="empty-inline"><CircleOff size={18} /> This API returned no records.</div>;
}

function ActionDialog({ action, selectedId, selectedLabel, onClose, onCompleted }: { action: ScreenAction; selectedId?: string; selectedLabel?:string; onClose: () => void; onCompleted: (message: string) => void }) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    if (values.new_password && values.confirm_password && values.new_password !== values.confirm_password) {
      setError("The new password and confirmation do not match.");
      return;
    }
    setLoading(true);
    try {
      const jsonFields = new Set(action.fields?.filter((field) => field.type === "json").map((field) => field.name));
      const body = Object.fromEntries(Object.entries(values).map(([key, value]) => {
        if (!jsonFields.has(key) || !value.trim()) return [key, value];
        try { return [key, JSON.parse(value)]; }
        catch { throw new Error(`${action.fields?.find((field) => field.name === key)?.label || key} must contain valid JSON.`); }
      }));
      for (const field of action.fields || []) {
        if (field.type === "number" && values[field.name] !== undefined) body[field.name] = Number(values[field.name]);
        if (field.type === "select" && ["true", "false"].includes(values[field.name])) body[field.name] = values[field.name] === "true";
        if (field.type === "datetime-local" && values[field.name]) body[field.name] = new Date(values[field.name]).toISOString();
      }
      const path = action.path.includes(":id") ? (selectedId ? interpolatePath(action.path, selectedId) : "") : action.path;
      if (!path) throw new Error("Select a record from the table before running this action.");
      if (body.download === true && path.includes("/restore/owner")) {
        const restored = await apiBlob(path, { method: "POST", body });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(restored);
        link.download = "restored-protected-file";
        link.click();
        URL.revokeObjectURL(link.href);
      } else {
        await apiRequest(path, { method: action.method, body });
      }
      onCompleted(`${action.label} completed successfully.`);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "The request could not be completed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="modal module-action-modal" role="dialog" aria-modal="true" aria-labelledby="action-dialog-title" onMouseDown={(event) => event.stopPropagation()}>
        <div className="modal-header"><div><p className="eyebrow">LIVE BACKEND ACTION</p><h2 id="action-dialog-title">{action.label}</h2>{action.description && <p>{action.description}</p>}</div><button className="icon-button" type="button" onClick={onClose} aria-label="Close"><X size={19} /></button></div>
        {selectedLabel&&<div className="selected-action-target"><Check size={16}/><div><small>SELECTED CANARY FILE</small><strong>{selectedLabel}</strong></div></div>}{error && <div className="alert alert-error" role="alert">{error}</div>}
        <form onSubmit={submit}>
          <div className="form-grid">
            {action.fields?.map((field) => (
              <label key={field.name} className={field.type === "textarea" ? "field-wide" : undefined}>
                {field.label}{field.required && <span className="required-mark"> *</span>}
                {field.type === "textarea" || field.type === "json" ? (
                  <textarea value={values[field.name] || ""} placeholder={field.placeholder} onChange={(event) => setValues((current) => ({ ...current, [field.name]: event.target.value }))} required={field.required} />
                ) : field.type === "select" ? (
                  <select value={values[field.name] || ""} onChange={(event) => setValues((current) => ({ ...current, [field.name]: event.target.value }))} required={field.required}>
                    <option value="">Select an option</option>
                    {field.options?.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                  </select>
                ) : (
                  <input type={field.type || "text"} value={values[field.name] || ""} placeholder={field.placeholder} onChange={(event) => setValues((current) => ({ ...current, [field.name]: event.target.value }))} required={field.required} />
                )}
              </label>
            ))}
          </div>
          <div className="modal-actions"><button className="secondary" type="button" onClick={onClose}>Cancel</button><button className="primary" type="submit" disabled={loading}>{loading ? "Submitting…" : action.label}</button></div>
        </form>
      </section>
    </div>
  );
}

function ScreenSidebar({ moduleId, activeId }: { moduleId: string; activeId: string }) {
  const module = getModule(moduleId);
  if (!module) return null;
  return (
    <aside className="screen-sidebar">
      <p>IN THIS MODULE</p>
      <h2>{module.title}</h2>
      <nav>
        {module.screens.map((item) => <Link className={item.id === activeId ? "active" : ""} key={item.id} to={modulePath(module.id, item.id)}>{item.shortTitle || item.title}<ChevronRight size={15} /></Link>)}
      </nav>
    </aside>
  );
}

function ForensicReportDocumentControls({ report }: { report: UnknownRecord }) {
  const reportID = getRecordId(report);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function openDocument(download: boolean) {
    if (!reportID) return;
    setBusy(true); setError(null); setNotice(null);
    try {
      const pdf = await apiBlob(`/deepfake-forensics/forensic-reports/${reportID}/${download ? "download" : "preview"}`, { method: "POST", body: { access_password: password } });
      const url = URL.createObjectURL(pdf);
      if (download) { const link = document.createElement("a"); link.href = url; link.download = `${String(report.report_number || "forensic-report")}.pdf`; link.click(); URL.revokeObjectURL(url); }
      else { window.open(url, "_blank", "noopener,noreferrer"); window.setTimeout(() => URL.revokeObjectURL(url), 60_000); }
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to open the forensic report."); }
    finally { setBusy(false); }
  }

  async function setAccessPassword() {
    if (!reportID) return;
    if (password.length < 12) { setError("Use at least 12 characters for the evidence access password."); return; }
    if (password !== confirmation) { setError("Password and confirmation do not match."); return; }
    setBusy(true); setError(null); setNotice(null);
    try { await api.post(`/deepfake-forensics/forensic-reports/${reportID}/access-password`, { access_password: password }); setConfirmation(""); setNotice("Evidence access password saved. It is stored only as a secure hash."); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to set the evidence access password."); }
    finally { setBusy(false); }
  }

  return <section className="soc-detail-section"><h3>Protected evidence document</h3><p>The PDF preserves the recorded asset identity and SHA-256. Set an access password before sharing it; the password itself is never stored or displayed.</p>{error && <div className="alert alert-error">{error}</div>}{notice && <div className="alert alert-success">{notice}</div>}<div className="form-grid"><label>Evidence access password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="At least 12 characters" /></label><label>Confirm password<input type="password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} placeholder="Required when setting or changing" /></label></div><div className="modal-actions"><button className="secondary" type="button" disabled={busy} onClick={() => void openDocument(false)}>View PDF</button><button className="secondary" type="button" disabled={busy} onClick={() => void openDocument(true)}>Download PDF</button><button className="primary" type="button" disabled={busy} onClick={() => void setAccessPassword()}>{busy ? "Working…" : "Set / change password"}</button></div></section>;
}

export function ModuleWorkspacePage() {
  const { moduleId, screenId } = useParams();
  const user = session.getUser<{ roles?: string[]; permissions?: string[] }>();
  const module = getModule(moduleId);
  const screen = getScreen(moduleId, screenId);
  const userHasAccess = canAccessModule(moduleId, user);
  const [resources, setResources] = useState<ResourceState[]>([]);
  const [detail, setDetail] = useState<DetailState>(null);
  const [activeAction, setActiveAction] = useState<ScreenAction | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string>();
  const [selectedLabel,setSelectedLabel]=useState<string>();

  const loadResources = useCallback(async () => {
    if (!screen?.sources?.length) {
      setResources([]);
      return;
    }
    setResources(screen.sources.map((source) => ({ source, status: "loading" })));
    const loaded = await Promise.all(screen.sources.map(async (source): Promise<ResourceState> => {
      try {
        const data = await api.get<unknown>(source.path);
        if(moduleId==="adaptive-deception"&&screenId==="health"&&source.id==="canaries"){
          const canaries=toCollection(data).filter(isRecord);
          const healthRecords=await Promise.all(canaries.map(async canary=>{
            const id=getRecordId(canary);if(!id)return canary;
            try{const response=objectValue(await api.get<unknown>(`/adaptive-deception/canaries/${encodeURIComponent(id)}/health`));const check=objectValue(response.latest_health_check);const snapshot=objectValue(response.canary_file);return {...canary,...snapshot,...check,id,file_name:snapshot.file_name||canary.file_name||getRecordLabel(canary),canary_file_id:id,canary_status:canary.status,status:check.health_status||"NOT_CHECKED"};}
            catch{return {...canary,id,file_name:canary.file_name||getRecordLabel(canary),health_status:"NOT_CHECKED",status:"NOT_CHECKED",is_healthy:false,health_score:0,canary_file_id:id,canary_status:canary.status};}
          }));
          return {source,status:"success",data:healthRecords};
        }
        return { source, status: "success", data };
      } catch (err) {
        return { source, status: "error", error: err instanceof Error ? err.message : "Unknown API error" };
      }
    }));
    setResources(loaded);
  }, [screen,moduleId,screenId]);

  useEffect(() => { void loadResources(); }, [loadResources]);
  useEffect(()=>{setSelectedId(undefined);setSelectedLabel(undefined);setNotice(null)},[moduleId,screenId]);

  const connectedCount = useMemo(() => resources.filter((resource) => resource.status === "success").length, [resources]);
  const workspaceRecords = useMemo(() => resources.flatMap((resource) => resource.status === "success" ? toCollection(resource.data) : []), [resources]);
  const workspaceStatuses = useMemo(() => {
    const counts = new Map<string, number>();
    for (const record of workspaceRecords) {
      const status = isRecord(record) ? getRecordStatus(record) : "";
      if (status) counts.set(status, (counts.get(status) || 0) + 1);
    }
    return [...counts.entries()].sort((left, right) => right[1] - left[1]).slice(0, 4);
  }, [workspaceRecords]);
  const adaptiveHealthRecords=useMemo(()=>moduleId==="adaptive-deception"&&screenId==="health"?toCollection(resources.find(resource=>resource.source.id==="canaries")?.data).filter(isRecord):[],[moduleId,screenId,resources]);
  const selectedHealthRecord=adaptiveHealthRecords.find(record=>getRecordId(record)===selectedId);
  const preEncryptionEngine=moduleId==="pre-encryption"?resources.find(resource=>resource.source.id==="health"):undefined;
  const preEncryptionEngineStatus=preEncryptionEngine?.status==="success"?String(objectValue(preEncryptionEngine.data).status||"HEALTHY"):preEncryptionEngine?.status==="error"?"UNAVAILABLE":"CHECKING";
  if (!module || !screen || !moduleId || !screenId) return <Navigate to="/dashboard" replace />;
  if (!userHasAccess) {
    return <div className="page"><div className="hero"><div><h1>Access denied</h1><p>You do not have permission to view this workspace for your current organization.</p></div></div><div className="alert alert-error">This module is restricted to authorized users only. Organization data remains isolated and is never shared across tenants.</div></div>;
  }

  async function inspect(source: ApiSource, record: unknown) {
    const id = getRecordId(record);
    if (!id) return;
    const isRotationHistory = moduleId === "adaptive-deception" && screenId === "rotation" && source.id === "history";
    const usesExplicitCanarySelection=moduleId==="adaptive-deception"&&source.id==="canaries"&&(screenId==="health"||screenId==="rotation");
    if (!isRotationHistory&&!usesExplicitCanarySelection) setSelectedId(id);
    if (!source.detailPath) {
      setNotice(`${getRecordLabel(record)} selected for workflow actions.`);
      return;
    }
    setDetail({ title: `${source.label}: ${getRecordLabel(record)}`, status: "loading" });
    try {
      const data = await api.get<unknown>(interpolatePath(source.detailPath, id));
      setDetail({ title: `${source.label}: ${getRecordLabel(record)}`, status: "success", data });
    } catch (err) {
      setDetail({ title: `${source.label}: ${getRecordLabel(record)}`, status: "error", error: err instanceof Error ? err.message : "Unable to load record details" });
    }
  }
  function selectWorkflowRecord(record:unknown){const id=getRecordId(record);if(!id)return;if(selectedId===id){setSelectedId(undefined);setSelectedLabel(undefined);setNotice(`${getRecordLabel(record)} unselected.`);return;}setSelectedId(id);setSelectedLabel(getRecordLabel(record));setNotice(`${getRecordLabel(record)} selected. You can now run the action above.`)}

  return (
    <div className="module-layout">
      <ScreenSidebar moduleId={moduleId} activeId={screenId} />
      <section className="page module-page">
        <header className="hero module-hero">
          <div>
            <div className="breadcrumbs"><Link to="/dashboard">SOC Command</Link><ChevronRight size={14} /><span>{module.title}</span></div>
            <h1>{screen.title}</h1>
            <p>{screen.description}</p>
          </div>
          <div className="hero-actions">
            {screen.actions?.map((action) => <button key={action.label} className="primary" type="button" disabled={action.path.includes(":id") && !selectedId} title={action.path.includes(":id") && !selectedId ? "Open a record first" : undefined} onClick={() => setActiveAction(action)}><Plus size={16} /> {action.label}</button>)}
            {screen.sources?.length ? <button className="secondary with-icon" type="button" onClick={() => void loadResources()}><RefreshCw size={16} /> Refresh</button> : null}
          </div>
        </header>
        {moduleId === "pre-encryption" && <div className="module-role-callout"><strong>Role in this platform</strong><span>Correlates rapid file changes and suspicious process activity to detect ransomware before mass encryption begins, then sends the finding to the response team.</span></div>}
        {moduleId === "adaptive-deception" && <AdaptiveDeceptionGuide screenId={screenId}/>} 
        {notice && <div className="alert alert-success" role="status"><Check size={17} /> {notice}</div>}
        {screen.unavailable ? (
          <div className="api-unavailable"><CircleOff size={23} /><div><h2>Backend API not available yet</h2><p>{screen.unavailable}</p><span>This interface does not invent or display mock records.</span></div></div>
        ) : (
          <>
            <div className="connection-strip"><span className="live-dot" /> {connectedCount} of {screen.sources?.length || 0} live source{(screen.sources?.length || 0) === 1 ? "" : "s"} connected <span>·</span> API responses are displayed as returned by the backend.</div>
            {moduleId === "adaptive-deception" ? <AdaptiveSummary screenId={screenId} resources={resources}/> : <div className="iam-summary-grid" aria-label="Live workspace summary">
              <article><span>Total records</span><strong>{workspaceRecords.length}</strong><small>Across connected sources</small></article>
              <article><span>Matching search</span><strong>{workspaceRecords.filter((record) => matchesQuery(record, query)).length}</strong><small>Current filter</small></article>
              {workspaceStatuses.slice(0, 2).map(([status, count]) => <article key={status}><span>{status.replaceAll("_", " ")}</span><strong>{count}</strong><small>{workspaceRecords.length ? Math.round((count / workspaceRecords.length) * 100) : 0}% of loaded records</small></article>)}
            </div>}
            {moduleId==="pre-encryption"&&screenId==="dashboard"&&<div className={`engine-status-strip ${preEncryptionEngineStatus.toLowerCase()}`}><div><Zap size={19}/><span><small>DETECTION ENGINE</small><strong>Pre-encryption analysis service</strong></span></div><b>{preEncryptionEngineStatus}</b></div>}
            {!(moduleId==="adaptive-deception"&&screenId==="health")&&<label className="inventory-search"><Search size={16}/><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search all loaded fields…"/></label>}
            {moduleId==="adaptive-deception"&&screenId==="health"?<section className="health-focus"><header><div><p>CANARY HEALTH LOOKUP</p><h2>Choose one canary to inspect</h2><span>The page shows only the selected file's latest integrity result.</span></div><select value={selectedId||""} onChange={event=>{const record=adaptiveHealthRecords.find(item=>getRecordId(item)===event.target.value);if(record)selectWorkflowRecord(record);else{setSelectedId(undefined);setSelectedLabel(undefined)}}}><option value="">Select a canary file</option>{adaptiveHealthRecords.map(record=><option key={getRecordId(record)} value={getRecordId(record)}>{getRecordLabel(record)}</option>)}</select></header>{selectedHealthRecord?<><div className="workflow-selection ready"><div><small>SELECTED HEALTH TARGET</small><strong>{selectedLabel}</strong><span>Run a fresh check using the action above, or review the latest result below.</span></div><button type="button" className="secondary" onClick={()=>{setSelectedId(undefined);setSelectedLabel(undefined)}}>Clear selection</button></div><CanaryHealthVisual value={selectedHealthRecord}/></>:<div className="health-empty"><ShieldAlert size={28}/><strong>No canary selected</strong><span>Select a file above to view its integrity checks. No file inventory is displayed on this page.</span></div>}</section>:<>{moduleId==="adaptive-deception"&&screenId==="rotation"&&<div className={`workflow-selection ${selectedId?"ready":""}`}><div><small>WORKFLOW TARGET</small><strong>{selectedLabel||"No canary selected"}</strong><span>{selectedId?"The action will apply only to this canary file.":"Use the Select button beside a canary file before running the action."}</span></div>{selectedId&&<button type="button" className="secondary" onClick={()=>{setSelectedId(undefined);setSelectedLabel(undefined)}}>Clear selection</button>}</div>}<div className={`resource-stack ${moduleId==="adaptive-deception"&&screenId==="rotation"?"adaptive-rotation-stack":""}`}>
              {resources.filter(resource=>!(moduleId==="pre-encryption"&&screenId==="dashboard"&&resource.source.id==="health")).map((resource) => (
                <article className="resource-card" key={resource.source.id}>
                  <div className="resource-heading"><div><p>LIVE SOURCE</p><h2>{resource.source.label}</h2>{resource.source.description && <span>{resource.source.description}</span>}</div><code>{resource.source.path}</code></div>
                  <ResourceContents resource={resource} onInspect={inspect} onSelect={selectWorkflowRecord} selectedId={selectedId} query={query} moduleId={moduleId} screenId={screenId} />
                </article>
              ))}
              {!resources.length && <div className="empty-inline"><CircleOff size={18} /> No live source is configured for this screen.</div>}
            </div></>}
          </>
        )}
      </section>
      {detail && <><button type="button" className="module-detail-backdrop" aria-label="Close record details" onClick={() => setDetail(null)}/><aside className="details-panel" aria-live="polite"><div className="details-panel-head"><div><p>LIVE RECORD DETAIL</p><h2>{detail.title}</h2></div><button type="button" className="icon-button" onClick={() => setDetail(null)} aria-label="Close details"><X size={18} /></button></div><div className="details-panel-body">{detail.status === "loading" ? <div className="resource-loading"><LoaderCircle size={18} className="spin" /> Loading record…</div> : detail.status === "error" ? <div className="resource-error"><AlertCircle size={17} /><span>{detail.error}</span></div> : moduleId === "adaptive-deception"&&screenId==="fingerprints" ? <FingerprintVisual value={detail.data}/> : moduleId === "adaptive-deception"&&screenId==="health" ? <CanaryHealthVisual value={detail.data}/> : moduleId === "adaptive-deception"&&screenId==="rotation" ? <CanaryRotationVisual value={detail.data}/> : moduleId === "pre-encryption" ? <PreEncryptionVisual value={detail.data}/> : <>{screenId === "reports" && isRecord(detail.data) ? <ForensicReportDocumentControls report={detail.data} /> : null}<JSONDetail value={detail.data} /></>}</div></aside></>}
      {activeAction && <ActionDialog action={activeAction} selectedId={selectedId} selectedLabel={selectedLabel} onClose={() => setActiveAction(null)} onCompleted={(message) => { setNotice(message); void loadResources(); }} />}
    </div>
  );
}
