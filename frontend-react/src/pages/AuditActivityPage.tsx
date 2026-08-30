import { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, BellRing, CalendarDays, Eye, RefreshCw, Search, Volume2, VolumeX, X } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { api, ApiError } from "../lib/api";

type EventRow = Record<string, unknown> & { id: string };
type DetailItem = { label: string; value: unknown; date?: boolean };
type AuditFilters = { source: string; severity: string; suspicious: boolean; from: string; to: string };
type TimelineList = { items?: EventRow[]; total?: number; page?: number; page_size?: number; total_pages?: number };

const emptyFilters: AuditFilters = { source: "", severity: "", suspicious: false, from: "", to: "" };
const text = (value: unknown) => value == null || value === "" ? "Not reported" : String(value);
const date = (value: unknown) => value ? new Date(String(value)).toLocaleString() : "Not reported";
const bytes = (value: unknown) => { if (value == null || value === "") return "Not reported"; const size=Number(value); if(!Number.isFinite(size))return text(value); if(size<1024)return `${size} B`; if(size<1048576)return `${(size/1024).toFixed(1)} KB`; return `${(size/1048576).toFixed(2)} MB`; };

function playAlert(event: EventRow) {
  try { const AudioContextCtor=window.AudioContext || (window as unknown as {webkitAudioContext?:typeof AudioContext}).webkitAudioContext; if(AudioContextCtor){const context=new AudioContextCtor(); const oscillator=context.createOscillator(); const gain=context.createGain(); oscillator.frequency.value=event.severity === "CRITICAL" ? 880 : 660; gain.gain.setValueAtTime(.04,context.currentTime); gain.gain.exponentialRampToValueAtTime(.001,context.currentTime+.35); oscillator.connect(gain).connect(context.destination); oscillator.start(); oscillator.stop(context.currentTime+.35); oscillator.addEventListener("ended",()=>void context.close());} if("Notification" in window && Notification.permission === "granted") new Notification("New security event",{body:`${text(event.event_type)} · ${text(event.file_name)}`}); } catch { /* Browser policy can block audio until a user gesture. */ }
}

function requestParams(filters: AuditFilters, query: string, page: number) {
  const params=new URLSearchParams({page:String(page),page_size:"100"});
  if(filters.source)params.set("source_type",filters.source);
  if(filters.severity)params.set("risk_level",filters.severity);
  if(filters.suspicious)params.set("suspicious","true");
  if(filters.from)params.set("from",new Date(`${filters.from}T00:00:00`).toISOString());
  if(filters.to)params.set("to",new Date(`${filters.to}T23:59:59.999`).toISOString());
  if(query.trim())params.set("search",query.trim());
  return params;
}

function timelineRow(entry: EventRow): EventRow { return {...entry, file_name:entry.resource, system_username:entry.actor, process_name:entry.event_source, is_suspicious:entry.severity === "HIGH" || entry.severity === "CRITICAL"}; }

export function AuditActivityPage() {
  const [searchParams] = useSearchParams();
  const requestedSource = searchParams.get("source") || "";
  const initialFilters = ["PROTECTED_FILE", "HONEYTOKEN", "CANARY_FILE", "UNMANAGED_FILE"].includes(requestedSource) ? { ...emptyFilters, source: requestedSource } : emptyFilters;
  const [items,setItems]=useState<EventRow[]>([]);
  const [query,setQuery]=useState("");
  const [draft,setDraft]=useState<AuditFilters>(initialFilters);
  const [applied,setApplied]=useState<AuditFilters>(initialFilters);
  const [total,setTotal]=useState(0);
  const [page,setPage]=useState(1);
  const [totalPages,setTotalPages]=useState(1);
  const [loading,setLoading]=useState(false);
  const [error,setError]=useState("");
  const [selected,setSelected]=useState<EventRow|null>(null);
  const [alert,setAlert]=useState<EventRow|null>(null);
  const [alertsEnabled,setAlertsEnabled]=useState(()=>localStorage.getItem("ddh_deception_alerts")==="enabled");
  const alertFeedInitialized=useRef(false);
  const alertIds=useRef(new Set<string>());

  const load=useCallback(async(filters: AuditFilters, withSpinner=true)=>{
    if(withSpinner)setLoading(true);
    try{
      const result=await api.get<TimelineList>(`/admin/audit-activity?${requestParams(filters,query,page).toString()}`);
      const rows=Array.isArray(result.items)?result.items.map(timelineRow):[];
      setItems(rows);
      setTotal(Number(result.total||0));
      setTotalPages(Math.max(1,Number(result.total_pages||Math.ceil(Number(result.total||0)/100))));
      setError("");
    }catch(reason){
      const message=reason instanceof Error?reason.message:"Unable to load audit events.";
      const detail=reason instanceof ApiError&&typeof reason.details==="string"?reason.details:"";
      setError(detail?`${message}: ${detail}`:message);
    }
    finally{if(withSpinner)setLoading(false);}
  },[page,query]);

  const pollSecurityAlerts=useCallback(async()=>{
    try{
      const result=await api.get<TimelineList>("/admin/audit-activity?page=1&page_size=100");
      const next=Array.isArray(result.items)?result.items:[];
      if(alertFeedInitialized.current){
        const critical=next.find(event=>!alertIds.current.has(event.id)&&(event.source_type==="CANARY_FILE"||event.source_type==="HONEYTOKEN"||event.severity==="CRITICAL"));
        if(critical){
          setAlert(critical);
          if(alertsEnabled) playAlert(critical);
        }
      }
      alertIds.current=new Set(next.map(event=>event.id));
      alertFeedInitialized.current=true;
    }catch{
      // The visible audit request reports connectivity errors. Polling must not overwrite it.
    }
  },[alertsEnabled]);

  useEffect(()=>{void load(applied);},[applied,load]);
  useEffect(()=>{void pollSecurityAlerts();const timer=window.setInterval(()=>{void pollSecurityAlerts();void load(applied,false);},15000);return()=>window.clearInterval(timer);},[applied,load,pollSecurityAlerts]);

  async function toggleAlerts(){
    if(alertsEnabled){localStorage.removeItem("ddh_deception_alerts");setAlertsEnabled(false);return;}
    if("Notification" in window&&Notification.permission==="default")await Notification.requestPermission();
    localStorage.setItem("ddh_deception_alerts","enabled");
    setAlertsEnabled(true);
    if("Notification" in window&&Notification.permission==="denied")setError("Sound alerts are enabled, but browser desktop notifications are blocked in the site settings.");
  }

  function applyFilters(){
    if(draft.from&&draft.to&&draft.from>draft.to){setError("The From date must be earlier than or equal to the To date.");return;}
    setError("");
    setPage(1);setApplied({...draft});
  }

  function clearFilters(){setDraft(emptyFilters);setApplied(emptyFilters);setQuery("");setPage(1);setError("");}
  function openPicker(event: React.MouseEvent<HTMLInputElement>){const input=event.currentTarget as HTMLInputElement&{showPicker?:()=>void};input.showPicker?.();}

  function exportVisibleEvents(){
    const columns=["occurred_at","event_code","source_type","event_type","severity","status","file_name","system_username","device_name","process_name","threat_score","is_suspicious"];
    const quote=(value:unknown)=>`"${String(value??"").replaceAll('"','""')}"`;
    const csv=[columns.join(","),...filtered.map(item=>columns.map(column=>quote(item[column])).join(","))].join("\r\n");
    const url=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));
    const link=document.createElement("a");link.href=url;link.download=`ddh-audit-events-${new Date().toISOString().slice(0,10)}.csv`;link.click();URL.revokeObjectURL(url);
  }

  const filtered=items;

  return <section className="page deception-page audit-page">
    <header className="deception-header"><div><span className="eyebrow">CENTRAL SECURITY TIMELINE</span><h1>Audit Activity</h1><p>Real file and deception events reported by managed agents. Missing values are shown as not reported.</p></div><div className="deception-actions"><button className={alertsEnabled?"secondary with-icon alert-enabled":"secondary with-icon"} type="button" onClick={()=>void toggleAlerts()} title={alertsEnabled?"Disable sound and desktop alerts":"Enable alerts for newly received security events"}>{alertsEnabled?<Volume2 size={16}/>:<VolumeX size={16}/>} {alertsEnabled?"Alerts enabled":"Enable alerts"}</button><button className="secondary with-icon" type="button" onClick={()=>{void load(applied);void pollSecurityAlerts();}} disabled={loading}><RefreshCw className={loading?"spin":""} size={16}/>{loading?"Refreshing…":"Refresh"}</button></div></header>
    {alert&&<div className="critical-event-banner"><BellRing/><div><strong>New deception event</strong><span>{text(alert.event_type)} · {text(alert.file_name)} · {text(alert.device_name)}</span></div><button type="button" onClick={()=>setAlert(null)}>Acknowledge</button></div>}
    {error&&<div className="alert alert-error"><AlertTriangle size={17}/>{error}</div>}
    <article className="deception-inventory">
      <div className="audit-filter-panel">
        <div className="audit-filter-primary"><label className="inventory-search"><Search size={16}/><input value={query} onChange={event=>setQuery(event.target.value)} placeholder="Search user, resource, device, event code or action"/></label><label><span>Source</span><select value={draft.source} onChange={event=>setDraft(current=>({...current,source:event.target.value}))}><option value="">All sources</option>{["ADMIN_AUDIT","PROTECTED_FILE","HONEYTOKEN","CANARY_FILE","UNMANAGED_FILE","THREAT","INCIDENT","FORENSIC_REVIEW","FORENSIC_ANNOTATION"].map(value=><option key={value}>{value}</option>)}</select></label><label><span>Risk</span><select value={draft.severity} onChange={event=>setDraft(current=>({...current,severity:event.target.value}))}><option value="">All risks</option>{["LOW","MEDIUM","HIGH","CRITICAL"].map(value=><option key={value}>{value}</option>)}</select></label><label className="checkbox-field"><input type="checkbox" checked={draft.suspicious} onChange={event=>setDraft(current=>({...current,suspicious:event.target.checked}))}/><span>Suspicious only</span></label></div>
        <div className="audit-filter-secondary"><div className="audit-date-range"><CalendarDays size={17}/><label><span>From</span><input type="date" value={draft.from} onClick={openPicker} onChange={event=>setDraft(current=>({...current,from:event.target.value}))}/></label><span className="date-separator">to</span><label><span>To</span><input type="date" value={draft.to} onClick={openPicker} onChange={event=>setDraft(current=>({...current,to:event.target.value}))}/></label></div><div className="audit-filter-actions"><button className="secondary" type="button" onClick={clearFilters}>Clear</button><button className="primary" type="button" onClick={applyFilters}>Apply filters</button></div></div>
      </div>
      <div className="audit-result-count"><span>Showing {total?((page-1)*100)+1:0}–{Math.min(page*100,total)} of {total} matching backend events{loading?" · Refreshing…":""}</span><div className="audit-pagination"><button type="button" className="secondary" disabled={loading||page<=1} onClick={()=>setPage(current=>Math.max(1,current-1))}>Previous</button><strong>Page {page} of {totalPages}</strong><button type="button" className="secondary" disabled={loading||page>=totalPages} onClick={()=>setPage(current=>Math.min(totalPages,current+1))}>Next</button><button type="button" className="secondary" disabled={!filtered.length} onClick={exportVisibleEvents}>Export this page</button></div></div>
      <div className="table-wrap"><table className="table deception-table audit-table"><thead><tr><th>Time</th><th>User / device</th><th>Category</th><th>Action</th><th>Resource</th><th>Risk</th><th>Status</th><th/></tr></thead><tbody>{filtered.map(row=><tr key={row.id} onClick={()=>setSelected(row)}><td>{date(row.occurred_at)}</td><td><strong>{text(row.system_username)}</strong><small>{text(row.device_name)}</small></td><td>{text(row.source_type)}</td><td>{text(row.event_type)}</td><td>{text(row.file_name)}</td><td><span className={`severity ${text(row.severity).toLowerCase()}`}>{text(row.severity)}</span></td><td>{text(row.status)}</td><td><Eye size={16}/></td></tr>)}</tbody></table>{!loading&&!filtered.length&&<div className="empty-inline">No matching backend audit records.</div>}</div>
    </article>
    {selected&&<AuditDrawer event={selected} onClose={()=>setSelected(null)}/>} 
  </section>;
}

function AuditDrawer({event,onClose}:{event:EventRow;onClose:()=>void}){
  const groups:{title:string;items:DetailItem[]}[]=[
    {title:"Event identity",items:[{label:"Event code",value:event.event_code},{label:"Sequence",value:event.event_sequence},{label:"Source",value:event.source_type},{label:"Action",value:event.event_type},{label:"Collector",value:event.event_source},{label:"Detection method",value:event.detection_method}]},
    {title:"Resource",items:[{label:"File name",value:event.file_name},{label:"Extension",value:event.file_extension},{label:"MIME type",value:event.mime_type},{label:"Size before",value:bytes(event.file_size_before)},{label:"Size after",value:bytes(event.file_size_after)},{label:"Hash algorithm",value:event.hash_algorithm}]},
    {title:"Actor and device",items:[{label:"System user",value:event.system_username},{label:"Device",value:event.device_name},{label:"Device identifier",value:event.device_identifier},{label:"Process",value:event.process_name},{label:"Process ID",value:event.process_id},{label:"Parent process",value:event.parent_process_name}]},
    {title:"Risk assessment",items:[{label:"Severity",value:event.severity},{label:"Threat score",value:event.threat_score},{label:"Suspicious",value:event.is_suspicious===true?"Yes":"No"},{label:"Processing status",value:event.status}]},
    {title:"Integrity",items:[{label:"Previous hash",value:event.previous_hash},{label:"Current hash",value:event.current_hash},{label:"Process hash",value:event.process_hash},{label:"Evidence hash",value:event.evidence_hash}]},
    {title:"Timeline",items:[{label:"Occurred",value:event.occurred_at,date:true},{label:"Received",value:event.received_at,date:true},{label:"Processed",value:event.processed_at,date:true},{label:"Updated",value:event.updated_at,date:true}]}
  ];
  return <><button className="drawer-backdrop" type="button" aria-label="Close event details" onClick={onClose}/><aside className="deception-drawer"><div className="drawer-heading"><div><span className="eyebrow">SAFE FORENSIC EVENT</span><h2>{text(event.event_code)}</h2></div><button type="button" onClick={onClose}><X size={18}/></button></div>{groups.map(group=><section className="audit-detail-section" key={group.title}><h3>{group.title}</h3><dl className="detail-grid">{group.items.map(item=><div key={item.label}><dt>{item.label}</dt><dd>{item.date?date(item.value):text(item.value)}</dd></div>)}</dl></section>)}</aside></>;
}
