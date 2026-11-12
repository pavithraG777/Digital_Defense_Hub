import { useEffect, useMemo, useState } from "react";
import { Activity, Crosshair, FileCheck2, Network, RefreshCw, Search, ShieldCheck, Siren } from "lucide-react";
import { api } from "../lib/api";
import "./dfirWorkspace.css";

type Incident = { id:string; incident_number:string; incident_title:string; description?:string; incident_category:string; severity:string; priority:string; status:string; detection_source:string; affected_device_name?:string; ransomware_suspected:boolean; device_isolated:boolean; evidence_preserved:boolean; detected_at:string; created_at:string; initial_findings?:string; root_cause?:string; containment_summary?:string; resolution_summary?:string };
type Evidence = { id:string; evidence_code:string; evidence_type:string; evidence_name:string; original_file_name?:string; hash_algorithm:string; evidence_hash?:string; integrity_status:string; collected_at:string };
type Timeline = { id:string; event_type:string; title:string; description?:string; occurred_at:string; new_status?:string };
type IncidentPage = { incidents:Incident[]; total:number };
type EvidencePage = { evidence:Evidence[]; total:number };
type TimelinePage = { entries:Timeline[]; total:number };

const readable = (value?:string) => value ? value.replaceAll("_", " ") : "Not reported";

export function DfirWorkspacePage() {
  const [incidents,setIncidents]=useState<Incident[]>([]);
  const [selected,setSelected]=useState<Incident|null>(null);
  const [evidence,setEvidence]=useState<Evidence[]>([]);
  const [timeline,setTimeline]=useState<Timeline[]>([]);
  const [query,setQuery]=useState("");
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState("");

  const load=async()=>{setLoading(true);setError("");try{const result=await api.get<IncidentPage>("/incidents?page=1&page_size=100");setIncidents(result.incidents||[]);}catch(reason){setError(reason instanceof Error?reason.message:"Unable to load incidents for DFIR.");}finally{setLoading(false);}};
  useEffect(()=>{void load();},[]);
  const visible=useMemo(()=>incidents.filter(item=>`${item.incident_number} ${item.incident_title} ${item.affected_device_name||""}`.toLowerCase().includes(query.toLowerCase())),[incidents,query]);

  const open=async(item:Incident)=>{setSelected(item);setEvidence([]);setTimeline([]);setError("");try{const [record,evidenceResult,timelineResult]=await Promise.all([api.get<Incident>(`/incidents/${item.id}`),api.get<EvidencePage>(`/incidents/${item.id}/evidence?page=1&page_size=100`),api.get<TimelinePage>(`/incidents/${item.id}/timeline?page=1&page_size=100`)]);setSelected(record);setEvidence(evidenceResult.evidence||[]);setTimeline(timelineResult.entries||[]);}catch(reason){setError(reason instanceof Error?reason.message:"Unable to load forensic case evidence.");}};

  return <div className="dfir-page">
    <header className="dfir-hero"><div><span>INCIDENT INVESTIGATION</span><h1>Digital Forensics &amp; Incident Response</h1><p>Incident Creation opens the official security case. DFIR uses that same case to establish what happened, preserve proof, build the attack timeline, contain the threat and document recovery.</p></div><button onClick={()=>void load()} disabled={loading}><RefreshCw size={17}/>{loading?"Loading…":"Refresh"}</button></header>
    <section className="dfir-flow"><article><Siren/><b>1</b><span>Threat detected</span><small>Canary, honeytoken, ransomware, malware or deepfake signal</small></article><i>→</i><article><ShieldCheck/><b>2</b><span>Incident created</span><small>Official tenant-scoped case with severity and affected resource</small></article><i>→</i><article><Crosshair/><b>3</b><span>DFIR investigation</span><small>Evidence, hashes, actor/process trace and event timeline</small></article><i>→</i><article><Activity/><b>4</b><span>Respond &amp; recover</span><small>Contain, eradicate, recover and close with an audit trail</small></article></section>
    {error&&<div className="dfir-error">{error}</div>}
    <section className="dfir-workspace">
      <div className="dfir-cases"><div className="dfir-section-head"><div><span>OFFICIAL CASES</span><h2>Incidents awaiting forensic work</h2></div><label><Search size={16}/><input value={query} onChange={event=>setQuery(event.target.value)} placeholder="Search incident or device"/></label></div>{!loading&&!visible.length?<div className="dfir-empty">No incidents are available in this organization.</div>:visible.map(item=><button key={item.id} className={selected?.id===item.id?"selected":""} onClick={()=>void open(item)}><span className={`dfir-severity ${item.severity.toLowerCase()}`}>{item.severity}</span><span><strong>{item.incident_number} · {item.incident_title}</strong><small>{readable(item.detection_source)} · {item.affected_device_name||"Device not reported"}</small></span><span><b>{readable(item.status)}</b><small>{new Date(item.created_at).toLocaleString()}</small></span></button>)}</div>
      <aside className="dfir-detail">{!selected?<div className="dfir-empty"><Crosshair/><h3>Select an incident</h3><p>The forensic evidence and attack timeline for that official case will appear here.</p></div>:<><header><span>{readable(selected.incident_category)}</span><h2>{selected.incident_number}</h2><p>{selected.incident_title}</p></header><div className="dfir-posture"><div className={selected.device_isolated?"done":"pending"}>Containment<b>{selected.device_isolated?"Device isolated":"Action pending"}</b></div><div className={selected.evidence_preserved?"done":"pending"}>Evidence<b>{selected.evidence_preserved?"Preserved":"Not preserved"}</b></div><div className={selected.ransomware_suspected?"risk":"done"}>Ransomware<b>{selected.ransomware_suspected?"Suspected":"No current flag"}</b></div></div><section><h3><FileCheck2/> Preserved evidence <em>{evidence.length}</em></h3>{evidence.length?evidence.map(item=><article className="dfir-evidence" key={item.id}><FileCheck2/><div><b>{item.evidence_name}</b><span>{readable(item.evidence_type)} · {item.evidence_code}</span><code>{item.hash_algorithm} {item.evidence_hash||"Hash not recorded"}</code></div><small>{readable(item.integrity_status)}</small></article>):<p className="muted">No evidence has been linked yet. Preserve file, endpoint, network or media evidence before remediation.</p>}</section><section><h3><Network/> Attack and response timeline <em>{timeline.length}</em></h3>{timeline.length?<ol>{timeline.map(item=><li key={item.id}><time>{new Date(item.occurred_at).toLocaleString()}</time><b>{item.title}</b><span>{item.description||readable(item.event_type)}</span></li>)}</ol>:<p className="muted">No forensic timeline entries are available yet.</p>}</section></>}</aside>
    </section>
  </div>;
}
