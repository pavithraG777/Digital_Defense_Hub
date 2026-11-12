import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Activity, CheckCircle2, FileCheck2, FolderSearch2, Link2, LockKeyhole, Microscope, Plus, RefreshCw, Search, ShieldAlert, Siren } from "lucide-react";
import { api } from "../lib/api";
import { DetailDrawer, EmptyState, ErrorBanner, FactGrid, LoadingState, MetricCard, StatusBadge, formatDate, humanize } from "./securityOperationsUI";
import "./securityOperations.css";
import "./investigationFlow.css";

type Case = { id:string; case_number:string; title:string; description?:string; status:string; priority:string; opened_at:string; closed_at?:string; updated_at:string };
type Incident = { id:string; incident_number:string; incident_title:string; severity:string; status:string; description?:string; category?:string; source?:string; affected_device_name?:string; affected_device_ip?:string; initial_findings?:string; root_cause?:string; containment_actions?:string; resolution_summary?:string };
type IncidentThreat = { threat_id:string; threat_code:string; threat_type:string; severity:string; status:string; relation_type:string; added_at?:string };
type IncidentTimeline = { id:string; event_type:string; title:string; description?:string; previous_status?:string; new_status?:string; occurred_at?:string; created_at?:string };
type IncidentEvidence = { id:string; evidence_code:string; evidence_type:string; evidence_name:string; description?:string; original_file_name?:string; evidence_hash?:string; hash_algorithm?:string; integrity_status?:string; collected_at?:string };
type Correlated<T> = T & { incident_id:string; incident_number:string };
type CaseList = { cases:Case[]; total:number };
type IncidentList = { incidents:Incident[] };
const caseStatuses=["OPEN","ACTIVE","ON_HOLD","CLOSED","CANCELLED"];
const priorities=["LOW","MEDIUM","HIGH","URGENT"];

export function InvestigationCasesPage() {
  const [data,setData]=useState<CaseList|null>(null);
  const [incidents,setIncidents]=useState<Incident[]>([]);
  const [query,setQuery]=useState("");
  const [statusFilter,setStatusFilter]=useState("");
  const [priorityFilter,setPriorityFilter]=useState("");
  const [loading,setLoading]=useState(true);
  const [refreshing,setRefreshing]=useState(false);
  const [error,setError]=useState("");
  const [selected,setSelected]=useState<Case|null>(null);
  const [linked,setLinked]=useState<Incident[]>([]);
  const [caseThreats,setCaseThreats]=useState<Correlated<IncidentThreat>[]>([]);
  const [caseTimeline,setCaseTimeline]=useState<Correlated<IncidentTimeline>[]>([]);
  const [caseEvidence,setCaseEvidence]=useState<Correlated<IncidentEvidence>[]>([]);
  const [detailLoading,setDetailLoading]=useState(false);
  const [detailError,setDetailError]=useState("");
  const [createOpen,setCreateOpen]=useState(false);
  const [saving,setSaving]=useState(false);
  const [form,setForm]=useState({title:"",description:"",priority:"MEDIUM"});
  const [incidentID,setIncidentID]=useState("");

  const load=useCallback(async(refresh=false)=>{
    refresh?setRefreshing(true):setLoading(true); setError("");
    try {
      const [caseResult,incidentResult]=await Promise.all([
        api.get<CaseList>("/investigation-cases"),
        api.get<IncidentList>("/incidents?page=1&page_size=100").catch(()=>({incidents:[]})),
      ]);
      setData(caseResult); setIncidents(incidentResult.incidents||[]);
    } catch(cause) { setError(cause instanceof Error?cause.message:"Investigation cases could not be loaded."); }
    finally { setLoading(false); setRefreshing(false); }
  },[]);
  useEffect(()=>{void load();},[load]);

  const cases=data?.cases||[];
  const visible=useMemo(()=>cases.filter(item=>{
    const matchesText=`${item.case_number} ${item.title}`.toLowerCase().includes(query.trim().toLowerCase());
    return matchesText&&(!statusFilter||item.status===statusFilter)&&(!priorityFilter||item.priority===priorityFilter);
  }),[cases,query,statusFilter,priorityFilter]);
  const active=cases.filter(item=>!["CLOSED","CANCELLED"].includes(item.status)).length;
  const availableIncidents=incidents.filter(item=>!linked.some(link=>link.id===item.id));

  async function open(item:Case) {
    setSelected(item); setLinked([]); setCaseThreats([]); setCaseTimeline([]); setCaseEvidence([]); setDetailError(""); setDetailLoading(true);
    try {
      const [record,caseIncidents]=await Promise.all([
        api.get<Case>(`/investigation-cases/${encodeURIComponent(item.id)}`),
        api.get<Incident[]>(`/investigation-cases/${encodeURIComponent(item.id)}/incidents`),
      ]);
      const linkedRows=Array.isArray(caseIncidents)?caseIncidents:[];
      const enriched=await Promise.all(linkedRows.map(async incident=>{
        const base=`/incidents/${encodeURIComponent(incident.id)}`;
        const [detail,threatResult,timelineResult,evidenceResult]=await Promise.all([
          api.get<Incident>(base).catch(()=>incident),
          api.get<IncidentThreat[]|{threats:IncidentThreat[]}>(`${base}/threats`).catch(()=>[]),
          api.get<{entries:IncidentTimeline[]}>(`${base}/timeline?page=1&page_size=100`).catch(()=>({entries:[]})),
          api.get<{evidence:IncidentEvidence[]}>(`${base}/evidence?page=1&page_size=100`).catch(()=>({evidence:[]})),
        ]);
        const threats=Array.isArray(threatResult)?threatResult:threatResult.threats||[];
        const context={incident_id:incident.id,incident_number:incident.incident_number};
        return {detail:{...incident,...detail},threats:threats.map(value=>({...value,...context})),timeline:(timelineResult.entries||[]).map(value=>({...value,...context})),evidence:(evidenceResult.evidence||[]).map(value=>({...value,...context}))};
      }));
      setSelected(record); setLinked(enriched.map(value=>value.detail));
      setCaseThreats(enriched.flatMap(value=>value.threats));
      setCaseTimeline(enriched.flatMap(value=>value.timeline).sort((a,b)=>new Date(a.occurred_at||a.created_at||0).getTime()-new Date(b.occurred_at||b.created_at||0).getTime()));
      setCaseEvidence(enriched.flatMap(value=>value.evidence));
    } catch(cause) { setDetailError(cause instanceof Error?cause.message:"Case detail could not be loaded."); }
    finally { setDetailLoading(false); }
  }
  async function create(event:FormEvent) {
    event.preventDefault(); setSaving(true); setError("");
    try { await api.post("/investigation-cases",{title:form.title.trim(),description:form.description.trim()||undefined,priority:form.priority}); setCreateOpen(false); setForm({title:"",description:"",priority:"MEDIUM"}); await load(true); }
    catch(cause) { setError(cause instanceof Error?cause.message:"Investigation case could not be created."); }
    finally { setSaving(false); }
  }
  async function updateCase(patch:Record<string,string>) {
    if(!selected)return; setSaving(true); setDetailError("");
    try { const updated=await api.patch<Case>(`/investigation-cases/${encodeURIComponent(selected.id)}`,patch); setSelected(updated); await load(true); }
    catch(cause) { setDetailError(cause instanceof Error?cause.message:"Case could not be updated."); }
    finally { setSaving(false); }
  }
  async function linkIncident(event:FormEvent) {
    event.preventDefault(); if(!selected||!incidentID)return; setSaving(true); setDetailError("");
    try { await api.post(`/investigation-cases/${encodeURIComponent(selected.id)}/incidents`,{incident_id:incidentID}); setIncidentID(""); await open(selected); }
    catch(cause) { setDetailError(cause instanceof Error?cause.message:"Incident could not be linked."); }
    finally { setSaving(false); }
  }

  return <section className="page soc-ops-page">
    <header className="soc-ops-hero"><div><p className="eyebrow">SECURITY OPERATIONS · CASE MANAGEMENT</p><h1>Investigations</h1><span>Use evidence to reconstruct the complete story behind one or more incidents: what happened, how it happened, what was affected and the verified root cause.</span></div><div className="hero-actions"><button className="primary with-icon" onClick={()=>setCreateOpen(true)}><Plus size={16}/>Create case</button><button className="secondary with-icon" disabled={refreshing} onClick={()=>void load(true)}><RefreshCw size={16} className={refreshing?"spin":""}/>Refresh</button></div></header>
    <section className="investigation-flow" aria-label="Security investigation workflow"><article><ShieldAlert/><b>Threat detected</b><small>Security signal</small></article><i>→</i><article><Siren/><b>Incident created</b><small>Official record</small></article><i>→</i><article><FolderSearch2/><b>Case opened</b><small>Full investigation</small></article><i>→</i><article><LockKeyhole/><b>Evidence preserved</b><small>Integrity proof</small></article><i>→</i><article><Microscope/><b>DFIR analysis</b><small>Cause and timeline</small></article><i>→</i><article><CheckCircle2/><b>Respond &amp; close</b><small>Verified recovery</small></article></section>
    <div className="soc-role-guide"><article><ShieldAlert size={19}/><div><strong>Incident Response</strong><span>Immediate action: assign, contain, eradicate and recover one incident.</span></div></article><i>→</i><article><FolderSearch2 size={19}/><div><strong>Investigation</strong><span>Deep analysis: correlate incidents, reconstruct the timeline, preserve evidence and establish root cause.</span></div></article></div>
    {error&&<ErrorBanner message={error}/>}
    <div className="soc-filterbar investigation-filters"><label className="soc-search"><Search size={17}/><input value={query} onChange={event=>setQuery(event.target.value)} placeholder="Search case number or title"/></label><label><span>Status</span><select value={statusFilter} onChange={event=>setStatusFilter(event.target.value)}><option value="">All statuses</option>{caseStatuses.map(value=><option key={value} value={value}>{humanize(value)}</option>)}</select></label><label><span>Priority</span><select value={priorityFilter} onChange={event=>setPriorityFilter(event.target.value)}><option value="">All priorities</option>{priorities.map(value=><option key={value} value={value}>{humanize(value)}</option>)}</select></label><button type="button" className="secondary" onClick={()=>{setQuery("");setStatusFilter("");setPriorityFilter("");}}>Clear filters</button></div>
    {loading?<LoadingState label="Loading investigation cases…"/>:<><div className="soc-metrics"><MetricCard label="Total cases" value={data?.total||0}/><MetricCard label="Active" value={active} accent="amber"/><MetricCard label="Open" value={cases.filter(item=>item.status==="OPEN").length} accent="violet"/><MetricCard label="Urgent" value={cases.filter(item=>item.priority==="URGENT").length} accent="red"/></div>{!visible.length?<EmptyState title="No investigation cases" message={cases.length?"No case matches this search.":"Create a case to begin linking incidents and preserving evidence."}/>:<article className="soc-panel soc-table-panel"><header><div><p>LIVE CASE DIRECTORY</p><h2>Investigation records</h2></div><FolderSearch2 size={20}/></header><div className="table-wrap"><table className="soc-table"><thead><tr><th>Case</th><th>Priority</th><th>Status</th><th>Opened</th><th/></tr></thead><tbody>{visible.map(item=><tr key={item.id} onClick={()=>void open(item)}><td><strong>{item.case_number}</strong><small>{item.title}</small></td><td><StatusBadge value={item.priority}/></td><td><StatusBadge value={item.status}/></td><td>{formatDate(item.opened_at)}</td><td><button className="icon-button" onClick={event=>{event.stopPropagation();void open(item)}} aria-label={`Open ${item.case_number}`}>→</button></td></tr>)}</tbody></table></div></article>}</>}
    {selected&&<DetailDrawer eyebrow="INVESTIGATION CASE" title={`${selected.case_number} · ${selected.title}`} onClose={()=>setSelected(null)}>{detailError&&<ErrorBanner message={detailError}/>} {detailLoading?<LoadingState label="Correlating incidents, threats and evidence…"/>:<><section className="soc-detail-section"><h3>Case overview</h3><FactGrid facts={[{label:"Description",value:selected.description||"Not recorded"},{label:"Opened",value:formatDate(selected.opened_at)},{label:"Closed",value:formatDate(selected.closed_at)},{label:"Last updated",value:formatDate(selected.updated_at)}]}/></section><div className="soc-case-summary"><span><Activity size={17}/><strong>{linked.length}</strong><small>Incidents</small></span><span><ShieldAlert size={17}/><strong>{caseThreats.length}</strong><small>Threats</small></span><span><FileCheck2 size={17}/><strong>{caseEvidence.length}</strong><small>Evidence</small></span></div><section className="soc-detail-section"><h3>Case controls</h3><div className="soc-create-form"><label>Status<select value={selected.status} disabled={saving} onChange={event=>void updateCase({status:event.target.value})}>{caseStatuses.map(value=><option key={value}>{value}</option>)}</select></label><label>Priority<select value={selected.priority} disabled={saving} onChange={event=>void updateCase({priority:event.target.value})}>{priorities.map(value=><option key={value}>{value}</option>)}</select></label></div></section><section className="soc-detail-section"><h3>Linked incidents ({linked.length})</h3>{linked.length?<div className="table-wrap"><table className="soc-table"><thead><tr><th>Incident</th><th>Severity</th><th>Status</th></tr></thead><tbody>{linked.map(item=><tr key={item.id}><td><strong>{item.incident_number}</strong><small>{item.incident_title}</small></td><td><StatusBadge value={item.severity}/></td><td><StatusBadge value={item.status}/></td></tr>)}</tbody></table></div>:<p>No incidents are linked yet. Link one to build the investigation timeline.</p>}<form className="soc-create-form" onSubmit={linkIncident}><label className="field-wide">Incident<select required value={incidentID} onChange={event=>setIncidentID(event.target.value)}><option value="">Select an incident</option>{availableIncidents.map(item=><option key={item.id} value={item.id}>{item.incident_number} — {item.incident_title} ({humanize(item.status)})</option>)}</select>{!availableIncidents.length&&<small>No unlinked incident records are currently available.</small>}</label><footer><button className="primary with-icon" disabled={saving||!incidentID}><Link2 size={15}/>Link incident</button></footer></form></section><section className="soc-detail-section"><h3>Analyst findings</h3>{linked.some(item=>item.initial_findings||item.root_cause||item.containment_actions||item.resolution_summary)?<div className="soc-findings">{linked.map(item=>(item.initial_findings||item.root_cause||item.containment_actions||item.resolution_summary)&&<article key={item.id}><strong>{item.incident_number}</strong>{item.initial_findings&&<p><b>Initial findings:</b> {item.initial_findings}</p>}{item.root_cause&&<p><b>Root cause:</b> {item.root_cause}</p>}{item.containment_actions&&<p><b>Containment:</b> {item.containment_actions}</p>}{item.resolution_summary&&<p><b>Resolution:</b> {item.resolution_summary}</p>}</article>)}</div>:<p>No analyst findings recorded in the linked incidents yet.</p>}</section><section className="soc-detail-section"><h3>Correlated event timeline ({caseTimeline.length})</h3>{caseTimeline.length?<div className="soc-case-timeline">{caseTimeline.map(item=><article key={`${item.incident_id}-${item.id}`}><i/><div><small>{item.incident_number} · {formatDate(item.occurred_at||item.created_at)}</small><strong>{humanize(item.title||item.event_type)}</strong>{item.description&&<p>{item.description}</p>}{item.new_status&&<StatusBadge value={item.new_status}/>}</div></article>)}</div>:<p>No timeline events are available for the linked incidents.</p>}</section><section className="soc-detail-section"><h3>Correlated threats ({caseThreats.length})</h3>{caseThreats.length?<div className="soc-evidence-list">{caseThreats.map(item=><article key={`${item.incident_id}-${item.threat_id}`}><div><strong>{item.threat_code||humanize(item.threat_type)}</strong><small>{item.incident_number} · {humanize(item.relation_type)}</small></div><StatusBadge value={item.severity}/></article>)}</div>:<p>No linked threat records.</p>}</section><section className="soc-detail-section"><h3>Evidence ledger ({caseEvidence.length})</h3>{caseEvidence.length?<div className="soc-evidence-list">{caseEvidence.map(item=><article key={`${item.incident_id}-${item.id}`}><div><strong>{item.evidence_name||item.original_file_name||item.evidence_code}</strong><small>{item.incident_number} · {humanize(item.evidence_type)}{item.evidence_hash?` · ${item.hash_algorithm||"Hash"}: ${item.evidence_hash.slice(0,18)}…`:""}</small></div><StatusBadge value={item.integrity_status||"RECORDED"}/></article>)}</div>:<p>No preserved evidence is attached to the linked incidents.</p>}</section></>}</DetailDrawer>}
    {createOpen&&<div className="soc-drawer-backdrop" onMouseDown={()=>!saving&&setCreateOpen(false)}><form className="soc-modal" onSubmit={create} onMouseDown={event=>event.stopPropagation()}><header><div><p>NEW INVESTIGATION</p><h2>Create case</h2></div></header><div className="soc-create-form"><label className="field-wide">Case title<input required minLength={3} maxLength={255} value={form.title} onChange={event=>setForm(value=>({...value,title:event.target.value}))}/></label><label>Priority<select value={form.priority} onChange={event=>setForm(value=>({...value,priority:event.target.value}))}>{priorities.map(value=><option key={value}>{humanize(value)}</option>)}</select></label><label className="field-wide">Description<textarea maxLength={10000} value={form.description} onChange={event=>setForm(value=>({...value,description:event.target.value}))} placeholder="Scope, indicators, and analyst context"/></label><footer><button type="button" className="secondary" onClick={()=>setCreateOpen(false)}>Cancel</button><button className="primary" disabled={saving}>{saving?"Creating…":"Create case"}</button></footer></div></form></div>}
  </section>;
}
