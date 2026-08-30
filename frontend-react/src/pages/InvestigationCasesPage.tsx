import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { FolderSearch2, Link2, Plus, RefreshCw, Search } from "lucide-react";
import { api } from "../lib/api";
import { DetailDrawer, EmptyState, ErrorBanner, FactGrid, LoadingState, MetricCard, StatusBadge, formatDate, humanize } from "./securityOperationsUI";
import "./securityOperations.css";

type Case = { id:string; case_number:string; title:string; description?:string; status:string; priority:string; opened_at:string; closed_at?:string; updated_at:string };
type Incident = { id:string; incident_number:string; incident_title:string; severity:string; status:string };
type CaseList = { cases:Case[]; total:number };
type IncidentList = { incidents:Incident[] };
const caseStatuses=["OPEN","ACTIVE","ON_HOLD","CLOSED","CANCELLED"];
const priorities=["LOW","MEDIUM","HIGH","URGENT"];

export function InvestigationCasesPage() {
  const [data,setData]=useState<CaseList|null>(null);
  const [incidents,setIncidents]=useState<Incident[]>([]);
  const [query,setQuery]=useState("");
  const [loading,setLoading]=useState(true);
  const [refreshing,setRefreshing]=useState(false);
  const [error,setError]=useState("");
  const [selected,setSelected]=useState<Case|null>(null);
  const [linked,setLinked]=useState<Incident[]>([]);
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
  const visible=useMemo(()=>cases.filter(item=>`${item.case_number} ${item.title} ${item.status} ${item.priority}`.toLowerCase().includes(query.toLowerCase())),[cases,query]);
  const active=cases.filter(item=>!["CLOSED","CANCELLED"].includes(item.status)).length;
  const availableIncidents=incidents.filter(item=>!linked.some(link=>link.id===item.id));

  async function open(item:Case) {
    setSelected(item); setLinked([]); setDetailError(""); setDetailLoading(true);
    try {
      const [record,caseIncidents]=await Promise.all([
        api.get<Case>(`/investigation-cases/${encodeURIComponent(item.id)}`),
        api.get<Incident[]>(`/investigation-cases/${encodeURIComponent(item.id)}/incidents`),
      ]);
      setSelected(record); setLinked(Array.isArray(caseIncidents)?caseIncidents:[]);
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
    <header className="soc-ops-hero"><div><p className="eyebrow">SECURITY OPERATIONS · CASE MANAGEMENT</p><h1>Investigations</h1><span>Create and manage investigations, then associate live incident records and preserved evidence.</span></div><div className="hero-actions"><button className="primary with-icon" onClick={()=>setCreateOpen(true)}><Plus size={16}/>Create case</button><button className="secondary with-icon" disabled={refreshing} onClick={()=>void load(true)}><RefreshCw size={16} className={refreshing?"spin":""}/>Refresh</button></div></header>
    {error&&<ErrorBanner message={error}/>}
    <div className="soc-filterbar"><label className="soc-search"><Search size={17}/><input value={query} onChange={event=>setQuery(event.target.value)} placeholder="Search case number, title, status or priority"/></label></div>
    {loading?<LoadingState label="Loading investigation cases…"/>:<><div className="soc-metrics"><MetricCard label="Total cases" value={data?.total||0}/><MetricCard label="Active" value={active} accent="amber"/><MetricCard label="Open" value={cases.filter(item=>item.status==="OPEN").length} accent="violet"/><MetricCard label="Urgent" value={cases.filter(item=>item.priority==="URGENT").length} accent="red"/></div>{!visible.length?<EmptyState title="No investigation cases" message={cases.length?"No case matches this search.":"Create a case to begin linking incidents and preserving evidence."}/>:<article className="soc-panel soc-table-panel"><header><div><p>LIVE CASE DIRECTORY</p><h2>Investigation records</h2></div><FolderSearch2 size={20}/></header><div className="table-wrap"><table className="soc-table"><thead><tr><th>Case</th><th>Priority</th><th>Status</th><th>Opened</th><th/></tr></thead><tbody>{visible.map(item=><tr key={item.id} onClick={()=>void open(item)}><td><strong>{item.case_number}</strong><small>{item.title}</small></td><td><StatusBadge value={item.priority}/></td><td><StatusBadge value={item.status}/></td><td>{formatDate(item.opened_at)}</td><td><button className="icon-button" onClick={event=>{event.stopPropagation();void open(item)}} aria-label={`Open ${item.case_number}`}>→</button></td></tr>)}</tbody></table></div></article>}</>}
    {selected&&<DetailDrawer eyebrow="INVESTIGATION CASE" title={`${selected.case_number} · ${selected.title}`} onClose={()=>setSelected(null)}>{detailError&&<ErrorBanner message={detailError}/>} {detailLoading?<LoadingState label="Loading linked incidents…"/>:<><section className="soc-detail-section"><h3>Case overview</h3><FactGrid facts={[{label:"Description",value:selected.description||"Not recorded"},{label:"Opened",value:formatDate(selected.opened_at)},{label:"Closed",value:formatDate(selected.closed_at)},{label:"Last updated",value:formatDate(selected.updated_at)}]}/></section><section className="soc-detail-section"><h3>Case controls</h3><div className="soc-create-form"><label>Status<select value={selected.status} disabled={saving} onChange={event=>void updateCase({status:event.target.value})}>{caseStatuses.map(value=><option key={value}>{value}</option>)}</select></label><label>Priority<select value={selected.priority} disabled={saving} onChange={event=>void updateCase({priority:event.target.value})}>{priorities.map(value=><option key={value}>{value}</option>)}</select></label></div></section><section className="soc-detail-section"><h3>Linked incidents ({linked.length})</h3>{linked.length?<div className="table-wrap"><table className="soc-table"><thead><tr><th>Incident</th><th>Severity</th><th>Status</th></tr></thead><tbody>{linked.map(item=><tr key={item.id}><td><strong>{item.incident_number}</strong><small>{item.incident_title}</small></td><td><StatusBadge value={item.severity}/></td><td><StatusBadge value={item.status}/></td></tr>)}</tbody></table></div>:<p>No incidents are linked yet.</p>}<form className="soc-create-form" onSubmit={linkIncident}><label className="field-wide">Incident<select required value={incidentID} onChange={event=>setIncidentID(event.target.value)}><option value="">Select an incident</option>{availableIncidents.map(item=><option key={item.id} value={item.id}>{item.incident_number} — {item.incident_title} ({humanize(item.status)})</option>)}</select>{!availableIncidents.length&&<small>No unlinked incident records are currently available.</small>}</label><footer><button className="primary with-icon" disabled={saving||!incidentID}><Link2 size={15}/>Link incident</button></footer></form></section></>}</DetailDrawer>}
    {createOpen&&<div className="soc-drawer-backdrop" onMouseDown={()=>!saving&&setCreateOpen(false)}><form className="soc-modal" onSubmit={create} onMouseDown={event=>event.stopPropagation()}><header><div><p>NEW INVESTIGATION</p><h2>Create case</h2></div></header><div className="soc-create-form"><label className="field-wide">Case title<input required minLength={3} maxLength={255} value={form.title} onChange={event=>setForm(value=>({...value,title:event.target.value}))}/></label><label>Priority<select value={form.priority} onChange={event=>setForm(value=>({...value,priority:event.target.value}))}>{priorities.map(value=><option key={value}>{humanize(value)}</option>)}</select></label><label className="field-wide">Description<textarea maxLength={10000} value={form.description} onChange={event=>setForm(value=>({...value,description:event.target.value}))} placeholder="Scope, indicators, and analyst context"/></label><footer><button type="button" className="secondary" onClick={()=>setCreateOpen(false)}>Cancel</button><button className="primary" disabled={saving}>{saving?"Creating…":"Create case"}</button></footer></div></form></div>}
  </section>;
}
