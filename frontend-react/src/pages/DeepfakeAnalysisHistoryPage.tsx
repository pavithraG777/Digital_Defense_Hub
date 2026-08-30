import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, FileAudio, FileImage, Film, LoaderCircle, Search, ShieldCheck, Video } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";

type Asset = { id:string; asset_code:string; original_file_name:string; media_type:string; uploaded_at:string };
type Job = { id:string; media_asset_id?:string; job_number:string; job_type:string; status:string; progress_percentage:number; created_at:string; completed_at?:string; error_message?:string };
type Result = { deepfake?:{ detection_result?:string; confidence_score?:number }; evidence_analysis?:{ result?:string; confidence_score?:number } };
type Page<T> = { items:T[]; total:number };
type HistoryRow = { job:Job; asset?:Asset; result?:Result };

const mapInBatches = async <T, R>(items:T[], batchSize:number, mapper:(item:T)=>Promise<R>) => {
  const mapped:R[] = [];
  for (let offset = 0; offset < items.length; offset += batchSize) {
    mapped.push(...await Promise.all(items.slice(offset, offset + batchSize).map(mapper)));
  }
  return mapped;
};

const categories = [
  { id:"IMAGE", label:"Images", jobType:"DEEPFAKE_IMAGE_DETECTION", icon:FileImage },
  { id:"VIDEO", label:"Videos", jobType:"DEEPFAKE_VIDEO_DETECTION", icon:Video },
  { id:"AUDIO", label:"Audio", jobType:"DEEPFAKE_AUDIO_DETECTION", icon:FileAudio },
  { id:"CCTV", label:"CCTV", jobType:"DEEPFAKE_CCTV_DETECTION", icon:Film },
] as const;
const when = (value?:string) => value ? new Date(value).toLocaleString() : "—";
const percent = (value?:number) => value == null ? "—" : `${(value <= 1 ? value * 100 : value).toFixed(1)}%`;
const verdict = (row:HistoryRow) => (row.result?.deepfake?.detection_result || row.result?.evidence_analysis?.result || row.job.status).replaceAll("_", " ");

export function DeepfakeAnalysisHistoryPage() {
  const navigate = useNavigate();
  const [category, setCategory] = useState<typeof categories[number]>(categories[0]);
  const [rows, setRows] = useState<HistoryRow[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();

  const load = useCallback(async () => {
    setLoading(true); setError(undefined);
    try {
      const [jobs, assets] = await Promise.all([
        api.get<Page<Job>>(`/deepfake-forensics/analysis-jobs?page=1&page_size=100&job_type=${category.jobType}`),
        api.get<Page<Asset>>(`/deepfake-forensics/media-assets?page=1&page_size=100&media_type=${category.id}`),
      ]);
      const assetByID = new Map(assets.items.map(asset => [asset.id, asset]));
      // Keep history hydration from exhausting the backend database pool while
      // an active analysis worker is trying to persist a newly computed result.
      const records = await mapInBatches(jobs.items, 5, async job => ({
        job,
        asset:job.media_asset_id ? assetByID.get(job.media_asset_id) : undefined,
        result:job.status === "COMPLETED"
          ? await api.get<Result>(`/deepfake-forensics/analysis-jobs/${job.id}/result`).catch(()=>undefined)
          : undefined,
      }));
      setRows(records); setTotal(jobs.total);
    } catch (cause) { setRows([]); setTotal(0); setError(cause instanceof Error ? cause.message : "Unable to load analysis history."); }
    finally { setLoading(false); }
  }, [category]);
  useEffect(() => { void load(); }, [load]);
  const visible = useMemo(() => rows.filter(row => `${row.asset?.original_file_name} ${row.asset?.asset_code} ${row.job.job_number}`.toLowerCase().includes(search.toLowerCase())), [rows, search]);

  return <section className="df-page">
    <header className="df-header"><div><p className="eyebrow">AI & MEDIA FORENSICS</p><h1>Analysis History</h1><span>Each media type has its own record stream. Select one to review only that type.</span></div><div className="df-header-tools"><label><Search size={16}/><input value={search} onChange={event=>setSearch(event.target.value)} placeholder="Search current history"/></label></div></header>
    <div className="df-filters df-history-tabs">{categories.map(item => { const Icon=item.icon; return <button className={category.id===item.id?"active":""} key={item.id} onClick={()=>setCategory(item)}><Icon size={16}/>{item.label}</button>; })}</div>
    {error && <div className="alert alert-error"><AlertTriangle size={17}/>{error}</div>}
    <article className="df-card df-history"><div className="df-card-title"><span>{category.label.toUpperCase()} FORENSIC RECORDS</span><h2>{category.label} analysis history</h2><small>{total} backend record(s)</small></div>{loading ? <div className="resource-loading"><LoaderCircle className="spin"/>Loading {category.label.toLowerCase()} records…</div> : <div className="table-wrap"><table><thead><tr><th>File</th><th>Analysis ID</th><th>Verdict</th><th>Confidence</th><th>Status</th><th>Completed</th><th/></tr></thead><tbody>{visible.map(row=><tr key={row.job.id} className="df-history-row" onClick={()=>navigate(`/deepfake-image-analysis?job=${encodeURIComponent(row.job.id)}`)}><td><strong>{row.asset?.original_file_name || "Media asset"}</strong><small>{row.asset?.asset_code || row.job.media_asset_id || "Asset pending"}</small></td><td className="mono">{row.job.job_number}</td><td>{verdict(row)}</td><td>{percent(row.result?.deepfake?.confidence_score ?? row.result?.evidence_analysis?.confidence_score)}</td><td>{row.job.status}{["QUEUED","PROCESSING"].includes(row.job.status) && ` (${row.job.progress_percentage}%)`}</td><td>{when(row.job.completed_at || row.job.created_at)}</td><td>View →</td></tr>)}</tbody></table>{!visible.length&&<div className="df-table-empty"><ShieldCheck size={24}/>No {category.label.toLowerCase()} analyses match this search.</div>}</div>}</article>
  </section>;
}
