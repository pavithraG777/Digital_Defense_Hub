import { useEffect, useRef, useState } from "react";
import type { ChangeEvent, DragEvent } from "react";
import { AlertTriangle, CheckCircle2, ClipboardPaste, Eye, FileImage, LoaderCircle, ShieldCheck, Upload, X } from "lucide-react";
import { api, apiBlob, apiRequest } from "../lib/api";
import { useSearchParams } from "react-router-dom";

type Asset = { id:string; asset_code:string; original_file_name:string; media_type:string; mime_type:string; file_size_bytes:number; file_hash:string; hash_algorithm:string; is_encrypted:boolean; encryption_algorithm?:string; status:string; uploaded_by?:string; uploaded_at:string; analyzed_at?:string; metadata?:Record<string,unknown> };
type Job = { id:string; media_asset_id?:string; ai_model_id:string; ai_model_version_id:string; job_number:string; job_type:string; priority:string; status:string; progress_percentage:number; processing_duration_ms?:number; created_at:string; queued_at?:string; started_at?:string; completed_at?:string; error_message?:string };
type DeepfakeResult = { detection_result:string; deepfake_probability?:number; authenticity_probability?:number; confidence_score?:number; faces_detected?:number; manipulated_faces_detected?:number; facial_artifact_detected:boolean; metadata_inconsistency_detected:boolean; detection_summary?:string; feature_data?:Record<string,unknown>; suspicious_regions?:Record<string,unknown>[]; created_at:string };
type ForensicsResult = { forensic_result:string; confidence_score?:number; editing_trace_detected:boolean; compression_anomaly_detected:boolean; copy_move_detected:boolean; splicing_detected:boolean; noise_inconsistency_detected:boolean; timestamp_anomaly_detected:boolean; analysis_summary?:string; findings?:string[]; suspicious_locations?:Record<string,unknown>[]; forensic_feature_data?:Record<string,unknown>; created_at:string };
type EvidenceAnalysis = { ai_model_name?:string; ai_model_version?:string; analysis_tool?:string; tool_version?:string; analysis_status:string; result?:string; confidence_score?:number; summary?:string; findings?:string; recommendation?:string; extracted_metadata?:Record<string,unknown>; result_data?:Record<string,unknown>; started_at?:string; completed_at?:string; reviewed_at?:string; review_notes?:string };
type ResultBundle = { deepfake?:DeepfakeResult; forensics?:ForensicsResult; evidence_analysis?:EvidenceAnalysis };
type TrustAssessment = { trust_score:number; risk_score:number; confidence_score:number; verdict:string; classification:string; risk_level:string; trained_model_used:boolean; requires_human_review:boolean; finalized:boolean; component_scores?:Record<string,unknown>; signals?:Record<string,unknown>[]; warnings?:string[]; completed_job_count:number; terminal_job_count:number; escalation_status:string; incident_id?:string; evaluated_at:string };
type SecurityEvent = { id:string; event_type:string; reason:string; metadata?:Record<string,unknown>; created_at:string };
type Page<T> = { items:T[]; total:number; page:number; page_size:number; total_pages:number };
type AnalysisRow = { job:Job; asset?:Asset; result?:ResultBundle };
type ReviewWorkflow = { reviews?:Record<string,unknown>[]; annotations?:Record<string,unknown>[]; case_links?:Record<string,unknown>[] };

const sensitiveKeys = new Set(["storage_path","stored_file_name","token","secret","password","model_file_path","visualization_file_path"]);
function safeEntries(value?:Record<string,unknown>) { return Object.entries(value || {}).filter(([key])=>!sensitiveKeys.has(key.toLowerCase())); }
function labelFor(key:string) { return key.replace(/_/g," ").replace(/\b\w/g,letter=>letter.toUpperCase()); }
function shown(value:unknown) {
  if (value == null || value === "") return "Not reported";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(3).replace(/0+$/,"").replace(/\.$/,"");
  return String(value).replaceAll("_"," ");
}
function HumanData({value,name}:{value:unknown;name?:string}) {
  if (Array.isArray(value)) {
    if (!value.length) return <span className="df-human-empty">None reported</span>;
    if (value.every(item=>typeof item!=="object"||item===null)) return <div className="df-human-tags">{value.map((item,index)=><span key={index}>{shown(item)}</span>)}</div>;
    return <div className="df-human-cards">{value.map((item,index)=><article key={index}><strong>{name ? `${labelFor(name)} ${index+1}` : `Item ${index+1}`}</strong><HumanData value={item}/></article>)}</div>;
  }
  if (value && typeof value === "object") {
    const entries = safeEntries(value as Record<string,unknown>);
    if (!entries.length) return <span className="df-human-empty">No details reported</span>;
    return <div className="df-human-object">{entries.map(([key,item])=><div className="df-human-row" key={key}><span>{labelFor(key)}</span><HumanData value={item} name={key}/></div>)}</div>;
  }
  return <strong className={typeof value==="boolean"?(value?"df-human-yes":"df-human-no"):""}>{shown(value)}</strong>;
}

const terminal = new Set(["COMPLETED", "FAILED", "CANCELLED"]);
const normalized = (value?:string) => (value || "UNKNOWN").toUpperCase();
const probability = (value?:number) => value == null ? undefined : value <= 1 ? value * 100 : value;
const percent = (value?:number) => value == null ? "—" : `${probability(value)!.toFixed(1)}%`;
const when = (value?:string) => value ? new Date(value).toLocaleString() : "—";
const size = (bytes?:number) => bytes == null ? "—" : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1024 / 1024).toFixed(2)} MB`;
const verdict = (row:AnalysisRow) => normalized(row.result?.deepfake?.detection_result || (row.job.status === "COMPLETED" ? row.result?.evidence_analysis?.result : row.job.status));
const isFake = (value:string) => value.includes("DEEPFAKE") || value.includes("MANIPULATED");
const isReal = (value:string) => value.includes("AUTHENTIC") || value === "REAL";

function explanation(result?:DeepfakeResult) {
  if (!result) return ["Analysis result is not available yet."];
  const facts:string[] = [];
  if (result.detection_summary) facts.push(result.detection_summary);
  if (result.facial_artifact_detected) facts.push("The forensic engine detected facial artifact indicators.");
  if (result.metadata_inconsistency_detected) facts.push("The extracted metadata contains an inconsistency indicator.");
  if ((result.manipulated_faces_detected || 0) > 0) facts.push(`${result.manipulated_faces_detected} manipulated face region(s) were reported.`);
  if (result.suspicious_regions?.length) facts.push(`${result.suspicious_regions.length} suspicious image region(s) were localized by the engine.`);
  if (!facts.length && isReal(normalized(result.detection_result))) facts.push("The configured model did not report a strong manipulation indicator for this image.");
  if (!facts.length) facts.push("The verdict is based on the active model probability and configured decision threshold.");
  return facts;
}

function FullBackendDetails({ row, trust, forensics, events, workflow, loading, preview, onClose, onWorkflowAction }:{ row:AnalysisRow; trust?:TrustAssessment; forensics?:ResultBundle; events:SecurityEvent[]; workflow?:ReviewWorkflow; loading:boolean; preview?:string; onClose:()=>void; onWorkflowAction:(kind:"review"|"annotation"|"link")=>void }) {
  const deep = row.result?.deepfake;
  const classical = forensics?.forensics;
  const evidence = row.result?.evidence_analysis;
  const evidencePackage = row.asset?.metadata?.evidence_package as Record<string,unknown>|undefined;
  const hashes = evidencePackage?.hashes as Record<string,unknown>|undefined;
  const fingerprint = evidencePackage?.media_fingerprint as Record<string,unknown>|undefined;
  const timeline = [
    ["Secure upload",row.asset?.uploaded_at],["Queued",row.job.queued_at],["Analysis started",row.job.started_at],
    ["Deepfake result",deep?.created_at],["Forensic result",classical?.created_at],["Completed",row.job.completed_at],["Trust evaluated",trust?.evaluated_at],
  ].filter((item):item is [string,string]=>Boolean(item[1]));
  return <aside className="df-full-drawer"><header><div><span>COMPLETE NON-SENSITIVE FORENSIC RECORD</span><h2>{row.asset?.original_file_name || row.job.job_number}</h2></div><button type="button" onClick={onClose}><X/></button></header>
    {loading&&<div className="resource-loading"><LoaderCircle className="spin"/> Loading linked forensic records…</div>}
    <div className="df-drawer-preview">{preview?<img src={preview} alt={row.asset?.original_file_name || "Analyzed evidence"}/>:<><FileImage/><span>Secure historical preview is not available for this record.</span></>}</div>
    <div className={`df-drawer-verdict ${isFake(verdict(row))?"fake":isReal(verdict(row))?"real":"pending"}`}><span>AI detection verdict</span><strong>{verdict(row).replaceAll("_"," ")}</strong><small>{percent(deep?.confidence_score)} confidence</small></div>
    <section><h3>Decision probabilities</h3><div className="df-full-metrics"><article><span>Authentic</span><strong>{percent(deep?.authenticity_probability)}</strong></article><article><span>Deepfake</span><strong>{percent(deep?.deepfake_probability)}</strong></article><article><span>Faces</span><strong>{deep?.faces_detected ?? "—"}</strong></article><article><span>Manipulated faces</span><strong>{deep?.manipulated_faces_detected ?? "—"}</strong></article></div><p>{deep?.detection_summary || evidence?.summary || "No summary returned."}</p><p className="df-warning"><AlertTriangle/>{row.job.job_type==="AI_GENERATED_IMAGE_DETECTION"?"Model scope: this whole-image model detects AI-generated imagery; it is not a dedicated face-swap detector.":"Model scope: this face-context model detects FaceForensics-style facial manipulation; it is not a whole-image AI generator detector."}</p></section>
    <section><h3>Trust and risk assessment</h3>{trust?<><div className="df-full-metrics"><article><span>Trust score</span><strong>{trust.trust_score.toFixed(1)}</strong></article><article><span>Risk score</span><strong>{trust.risk_score.toFixed(1)}</strong></article><article><span>Risk level</span><strong>{trust.risk_level}</strong></article><article><span>Human review</span><strong>{trust.requires_human_review?"Required":"Not required"}</strong></article></div><dl><div><dt>Final verdict</dt><dd>{trust.verdict}</dd></div><div><dt>Classification</dt><dd>{trust.classification}</dd></div><div><dt>Trained model used</dt><dd>{trust.trained_model_used?"Yes":"No"}</dd></div><div><dt>Assessment status</dt><dd>{trust.finalized?"Finalized":"Provisional"}</dd></div></dl>{trust.warnings?.map((warning,index)=><p className="df-warning" key={index}><AlertTriangle/>{warning}</p>)}{trust.signals?.length?<div className="df-human-section"><h4>Assessment signals</h4><HumanData value={trust.signals} name="Signal"/></div>:null}{safeEntries(trust.component_scores).length>0&&<div className="df-human-section"><h4>Component scores</h4><HumanData value={trust.component_scores}/></div>}</>:<p>Trust assessment is not available for this media asset yet.</p>}</section>
    <section><h3>Classical image forensics</h3>{classical?<><div className="df-full-metrics"><article><span>Result</span><strong>{classical.forensic_result}</strong></article><article><span>Confidence</span><strong>{percent(classical.confidence_score)}</strong></article><article><span>Suspicious locations</span><strong>{classical.suspicious_locations?.length || 0}</strong></article></div><div className="df-indicators">{[["Editing trace",classical.editing_trace_detected],["Compression anomaly",classical.compression_anomaly_detected],["Copy-move",classical.copy_move_detected],["Splicing",classical.splicing_detected],["Noise inconsistency",classical.noise_inconsistency_detected],["Timestamp anomaly",classical.timestamp_anomaly_detected]].map(([label,flag])=><span className={flag?"found":"clear"} key={String(label)}>{flag?"Detected":"Not detected"}<b>{label}</b></span>)}</div>{classical.analysis_summary&&<p>{classical.analysis_summary}</p>}{classical.findings?.map((finding,index)=><p className="df-drawer-reason" key={index}><CheckCircle2/>{finding}</p>)}</>:<p>Classical IMAGE_FORENSICS result is not present. Run COMBINED analysis to populate it.</p>}</section>
    <section><h3>Explainable AI features</h3>{safeEntries(deep?.feature_data).length?<HumanData value={deep?.feature_data}/>:<p>No feature values were returned by this model.</p>}<h4>Suspicious regions</h4>{deep?.suspicious_regions?.length?<HumanData value={deep.suspicious_regions} name="Region"/>:<p>No localized suspicious regions were returned.</p>}</section>
    <section><h3>Evidence analysis</h3><dl><div><dt>Model</dt><dd>{evidence?.ai_model_name || row.job.ai_model_id}</dd></div><div><dt>Version</dt><dd>{evidence?.ai_model_version || row.job.ai_model_version_id}</dd></div><div><dt>Tool</dt><dd>{evidence?.analysis_tool || "Not reported"}</dd></div><div><dt>Tool version</dt><dd>{evidence?.tool_version || "Not reported"}</dd></div><div><dt>Recommendation</dt><dd>{evidence?.recommendation || "Not reported"}</dd></div><div><dt>Review status</dt><dd>{evidence?.reviewed_at?`Reviewed ${when(evidence.reviewed_at)}`:"Not reviewed"}</dd></div></dl>{evidence?.findings&&<p>{evidence.findings}</p>}{safeEntries(evidence?.extracted_metadata).length>0&&<div className="df-human-section"><h4>Extracted metadata</h4><HumanData value={evidence?.extracted_metadata}/></div>}</section>
    <section><h3>Analyst review workflow</h3><p>Record a human decision, preserve annotations, and link this analysis to the active investigation.</p><div className="df-upload-actions"><button type="button" className="df-secondary" onClick={()=>onWorkflowAction("review")}>Record decision</button><button type="button" className="df-secondary" onClick={()=>onWorkflowAction("annotation")}>Add annotation</button><button type="button" className="df-secondary" onClick={()=>onWorkflowAction("link")}>Link case / incident</button></div><div className="df-human-section"><h4>Decisions</h4><HumanData value={workflow?.reviews || []} name="Review"/><h4>Annotations</h4><HumanData value={workflow?.annotations || []} name="Annotation"/><h4>Linked investigations</h4><HumanData value={workflow?.case_links || []} name="Link"/></div></section>
    <section><h3>Evidence integrity</h3><dl><div><dt>Media ID</dt><dd>{row.asset?.asset_code || row.job.media_asset_id}</dd></div><div><dt>SHA-256</dt><dd className="mono">{row.asset?.file_hash || shown(hashes?.sha256)}</dd></div><div><dt>SHA-512</dt><dd className="mono">{shown(hashes?.sha512)}</dd></div><div><dt>Evidence fingerprint</dt><dd className="mono">{shown(fingerprint?.value)}</dd></div><div><dt>Encryption</dt><dd>{row.asset?.is_encrypted?row.asset.encryption_algorithm || "Encrypted":"Not encrypted"}</dd></div></dl>{Boolean(evidencePackage?.file_signature)&&<div className="df-human-section"><h4>File signature validation</h4><HumanData value={evidencePackage?.file_signature}/></div>}</section>
    <section><h3>Analysis timeline</h3><div className="df-timeline">{timeline.map(([label,time])=><article key={`${label}-${time}`}><i/><div><strong>{label}</strong><time>{when(time)}</time></div></article>)}{events.map(event=><article key={event.id}><i/><div><strong>{event.event_type.replace(/_/g," ")}</strong><span>{event.reason}</span><time>{when(event.created_at)}</time></div></article>)}</div></section>
  </aside>;
}

export function DeepfakeImageAnalysisPage() {
  const [searchParams] = useSearchParams();
  const inputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<number>();
  const pollingRef = useRef(false);
  const reportRequestsRef = useRef(new Set<string>());
  const [file,setFile] = useState<File|null>(null);
  const [preview,setPreview] = useState<string>();
  const [busy,setBusy] = useState(false);
  const [analysisProgress,setAnalysisProgress] = useState<string>();
  const [error,setError] = useState<string>();
  const [selected,setSelected] = useState<AnalysisRow>();
  const [detailSelected,setDetailSelected] = useState<AnalysisRow>();
  const [detailOpen,setDetailOpen] = useState(false);
  const [detailPreview,setDetailPreview] = useState<string>();
  const [detailPreviewError,setDetailPreviewError] = useState<string>();
  const [detailLoading,setDetailLoading] = useState(false);
  const [trust,setTrust] = useState<TrustAssessment>();
  const [forensics,setForensics] = useState<ResultBundle>();
  const [securityEvents,setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [workflow,setWorkflow] = useState<ReviewWorkflow>();
  useEffect(() => () => { if (pollRef.current) window.clearInterval(pollRef.current); },[]);
  useEffect(() => () => { if (detailPreview) URL.revokeObjectURL(detailPreview); },[detailPreview]);
  useEffect(() => {
    if (!detailOpen || !selected || !detailSelected) return;
    const sameAsset = selected.asset?.id && selected.asset.id === detailSelected.asset?.id;
    if (sameAsset && selected.job.id !== detailSelected.job.id) void openDetails(selected);
  },[selected?.job.id,detailOpen]);

  async function generateReportWhenReady(assetID:string, attempt=0) {
    if (reportRequestsRef.current.has(assetID)) return;
    try {
      const jobs = await api.get<Page<Job>>(`/deepfake-forensics/analysis-jobs?page=1&page_size=100&media_asset_id=${encodeURIComponent(assetID)}`);
      const records = jobs.items || [];
      if (!records.length || records.some(job=>!terminal.has(job.status))) {
        if (attempt < 90) window.setTimeout(()=>void generateReportWhenReady(assetID,attempt+1),2000);
        return;
      }
      if (!records.some(job=>job.status==="COMPLETED")) return;
      reportRequestsRef.current.add(assetID);
      await api.post(`/deepfake-forensics/media-assets/${encodeURIComponent(assetID)}/forensic-reports`);
    } catch {
      reportRequestsRef.current.delete(assetID);
      if (attempt < 90) window.setTimeout(()=>void generateReportWhenReady(assetID,attempt+1),2000);
    }
  }
  useEffect(() => {
    const jobID = searchParams.get("job");
    if (!jobID) return;
    let disposed = false;
    void (async () => {
      setError(undefined); setAnalysisProgress("Loading the selected forensic record…");
      try {
        const job = await api.get<Job>(`/deepfake-forensics/analysis-jobs/${encodeURIComponent(jobID)}`);
        const [asset,result] = await Promise.all([
          job.media_asset_id ? api.get<Asset>(`/deepfake-forensics/media-assets/${job.media_asset_id}`) : Promise.resolve(undefined),
          job.status === "COMPLETED" ? api.get<ResultBundle>(`/deepfake-forensics/analysis-jobs/${job.id}/result`).catch(()=>undefined) : Promise.resolve(undefined),
        ]);
        let row:AnalysisRow={job,asset,result};
        if(asset?.id){
          const related=await api.get<Page<Job>>(`/deepfake-forensics/analysis-jobs?page=1&page_size=100&media_asset_id=${encodeURIComponent(asset.id)}`).catch(()=>undefined);
          const detectorJobs=(related?.items||[]).filter(item=>item.status==="COMPLETED"&&["DEEPFAKE_IMAGE_DETECTION","AI_GENERATED_IMAGE_DETECTION"].includes(item.job_type));
          const candidates=await Promise.all(detectorJobs.map(async item=>({job:item,asset,result:await api.get<ResultBundle>(`/deepfake-forensics/analysis-jobs/${item.id}/result`).catch(()=>undefined)})));
          row=candidates.sort((first,second)=>(probability(second.result?.deepfake?.deepfake_probability)||0)-(probability(first.result?.deepfake?.deepfake_probability)||0))[0]||row;
        }
        if (!disposed) { setSelected(row); setAnalysisProgress(undefined); if(row.job.status==="COMPLETED"&&asset?.id)void generateReportWhenReady(asset.id); }
      } catch (cause) { if (!disposed) { setAnalysisProgress(undefined); setError(cause instanceof Error ? cause.message : "Unable to load the requested forensic record."); } }
    })();
    return ()=>{disposed=true;};
  },[searchParams]);
  useEffect(() => {
    const pasteImage = (event:ClipboardEvent) => {
      const imageItem = Array.from(event.clipboardData?.items || []).find(item=>item.kind==="file"&&item.type.startsWith("image/"));
      if (!imageItem) return;
      event.preventDefault();
      if (busy) { setError("Current analysis is running. Choose 'Analyze another image' before pasting a new image."); return; }
      const blob = imageItem.getAsFile();
      if (!blob) { setError("The copied image could not be read from the clipboard."); return; }
      const extension = blob.type.split("/")[1]?.replace("jpeg","jpg") || "png";
      choose(new File([blob],`clipboard-image-${Date.now()}.${extension}`,{type:blob.type,lastModified:Date.now()}));
    };
    window.addEventListener("paste",pasteImage);
    return ()=>window.removeEventListener("paste",pasteImage);
  },[busy,preview]);

  function choose(next:File|null) {
    if (!next) return;
    if (!next.type.startsWith("image/")) { setError("Choose a JPG, JPEG, PNG or WEBP image."); return; }
    if (preview) URL.revokeObjectURL(preview);
    setFile(next); setPreview(URL.createObjectURL(next)); setError(undefined); setAnalysisProgress(undefined);
  }

  function resetUpload() {
    if (pollRef.current) window.clearInterval(pollRef.current);
    pollRef.current = undefined;
    pollingRef.current = false;
    if (preview) URL.revokeObjectURL(preview);
    setFile(null); setPreview(undefined); setBusy(false); setError(undefined);
    setAnalysisProgress("Ready for another image. Any already-submitted backend job will continue safely in the analysis history.");
    if (inputRef.current) inputRef.current.value = "";
  }

  async function pasteFromClipboard() {
    if (busy) { setError("Current analysis is running. Choose 'Analyze another image' before pasting a new image."); return; }
    try {
      if (!navigator.clipboard?.read) throw new Error("Clipboard image access is not supported by this browser. Copy the image and press Ctrl + V instead.");
      const clipboardItems = await navigator.clipboard.read();
      for (const item of clipboardItems) {
        const imageType = item.types.find(type=>type.startsWith("image/"));
        if (!imageType) continue;
        const blob = await item.getType(imageType);
        const extension = imageType.split("/")[1]?.replace("jpeg","jpg") || "png";
        choose(new File([blob],`clipboard-image-${Date.now()}.${extension}`,{type:imageType,lastModified:Date.now()}));
        return;
      }
      setError("No image was found in the clipboard. Copy an image first, then try again.");
    } catch (cause) { setError(cause instanceof Error?cause.message:"Unable to read the image from the clipboard."); }
  }

  async function analyze() {
    if (!file) return;
    if (pollRef.current) window.clearInterval(pollRef.current);
    setBusy(true); setError(undefined); setAnalysisProgress("Securely uploading image…");
    try {
      const form = new FormData(); form.append("file",file); form.append("source_type","DIRECT_UPLOAD"); form.append("metadata",JSON.stringify({ upload_source:"FRONTEND_IMAGE_ANALYSIS", dataset_member:false }));
      const asset = await apiRequest<Asset>("/deepfake-forensics/media-assets",{ method:"POST",body:form });
      setAnalysisProgress("Upload complete. Unified deepfake analysis is being prepared…");
      const accepted = await api.post<{ jobs:{id:string;job_type?:string}[] }>(`/deepfake-forensics/media-assets/${asset.id}/analyze`,{
        analysis_modes:["DEEPFAKE","SYNTHETIC"],
        priority:"HIGH",
        execution_device:"CPU",
        force_reanalysis:false,
      });
      const ids = accepted.jobs.map(job=>job.id);
      const detectorIDs = accepted.jobs.filter(job=>["DEEPFAKE_IMAGE_DETECTION","AI_GENERATED_IMAGE_DETECTION"].includes(job.job_type || "")).map(job=>job.id);
      if (!detectorIDs.length || !ids.length) throw new Error("The backend accepted no image-detection job.");
      const startedAt = Date.now();
      let settled = false;
      const checkStatus = async () => {
        if (pollingRef.current) return;
        pollingRef.current = true;
        try {
          const jobs = await Promise.all(ids.map(id=>api.get<Job>(`/deepfake-forensics/analysis-jobs/${id}`).catch(() => undefined)));
          const available = jobs.filter((job):job is Job=>Boolean(job));
          const detectorJobs = available.filter(job=>detectorIDs.includes(job.id));
          setAnalysisProgress(available.length ? available.map(job=>`${job.job_type.replaceAll("_"," ")}: ${job.status}`).join(" · ") : "Waiting for backend job status…");

          if (detectorJobs.length === detectorIDs.length && detectorJobs.every(job=>terminal.has(job.status))) {
            if (pollRef.current) window.clearInterval(pollRef.current);
            pollRef.current = undefined;
            const completed = detectorJobs.filter(job=>job.status === "COMPLETED");
            const candidates = await Promise.all(completed.map(async job=>({job,result:await api.get<ResultBundle>(`/deepfake-forensics/analysis-jobs/${job.id}/result`).catch(()=>undefined)})));
            const strongest = candidates.sort((first,second)=>(probability(second.result?.deepfake?.deepfake_probability) || 0)-(probability(first.result?.deepfake?.deepfake_probability) || 0))[0];
            if (!strongest) {
              settled = true; setBusy(false);
              setAnalysisProgress(undefined);
              setError(detectorJobs.map(job=>job.error_message).filter(Boolean).join(" · ") || "Both image detectors failed.");
              return;
            }
            const row = {job:strongest.job,asset,result:strongest.result};
            setSelected(row); setBusy(false);
            void generateReportWhenReady(asset.id);
            settled = true;
            const companionPending = available.some(job=>!detectorIDs.includes(job.id)&&!terminal.has(job.status));
            setAnalysisProgress(companionPending ? "Unified detection completed. Extended processing continues in the backend." : "Unified AI-generated and face-manipulation analysis completed.");
            return;
          }

          if (Date.now()-startedAt > 180000) {
            if (pollRef.current) window.clearInterval(pollRef.current);
            pollRef.current = undefined; setBusy(false);
            setAnalysisProgress("The analysis is still running in the backend. You can analyze another image and check this result in Analysis History shortly.");
          }
        } finally { pollingRef.current = false; }
      };
      setAnalysisProgress("Analysis queued. Running the unified deepfake image detector…");
      await checkStatus();
      if (!settled) {
        pollRef.current = window.setInterval(()=>{ void checkStatus(); },1500);
      }
    } catch (cause) { setBusy(false); setAnalysisProgress(undefined); setError(cause instanceof Error ? cause.message : "Unable to analyze image."); }
  }

  async function openDetails(row:AnalysisRow) {
    setDetailSelected(row);
    setDetailOpen(true);
    setDetailLoading(true); setTrust(undefined); setForensics(undefined); setSecurityEvents([]); setWorkflow(undefined); setDetailPreviewError(undefined);
    if (detailPreview) { URL.revokeObjectURL(detailPreview); setDetailPreview(undefined); }
    if (!row.asset?.id) { setDetailLoading(false); return; }
    const [trustResult,eventPage,relatedJobs,previewBlob,workflowResult] = await Promise.all([
      api.get<TrustAssessment>(`/deepfake-forensics/media-assets/${row.asset.id}/trust-assessment`).catch(()=>undefined),
      api.get<Page<SecurityEvent>>(`/deepfake-forensics/media-assets/${row.asset.id}/security-events?page=1&page_size=100`).catch(()=>undefined),
      api.get<Page<Job>>(`/deepfake-forensics/analysis-jobs?page=1&page_size=100&media_asset_id=${row.asset.id}`).catch(()=>undefined),
      apiBlob(`/deepfake-forensics/media-assets/${row.asset.id}/preview`).catch(cause=>{ setDetailPreviewError(cause instanceof Error?cause.message:"Preview unavailable"); return undefined; }),
      api.get<ReviewWorkflow>(`/deepfake-forensics/analysis-jobs/${row.job.id}/review-workflow`).catch(()=>undefined),
    ]);
    const forensicJob = relatedJobs?.items.find(job=>job.job_type==="IMAGE_FORENSICS"&&job.status==="COMPLETED");
    const forensicResult = forensicJob ? await api.get<ResultBundle>(`/deepfake-forensics/analysis-jobs/${forensicJob.id}/result`).catch(()=>undefined) : undefined;
    if (previewBlob) setDetailPreview(URL.createObjectURL(previewBlob));
    setTrust(trustResult); setSecurityEvents(eventPage?.items || []); setForensics(forensicResult); setWorkflow(workflowResult); setDetailLoading(false);
  }

  async function workflowAction(kind:"review"|"annotation"|"link") {
    if (!detailSelected) return;
    try { if (kind === "review") { const decision=window.prompt("Decision: CONFIRMED_AUTHENTIC, CONFIRMED_MANIPULATED, INCONCLUSIVE, or ESCALATED", "INCONCLUSIVE"); const rationale=window.prompt("Analyst rationale"); if (!decision || !rationale) return; await api.post(`/deepfake-forensics/analysis-jobs/${detailSelected.job.id}/reviews`,{decision,rationale}); } else if(kind === "annotation") { const body=window.prompt("Annotation"); if (!body) return; await api.post(`/deepfake-forensics/analysis-jobs/${detailSelected.job.id}/annotations`,{annotation_type:"NOTE",body}); } else { const incident_id=window.prompt("Incident ID (leave blank to link an investigation case)"); const investigation_case_id=incident_id ? "" : window.prompt("Investigation case ID"); if (!incident_id && !investigation_case_id) return; await api.post(`/deepfake-forensics/analysis-jobs/${detailSelected.job.id}/case-links`,{incident_id:incident_id||undefined,investigation_case_id:investigation_case_id||undefined}); } await openDetails(detailSelected); } catch(cause) { setError(cause instanceof Error?cause.message:"Unable to save review workflow item."); }
  }

  const active = selected?.result?.deepfake;
  const activeVerdict = selected ? verdict(selected) : "";
  const deepfakeProbability = probability(active?.deepfake_probability);
  const authenticProbability = probability(active?.authenticity_probability) ?? (deepfakeProbability == null ? undefined : 100-deepfakeProbability);

  return <section className="df-page">
    <header className="df-header"><div><p className="eyebrow">AI & MEDIA FORENSICS</p><h1>Deepfake Image Analysis</h1><span>Upload one image to receive its current forensic verdict and evidence details.</span></div></header>
    {error && <div className="alert alert-error"><AlertTriangle size={17}/>{error}</div>}

    <div className="df-workspace">
      <article className="df-card df-upload"><div className="df-card-title"><span>NEW ANALYSIS</span><h2>Upload or paste image</h2></div><div className={`df-drop ${file?"selected":""}`} onDragOver={e=>e.preventDefault()} onDrop={(e:DragEvent)=>{e.preventDefault();choose(e.dataTransfer.files[0])}} onClick={()=>inputRef.current?.click()}>{preview?<img src={preview} alt="Selected evidence preview"/>:<><Upload size={35}/><strong>Drop an image here</strong><span>or choose a file</span><small>JPG · JPEG · PNG · WEBP</small></>}<input ref={inputRef} type="file" accept="image/jpeg,image/png,image/webp" hidden onChange={(e:ChangeEvent<HTMLInputElement>)=>choose(e.target.files?.[0]||null)}/></div>{!file&&<button type="button" className="df-paste" disabled={busy} onClick={()=>void pasteFromClipboard()}><ClipboardPaste/> Paste image <kbd>Ctrl + V</kbd></button>}{file&&<div className="df-file"><strong>{file.name}</strong><span>{file.type} · {size(file.size)}</span></div>}{analysisProgress&&<p className="df-analysis-progress">{busy&&<LoaderCircle className="spin"/>}{analysisProgress}</p>}<div className="df-upload-actions"><button className="df-primary" disabled={!file||busy} onClick={analyze}>{busy?<><LoaderCircle className="spin"/> Analyzing…</>:<><ShieldCheck/> Analyze image</>}</button>{file&&<button type="button" className="df-secondary" onClick={resetUpload}>{busy?"Analyze another image":"Choose another image"}</button>}</div></article>

      <article className="df-card df-result">{selected?<><div className="df-verdict"><div><span>FORENSIC VERDICT</span><h2 className={isFake(activeVerdict)?"fake":isReal(activeVerdict)?"real":"pending"}>{activeVerdict.replaceAll("_"," ")}</h2><p>{active?.detection_summary || selected.job.error_message || `Analysis is ${selected.job.status.toLowerCase()}.`}</p></div><div className="df-confidence"><strong>{percent(active?.confidence_score)}</strong><span>Confidence</span></div></div><div className="df-probability"><span style={{width:`${Math.max(0,Math.min(100,authenticProbability||0))}%`}}/><i style={{width:`${Math.max(0,Math.min(100,deepfakeProbability||0))}%`}}/><div><b>{percent(authenticProbability)} Authentic</b><b>{percent(deepfakeProbability)} Deepfake</b></div></div><div className="df-reasons"><h3>{isFake(activeVerdict)?"Why manipulation is suspected":"Why this verdict was produced"}</h3>{explanation(active).map((item,index)=><p key={index}><CheckCircle2 size={15}/>{item}</p>)}</div>{selected.job.status==="COMPLETED"&&<p className="df-warning"><AlertTriangle/>{selected.job.job_type==="AI_GENERATED_IMAGE_DETECTION"?"The AI-generated image detector produced the strongest risk signal for this upload.":"The face-swap detector produced the strongest risk signal for this upload."} An authentic verdict is not proof of original camera provenance.</p>}<div className="df-detail-grid"><div><span>Model</span><strong>{selected.result?.evidence_analysis?.ai_model_name || selected.job.ai_model_id}</strong></div><div><span>Version</span><strong>{selected.result?.evidence_analysis?.ai_model_version || selected.job.ai_model_version_id}</strong></div><div><span>Faces detected</span><strong>{active?.faces_detected ?? "Not reported"}</strong></div><div><span>Analysis time</span><strong>{selected.job.processing_duration_ms ? `${(selected.job.processing_duration_ms/1000).toFixed(2)} sec` : "Not reported"}</strong></div></div></>:<div className="df-empty"><ShieldCheck size={42}/><h2>Select or analyze an image</h2><p>The backend verdict, probabilities and forensic reasons will appear here.</p></div>}</article>
    </div>

    {selected && <article className="df-card df-evidence"><div className="df-card-title"><span>EVIDENCE & INTEGRITY</span><h2>{selected.asset?.original_file_name || selected.job.job_number}</h2><button type="button" className="df-secondary" onClick={()=>void openDetails(selected)}><Eye size={15}/> View complete record</button></div><div className="df-evidence-grid"><div className="df-evidence-canvas">{preview && selected.asset?.original_file_name===file?.name?<img src={preview} alt="Analyzed evidence"/>:<FileImage size={62}/>} {active?.suspicious_regions?.map((region,index)=>{ const x=Number(region.x??region.left), y=Number(region.y??region.top), w=Number(region.width), h=Number(region.height); return [x,y,w,h].every(Number.isFinite)?<i key={index} style={{left:`${x}%`,top:`${y}%`,width:`${w}%`,height:`${h}%`}}/>:null })}</div><dl><div><dt>Media ID</dt><dd>{selected.asset?.asset_code || selected.job.media_asset_id}</dd></div><div><dt>SHA-256</dt><dd className="mono">{selected.asset?.file_hash || "Not returned"}</dd></div><div><dt>Integrity</dt><dd>{selected.asset?.hash_algorithm === "SHA256" ? "SHA-256 recorded" : selected.asset?.hash_algorithm || "Not reported"}</dd></div><div><dt>Encryption</dt><dd>{selected.asset?.is_encrypted ? selected.asset.encryption_algorithm || "Encrypted" : "Not reported as encrypted"}</dd></div><div><dt>Uploaded</dt><dd>{when(selected.asset?.uploaded_at)}</dd></div><div><dt>Completed</dt><dd>{when(selected.job.completed_at)}</dd></div></dl></div></article>}

    {detailOpen && detailSelected && <><button type="button" className="df-detail-backdrop" aria-label="Close analysis details" onClick={()=>setDetailOpen(false)}/><FullBackendDetails row={detailSelected} trust={trust} forensics={forensics} events={securityEvents} workflow={workflow} loading={detailLoading} preview={detailPreview || (preview&&detailSelected.asset?.original_file_name===file?.name?preview:undefined)} onClose={()=>setDetailOpen(false)} onWorkflowAction={kind=>void workflowAction(kind)}/>{detailPreviewError&&<span className="sr-only">{detailPreviewError}</span>}</>}
  </section>;
}
