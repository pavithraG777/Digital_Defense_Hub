import { useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, FolderSearch, History, Radar, ShieldAlert, Square, Radio, Volume2 } from "lucide-react";
import { api } from "../lib/api";
import "./ransomwareScanner.css";
import "./liveRansomwareMonitor.css";
import "./ransomwareSoundTest.css";

type ScanFinding = { file: string; reason: string; severity: string };
type Scan = { id: string; folder_name: string; total_files: number; suspicious_files: number; risk_score: number; verdict: string; findings: ScanFinding[]; completed_at: string };
type FileEntry = { name: string; kind: "file"; getFile(): Promise<File> };
type DirectoryEntry = { name: string; kind: "directory"; values(): AsyncIterableIterator<FileEntry | DirectoryEntry> };

async function collectFiles(directory: DirectoryEntry, prefix = "", output: Array<{name:string;relative_path:string;size:number;modified_at:number}> = [], onProgress?: (count:number,path:string)=>void) {
  for await (const entry of directory.values()) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.kind === "directory") await collectFiles(entry, relative, output, onProgress);
    else {
      const file = await entry.getFile();
      output.push({ name: file.name, relative_path: relative, size: file.size, modified_at: file.lastModified });
      if (output.length === 1 || output.length % 25 === 0) onProgress?.(output.length, relative);
      if (output.length >= 25000) throw new Error("This scan supports up to 25,000 files at a time. Select a smaller folder.");
    }
  }
  return output;
}

function verdictLabel(verdict: string) {
  return ({ CLEAN: "No ransomware indicators", SUSPICIOUS: "Suspicious files found", HIGH_RISK: "High ransomware risk", RANSOMWARE_DETECTED: "Ransomware indicators detected" } as Record<string,string>)[verdict] || verdict.replaceAll("_", " ");
}

export function RansomwareScannerPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [active, setActive] = useState<Scan | null>(null);
  const [stage, setStage] = useState<"idle"|"permission"|"reading"|"analysing">("idle");
  const [progress, setProgress] = useState(0);
  const [discoveredFiles, setDiscoveredFiles] = useState(0);
  const [currentFile, setCurrentFile] = useState("");
  const [error, setError] = useState("");
  const [monitoring,setMonitoring]=useState(false);
  const [monitorFolder,setMonitorFolder]=useState("");
  const [liveActivity,setLiveActivity]=useState({modified:0,created:0,deleted:0,renamed:0,extensions:0});
  const monitorTimer=useRef<number | undefined>(undefined);
  const monitorBusy=useRef(false);
  const alertAudio=useRef<AudioContext | null>(null);
  const [soundStatus,setSoundStatus]=useState("Sound not tested");

  async function loadHistory() {
    const result = await api.get<{scans: Scan[]}>("/ransomware/scans");
    setScans(result.scans || []);
    setActive((current) => current || result.scans?.[0] || null);
  }
  useEffect(() => { void loadHistory().catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load ransomware scan history.")); }, []);
  useEffect(()=>()=>{if(monitorTimer.current)window.clearInterval(monitorTimer.current);void alertAudio.current?.close();},[]);

  async function ensureAlertAudio(){
    const AudioCtor=window.AudioContext||(window as unknown as {webkitAudioContext?:typeof AudioContext}).webkitAudioContext;
    if(!AudioCtor)return null;
    if(!alertAudio.current||alertAudio.current.state==="closed")alertAudio.current=new AudioCtor();
    if(alertAudio.current.state==="suspended")await alertAudio.current.resume();
    return alertAudio.current;
  }
  async function playRansomwareAlarm(){
    const context=await ensureAlertAudio();
    if(!context){setSoundStatus("Audio unsupported");return false;}
    const start=context.currentTime+.03,master=context.createGain();
    master.gain.setValueAtTime(.28,start);master.gain.setValueAtTime(.28,start+2.7);master.gain.exponentialRampToValueAtTime(.001,start+3);master.connect(context.destination);
    for(let index=0;index<12;index++){const offset=index*.25,oscillator=context.createOscillator(),pulse=context.createGain();oscillator.type="square";oscillator.frequency.setValueAtTime(index%2===0?920:610,start+offset);pulse.gain.setValueAtTime(.001,start+offset);pulse.gain.linearRampToValueAtTime(1,start+offset+.025);pulse.gain.setValueAtTime(1,start+offset+.19);pulse.gain.exponentialRampToValueAtTime(.001,start+offset+.235);oscillator.connect(pulse).connect(master);oscillator.start(start+offset);oscillator.stop(start+offset+.24);}
    window.navigator.vibrate?.([250,100,250,100,500]);setSoundStatus("Loud siren enabled");window.setTimeout(()=>void context.suspend().catch(()=>undefined),3400);return true;
  }

  function stopMonitoring(){if(monitorTimer.current)window.clearInterval(monitorTimer.current);monitorTimer.current=undefined;monitorBusy.current=false;setMonitoring(false);}
  async function startMonitoring(){
    setError("");
    await ensureAlertAudio();
    if("Notification" in window&&Notification.permission==="default")await Notification.requestPermission();
    const picker=(window as unknown as {showDirectoryPicker?:()=>Promise<DirectoryEntry>}).showDirectoryPicker;
    if(!picker){setError("Live folder monitoring requires Chrome or Edge folder permission support.");return;}
    try{
      const directory=await picker();
      let previous=await collectFiles(directory);
      setMonitorFolder(directory.name);setMonitoring(true);setLiveActivity({modified:0,created:0,deleted:0,renamed:0,extensions:0});
      monitorTimer.current=window.setInterval(async()=>{
        if(monitorBusy.current)return;monitorBusy.current=true;
        try{
          const current=await collectFiles(directory);
          const before=new Map(previous.map(file=>[file.relative_path,file]));
          const after=new Map(current.map(file=>[file.relative_path,file]));
          const removed=previous.filter(file=>!after.has(file.relative_path));
          const added=current.filter(file=>!before.has(file.relative_path));
          const modified=current.filter(file=>{const old=before.get(file.relative_path);return Boolean(old&&(old.modified_at!==file.modified_at||old.size!==file.size));}).length;
          const renamed=Math.min(removed.length,added.length);
          const extension=(name:string)=>name.includes(".")?name.slice(name.lastIndexOf(".")).toLowerCase():"";
          const extensions=Math.min(removed.filter((file,index)=>added[index]&&extension(file.name)!==extension(added[index].name)).length,renamed);
          const activity={modified,created:Math.max(0,added.length-renamed),deleted:Math.max(0,removed.length-renamed),renamed,extensions};
          const total=activity.modified+activity.created+activity.deleted+activity.renamed+activity.extensions;
          if(total>0){
            setLiveActivity(value=>({modified:value.modified+activity.modified,created:value.created+activity.created,deleted:value.deleted+activity.deleted,renamed:value.renamed+activity.renamed,extensions:value.extensions+activity.extensions}));
            if(total>=3||activity.extensions>0||activity.renamed>=2||activity.deleted>=3){
              const alert=await api.post<Scan>("/ransomware/activity-alerts",{folder_name:directory.name,total_files:current.length,window_seconds:2,modified_count:activity.modified,created_count:activity.created,deleted_count:activity.deleted,renamed_count:activity.renamed,extension_changed_count:activity.extensions});
              setActive(alert);await loadHistory();
              await playRansomwareAlarm();
              if("Notification" in window&&Notification.permission==="granted")new Notification("Ransomware activity alert",{body:`${directory.name}: ${total} rapid file changes detected`});
            }
          }
          previous=current;
        }catch(reason){
          const removedCount=previous.length;
          if(removedCount>0){
            try{const alert=await api.post<Scan>("/ransomware/activity-alerts",{folder_name:directory.name,total_files:0,window_seconds:2,modified_count:0,created_count:0,deleted_count:removedCount,renamed_count:0,extension_changed_count:0});setLiveActivity(value=>({...value,deleted:value.deleted+removedCount}));setActive(alert);await loadHistory();await playRansomwareAlarm();if("Notification" in window&&Notification.permission==="granted")new Notification("Critical ransomware activity",{body:`Monitored folder ${directory.name} was removed or became unavailable.`});setError(`Critical alert recorded: monitored folder ${directory.name} was removed or became unavailable.`);}catch(alertError){setError(alertError instanceof Error?alertError.message:"Folder removal was detected but the alert could not be saved.");}
          }else setError(reason instanceof Error?reason.message:"Live folder monitoring failed.");
          stopMonitoring();
        }
        finally{monitorBusy.current=false;}
      },2000);
    }catch(reason){if(!(reason instanceof DOMException&&reason.name==="AbortError"))setError(reason instanceof Error?reason.message:"Folder permission failed.");}
  }

  async function startScan() {
    setError(""); setStage("permission"); setProgress(5); setDiscoveredFiles(0); setCurrentFile("");
    try {
      const picker = (window as unknown as { showDirectoryPicker?: () => Promise<DirectoryEntry> }).showDirectoryPicker;
      if (!picker) throw new Error("Folder scanning requires Chrome or Edge with folder permission support.");
      const directory = await picker();
      setStage("reading"); setProgress(25); setCurrentFile(directory.name);
      const files = await collectFiles(directory, "", [], (count,path) => { setDiscoveredFiles(count); setCurrentFile(path); });
      if (!files.length) throw new Error("The selected folder contains no files.");
      setDiscoveredFiles(files.length); setStage("analysing"); setProgress(78); setCurrentFile("Evaluating suspicious extensions and ransom-note patterns");
      const result = await api.post<Scan>("/ransomware/scans", { folder_name: directory.name, files });
      setProgress(100); setActive(result); await loadHistory();
    } catch (reason) {
      if (reason instanceof DOMException && reason.name === "AbortError") setError("Folder permission was cancelled. No files were scanned.");
      else setError(reason instanceof Error ? reason.message : "Unable to complete the scan.");
    } finally { window.setTimeout(() => { setStage("idle"); setProgress(0); }, 700); }
  }

  const summary = useMemo(() => ({ total: scans.length, threats: scans.filter((scan) => scan.verdict !== "CLEAN").length, files: scans.reduce((sum, scan) => sum + scan.total_files, 0) }), [scans]);
  const scanning = stage !== "idle";
  return <div className="ransomware-page">
    <section className="ransomware-hero">
      <div><span className="eyebrow">ON-DEMAND PROTECTION</span><h1>Ransomware Scanner</h1><p>Select a folder, grant browser access, and inspect file names and metadata for ransomware indicators. Files are not uploaded.</p></div>
      <button className="scan-button" onClick={() => void startScan()} disabled={scanning}><FolderSearch size={20}/>{scanning ? "Scanning…" : "Choose folder & scan"}</button>
    </section>

    <section className={`live-folder-monitor ${monitoring?"armed":""}`}><div><span className="eyebrow">LIVE BEHAVIOUR MONITOR</span><h2>{monitoring?`Watching ${monitorFolder}`:"Watch external bulk file activity"}</h2><p>{monitoring?"Keep this page open. Edit, rename, change extensions or delete files in the approved test folder from File Explorer; changes are measured every 2 seconds.":"Select only a safe test folder. The browser asks permission and creates a baseline; file contents are never uploaded."}</p><button type="button" className="sound-test" onClick={()=>void playRansomwareAlarm()}><Volume2 size={16}/>Test loud siren <small>{soundStatus}</small></button></div><button className={monitoring?"stop-monitor":"scan-button"} onClick={()=>monitoring?stopMonitoring():void startMonitoring()}>{monitoring?<><Square size={17}/>Stop monitoring</>:<><Radio size={18}/>Choose test folder & monitor</>}</button>{monitoring&&<div className="activity-pulse"><span><b>{liveActivity.modified}</b>Modified</span><span><b>{liveActivity.renamed}</b>Renamed</span><span><b>{liveActivity.extensions}</b>Extension changes</span><span><b>{liveActivity.deleted}</b>Deleted</span><span><b>{liveActivity.created}</b>Created</span></div>}</section>

    {scanning && <section className="scan-console">
      <div className="scanner-visual"><div className="laptop-screen"><div className="screen-grid"/><div className="scan-beam"/><Radar/><span>{stage === "permission" ? "ACCESS" : stage === "reading" ? "INDEXING" : "ANALYSING"}</span></div><div className="laptop-base"/></div>
      <div className="scanner-status"><span className="eyebrow">LIVE RANSOMWARE SCAN</span><h2>{stage === "permission" ? "Permission required" : stage === "reading" ? "Mapping the approved folder" : "Inspecting ransomware indicators"}</h2><p>{stage === "permission" ? "Choose a folder in the browser dialog. Scanning starts only after you approve access." : stage === "reading" ? "Discovering files and subfolders. Large folders can take several minutes." : "The approved file inventory is being risk-scored. Files remain on this device."}</p>
        <div className="live-scan-metrics"><div><b>{discoveredFiles.toLocaleString()}</b><small>FILES DISCOVERED</small></div><div><b>{stage === "reading" ? "IN PROGRESS" : `${progress}%`}</b><small>CURRENT STAGE</small></div></div>
        <div className={`progress-track ${stage === "reading" ? "indeterminate" : ""}`}><b style={stage === "reading" ? undefined : {width:`${progress}%`}}/></div><div className="current-file"><span>Scanning</span><code>{currentFile || "Waiting for folder selection…"}</code></div>
        <div className="scan-stages"><span className={stage !== "permission" ? "done":"active"}>1. Permission</span><span className={stage === "reading" ? "active" : stage === "analysing" ? "done":""}>2. File indexing</span><span className={stage === "analysing" ? "active":""}>3. Threat analysis</span></div>
      </div>
    </section>}
    {error && <div className="scanner-error"><AlertTriangle size={18}/>{error}</div>}

    <section className="scan-stat-grid">
      <article><History/><span>Completed scans</span><strong>{summary.total}</strong></article>
      <article><FolderSearch/><span>Files inspected</span><strong>{summary.files.toLocaleString()}</strong></article>
      <article className={summary.threats ? "danger" : "safe"}>{summary.threats ? <ShieldAlert/> : <CheckCircle2/>}<span>Scans with indicators</span><strong>{summary.threats}</strong></article>
    </section>

    {active && <section className={`scan-result ${active.verdict === "CLEAN" ? "clean" : "threat"}`}>
      <div className="result-heading">{active.verdict === "CLEAN" ? <CheckCircle2/> : <ShieldAlert/>}<div><span>LATEST / SELECTED RESULT</span><h2>{verdictLabel(active.verdict)}</h2><p>{active.folder_name} · {new Date(active.completed_at).toLocaleString()}</p></div><div className="risk-ring" style={{"--risk":`${active.risk_score * 3.6}deg`} as React.CSSProperties}><b>{active.risk_score}</b><small>RISK</small></div></div>
      <div className="result-metrics"><div><b>{active.total_files}</b><span>Files scanned</span></div><div><b>{active.suspicious_files}</b><span>Indicators</span></div><div><b>{active.verdict === "CLEAN" ? "Protected" : "Review now"}</b><span>Recommended action</span></div></div>
      {active.findings?.length > 0 && <div className="finding-list"><h3>Detected indicators</h3>{active.findings.slice(0,20).map((finding,index)=><div key={`${finding.file}-${index}`}><span className={`severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span><strong>{finding.file}</strong><p>{finding.reason}</p></div>)}</div>}
    </section>}

    <section className="scan-history"><div className="section-title"><div><span className="eyebrow">ORGANIZATION HISTORY</span><h2>Previous scans</h2></div></div>
      {scans.length === 0 ? <div className="empty-scan"><FolderSearch/><h3>No scans yet</h3><p>Choose a folder to create the first ransomware scan record.</p></div> : <div className="history-list">{scans.map((scan)=><button key={scan.id} onClick={()=>setActive(scan)} className={active?.id===scan.id?"selected":""}><span className={`history-icon ${scan.verdict === "CLEAN" ? "clean":"threat"}`}>{scan.verdict === "CLEAN"?<CheckCircle2/>:<ShieldAlert/>}</span><span><strong>{scan.folder_name}</strong><small>{new Date(scan.completed_at).toLocaleString()}</small></span><span className="history-bar"><i style={{width:`${scan.risk_score}%`}}/></span><span><b>{scan.risk_score}</b><small>Risk score</small></span><span><b>{scan.suspicious_files}</b><small>Indicators</small></span></button>)}</div>}
    </section>
  </div>;
}
