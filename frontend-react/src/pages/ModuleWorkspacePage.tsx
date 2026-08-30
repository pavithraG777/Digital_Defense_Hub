import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Link, Navigate, useParams } from "react-router-dom";
import { AlertCircle, Check, ChevronRight, CircleOff, Eye, LoaderCircle, Plus, RefreshCw, X } from "lucide-react";
import type { ApiSource, ScreenAction } from "../types";
import { api, apiBlob, apiRequest } from "../lib/api";
import { displayValue, getRecordId, getRecordLabel, getRecordStatus, isRecord, recordTimestamp, toCollection, type UnknownRecord } from "../lib/records";
import { getModule, getScreen } from "../lib/modules";

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
  return path.replace(":id", encodeURIComponent(id));
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

function ResourceContents({ resource, onInspect }: { resource: ResourceState; onInspect: (source: ApiSource, value: unknown) => void }) {
  if (resource.status === "loading") {
    return <div className="resource-loading"><LoaderCircle size={18} className="spin" /> Loading live data…</div>;
  }
  if (resource.status === "error") {
    return <div className="resource-error"><AlertCircle size={17} /><div><strong>Could not load this source</strong><span>{resource.error}</span></div></div>;
  }

  const records = toCollection(resource.data);
  if (records.length) {
    return (
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Record</th><th>Status / severity</th><th>Last activity</th><th aria-label="Open details" /></tr></thead>
          <tbody>
            {records.slice(0, 50).map((record, index) => {
              const canInspect = Boolean(resource.source.detailPath && getRecordId(record));
              return (
                <tr key={getRecordId(record) || `${resource.source.id}-${index}`} className={canInspect ? "table-row-action" : ""} onClick={() => canInspect && onInspect(resource.source, record)}>
                  <td><strong>{getRecordLabel(record)}</strong>{isRecord(record) && record.description ? <small>{displayValue(record.description)}</small> : null}</td>
                  <td><span className={`status-chip status-${getRecordStatus(record).toLowerCase().replace(/[^a-z0-9]+/g, "-")}`}>{getRecordStatus(record)}</span></td>
                  <td>{recordTimestamp(record)}</td>
                  <td>{canInspect ? <button className="icon-button" type="button" aria-label="View details" onClick={(event) => { event.stopPropagation(); onInspect(resource.source, record); }}><Eye size={16} /></button> : null}</td>
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

function ActionDialog({ action, onClose, onCompleted }: { action: ScreenAction; onClose: () => void; onCompleted: (message: string) => void }) {
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
      const body = Object.fromEntries(Object.entries(values).map(([key, value]) => [key, value]));
      await apiRequest(action.path, { method: action.method, body });
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
      <section className="modal" role="dialog" aria-modal="true" aria-labelledby="action-dialog-title" onMouseDown={(event) => event.stopPropagation()}>
        <div className="modal-header"><div><p className="eyebrow">LIVE BACKEND ACTION</p><h2 id="action-dialog-title">{action.label}</h2>{action.description && <p>{action.description}</p>}</div><button className="icon-button" type="button" onClick={onClose} aria-label="Close"><X size={19} /></button></div>
        {error && <div className="alert alert-error" role="alert">{error}</div>}
        <form onSubmit={submit}>
          <div className="form-grid">
            {action.fields?.map((field) => (
              <label key={field.name} className={field.type === "textarea" ? "field-wide" : undefined}>
                {field.label}{field.required && <span className="required-mark"> *</span>}
                {field.type === "textarea" ? (
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
  const module = getModule(moduleId);
  const screen = getScreen(moduleId, screenId);
  const [resources, setResources] = useState<ResourceState[]>([]);
  const [detail, setDetail] = useState<DetailState>(null);
  const [activeAction, setActiveAction] = useState<ScreenAction | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const loadResources = useCallback(async () => {
    if (!screen?.sources?.length) {
      setResources([]);
      return;
    }
    setResources(screen.sources.map((source) => ({ source, status: "loading" })));
    const loaded = await Promise.all(screen.sources.map(async (source): Promise<ResourceState> => {
      try {
        const data = await api.get<unknown>(source.path);
        return { source, status: "success", data };
      } catch (err) {
        return { source, status: "error", error: err instanceof Error ? err.message : "Unknown API error" };
      }
    }));
    setResources(loaded);
  }, [screen]);

  useEffect(() => { void loadResources(); }, [loadResources]);

  const connectedCount = useMemo(() => resources.filter((resource) => resource.status === "success").length, [resources]);
  if (!module || !screen || !moduleId || !screenId) return <Navigate to="/dashboard" replace />;

  async function inspect(source: ApiSource, record: unknown) {
    const id = getRecordId(record);
    if (!id || !source.detailPath) return;
    setDetail({ title: `${source.label}: ${getRecordLabel(record)}`, status: "loading" });
    try {
      const data = await api.get<unknown>(interpolatePath(source.detailPath, id));
      setDetail({ title: `${source.label}: ${getRecordLabel(record)}`, status: "success", data });
    } catch (err) {
      setDetail({ title: `${source.label}: ${getRecordLabel(record)}`, status: "error", error: err instanceof Error ? err.message : "Unable to load record details" });
    }
  }

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
            {screen.actions?.map((action) => <button key={action.label} className="primary" type="button" onClick={() => setActiveAction(action)}><Plus size={16} /> {action.label}</button>)}
            {screen.sources?.length ? <button className="secondary with-icon" type="button" onClick={() => void loadResources()}><RefreshCw size={16} /> Refresh</button> : null}
          </div>
        </header>
        {notice && <div className="alert alert-success" role="status"><Check size={17} /> {notice}</div>}
        {screen.unavailable ? (
          <div className="api-unavailable"><CircleOff size={23} /><div><h2>Backend API not available yet</h2><p>{screen.unavailable}</p><span>This interface does not invent or display mock records.</span></div></div>
        ) : (
          <>
            <div className="connection-strip"><span className="live-dot" /> {connectedCount} of {screen.sources?.length || 0} live source{(screen.sources?.length || 0) === 1 ? "" : "s"} connected <span>·</span> API responses are displayed as returned by the backend.</div>
            <div className="resource-stack">
              {resources.map((resource) => (
                <article className="resource-card" key={resource.source.id}>
                  <div className="resource-heading"><div><p>LIVE SOURCE</p><h2>{resource.source.label}</h2>{resource.source.description && <span>{resource.source.description}</span>}</div><code>{resource.source.path}</code></div>
                  <ResourceContents resource={resource} onInspect={inspect} />
                </article>
              ))}
              {!resources.length && <div className="empty-inline"><CircleOff size={18} /> No live source is configured for this screen.</div>}
            </div>
          </>
        )}
      </section>
      {detail && <div className="details-panel"><div className="details-panel-head"><div><p>LIVE RECORD DETAIL</p><h2>{detail.title}</h2></div><button type="button" className="icon-button" onClick={() => setDetail(null)} aria-label="Close details"><X size={18} /></button></div>{detail.status === "loading" ? <div className="resource-loading"><LoaderCircle size={18} className="spin" /> Loading record…</div> : detail.status === "error" ? <div className="resource-error"><AlertCircle size={17} /><span>{detail.error}</span></div> : <>{screenId === "reports" && isRecord(detail.data) ? <ForensicReportDocumentControls report={detail.data} /> : null}<JSONDetail value={detail.data} /></>}</div>}
      {activeAction && <ActionDialog action={activeAction} onClose={() => setActiveAction(null)} onCompleted={(message) => { setNotice(message); void loadResources(); }} />}
    </div>
  );
}
