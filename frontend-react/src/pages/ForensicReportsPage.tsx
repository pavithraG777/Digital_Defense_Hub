import { useCallback, useEffect, useState } from "react";
import {
  Download,
  Eye,
  FileLock2,
  FileText,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  CheckCircle2,
  X,
} from "lucide-react";
import { api, apiBlob } from "../lib/api";

type Report = {
  id: string;
  report_number: string;
  media_asset_id: string;
  incident_id?: string;
  status: string;
  document_sha256: string;
  generated_at: string;
  approved_at?: string;
  approved_by?: string;
  approval_note?: string;
};
const when = (v?: string) =>
  v ? new Date(v).toLocaleString() : "Not recorded";

export function ForensicReportsPage() {
  const [rows, setRows] = useState<Report[]>([]);
  const [selected, setSelected] = useState<Report>();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [approvalNote, setApprovalNote] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    setError("");
    try {
      const r: any = await api.get(
        "/deepfake-forensics/forensic-reports?page=1&page_size=100",
      );
      setRows(Array.isArray(r) ? r : r.items || []);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Unable to load forensic reports.",
      );
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  const openPDF = async (download: boolean) => {
    if (!selected) return;
    setBusy(true);
    setError("");
    try {
      const blob = await apiBlob(
        `/deepfake-forensics/forensic-reports/${selected.id}/${download ? "download" : "preview"}`,
        { method: "POST", body: { access_password: password } },
      );
      const url = URL.createObjectURL(blob);
      if (download) {
        const a = document.createElement("a");
        a.href = url;
        a.download = `${selected.report_number}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        window.open(url, "_blank", "noopener,noreferrer");
        window.setTimeout(() => URL.revokeObjectURL(url), 60000);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to open PDF.");
    } finally {
      setBusy(false);
    }
  };
  const protect = async () => {
    if (!selected) return;
    if (password.length < 12) {
      setError("Use at least 12 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Password confirmation does not match.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api.post(
        `/deepfake-forensics/forensic-reports/${selected.id}/access-password`,
        { access_password: password },
      );
      setConfirm("");
      setNotice("Report access password saved securely.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to protect report.");
    } finally {
      setBusy(false);
    }
  };
  const approve = async () => {
    if (!selected || !approvalNote.trim()) return;
    setBusy(true);
    setError("");
    try {
      const response: any = await api.post(
        `/deepfake-forensics/forensic-reports/${selected.id}/approve`,
        { approval_note: approvalNote.trim() },
      );
      const approved = response?.data || response;
      setSelected(approved);
      setRows((current) => current.map((row) => row.id === approved.id ? approved : row));
      setNotice("Report approved and the signed PDF integrity hash was updated.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to approve report.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="page module-page">
      <header className="hero module-hero">
        <div>
          <p className="eyebrow">DEEPFAKE FORENSICS · SIGNED DOCUMENTS</p>
          <h1>Forensic Reports</h1>
          <p>
            Signed PDF findings, approval state, integrity hashes, and
            controlled report access.
          </p>
        </div>
        <button className="secondary with-icon" onClick={() => void load()}>
          <RefreshCw size={16} />
          Refresh
        </button>
      </header>
      {error && <div className="alert alert-error">{error}</div>}
      {notice && <div className="alert alert-success">{notice}</div>}
      <section className="iam-directory-panel">
        <p className="iam-record-count">
          {rows.length} report(s) returned by the forensic-report backend.
        </p>
        <div className="table-wrap">
          <table className="iam-table">
            <thead>
              <tr>
                <th>Report</th>
                <th>PDF integrity</th>
                <th>Linked record</th>
                <th>Approval</th>
                <th>Generated</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.length ? (
                rows.map((r) => (
                  <tr
                    className="table-row-action"
                    key={r.id}
                    onClick={() => {
                      setSelected(r);
                      setPassword("");
                      setConfirm("");
                      setApprovalNote("");
                      setNotice("");
                    }}
                  >
                    <td>
                      <strong>
                        <FileText size={16} />
                        {r.report_number}
                      </strong>
                      <small>Media asset {r.media_asset_id}</small>
                    </td>
                    <td className="mono">{r.document_sha256}</td>
                    <td>{r.incident_id || "No incident linked"}</td>
                    <td>
                      <span
                        className={`iam-status ${r.status === "APPROVED" ? "active" : "inactive"}`}
                      >
                        {r.status}
                      </span>
                    </td>
                    <td>{when(r.approved_at || r.generated_at)}</td>
                    <td>
                      <button className="icon-button">
                        <Eye size={16} />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6}>No forensic reports are available.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
      {selected && (
        <div
          className="evidence-report-overlay"
          onMouseDown={() => setSelected(undefined)}
        >
          <aside
            className="evidence-report-drawer"
            onMouseDown={(e) => e.stopPropagation()}
          >
            <div className="evidence-report-head">
              <div>
                <p>FORENSIC REPORT</p>
                <h2>{selected.report_number}</h2>
                <span>
                  {selected.status} · Generated {when(selected.generated_at)}
                </span>
              </div>
              <button
                className="icon-button"
                onClick={() => setSelected(undefined)}
              >
                <X size={18} />
              </button>
            </div>
            <section className="soc-detail-section">
              <h3>
                <ShieldCheck size={16} />
                Evidence integrity
              </h3>
              <dl className="detail-grid">
                <div className="hash-value">
                  <dt>PDF SHA-256</dt>
                  <dd className="mono">{selected.document_sha256}</dd>
                </div>
                <div>
                  <dt>Media asset</dt>
                  <dd className="mono">{selected.media_asset_id}</dd>
                </div>
                <div>
                  <dt>Linked incident</dt>
                  <dd>{selected.incident_id || "Not recorded"}</dd>
                </div>
                <div>
                  <dt>Approved at</dt>
                  <dd>{when(selected.approved_at)}</dd>
                </div>
              </dl>
            </section>
            {selected.status !== "APPROVED" && (
              <section className="soc-detail-section">
                <h3>
                  <CheckCircle2 size={16} />
                  Analyst approval
                </h3>
                <p>
                  Review the findings and record your approval note before
                  marking this report as approved.
                </p>
                <label>
                  Approval note
                  <textarea
                    value={approvalNote}
                    onChange={(e) => setApprovalNote(e.target.value)}
                    placeholder="Findings and evidence integrity reviewed."
                    rows={3}
                  />
                </label>
                <button
                  className="primary with-icon"
                  disabled={busy || !approvalNote.trim()}
                  onClick={() => void approve()}
                >
                  <CheckCircle2 size={15} />
                  Approve report
                </button>
              </section>
            )}
            <section className="soc-detail-section">
              <h3>
                <FileLock2 size={16} />
                Protected PDF access
              </h3>
              <p>
                Set a password to require it before a report is viewed or
                downloaded. Password is stored as a secure hash only.
              </p>
              <label>
                Report password
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="At least 12 characters"
                />
              </label>
              <label>
                Confirm password
                <input
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder="Only required to set/change password"
                />
              </label>
              <div className="modal-actions">
                <button
                  className="secondary"
                  disabled={busy}
              onClick={() => void openPDF(false)}
                >
                  <Eye size={15} />
                  View PDF
                </button>
                <button
                  className="secondary"
                  disabled={busy}
              onClick={() => void openPDF(true)}
                >
                  <Download size={15} />
                  Download
                </button>
                <button
                  className="primary"
                  disabled={busy}
                  onClick={() => void protect()}
                >
                  <KeyRound size={15} />
                  Protect report
                </button>
              </div>
            </section>
          </aside>
        </div>
      )}
    </section>
  );
}
