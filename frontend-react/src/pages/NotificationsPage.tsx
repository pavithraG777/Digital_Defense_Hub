import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, Bell, CheckCheck, Eye, RefreshCw, Search, X } from "lucide-react";
import { api } from "../lib/api";

type NotificationRecord = Record<string, unknown>;
type UserNotification = Record<string, unknown> & { notification?: NotificationRecord };
type NotificationList = {
  notifications?: UserNotification[];
  unread_count?: number;
  total?: number;
  page?: number;
  page_size?: number;
  total_pages?: number;
};

const value = (input: unknown) => input === null || input === undefined || input === "" ? "Not provided" : String(input);
const formatDate = (input: unknown) => input ? new Date(String(input)).toLocaleString() : "Not provided";

export function NotificationsPage() {
  const [items, setItems] = useState<UserNotification[]>([]);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [query, setQuery] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [total, setTotal] = useState(0);
  const [unread, setUnread] = useState(0);
  const [loading, setLoading] = useState(false);
  const [actionId, setActionId] = useState("");
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<UserNotification | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ page: "1", page_size: "100" });
      if (status) params.set("in_app_status", status);
      if (severity) params.set("severity", severity);
      const result = await api.get<NotificationList>(`/my-notifications?${params.toString()}`);
      setItems(Array.isArray(result.notifications) ? result.notifications : []);
      setTotal(Number(result.total || 0));
      setUnread(Number(result.unread_count || 0));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load notifications.");
    } finally {
      setLoading(false);
    }
  }, [severity, status]);

  useEffect(() => { void load(); }, [load]);

  const filtered = useMemo(() => items.filter((item) => {
    const note = item.notification || {};
    const searchable = [note.notification_code, note.title, note.message, note.category, note.notification_type, note.severity, item.in_app_status].map(value).join(" ").toLowerCase();
    if (query && !searchable.includes(query.trim().toLowerCase())) return false;
    const created = note.created_at ? new Date(String(note.created_at)).getTime() : 0;
    if (from && created < new Date(`${from}T00:00:00`).getTime()) return false;
    if (to && created > new Date(`${to}T23:59:59.999`).getTime()) return false;
    return true;
  }), [from, items, query, to]);

  async function runAction(item: UserNotification, action: "read" | "acknowledge" | "dismiss") {
    const note = item.notification || {};
    const id = String(note.id || "");
    if (!id) return;
    setActionId(`${id}:${action}`);
    setError("");
    try {
      // Acknowledgement-required notifications are intentionally not
      // dismissible in the backend: acknowledgement is the audited terminal
      // action for that recipient. Remove it from this active queue after the
      // successful acknowledgement, without issuing an invalid dismiss call.
      let updated: UserNotification;
      if (action === "dismiss" && note.requires_acknowledgement && stateOf(item) !== "ACKNOWLEDGED") {
        updated = await api.patch<UserNotification>(`/my-notifications/${id}/acknowledge`);
      } else {
        updated = await api.patch<UserNotification>(`/my-notifications/${id}/${action}`);
      }
      // Keep the server record in the user-visible history. This makes the
      // acknowledgement/dismissal state and timestamp reviewable without
      // needing an administrator audit-log query.
      setItems((current) => current.map((candidate) => String((candidate.notification || {}).id || candidate.recipient_id || "") === id ? updated : candidate));
      if (stateOf(item) === "UNREAD") setUnread((current) => Math.max(0, current - 1));
      if (selected && String((selected.notification || {}).id || "") === id) setSelected(updated);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : `Unable to ${action} the notification.`);
    } finally {
      setActionId("");
    }
  }

  async function markAllRead() {
    setActionId("read-all");
    setError("");
    try {
      await api.patch("/my-notifications/read-all");
      setItems([]);
      setTotal(0);
      setUnread(0);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to mark notifications as read.");
    } finally {
      setActionId("");
    }
  }

  function openPicker(event: React.MouseEvent<HTMLInputElement>) {
    const input = event.currentTarget as HTMLInputElement & { showPicker?: () => void };
    input.showPicker?.();
  }

  return <section className="page deception-page notifications-page">
    <header className="deception-header">
      <div><span className="eyebrow">PERSONAL NOTIFICATION CENTER</span><h1>Notification Management</h1><p>The bell badge shows unread items. This page retains your read, acknowledgement and dismissal history; use Audit Activity for organization-wide audit records.</p></div>
      <div className="deception-actions">
        <button className="secondary with-icon" type="button" onClick={() => void markAllRead()} disabled={loading || unread === 0 || actionId === "read-all"}><CheckCheck size={16}/>{actionId === "read-all" ? "Updating…" : "Mark all read"}</button>
        <button className="secondary with-icon" type="button" onClick={() => void load()} disabled={loading}><RefreshCw className={loading ? "spin" : ""} size={16}/>{loading ? "Refreshing…" : "Refresh"}</button>
      </div>
    </header>

    {error && <div className="alert alert-error"><AlertTriangle size={17}/>{error}</div>}

    <div className="notification-kpis">
      <article><Bell size={18}/><div><span>Matching records</span><strong>{total}</strong></div></article>
      <article><CheckCheck size={18}/><div><span>Unread for this account</span><strong>{unread}</strong></div></article>
      <article><Eye size={18}/><div><span>Visible after local search/date</span><strong>{filtered.length}</strong></div></article>
    </div>

    <article className="deception-inventory">
      <div className="notification-filter-bar">
        <label className="inventory-search"><Search size={16}/><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search code, title, message, category or type" /></label>
        <label><span>Read state</span><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">All states</option><option value="UNREAD">Unread</option><option value="READ">Read</option><option value="ACKNOWLEDGED">Acknowledged</option><option value="DISMISSED">Dismissed</option></select></label>
        <label><span>Severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option>{["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((level) => <option key={level}>{level}</option>)}</select></label>
        <div className="notification-date-range"><label><span>From</span><input type="date" value={from} onClick={openPicker} onChange={(event) => setFrom(event.target.value)} /></label><label><span>To</span><input type="date" value={to} onClick={openPicker} onChange={(event) => setTo(event.target.value)} /></label></div>
        <button className="secondary" type="button" onClick={() => { setQuery(""); setStatus(""); setSeverity(""); setFrom(""); setTo(""); }}>Clear</button>
      </div>

      <div className="notification-record-list">
        {loading && !items.length ? <div className="empty-inline">Loading real backend notifications…</div> : filtered.map((item) => {
          const note = item.notification || {};
          const id = String(note.id || item.recipient_id || "");
          const state = value(item.in_app_status).toUpperCase();
          return <article key={id} className={state === "UNREAD" ? "unread" : ""}>
            <button className="notification-open" type="button" onClick={() => setSelected(item)}>
              <div><span className={`severity ${value(note.severity).toLowerCase()}`}>{value(note.severity)}</span><span className="status-chip">{state}</span><time>{formatDate(note.created_at)}</time></div>
              <h2>{value(note.title)}</h2><p>{value(note.message)}</p>
              <small>{value(note.notification_code)} · {value(note.category)} · {value(note.notification_type)}</small>
            </button>
            <div className="notification-actions">
              {state === "UNREAD" && <button type="button" onClick={() => void runAction(item, "read")} disabled={Boolean(actionId)}>Mark as read</button>}
              {Boolean(note.requires_acknowledgement) && state !== "ACKNOWLEDGED" && state !== "DISMISSED" && <button type="button" onClick={() => void runAction(item, "acknowledge")} disabled={Boolean(actionId)}>Acknowledge</button>}
              {state !== "DISMISSED" && state !== "ACKNOWLEDGED" && <button type="button" onClick={() => void runAction(item, "dismiss")} disabled={Boolean(actionId)}>{note.requires_acknowledgement ? "Acknowledge & remove" : "Dismiss"}</button>}
            </div>
          </article>;
        })}
        {!loading && !filtered.length && <div className="empty-inline">No notification records match these filters.</div>}
      </div>
    </article>
    {selected && <NotificationDrawer item={selected} onClose={() => setSelected(null)} />}
  </section>;
}

function stateOf(item: UserNotification) { return value(item.in_app_status).toUpperCase(); }

function NotificationDrawer({ item, onClose }: { item: UserNotification; onClose: () => void }) {
  const note = item.notification || {};
  const fields: Array<[string, unknown, boolean?]> = [
    ["Notification code", note.notification_code], ["Type", note.notification_type], ["Category", note.category], ["Severity", note.severity],
    ["Priority level", note.priority_level], ["Delivery status", note.status], ["Read state", item.in_app_status], ["Requires acknowledgement", note.requires_acknowledgement ? "Yes" : "No"],
    ["Incident ID", note.incident_id], ["Threat ID", note.threat_id], ["Department ID", note.department_id], ["Recipient ID", item.recipient_id],
    ["Created", note.created_at, true], ["Updated", note.updated_at, true], ["Read", item.read_at, true], ["Acknowledged", item.acknowledged_at, true], ["Dismissed", item.dismissed_at, true], ["Expires", note.expires_at, true],
  ];
  return <><button className="drawer-backdrop" type="button" aria-label="Close notification details" onClick={onClose}/><aside className="deception-drawer notification-detail-drawer"><div className="drawer-heading"><div><span className="eyebrow">SAFE NOTIFICATION RECORD</span><h2>{value(note.title)}</h2></div><button type="button" onClick={onClose}><X size={18}/></button></div><section className="notification-message-panel"><span className={`severity ${value(note.severity).toLowerCase()}`}>{value(note.severity)}</span><p>{value(note.message)}</p></section><section><h3>Backend record</h3><dl className="detail-grid">{fields.map(([label, input, isDate]) => <div key={label}><dt>{label}</dt><dd>{isDate ? formatDate(input) : value(input)}</dd></div>)}</dl></section></aside></>;
}
