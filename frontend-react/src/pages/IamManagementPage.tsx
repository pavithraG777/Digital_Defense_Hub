import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Ban, Edit3, Eye, Plus, RefreshCw, Search, Trash2, X } from "lucide-react";
import { api } from "../lib/api";

type ModuleKind = "users" | "roles" | "permissions";
type RecordItem = Record<string, any>;

const moduleConfig = {
  users: { title: "Users", subtitle: "Create, update, block and review platform users.", endpoint: "/admin/users", singular: "User" },
  roles: { title: "Roles", subtitle: "Create roles and control their assigned permissions.", endpoint: "/admin/roles", singular: "Role" },
  permissions: { title: "Permissions", subtitle: "Maintain the platform permission catalogue.", endpoint: "/admin/permissions", singular: "Permission" },
} as const;

function recordsOf(response: any): RecordItem[] {
  const data = response?.data ?? response;
  if (Array.isArray(data)) return data;
  for (const key of ["users", "roles", "permissions", "items", "records"]) {
    if (Array.isArray(data?.[key])) return data[key];
  }
  return [];
}

async function loadAllActivePermissions(): Promise<RecordItem[]> {
  const first: any = await api.get("/admin/permissions?page=1&page_size=100");
  const firstData = first?.data ?? first;
  const totalPages = Math.max(1, Number(firstData?.total_pages || 1));
  if (totalPages === 1) return recordsOf(firstData);
  const pages = await Promise.all(Array.from({ length: totalPages - 1 }, (_, index) => api.get(`/admin/permissions?page=${index + 2}&page_size=100`)));
  return [
    ...recordsOf(firstData),
    ...pages.flatMap((response: any) => recordsOf(response?.data ?? response)),
  ];
}

export function IamManagementPage({ initialTab = "users" }: { initialTab?: ModuleKind }) {
  const kind = initialTab;
  const config = moduleConfig[kind];
  const [rows, setRows] = useState<RecordItem[]>([]);
  const [roles, setRoles] = useState<RecordItem[]>([]);
  const [permissions, setPermissions] = useState<RecordItem[]>([]);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<RecordItem | null>(null);
  const [dialog, setDialog] = useState<"create" | "edit" | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [current, roleResponse, permissionResponse] = await Promise.all([
        api.get(config.endpoint),
        api.get("/admin/roles"),
        loadAllActivePermissions(),
      ]);
      setRows(kind === "permissions" ? permissionResponse : recordsOf(current));
      setRoles(recordsOf(roleResponse));
      setPermissions(permissionResponse);
    } catch (cause: any) {
      setError(cause?.message || `Unable to load ${config.title.toLowerCase()}.`);
    } finally {
      setLoading(false);
    }
  }, [config.endpoint, config.title]);

  useEffect(() => { void load(); }, [load]);

  const filtered = useMemo(() => rows.filter((row) => {
    const text = JSON.stringify(row).toLowerCase();
    const currentStatus = String(row.account_status ?? row.status ?? "").toUpperCase();
    return text.includes(query.toLowerCase()) && (status === "ALL" || currentStatus === status);
  }), [rows, query, status]);

  const activeCount = rows.filter((row) => ["ACTIVE", "APPROVED"].includes(String(row.account_status ?? row.status).toUpperCase())).length;
  const blockedCount = rows.filter((row) => ["BLOCKED", "INACTIVE", "DISABLED"].includes(String(row.account_status ?? row.status).toUpperCase())).length;

  async function selectRecord(row: RecordItem, mode: "view" | "edit" = "view") {
    setError("");
    try {
      const response: any = await api.get(`${config.endpoint}/${row.id}`);
      setSelected(response?.data ?? response);
      if (mode === "edit") setDialog("edit");
    } catch (cause: any) {
      setError(cause?.message || `Unable to load ${config.singular.toLowerCase()} details.`);
    }
  }

  async function disableUser(row: RecordItem) {
    if (!window.confirm(`Block ${row.display_name || row.username || "this user"}?`)) return;
    try {
      await api.patch(`/admin/users/${row.id}/status`, { status: "BLOCKED", reason: "Blocked by administrator" });
      await load();
      setSelected(null);
    } catch (cause: any) { setError(cause?.message || "Unable to block user."); }
  }

  async function remove(row: RecordItem) {
    const label = row.display_name || row.role_name || row.permission_name || row.name || row.username;
    if (!window.confirm(`Delete ${label}? System records may be retained for audit.`)) return;
    try {
      await api.delete(`${config.endpoint}/${row.id}`);
      await load();
      setSelected(null);
    } catch (cause: any) { setError(cause?.message || `Unable to delete ${config.singular.toLowerCase()}.`); }
  }

  return (
    <section className="iam-page module-page">
      <header className="iam-page-header">
        <div>
          <span className="eyebrow">IDENTITY &amp; ACCESS MANAGEMENT</span>
          <h1>{config.title}</h1>
          <p>{config.subtitle}</p>
        </div>
        <div className="iam-header-actions">
          <button className="secondary-button" onClick={() => void load()}><RefreshCw size={16} /> Refresh</button>
          <button className="primary-button" onClick={() => setDialog("create")}><Plus size={17} /> Create {config.singular}</button>
        </div>
      </header>

      {error && <div className="error-banner">{error}</div>}

      <div className="iam-summary-grid">
        <article><span>Total {config.title}</span><strong>{rows.length}</strong><small>Backend records</small></article>
        <article><span>Active</span><strong>{activeCount}</strong><small>Currently enabled</small></article>
        <article><span>Blocked / inactive</span><strong>{blockedCount}</strong><small>Access unavailable</small></article>
      </div>

      <section className="iam-directory-panel">
        <div className="iam-toolbar">
          <label className="iam-search"><Search size={17} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={`Search ${config.title.toLowerCase()}...`} /></label>
          <select value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="ALL">All statuses</option><option value="ACTIVE">Active</option><option value="INACTIVE">Inactive</option>
            {kind === "users" && <option value="BLOCKED">Blocked</option>}
          </select>
        </div>
        <p className="iam-record-count">Showing {filtered.length} of {rows.length} real backend record(s)</p>
        <div className="iam-table-wrap">
          <table className="iam-table">
            <thead><TableHead kind={kind} /></thead>
            <tbody>
              {loading ? <tr><td colSpan={7}>Loading backend records...</td></tr> : filtered.length === 0 ? <tr><td colSpan={7}>No matching records.</td></tr> : filtered.map((row) => (
                <TableRow key={row.id} kind={kind} row={row} onView={() => void selectRecord(row)} onEdit={() => void selectRecord(row, "edit")} onDelete={() => void (kind === "users" ? disableUser(row) : remove(row))} />
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {selected && !dialog && <DetailsDrawer kind={kind} row={selected} onClose={() => setSelected(null)} onEdit={() => setDialog("edit")} onDelete={() => void (kind === "users" ? disableUser(selected) : remove(selected))} />}
      {dialog && <EditorDialog kind={kind} existing={dialog === "edit" ? selected : null} roles={roles} permissions={permissions} onClose={() => setDialog(null)} onSaved={async () => { setDialog(null); setSelected(null); await load(); }} />}
    </section>
  );
}

function TableHead({ kind }: { kind: ModuleKind }) {
  if (kind === "users") return <tr><th>User</th><th>Official email</th><th>Type</th><th>Status</th><th>Created</th><th>Actions</th></tr>;
  if (kind === "roles") return <tr><th>Role</th><th>Code</th><th>Scope</th><th>Priority</th><th>Status</th><th>Actions</th></tr>;
  return <tr><th>Permission</th><th>Code</th><th>Module</th><th>Action</th><th>Risk</th><th>Status</th><th>Actions</th></tr>;
}

function TableRow({ kind, row, onView, onEdit, onDelete }: { kind: ModuleKind; row: RecordItem; onView: () => void; onEdit: () => void; onDelete: () => void }) {
  const actions = <td className="iam-row-actions"><button title="View" onClick={onView}><Eye size={16} /></button><button title="Edit" onClick={onEdit}><Edit3 size={16} /></button><button title={kind === "users" ? "Block" : "Delete"} onClick={onDelete}>{kind === "users" ? <Ban size={16} /> : <Trash2 size={16} />}</button></td>;
  if (kind === "users") return <tr><td><strong>{row.display_name || row.username}</strong><small>@{row.username}</small></td><td>{row.official_email || "Not reported"}</td><td>{row.user_type || "Not reported"}</td><td><Status value={row.account_status} /></td><td>{formatDate(row.created_at)}</td>{actions}</tr>;
  if (kind === "roles") return <tr><td><strong>{row.role_name || row.name}</strong><small>{row.description || "No description"}</small></td><td>{row.role_code}</td><td>{row.role_scope || "Not reported"}</td><td>{row.priority_level ?? "—"}</td><td><Status value={row.status} /></td>{actions}</tr>;
  return <tr><td><strong>{row.permission_name || row.name}</strong><small>{row.description || "No description"}</small></td><td>{row.permission_code}</td><td>{row.module_name}</td><td>{row.action_name}</td><td><Status value={row.risk_level} /></td><td><Status value={row.status} /></td>{actions}</tr>;
}

function Status({ value }: { value: any }) { return <span className={`iam-status ${String(value || "unknown").toLowerCase()}`}>{String(value || "Not reported")}</span>; }
function formatDate(value: any) { if (!value) return "Not reported"; const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString(); }

function DetailsDrawer({ kind, row, onClose, onEdit, onDelete }: { kind: ModuleKind; row: RecordItem; onClose: () => void; onEdit: () => void; onDelete: () => void }) {
  const hidden = new Set(["password", "password_hash", "totp_secret", "secret", "token"]);
  const fields = Object.entries(row).filter(([key]) => !hidden.has(key.toLowerCase()) && !key.toLowerCase().includes("secret"));
  return <div className="iam-overlay" role="presentation"><aside className="iam-drawer" role="dialog" aria-modal="true"><header><div><span className="eyebrow">{moduleConfig[kind].singular.toUpperCase()} RECORD</span><h2>{row.display_name || row.role_name || row.permission_name || row.name || row.username}</h2></div><button className="icon-button" onClick={onClose}><X /></button></header><div className="iam-detail-grid">{fields.map(([key, value]) => <div key={key}><span>{key.replaceAll("_", " ")}</span><strong>{typeof value === "object" ? "Available in linked records" : String(value ?? "Not reported")}</strong></div>)}</div><footer><button className="secondary-button" onClick={onEdit}><Edit3 size={16} /> Edit</button><button className="danger-button" onClick={onDelete}>{kind === "users" ? <Ban size={16} /> : <Trash2 size={16} />}{kind === "users" ? "Block user" : `Delete ${kind.slice(0, -1)}`}</button></footer></aside></div>;
}

function EditorDialog({ kind, existing, roles, permissions, onClose, onSaved }: { kind: ModuleKind; existing: RecordItem | null; roles: RecordItem[]; permissions: RecordItem[]; onClose: () => void; onSaved: () => Promise<void> }) {
  const [form, setForm] = useState<RecordItem>(existing ? { ...existing } : { status: "ACTIVE", account_status: "ACTIVE", user_type: "INTERNAL", scope: "ORGANIZATION", risk_level: "MEDIUM", priority: 100, permission_ids: [] });
  const [saving, setSaving] = useState(false); const [error, setError] = useState("");
  const set = (key: string, value: any) => setForm((current) => ({ ...current, [key]: value }));
  const togglePermission = (id: string) => set("permission_ids", (form.permission_ids || []).includes(id) ? form.permission_ids.filter((item: string) => item !== id) : [...(form.permission_ids || []), id]);

  useEffect(() => {
    if (kind !== "roles" || !existing?.id) return;
    void api.get(`/admin/roles/${existing.id}/permissions`).then((response: any) => {
      setForm((current) => ({ ...current, permission_ids: recordsOf(response).map((item) => item.permission_id || item.id).filter(Boolean) }));
    }).catch(() => undefined);
  }, [kind, existing?.id]);

  async function submit(event: FormEvent) {
    event.preventDefault(); setSaving(true); setError("");
    try {
      if (kind === "users" && !existing && form.password !== form.confirm_password) {
        setError("Temporary password and confirm password must match.");
        return;
      }
      const endpoint = moduleConfig[kind].endpoint;
      const payload = kind === "users" ? userPayload(form, Boolean(existing)) : kind === "roles" ? rolePayload(form) : permissionPayload(form);
      const response: any = existing ? await api.put(`${endpoint}/${existing.id}`, payload) : await api.post(endpoint, payload);
      const saved = response?.data ?? response;
      if (kind === "roles" && saved?.id) {
        if (existing) await api.put(`/admin/roles/${saved.id}/permissions`, { permission_ids: form.permission_ids || [] });
        else if (form.permission_ids?.length) await api.post(`/admin/roles/${saved.id}/permissions`, { permission_ids: form.permission_ids });
      }
      await onSaved();
    } catch (cause: any) { setError(cause?.message || "Unable to save record."); } finally { setSaving(false); }
  }

  return <div className="iam-overlay"><form className="iam-modal" onSubmit={submit}><header><div><span className="eyebrow">{existing ? "EDIT" : "CREATE"}</span><h2>{existing ? `Edit ${moduleConfig[kind].singular}` : `Create ${moduleConfig[kind].singular}`}</h2></div><button type="button" className="icon-button" onClick={onClose}><X /></button></header>{error && <div className="error-banner">{error}</div>}<div className="iam-form-grid">{kind === "users" ? <UserFields form={form} set={set} roles={roles} editing={Boolean(existing)} /> : kind === "roles" ? <RoleFields form={form} set={set} permissions={permissions} togglePermission={togglePermission} /> : <PermissionFields form={form} set={set} />}</div><footer><button type="button" className="secondary-button" onClick={onClose}>Cancel</button><button className="primary-button" disabled={saving}>{saving ? "Saving..." : "Save"}</button></footer></form></div>;
}

function Field({ label, value, onChange, required = false, type = "text", placeholder = "", help = "" }: any) { return <label><span>{label}{required && " *"}</span><input type={type} value={value || ""} placeholder={placeholder} required={required} onChange={(event) => onChange(event.target.value)} />{help && <small>{help}</small>}</label>; }
function SelectField({ label, value, onChange, children, required = false }: any) { return <label><span>{label}{required && " *"}</span><select value={value || ""} required={required} onChange={(event) => onChange(event.target.value)}>{children}</select></label>; }

function UserFields({ form, set, roles, editing }: any) { const [showPassword, setShowPassword] = useState(false); return <><Field label="Username" value={form.username} onChange={(v: string) => set("username", v)} required /><Field label="Official email" type="email" value={form.official_email} onChange={(v: string) => set("official_email", v)} required /><Field label="First name" value={form.first_name} onChange={(v: string) => set("first_name", v)} required /><Field label="Last name" value={form.last_name} onChange={(v: string) => set("last_name", v)} /><Field label="Display name" value={form.display_name} onChange={(v: string) => set("display_name", v)} /><Field label="Employee code" value={form.employee_code} onChange={(v: string) => set("employee_code", v.toUpperCase())} placeholder="ACME-BANK-ADMIN-001" help="Use uppercase letters, numbers, and hyphens. Keep it unique within the organization." /><Field label="Designation" value={form.designation} onChange={(v: string) => set("designation", v)} /><Field label="Official phone" value={form.official_phone} onChange={(v: string) => set("official_phone", v)} />{!editing && <><Field label="Temporary password" type={showPassword ? "text" : "password"} value={form.password} onChange={(v: string) => set("password", v)} required /><Field label="Confirm password" type={showPassword ? "text" : "password"} value={form.confirm_password} onChange={(v: string) => set("confirm_password", v)} required /><label><span>Password visibility</span><button type="button" className="secondary-button" onClick={() => setShowPassword((current) => !current)}>{showPassword ? "Hide password" : "Show password"}</button></label><SelectField label="Initial access role" value={form.role_id} onChange={(v: string) => set("role_id", v)} required><option value="">Select a role</option>{roles.filter((role: any) => role.status === "ACTIVE").map((role: any) => <option key={role.id} value={role.id}>{role.role_name || role.name}</option>)}</SelectField></>}<SelectField label="User type" value={form.user_type} onChange={(v: string) => set("user_type", v)}><option>INTERNAL</option><option>EXTERNAL</option><option>SERVICE</option></SelectField></>; }
function roleCode(name: string) { return name.trim().toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, ""); }
function RoleFields({ form, set, permissions, togglePermission }: any) { const [module, setModule] = useState("ALL"); const currentName = form.role_name || form.name || ""; const updateName = (value: string) => { if (!form.role_code || form.role_code === roleCode(currentName)) set("role_code", roleCode(value)); set("role_name", value); }; const modules: string[] = [...new Set<string>(permissions.map((permission: any) => String(permission.module_name || "OTHER")))].sort(); const visible = permissions.filter((permission: any) => module === "ALL" || permission.module_name === module); const selected = (form.permission_ids || []).length; return <><Field label="Role name" value={currentName} onChange={updateName} required /><Field label="Role code" value={form.role_code} placeholder="Auto-generated, e.g. BANK_ADMIN" help="Uppercase letters, numbers, and underscores only. It must be unique in this organization." onChange={(v: string) => set("role_code", roleCode(v))} required /><Field label="Description" value={form.description} onChange={(v: string) => set("description", v)} /><Field label="Priority" type="number" value={form.priority_level ?? form.priority} onChange={(v: string) => set("priority_level", Number(v))} /><SelectField label="Scope" value={form.role_scope || form.scope} onChange={(v: string) => set("role_scope", v)}><option>ORGANIZATION</option><option>GLOBAL</option><option>DEPARTMENT</option></SelectField><SelectField label="Status" value={form.status} onChange={(v: string) => set("status", v)}><option>ACTIVE</option><option>INACTIVE</option></SelectField><fieldset className="iam-permission-picker"><legend>Permissions selected: {selected}</legend><SelectField label="Permission module" value={module} onChange={setModule}><option value="ALL">All modules ({permissions.length})</option>{modules.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")} ({permissions.filter((permission: any) => permission.module_name === value).length})</option>)}</SelectField>{visible.length ? visible.map((permission: any) => { const available = String(permission.status || "ACTIVE").toUpperCase() === "ACTIVE"; return <label key={permission.id} title={available ? "" : "Inactive permissions cannot be assigned"}><input type="checkbox" disabled={!available} checked={(form.permission_ids || []).includes(permission.id)} onChange={() => togglePermission(permission.id)} /><span><strong>{permission.permission_name || permission.name}{!available && " (inactive)"}</strong><small>{permission.action_name} · {permission.risk_level}</small></span></label>; }) : <p>No permissions are available for this module.</p>}</fieldset></>; }
function PermissionFields({ form, set }: any) { return <><Field label="Permission name" value={form.permission_name || form.name} onChange={(v: string) => set("permission_name", v)} required /><Field label="Permission code" value={form.permission_code} onChange={(v: string) => set("permission_code", v.toUpperCase())} required /><Field label="Module" value={form.module_name} onChange={(v: string) => set("module_name", v.toUpperCase())} required /><Field label="Action" value={form.action_name} onChange={(v: string) => set("action_name", v.toUpperCase())} required /><Field label="Description" value={form.description} onChange={(v: string) => set("description", v)} /><SelectField label="Risk level" value={form.risk_level} onChange={(v: string) => set("risk_level", v)}><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></SelectField><SelectField label="Status" value={form.status} onChange={(v: string) => set("status", v)}><option>ACTIVE</option><option>INACTIVE</option></SelectField></>; }

function userPayload(form: RecordItem, editing: boolean) { const payload: RecordItem = { official_email: form.official_email, employee_code: form.employee_code || null, first_name: form.first_name, last_name: form.last_name || null, display_name: form.display_name || null, designation: form.designation || null, official_phone: form.official_phone || null }; if (!editing) { payload.username = form.username; payload.password = form.password; payload.role_id = form.role_id; payload.user_type = form.user_type; } return payload; }
function rolePayload(form: RecordItem) { return { role_code: form.role_code, role_name: form.role_name || form.name, description: form.description, role_scope: form.role_scope || form.scope || "ORGANIZATION", department_id: form.department_id || null, priority_level: Number(form.priority_level || 100), status: form.status }; }
function permissionPayload(form: RecordItem) { return { permission_code: form.permission_code, permission_name: form.permission_name || form.name, module_name: form.module_name, action_name: form.action_name, description: form.description, risk_level: form.risk_level, status: form.status, is_system: Boolean(form.is_system) }; }

export default IamManagementPage;
