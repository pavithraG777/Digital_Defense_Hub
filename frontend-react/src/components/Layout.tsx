import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { Activity, Bell, BellRing, BookOpen, Bot, Building2, Camera, ChevronLeft, ChevronRight, FileClock, FileWarning, FolderSearch2, GitBranch, HeartPulse, Inbox, KeyRound, LayoutDashboard, LogOut, Menu, Microscope, Pencil, Radar, ScanSearch, Search, ShieldAlert, ShieldCheck, Siren, Users, Workflow, X } from "lucide-react";
import type { AuthUser } from "../types";
import { api, session } from "../lib/api";
import { BrandLogo } from "./BrandLogo";

const navigation = [
  { label: "Overview", items: [{ to: "/dashboard", label: "Dashboard", icon: LayoutDashboard }] },
  { label: "Organization", items: [{ to: "/organizations", label: "Organizations", icon: Building2 }, { to: "/users", label: "Users", icon: Users }, { to: "/roles", label: "Roles", icon: ShieldCheck }, { to: "/permissions", label: "Permissions", icon: KeyRound }] },
  { label: "Deception", items: [{ to: "/honeytokens", label: "Honeytokens", icon: KeyRound }, { to: "/canary-files", label: "Canary Files", icon: FileWarning }] },
  { label: "Security Operations", items: [{ to: "/threats", label: "Threat Center", icon: ShieldAlert }, { to: "/threat-score", label: "Threat Score", icon: Activity }, { to: "/incidents", label: "Incident Response", icon: Siren }, { to: "/investigations", label: "Investigations", icon: FolderSearch2 }, { to: "/attack-stories", label: "Attack Stories", icon: GitBranch }] },
  { label: "AI Forensics", items: [{ to: "/deepfake-image-analysis", label: "Image Analysis", icon: Bot }, { to: "/module/deepfake/analysis", label: "Analysis History", icon: FileClock }, { to: "/evidence-vault", label: "Evidence Vault", icon: BookOpen }, { to: "/module/deepfake/reports", label: "Forensic Reports", icon: BookOpen }] },
  { label: "Operational Modules", items: [{ to: "/module/exposure-operations/assets", label: "Exposure Management", icon: ScanSearch }, { to: "/module/detection-operations/alerts", label: "Detection Operations", icon: Radar }, { to: "/module/governance-operations/access", label: "Security Governance", icon: ShieldCheck }, { to: "/module/analysis-operations/malware", label: "Analysis Operations", icon: Microscope }, { to: "/module/response-automation/analysis", label: "Response Automation", icon: Workflow }] },
  { label: "System", items: [{ to: "/notifications", label: "Notifications", icon: Inbox }, { to: "/audit-activity", label: "Audit Activity", icon: Activity }, { to: "/module/system/health", label: "System Health", icon: HeartPulse }] },
];

type SecurityEvent = Record<string, unknown> & { id: string };

function playSecurityAlertTone() {
  const AudioContextClass = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
  if (!AudioContextClass) return;
  const context = new AudioContextClass();
  [0, .32].forEach((offset) => {
    const oscillator = context.createOscillator();
    const gain = context.createGain();
    oscillator.frequency.value = 920;
    gain.gain.setValueAtTime(.14, context.currentTime + offset);
    gain.gain.exponentialRampToValueAtTime(.001, context.currentTime + offset + .22);
    oscillator.connect(gain).connect(context.destination);
    oscillator.start(context.currentTime + offset);
    oscillator.stop(context.currentTime + offset + .23);
  });
  window.setTimeout(() => void context.close(), 900);
}

export function Layout() {
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profile, setProfile] = useState<Record<string, unknown> | null>(null);
  const [notifications, setNotifications] = useState<Array<Record<string, unknown>>>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [drawerError, setDrawerError] = useState("");
  const [loggingOut, setLoggingOut] = useState(false);
  const [securityAlert, setSecurityAlert] = useState<SecurityEvent | null>(null);
  const [query, setQuery] = useState("");
  const [user, setUser] = useState<AuthUser | null>(() => session.getUser<AuthUser>());
  const photoStorageKey = `ddh.profile-photo.${user?.id || "anonymous"}`;
  const [profilePhoto, setProfilePhoto] = useState(() => localStorage.getItem(photoStorageKey) || "");
  const securityFeedInitialized = useRef(false);
  const seenSecurityEventIDs = useRef(new Set<string>());

  useEffect(() => {
    const sync = () => setUser(session.getUser<AuthUser>());
    window.addEventListener("ddh:session-changed", sync);
    return () => window.removeEventListener("ddh:session-changed", sync);
  }, []);

  useEffect(() => {
    const receiveDeceptionAlert = (event: Event) => {
      const detail = (event as CustomEvent<SecurityEvent>).detail;
      if (detail?.id) setSecurityAlert(detail);
    };
    window.addEventListener("ddh:deception-alert", receiveDeceptionAlert);
    return () => window.removeEventListener("ddh:deception-alert", receiveDeceptionAlert);
  }, []);

  useEffect(() => {
    let active = true;
    const pollSecurityEvents = async () => {
      try {
        const result = await api.get<{ items?: SecurityEvent[] }>("/file-events?page=1&page_size=100");
        const events = Array.isArray(result.items) ? result.items : [];
        if (securityFeedInitialized.current) {
          const event = events.find((item) => !seenSecurityEventIDs.current.has(item.id) && (item.source_type === "CANARY_FILE" || item.source_type === "HONEYTOKEN" || item.severity === "CRITICAL"));
          if (event && active) {
            setSecurityAlert(event);
            if (localStorage.getItem("ddh_deception_alerts") === "enabled") {
              playSecurityAlertTone();
              if ("Notification" in window && Notification.permission === "granted") new Notification("Digital Defense Hub security alert", { body: `${String(event.event_type || "Security event")} · ${String(event.file_name || "Unknown file")}` });
            }
          }
        }
        seenSecurityEventIDs.current = new Set(events.map((item) => item.id));
        securityFeedInitialized.current = true;
      } catch {
        // Individual pages display API errors; a transient global polling error must stay silent.
      }
    };
    void pollSecurityEvents();
    const timer = window.setInterval(() => void pollSecurityEvents(), 4000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  useEffect(() => {
    let active = true;
    const refreshUnreadCount = async () => {
      try {
        const result = await api.get<Record<string, unknown>>("/my-notifications?in_app_status=UNREAD&page=1&page_size=1");
        if (active) setUnreadCount(Number(result.unread_count || result.total || 0));
      } catch {
        // Keep the last successful count when the API is temporarily unavailable.
      }
    };
    void refreshUnreadCount();
    const timer = window.setInterval(() => void refreshUnreadCount(), 30000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  async function openProfile() {
    setNotificationsOpen(false); setProfileOpen(true); setDrawerLoading(true); setDrawerError("");
    try {
      const result = await api.get<Record<string, unknown>>(`/admin/users/${user?.id}`);
      setProfile(result);
    } catch {
      try { setProfile(await api.get<Record<string, unknown>>("/profile")); }
      catch (error) { setProfile(null); setDrawerError(error instanceof Error ? error.message : "Unable to load the profile."); }
    } finally { setDrawerLoading(false); }
  }

  async function openNotifications() {
    setProfileOpen(false); setNotificationsOpen(true); setDrawerLoading(true); setDrawerError("");
    try {
      const result = await api.get<Record<string, unknown>>("/my-notifications?in_app_status=UNREAD&page=1&page_size=20");
      setNotifications(Array.isArray(result.notifications) ? result.notifications as Array<Record<string, unknown>> : []);
      setUnreadCount(Number(result.unread_count || 0));
    } catch (error) { setNotifications([]); setDrawerError(error instanceof Error ? error.message : "Unable to load notifications."); }
    finally { setDrawerLoading(false); }
  }

  const searchable = useMemo(() => navigation.flatMap((group) => group.items), []);
  function submitSearch(event: FormEvent) {
    event.preventDefault();
    const needle = query.trim().toLowerCase();
    if (!needle) return;
    const match = searchable.find((item) => item.label.toLowerCase().includes(needle));
    if (match) navigate(match.to);
  }
  async function logout() {
    setLoggingOut(true);
    try { await api.post("/auth/logout"); } catch { /* Clear an expired local session too. */ }
    finally { session.clear(); setLoggingOut(false); navigate("/login", { replace: true }); }
  }
  const initials = (user?.display_name || user?.username || "U").slice(0, 2).toUpperCase();

  return <div className={`app-shell dashboard-shell${collapsed ? " shell-collapsed" : ""}`}>
    <button className="mobile-menu-button" type="button" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={21} /></button>
    {mobileOpen && <button className="nav-backdrop" type="button" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
    <aside className={`sidebar command-sidebar${mobileOpen ? " sidebar-open" : ""}`}>
      <div className="sidebar-top">
        <div className="brand command-brand"><BrandLogo compact={collapsed} /><button className="sidebar-close" type="button" aria-label="Close navigation" onClick={() => setMobileOpen(false)}><X size={19} /></button></div>
        <nav aria-label="Primary navigation" className="command-navigation">
          {navigation.map((group) => <section className="nav-group" key={group.label}>
            {!collapsed && <p>{group.label}</p>}
            {group.items.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} title={collapsed ? label : undefined} className={`nav-link${location.pathname === to ? " active" : ""}`} onClick={() => setMobileOpen(false)}><Icon size={17} /><span>{label}</span>{!collapsed && <ChevronRight size={13} className="nav-chevron" />}</NavLink>)}
          </section>)}
        </nav>
      </div>
      <div className="sidebar-footer">
        <div className="sidebar-account-card">
          <button className="profile-summary" type="button" onClick={() => void openProfile()}>{profilePhoto ? <img className="nav-profile-photo" src={profilePhoto} alt="Profile" /> : <span className="avatar">{initials}</span>}<span><strong>{user?.display_name || user?.username || "Authenticated user"}</strong><small>{user?.roles?.[0] || user?.user_type || "Security operator"}</small></span><ChevronRight size={15} /></button>
          <button className="account-signout" type="button" onClick={logout} disabled={loggingOut} title="Sign out"><LogOut size={16} />{!collapsed && <span>{loggingOut ? "Signing out…" : "Sign out"}</span>}</button>
        </div>
      </div>
    </aside>
    <div className="workspace-column">
      <header className="command-header"><button className="collapse-control" type="button" onClick={() => setCollapsed((value) => !value)} aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}>{collapsed ? <Menu size={19} /> : <ChevronLeft size={19} />}</button><form className="global-search" onSubmit={submitSearch}><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search modules and workspaces" aria-label="Search modules and workspaces" /><kbd>Enter</kbd></form><div className="header-actions"><span className="system-online"><i /> Local platform</span><button type="button" className="notification-button" aria-label="Notifications" onClick={() => void openNotifications()}><Bell size={18} />{unreadCount > 0 && <b>{unreadCount > 99 ? "99+" : unreadCount}</b>}</button><button type="button" className="header-avatar" onClick={() => void openProfile()}>{profilePhoto ? <img className="header-profile-photo" src={profilePhoto} alt="Profile" /> : initials}</button></div></header>
      <main className="content-area">
        {securityAlert && <div className="critical-event-banner"><BellRing /><div><strong>{securityAlert.source_type === "HONEYTOKEN" ? "Honeytoken trigger detected" : "Canary tampering detected"}</strong><span>{String(securityAlert.event_type || "Security event")} · {String(securityAlert.file_name || "Unknown resource")} · {String(securityAlert.device_name || "This device")}</span></div><button type="button" onClick={() => { const source=securityAlert.source_type === "HONEYTOKEN" ? "HONEYTOKEN" : "CANARY_FILE"; setSecurityAlert(null); navigate(`/audit-activity?source=${source}`); }}>View event</button><button type="button" onClick={() => setSecurityAlert(null)}>Dismiss</button></div>}
        <Outlet />
      </main>
    </div>
    {(profileOpen || notificationsOpen) && <button className="drawer-backdrop" type="button" aria-label="Close panel" onClick={() => { setProfileOpen(false); setNotificationsOpen(false); }} />}
    <aside className={`detail-drawer${profileOpen || notificationsOpen ? " open" : ""}`} aria-hidden={!profileOpen && !notificationsOpen}>
      <div className="drawer-heading"><div><span className="eyebrow">{profileOpen ? "Authenticated account" : "Notification center"}</span><h2>{profileOpen ? "My Profile" : "Notifications"}</h2></div><button type="button" onClick={() => { setProfileOpen(false); setNotificationsOpen(false); }}><X size={18} /></button></div>
      {drawerError && <div className="drawer-error">{drawerError}</div>}
      {drawerLoading ? <div className="drawer-empty">Loading real backend data…</div> : profileOpen ? <ProfileDetails profile={profile} fallback={user} savedPhoto={profilePhoto} onPhotoUpdated={setProfilePhoto} onUpdated={setProfile} onSignOut={logout} /> : <NotificationDetails items={notifications} unreadCount={unreadCount} onRead={async (id) => { setNotifications((current) => current.filter((item) => String(((item.notification || {}) as Record<string, unknown>).id || "") !== id)); setUnreadCount((current) => Math.max(0, current - 1)); try { await api.patch(`/my-notifications/${id}/read`); } catch (error) { setDrawerError(error instanceof Error ? error.message : "Unable to mark the notification as read."); await openNotifications(); } }} />}
    </aside>
  </div>;
}

function displayValue(value: unknown) { return value === null || value === undefined || value === "" ? "Not provided" : String(value); }
function ProfileDetails({ profile, fallback, savedPhoto, onPhotoUpdated, onUpdated, onSignOut }: { profile: Record<string, unknown> | null; fallback: AuthUser | null; savedPhoto: string; onPhotoUpdated: (photo: string) => void; onUpdated: (profile: Record<string, unknown>) => void; onSignOut: () => Promise<void> }) {
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [photoName, setPhotoName] = useState("");
  const [photoPreview, setPhotoPreview] = useState(savedPhoto);
  const [form, setForm] = useState(() => ({ official_email: String(profile?.official_email || fallback?.official_email || ""), first_name: String(profile?.first_name || ""), middle_name: String(profile?.middle_name || ""), last_name: String(profile?.last_name || ""), display_name: String(profile?.display_name || fallback?.display_name || ""), employee_code: String(profile?.employee_code || ""), designation: String(profile?.designation || ""), official_phone: String(profile?.official_phone || "") }));
  const fields: Array<[string, unknown]> = [
    ["Display name", profile?.display_name || fallback?.display_name], ["Username", profile?.username || fallback?.username], ["Official email", profile?.official_email || fallback?.official_email],
    ["First name", profile?.first_name], ["Middle name", profile?.middle_name], ["Last name", profile?.last_name], ["Employee code", profile?.employee_code],
    ["Designation", profile?.designation], ["Official phone", profile?.official_phone], ["User type", profile?.user_type || fallback?.user_type],
    ["Role", profile?.role_name || profile?.role_code || fallback?.roles?.join(", ")], ["Account status", profile?.account_status || fallback?.account_status],
    ["Organization ID", profile?.organization_id], ["Created", profile?.created_at ? new Date(String(profile.created_at)).toLocaleString() : undefined],
    ["Last updated", profile?.updated_at ? new Date(String(profile.updated_at)).toLocaleString() : undefined],
  ];
  async function saveProfile() {
    if (!fallback?.id) return;
    setSaving(true); setMessage("");
    try { const updated = await api.put<Record<string, unknown>>(`/admin/users/${fallback.id}`, form); if (photoPreview) localStorage.setItem(`ddh.profile-photo.${fallback.id}`, photoPreview); else localStorage.removeItem(`ddh.profile-photo.${fallback.id}`); onPhotoUpdated(photoPreview); onUpdated(updated); setEditing(false); setMessage("Profile and photo saved successfully."); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Unable to update profile."); }
    finally { setSaving(false); }
  }
  function choosePhoto(file?: File) {
    if (!file) { setPhotoName(""); setPhotoPreview(""); return; }
    setPhotoName(file.name);
    const reader = new FileReader(); reader.onload = () => {
      const image = new Image(); image.onload = () => { const size = 256; const canvas = document.createElement("canvas"); canvas.width = size; canvas.height = size; const ctx = canvas.getContext("2d"); if (!ctx) return; const scale = Math.max(size / image.width, size / image.height); const width = image.width * scale, height = image.height * scale; ctx.drawImage(image, (size - width) / 2, (size - height) / 2, width, height); setPhotoPreview(canvas.toDataURL("image/webp", .82)); }; image.src = String(reader.result); }; reader.readAsDataURL(file);
  }
  return <div className="profile-details"><div className="profile-account-card"><div className="profile-identity">{photoPreview ? <img className="profile-photo-preview" src={photoPreview} alt="Profile" /> : <span className="avatar large">{String(profile?.display_name || fallback?.display_name || fallback?.username || "U").slice(0,2).toUpperCase()}</span>}<div><strong>{displayValue(profile?.display_name || fallback?.display_name)}</strong><span>{displayValue(profile?.official_email || fallback?.official_email)}</span><small>{displayValue(profile?.role_name || profile?.role_code || fallback?.roles?.join(", "))}</small></div></div><button className="profile-signout" type="button" onClick={() => void onSignOut()}><LogOut size={15} /> Sign out</button></div>{message && <p className="profile-message">{message}</p>}{editing ? <div className="profile-edit-form"><label className="photo-control profile-photo-editor"><Camera size={16} /><span>{photoName || (photoPreview ? "Change profile photo" : "Choose profile photo")}<small>JPG, PNG or WebP. Photo is saved with profile changes.</small></span><input type="file" accept="image/png,image/jpeg,image/webp" onChange={(event) => choosePhoto(event.target.files?.[0])} /></label>{Object.entries(form).map(([name, value]) => <label key={name}><span>{name.replace(/_/g, " ")}</span><input type={name === "official_email" ? "email" : "text"} value={value} onChange={(event) => setForm((current) => ({ ...current, [name]: event.target.value }))} /></label>)}<div><button type="button" onClick={() => { setEditing(false); setPhotoPreview(savedPhoto); }}>Cancel</button><button type="button" className="save" disabled={saving} onClick={() => void saveProfile()}>{saving ? "Saving…" : "Save changes"}</button></div></div> : <dl>{fields.map(([label, value]) => <div key={String(label)}><dt>{label}</dt><dd>{displayValue(value)}</dd></div>)}</dl>}<div className="profile-actions"><button type="button" onClick={() => setEditing(true)}><Pencil size={16} /> Edit Profile</button><NavLink to="/change-password"><KeyRound size={16} /> Change Password</NavLink><NavLink to="/mfa/setup"><KeyRound size={16} /> Manage Authenticator</NavLink></div></div>;
}
function NotificationDetails({ items, unreadCount, onRead }: { items: Array<Record<string, unknown>>; unreadCount: number; onRead: (id: string) => Promise<void> }) {
  if (!items.length) return <div className="drawer-empty"><span>No unread notifications.</span><NavLink className="drawer-manage-link" to="/notifications">Open Notification Management</NavLink></div>;
  return <div className="notification-list"><div className="notification-list-heading"><p className="notification-summary">{unreadCount} unread notification{unreadCount === 1 ? "" : "s"}</p><NavLink to="/notifications">Manage all</NavLink></div>{items.map((item) => { const note = (item.notification || {}) as Record<string, unknown>; return <article key={String(note.id || item.recipient_id)} className="unread"><div><span className={`severity ${String(note.severity || "LOW").toLowerCase()}`}>{displayValue(note.severity)}</span><time>{note.created_at ? new Date(String(note.created_at)).toLocaleString() : ""}</time></div><h3>{displayValue(note.title)}</h3><p>{displayValue(note.message)}</p><button type="button" onClick={() => void onRead(String(note.id))}>Mark as read</button></article>; })}</div>;
}
