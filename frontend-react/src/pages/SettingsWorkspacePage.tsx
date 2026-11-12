import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, session } from "../lib/api";
import type { AuthUser } from "../types";

type Preferences = { desktop_notifications: boolean; sound_notifications: boolean; email_notifications: boolean; theme: "dark" | "light" | "system"; language: "en" | "ta"; mfa_policy: "USER_CHOICE" | "EMAIL_ONLY" | "TOTP_ONLY" | "EMAIL_OR_TOTP" };
const defaults: Preferences = { desktop_notifications: true, sound_notifications: true, email_notifications: true, theme: "dark", language: "en", mfa_policy: "USER_CHOICE" };

export function SettingsWorkspacePage() {
  const { screenId = "profile" } = useParams();
  const [preferences, setPreferences] = useState(defaults);
  const [profile, setProfile] = useState<AuthUser | null>(() => session.getUser<AuthUser>());
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => { void Promise.all([api.get<AuthUser>("/profile"), api.get<Preferences>("/user-preferences")]).then(([user, prefs]) => { setProfile(user); session.setUser(user); setPreferences(prefs); document.documentElement.dataset.theme = prefs.theme; document.documentElement.lang = prefs.language; }).catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to load settings.")); }, []);
  async function save(next: Preferences) { setPreferences(next); setError(""); try { const stored = await api.put<Preferences>("/user-preferences", next); setPreferences(stored); document.documentElement.dataset.theme = stored.theme; document.documentElement.lang = stored.language; setSaved(true); window.setTimeout(() => setSaved(false), 1800); } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to save settings."); } }
  const toggle = (key: "desktop_notifications"|"sound_notifications"|"email_notifications") => void save({ ...preferences, [key]: !preferences[key] });
  return <div className="page"><div className="hero"><div><h1>User Settings</h1><p>Identity security, notifications, accessibility, theme and language.</p></div>{saved && <span className="badge">Saved</span>}</div>
    {error && <div className="alert alert-error">{error}</div>}<div className="card"><nav className="tabs"><Link to="/module/settings/mfa">MFA policy</Link><Link to="/module/settings/notifications">Notifications</Link><Link to="/module/settings/appearance">Theme & language</Link></nav></div>
    {screenId === "mfa" && <div className="card"><h2>MFA policy</h2><p>Account: <strong>{profile?.official_email || "Loading…"}</strong></p><p>Status: <strong>{profile?.mfa_enabled ? "Enabled" : "Enrollment required"}</strong></p><label>Preferred verification policy<select value={preferences.mfa_policy} onChange={(event) => void save({ ...preferences, mfa_policy: event.target.value as Preferences["mfa_policy"] })}><option value="USER_CHOICE">User choice</option><option value="EMAIL_OR_TOTP">Email or Authenticator</option><option value="EMAIL_ONLY">Email only</option><option value="TOTP_ONLY">Authenticator only</option></select></label><p className="muted">Secrets are never returned by this settings API.</p><Link className="primary-link" to="/mfa/setup">Set up or replace Google Authenticator</Link></div>}
    {screenId === "notifications" && <div className="card"><h2>Notification settings</h2>{(["desktop_notifications","sound_notifications","email_notifications"] as const).map((key) => <label className="preference-row" key={key}><span><strong>{key === "desktop_notifications" ? "Desktop notifications" : key === "sound_notifications" ? "Completion sounds" : "Security email"}</strong><small>Saved securely to your backend account.</small></span><input type="checkbox" checked={preferences[key]} onChange={() => toggle(key)}/></label>)}<Link className="secondary-button" to="/notifications">Open notification history</Link></div>}
    {screenId === "appearance" && <div className="card"><h2>Theme and language</h2><div className="form-grid"><label>Theme<select value={preferences.theme} onChange={(event) => void save({ ...preferences, theme: event.target.value as Preferences["theme"] })}><option value="dark">Dark</option><option value="light">Light</option><option value="system">System</option></select></label><label>Language<select value={preferences.language} onChange={(event) => void save({ ...preferences, language: event.target.value as Preferences["language"] })}><option value="en">English</option><option value="ta">Tamil</option></select></label></div><p className="muted">Preferences follow your account across browsers and devices.</p></div>}
  </div>;
}
