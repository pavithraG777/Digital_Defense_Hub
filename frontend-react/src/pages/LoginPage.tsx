import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Eye, EyeOff, KeyRound, LockKeyhole, ShieldCheck, UserRound } from "lucide-react";
import type { LoginMFAResponse, LoginResult } from "../types";
import { api, session } from "../lib/api";
import { safeReturnTo } from "../lib/auth-navigation";
import { BrandLogo } from "../components/BrandLogo";
import { AuthLiveBackground } from "../components/AuthLiveBackground";

export const MFA_CHALLENGE_STORAGE_KEY = "ddh.pending-mfa-challenge";

function isMFAChallenge(value: LoginResult | LoginMFAResponse): value is LoginMFAResponse {
  return "mfa_challenge" in value && Boolean(value.mfa_challenge?.mfa_required);
}

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberDevice, setRememberDevice] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const returnTo = safeReturnTo((location.state as { from?: unknown } | null)?.from);
  const notice = typeof (location.state as { notice?: unknown } | null)?.notice === "string" ? (location.state as { notice: string }).notice : null;

  useEffect(() => {
    if (!session.getTokens()) return;
    const user = session.getUser<LoginResult["user"]>();
    navigate(user?.must_change_password ? "/change-password" : returnTo, { replace: true });
  }, [navigate, returnTo]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await api.post<LoginResult | LoginMFAResponse>("/auth/login", {
        identifier: identifier.trim(),
        password,
        device_id: rememberDevice ? window.localStorage.getItem("ddh.device-id") || undefined : undefined,
      });
      if (isMFAChallenge(result)) {
        const challenge = result.mfa_challenge;
        const lifetimeSeconds = Math.max(600, challenge.expires_in_seconds || 0);
        sessionStorage.setItem(MFA_CHALLENGE_STORAGE_KEY, JSON.stringify({ id: challenge.mfa_challenge_id, type: challenge.mfa_challenge_type || "EMAIL", expiresAt: Date.now() + lifetimeSeconds * 1000, returnTo }));
        navigate("/mfa");
        return;
      }
      session.setLogin(result);
      navigate(result.user.must_change_password ? "/change-password" : !result.user.mfa_enabled ? "/mfa/setup" : returnTo);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to sign in. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-shell auth-shell-login">
      <AuthLiveBackground />
      <section className="auth-intro" aria-label="Digital Defense Hub security">
        <BrandLogo className="auth-brand" />
        <div className="auth-copy"><p className="eyebrow">PROTECTED ACCESS</p><h1>Secure access to your account.</h1><p>Identity verification, adaptive login risk checks, and multi-factor authentication protect every session.</p></div>
      </section>
      <section className="auth-panel">
        <form className="login-card" onSubmit={handleSubmit}>
          <div className="auth-card-heading"><BrandLogo compact className="auth-card-logo" /><p className="eyebrow">DIGITAL DEFENSE HUB</p><h2>Secure Sign In</h2><p className="muted">Use your approved username or official email.</p></div>
          {notice && <div className="alert alert-success" role="status"><ShieldCheck size={17} /> {notice}</div>}
          {error && <div className="alert alert-error" role="alert">{error}</div>}
          <label className="auth-field"><span>Username or official email</span><span className="input-with-icon"><UserRound size={17} /><input autoComplete="username" value={identifier} onChange={(event) => setIdentifier(event.target.value)} placeholder="name@organization.com" required /></span></label>
          <label className="auth-field"><span>Password</span><span className="input-with-icon password-field"><LockKeyhole size={17} /><input autoComplete="current-password" type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter your password" required /><button className="password-visibility" type="button" onClick={() => setShowPassword((current) => !current)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></span></label>
          <div className="auth-options"><label className="check-line"><input type="checkbox" checked={rememberDevice} onChange={(event) => setRememberDevice(event.target.checked)} /><span>Remember this device</span></label><Link className="text-link" to="/password-recovery">Forgot password?</Link></div>
          <button className="primary button-full" type="submit" disabled={loading || !identifier.trim() || !password}><KeyRound size={17} /> {loading ? "Signing in…" : "Secure Sign In"}</button>
          <div className="auth-divider"><span>NEW TO THE PLATFORM?</span></div>
          <p className="auth-switch">Do not have an approved account? <Link to="/register">Register securely</Link></p>
          <div className="mfa-indicator"><ShieldCheck size={17} /> MFA verification is enforced when enabled</div>
          <div className="security-status" aria-label="System security capabilities"><span><LockKeyhole size={16} /> Encrypted</span><span><ShieldCheck size={16} /> System Secure</span><span className="status-live"><i /> Local Ready</span></div>
        </form>
      </section>
      <footer className="auth-footer"><span>© 2026 Digital Defense Hub. All rights reserved.</span><span>Version 0.1.0</span></footer>
    </main>
  );
}
