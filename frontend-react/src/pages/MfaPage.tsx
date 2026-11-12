import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowLeft, KeyRound, Mail, ShieldCheck, Smartphone } from "lucide-react";
import type { LoginResult } from "../types";
import { api, session } from "../lib/api";
import { safeReturnTo } from "../lib/auth-navigation";
import { MFA_CHALLENGE_STORAGE_KEY } from "./LoginPage";

type MFAMethod = "EMAIL" | "TOTP" | "RECOVERY";
type PendingChallenge = { id: string; type: "EMAIL" | "EMAIL_OR_TOTP"; expiresAt: number; returnTo?: string };

function readChallenge(): PendingChallenge | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(MFA_CHALLENGE_STORAGE_KEY) || "null") as PendingChallenge | null;
    return value?.id && value.expiresAt > Date.now() ? { ...value, type: value.type || "EMAIL" } : null;
  } catch { return null; }
}

export function MfaPage() {
  const navigate = useNavigate();
  const [challenge] = useState(readChallenge);
  const [method, setMethod] = useState<MFAMethod>("EMAIL");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [replacementRequested, setReplacementRequested] = useState(false);
  const [now, setNow] = useState(Date.now());
  const supportsTOTP = challenge?.type === "EMAIL_OR_TOTP";
  const remainingSeconds = useMemo(() => challenge ? Math.max(0, Math.ceil((challenge.expiresAt - now) / 1000)) : 0, [challenge, now]);
  const countdown = `${String(Math.floor(remainingSeconds / 60)).padStart(2, "0")}:${String(remainingSeconds % 60).padStart(2, "0")}`;
  const expired = Boolean(challenge) && remainingSeconds === 0;
  const requiredLength = method === "RECOVERY" ? 8 : 6;

  useEffect(() => { if (!challenge) navigate("/login", { replace: true }); }, [challenge, navigate]);
  useEffect(() => {
    if (!challenge || expired) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [challenge, expired]);

  function chooseMethod(nextMethod: MFAMethod, requestReplacement = false) {
    setReplacementRequested(requestReplacement);
    setMethod(nextMethod);
    setCode("");
    setError(null);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!challenge || expired) return;
    setError(null);
    setLoading(true);
    const credential = method === "EMAIL" ? { email_code: code } : method === "TOTP" ? { totp_code: code } : { recovery_code: code.trim() };
    try {
      const result = await api.post<LoginResult>("/auth/mfa/verify", { mfa_challenge_id: challenge.id, ...credential });
      sessionStorage.removeItem(MFA_CHALLENGE_STORAGE_KEY);
      session.setLogin(result);
      navigate(result.user.must_change_password ? "/change-password" : replacementRequested ? "/mfa/setup" : safeReturnTo(challenge.returnTo));
    } catch (err) {
      setError(err instanceof Error ? err.message : "MFA verification failed.");
    } finally { setLoading(false); }
  }

  const methodDescription = method === "EMAIL"
    ? "Enter the six-digit OTP sent to your verified official email."
    : method === "TOTP"
      ? "Enter the current six-digit code shown in Google Authenticator."
      : "Enter one unused recovery code generated during MFA enrollment.";

  function requestNewAuthenticator() {
    chooseMethod("EMAIL", true);
  }

  return (
    <main className="auth-shell compact-auth-shell mfa-auth-shell">
      <section className="auth-panel auth-panel-centered">
        <form className="login-card mfa-card" onSubmit={handleSubmit}>
          <div className="auth-card-heading"><span className="auth-card-logo"><ShieldCheck size={34} /></span><p className="eyebrow">MULTI-FACTOR VERIFICATION</p><h2>Choose a verification method</h2><p className="muted">Select the OTP method you prefer for this sign-in.</p></div>
          <div className={`mfa-method-grid${supportsTOTP ? "" : " single-method"}`} role="radiogroup" aria-label="Verification method">
            <button className={`mfa-method${method === "EMAIL" ? " selected" : ""}`} type="button" role="radio" aria-checked={method === "EMAIL"} onClick={() => chooseMethod("EMAIL")}><Mail size={21} /><span><strong>Email OTP</strong><small>Code sent to official email</small></span></button>
            {supportsTOTP && <button className={`mfa-method${method === "TOTP" ? " selected" : ""}`} type="button" role="radio" aria-checked={method === "TOTP"} onClick={() => chooseMethod("TOTP")}><Smartphone size={21} /><span><strong>Google Authenticator</strong><small>Code from authenticator app</small></span></button>}
          </div>
          <p className="mfa-method-description">{methodDescription} {expired ? "This challenge has expired." : `Expires in ${countdown}.`}</p>
          {expired && <div className="alert alert-error" role="alert">This verification challenge has expired. Return to sign in to request a new one.</div>}
          {error && <div className="alert alert-error" role="alert">{error}</div>}
          <label className="auth-field"><span>{method === "EMAIL" ? "Email verification code" : method === "TOTP" ? "Authenticator code" : "Recovery code"}</span><span className="input-with-icon"><KeyRound size={17} /><input className="otp-input" inputMode={method === "RECOVERY" ? "text" : "numeric"} autoComplete="one-time-code" maxLength={method === "RECOVERY" ? 32 : 6} value={code} onChange={(event) => setCode(method === "RECOVERY" ? event.target.value.toUpperCase() : event.target.value.replace(/\D/g, ""))} placeholder={method === "RECOVERY" ? "Enter recovery code" : "000000"} required autoFocus disabled={expired} /></span></label>
          <button className="primary button-full" type="submit" disabled={loading || expired || code.trim().length < requiredLength}>{loading ? "Verifying…" : "Verify and Continue"}</button>
          {supportsTOTP && method === "TOTP" && <button className="new-qr-action" type="button" onClick={requestNewAuthenticator}><Smartphone size={16} /><span><strong>Cannot access the current Authenticator?</strong><small>Verify your official email, then set up a new Authenticator QR.</small></span></button>}
          {supportsTOTP && <button className="recovery-toggle" type="button" onClick={() => chooseMethod(method === "RECOVERY" ? "EMAIL" : "RECOVERY")}>{method === "RECOVERY" ? "Use an OTP method" : "Use a recovery code instead"}</button>}
          <Link className="text-link with-icon" to="/login" onClick={() => sessionStorage.removeItem(MFA_CHALLENGE_STORAGE_KEY)}><ArrowLeft size={15} /> Back to Sign In</Link>
        </form>
      </section>
    </main>
  );
}
