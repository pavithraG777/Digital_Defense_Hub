import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { KeyRound, Mail, QrCode, ShieldCheck, Smartphone } from "lucide-react";
import QRCode from "qrcode";
import type { AuthUser } from "../types";
import { api, session } from "../lib/api";

type SetupMethod = "EMAIL" | "TOTP";
type EmailStart = { mfa_challenge_id: string; expires_in_seconds: number };
type TOTPStart = { provisioning_uri: string; recovery_codes: string[]; enrollment_token?: string };

export function MfaSetupPage() {
  const navigate = useNavigate();
  const user = session.getUser<AuthUser>();
  const replacing = Boolean(user?.mfa_enabled);
  const [method, setMethod] = useState<SetupMethod | null>(null);
  const [emailChallenge, setEmailChallenge] = useState<EmailStart | null>(null);
  const [totp, setTotp] = useState<TOTPStart | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [complete, setComplete] = useState(false);

  useEffect(() => {
    if (!totp?.provisioning_uri) return;
    QRCode.toDataURL(totp.provisioning_uri, { width: 240, margin: 2, color: { dark: "#03101f", light: "#eaf6ff" } }).then(setQrDataUrl).catch(() => setError("Unable to generate the authenticator QR code."));
  }, [totp]);

  async function start(next: SetupMethod) {
    setMethod(next); setCode(""); setError(null); setLoading(true);
    try {
      if (next === "EMAIL") setEmailChallenge(await api.post<EmailStart>("/auth/mfa/email/enrollment/start"));
      else if (replacing) {
        const value = await api.post<{ provisioning_uri: string; enrollment_token: string }>("/auth/mfa/totp/replacement/start");
        setTotp({ ...value, recovery_codes: [] });
      } else setTotp(await api.post<TOTPStart>("/auth/mfa/enrollment/start"));
    } catch (err) { setError(err instanceof Error ? err.message : "MFA setup could not be started."); }
    finally { setLoading(false); }
  }

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!method) return;
    setError(null); setLoading(true);
    try {
      if (method === "EMAIL" && emailChallenge) await api.post("/auth/mfa/email/enrollment/confirm", { mfa_challenge_id: emailChallenge.mfa_challenge_id, email_code: code });
      else if (method === "TOTP" && totp && replacing) {
        const value = await api.post<{ recovery_codes: string[] }>("/auth/mfa/totp/replacement/confirm", { enrollment_token: totp.enrollment_token, totp_code: code });
        setTotp({ ...totp, recovery_codes: value.recovery_codes }); setComplete(true); return;
      } else if (method === "TOTP" && totp) await api.post("/auth/mfa/enrollment/confirm", { totp_code: code });
      else return;
      if (user) session.setUser({ ...user, mfa_enabled: true });
      navigate("/dashboard", { replace: true });
    } catch (err) { setError(err instanceof Error ? err.message : "The verification code was not accepted."); }
    finally { setLoading(false); }
  }

  function resetChoice() { setMethod(null); setEmailChallenge(null); setTotp(null); setQrDataUrl(""); setCode(""); setError(null); }

  return <main className="auth-shell compact-auth-shell mfa-auth-shell"><section className="auth-panel auth-panel-centered"><form className="login-card mfa-card" onSubmit={confirm}>
    <div className="auth-card-heading"><span className="auth-card-logo"><ShieldCheck size={34} /></span><p className="eyebrow">{replacing ? "MFA SECURITY" : "FIRST-TIME MFA SETUP"}</p><h2>{replacing ? "Replace Google Authenticator" : "Protect your account"}</h2><p className="muted">{replacing ? "Your current authenticator remains valid until the new QR code is verified." : "Choose one method and verify it before entering the platform."}</p></div>
    {!method && !complete && <div className={`mfa-method-grid${replacing ? " single-method" : ""}`}>{!replacing && <button className="mfa-method" type="button" onClick={() => start("EMAIL")}><Mail size={22} /><span><strong>Email OTP</strong><small>Verify your official email</small></span></button>}<button className="mfa-method" type="button" onClick={() => start("TOTP")}><Smartphone size={22} /><span><strong>{replacing ? "Generate New QR" : "Google Authenticator"}</strong><small>{replacing ? "Safely replace current setup" : "Scan a secure QR code"}</small></span></button></div>}
    {loading && !emailChallenge && !totp && <p className="mfa-method-description">Preparing secure enrollment…</p>}{error && <div className="alert alert-error" role="alert">{error}</div>}
    {method === "EMAIL" && emailChallenge && <><div className="setup-instruction"><Mail size={23} /><div><strong>Email OTP sent</strong><p>Enter the six-digit code delivered to your verified official email.</p></div></div><label className="auth-field"><span>Email verification code</span><span className="input-with-icon"><KeyRound size={17} /><input className="otp-input" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} placeholder="000000" required autoFocus /></span></label></>}
    {method === "TOTP" && totp && !complete && <><div className="authenticator-setup"><div className="qr-panel">{qrDataUrl ? <img src={qrDataUrl} alt="Google Authenticator enrollment QR code" /> : <QrCode size={68} />}</div><div className="setup-instruction"><Smartphone size={23} /><div><strong>Scan with Google Authenticator</strong><p>Add an account by scanning this QR code, then enter its current six-digit code.</p></div></div></div><label className="auth-field"><span>Authenticator verification code</span><span className="input-with-icon"><KeyRound size={17} /><input className="otp-input" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} placeholder="000000" required autoFocus /></span></label></>}
    {complete && totp && <div className="replacement-complete"><ShieldCheck size={42} /><h3>Authenticator replaced</h3><p>Save these new recovery codes. Previous authenticator and recovery codes are no longer valid.</p><div className="recovery-code-grid">{totp.recovery_codes.map((item) => <code key={item}>{item}</code>)}</div><button className="primary button-full" type="button" onClick={() => navigate("/profile")}>Continue to Profile</button></div>}
    {method && !complete && <><button className="primary button-full" type="submit" disabled={loading || code.length !== 6}>{loading ? "Verifying…" : replacing ? "Verify and Replace" : "Verify and Enable MFA"}</button><button className="recovery-toggle" type="button" onClick={resetChoice}>Choose a different method</button></>}
  </form></section></main>;
}
