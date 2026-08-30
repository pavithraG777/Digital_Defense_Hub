import { useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Info } from "lucide-react";
import { api, session } from "../lib/api";

export function PasswordRecoveryPage() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const authenticated = Boolean(session.getTokens());

  async function requestRecovery(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage(null);
    setError(null);
    setLoading(true);
    try {
      const result = await api.post<{ message?: string }>("/auth/forgot-password", { email });
      setMessage(result.message || "Password reset request created.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Password recovery request failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-shell compact-auth-shell">
      <section className="auth-panel auth-panel-centered">
        <form className="login-card" onSubmit={requestRecovery}>
          <p className="eyebrow">ACCOUNT RECOVERY</p>
          <h2>Password recovery</h2>
          <div className="alert alert-info"><Info size={17} /> The current Go backend protects password-recovery requests with an authenticated session.</div>
          <p className="muted">{authenticated ? "You can submit a recovery request below." : "Sign in first to use the available recovery API, or contact your organization administrator if you cannot sign in."}</p>
          {message && <div className="alert alert-success" role="status">{message}</div>}
          {error && <div className="alert alert-error" role="alert">{error}</div>}
          <label>
            Official email
            <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="name@organization.com" disabled={!authenticated} required />
          </label>
          <button className="primary button-full" type="submit" disabled={!authenticated || loading}>{loading ? "Submitting…" : "Request recovery"}</button>
          <Link className="text-link with-icon" to={authenticated ? "/module/settings/password" : "/login"}><ArrowLeft size={15} /> {authenticated ? "Go to password settings" : "Back to sign in"}</Link>
        </form>
      </section>
    </main>
  );
}
