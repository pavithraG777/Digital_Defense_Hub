import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Eye, EyeOff, KeyRound, ShieldCheck } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { DashboardLiveBackground } from "../components/DashboardLiveBackground";
import { api, session } from "../lib/api";

type ChangePasswordResult = {
  password_changed: boolean;
  sessions_terminated: boolean;
  login_required: boolean;
};

function passwordStrength(password: string) {
  const checks = [
    password.length >= 12,
    /[a-z]/.test(password) && /[A-Z]/.test(password),
    /\d/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ];

  return checks.filter(Boolean).length;
}

function PasswordField({
  label,
  value,
  onChange,
  autoComplete,
  hint,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete: string;
  hint?: string;
}) {
  const [visible, setVisible] = useState(false);
  const id = label.toLowerCase().replace(/\s+/g, "-");

  return (
    <label htmlFor={id}>
      <span>{label}</span>
      <span className="password-field">
        <input
          id={id}
          autoComplete={autoComplete}
          type={visible ? "text" : "password"}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          required
        />
        <button
          className="password-visibility"
          type="button"
          onClick={() => setVisible((current) => !current)}
          aria-label={`${visible ? "Hide" : "Show"} ${label.toLowerCase()}`}
        >
          {visible ? <EyeOff size={17} /> : <Eye size={17} />}
        </button>
      </span>
      {hint && <small className="field-hint">{hint}</small>}
    </label>
  );
}

export function ChangePasswordPage() {
  const navigate = useNavigate();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const strength = useMemo(() => passwordStrength(newPassword), [newPassword]);
  const matches = !confirmPassword || newPassword === confirmPassword;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (!matches) {
      setError("The new password and confirmation do not match.");
      return;
    }

    if (newPassword.length < 12) {
      setError("Use a new password with at least 12 characters.");
      return;
    }

    setLoading(true);
    try {
      const result = await api.post<ChangePasswordResult>("/change-password", {
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword,
      });

      if (!result.password_changed) {
        throw new Error("The password update was not completed.");
      }

      session.clear();
      navigate("/login", {
        replace: true,
        state: {
          notice: result.sessions_terminated
            ? "Password updated. All active sessions were signed out; please sign in again."
            : "Password updated. Please sign in again.",
        },
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to update your password.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-shell compact-auth-shell password-change-shell">
      <DashboardLiveBackground />
      <section className="auth-panel auth-panel-centered">
        <form className="login-card password-change-card" onSubmit={submit}>
          <span className="auth-icon"><KeyRound size={27} /></span>
          <p className="eyebrow">ACCOUNT SECURITY</p>
          <h1>Set a new password</h1>
          <p className="muted">This account requires a password update before access to the SOC workspace is granted.</p>
          <div className="alert alert-info"><ShieldCheck size={17} /> Updating your password signs out every active session for this identity.</div>
          {error && <div className="alert alert-error" role="alert">{error}</div>}

          <PasswordField label="Current password" value={currentPassword} onChange={setCurrentPassword} autoComplete="current-password" />
          <PasswordField label="New password" value={newPassword} onChange={setNewPassword} autoComplete="new-password" hint="Use 12+ characters with upper/lowercase, a number, and a symbol." />
          {newPassword && (
            <div className="password-strength" aria-label={`Password strength: ${["weak", "fair", "good", "strong", "strong"][strength]}`}>
              <span className={`strength-bar strength-${strength}`}><i /><i /><i /><i /></span>
              <small>{["Weak", "Weak", "Fair", "Good", "Strong"][strength]}</small>
            </div>
          )}
          <PasswordField label="Confirm new password" value={confirmPassword} onChange={setConfirmPassword} autoComplete="new-password" />
          {!matches && <p className="field-error" role="alert">Passwords do not match.</p>}
          <button className="primary button-full" type="submit" disabled={loading || !matches}>
            {loading ? "Updating secure access…" : "Update password and sign out"}
          </button>
        </form>
      </section>
    </main>
  );
}
