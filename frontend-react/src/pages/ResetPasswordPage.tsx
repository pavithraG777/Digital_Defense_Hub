import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Eye, EyeOff, KeyRound, ShieldCheck } from "lucide-react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";

type ResetPasswordResult = {
  password_reset: boolean;
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

export function ResetPasswordPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [token, setToken] = useState(searchParams.get("token") ?? "");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const strength = useMemo(() => passwordStrength(newPassword), [newPassword]);
  const matches = !confirmPassword || newPassword === confirmPassword;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (!token.trim()) {
      setError("A reset token is required. Use the link from your recovery email.");
      return;
    }

    if (!matches) {
      setError("The new password and confirmation do not match.");
      return;
    }

    if (strength < 3) {
      setError("Choose a stronger password with upper/lowercase letters, a number, and a symbol.");
      return;
    }

    setLoading(true);
    try {
      const result = await api.post<ResetPasswordResult>("/auth/reset-password", {
        reset_token: token.trim(),
        new_password: newPassword,
        confirm_password: confirmPassword,
      });

      if (!result.password_reset) {
        throw new Error("The password reset could not be completed.");
      }

      navigate("/login", {
        replace: true,
        state: {
          notice: result.login_required
            ? "Password reset complete. Please sign in with your new password."
            : "Password reset complete. Please sign in to continue.",
        },
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to reset your password.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-shell compact-auth-shell">
      <section className="auth-panel auth-panel-centered">
        <form className="login-card" onSubmit={submit}>
          <span className="auth-icon"><KeyRound size={27} /></span>
          <p className="eyebrow">ACCOUNT RECOVERY</p>
          <h1>Create a new password</h1>
          <p className="muted">Use the secure reset link issued by your organization to set a new password for your SOC account.</p>
          {error && <div className="alert alert-error" role="alert">{error}</div>}

          <label>
            Recovery token
            <input
              value={token}
              onChange={(event) => setToken(event.target.value)}
              placeholder="Paste the reset token"
              autoComplete="one-time-code"
              required
            />
          </label>
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
            {loading ? "Resetting password…" : "Reset password"}
          </button>
          <Link className="text-link with-icon" to="/login"><ShieldCheck size={15} /> Return to sign in</Link>
        </form>
      </section>
    </main>
  );
}
