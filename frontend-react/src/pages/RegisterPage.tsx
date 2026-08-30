import { useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router-dom";
import { Building2, CheckCircle2, Mail, Phone, UserRound } from "lucide-react";
import { api } from "../lib/api";
import { BrandLogo } from "../components/BrandLogo";
import { AuthLiveBackground } from "../components/AuthLiveBackground";

type RegistrationResult = { id: string; organization_code: string; legal_name: string; status: string };
const organizationTypes = [["GOVERNMENT", "Government"], ["POLICE", "Police"], ["FORENSIC_LAB", "Forensic Laboratory"], ["DEFENCE", "Defence"], ["RESEARCH_EDUCATION", "Research or Education"], ["CYBERSECURITY_PROVIDER", "Cybersecurity Provider"], ["BUSINESS", "Business"]] as const;

export function RegisterPage() {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [organizationType, setOrganizationType] = useState("GOVERNMENT");
  const [department, setDepartment] = useState("");
  const [officialPhone, setOfficialPhone] = useState("");
  const [contactPhone, setContactPhone] = useState("");
  const [registrationNumber, setRegistrationNumber] = useState("");
  const [website, setWebsite] = useState("");
  const [address, setAddress] = useState("");
  const [estimatedUsers, setEstimatedUsers] = useState("");
  const [purpose, setPurpose] = useState("");
  const [accepted, setAccepted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<RegistrationResult | null>(null);
  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      setResult(await api.post<RegistrationResult>("/organizations/register", {
        legal_name: organizationName.trim(), display_name: organizationName.trim(), organization_type: organizationType,
        primary_email: email.trim().toLowerCase(), security_email: email.trim().toLowerCase(),
        phone: officialPhone.trim(), registration_number: registrationNumber.trim(), website: website.trim(), address: address.trim(),
        admin_name: fullName.trim(), admin_designation: department.trim(), admin_email: email.trim().toLowerCase(), admin_phone: contactPhone.trim(),
        purpose: purpose.trim(), estimated_users: estimatedUsers ? Number(estimatedUsers) : 0, security_level: "RESTRICTED",
      }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration could not be submitted.");
    } finally { setLoading(false); }
  }

  return (
    <main className="auth-shell auth-shell-register">
      <AuthLiveBackground />
      <section className="auth-intro" aria-label="Secure organization onboarding">
        <BrandLogo className="auth-brand" />
        <div className="auth-copy"><p className="eyebrow">CONTROLLED ONBOARDING</p><h1>Request secure platform access.</h1><p>Organization validation and administrator approval prevent unauthorized public account creation.</p></div>
      </section>
      <section className="auth-panel">
        {result ? <div className="login-card registration-complete" role="status"><CheckCircle2 size={52} /><p className="eyebrow">REQUEST RECEIVED</p><h2>Approval pending</h2><p>Your request for <strong>{result.legal_name}</strong> was recorded with workspace code <strong>{result.organization_code}</strong>.</p><p className="muted">An administrator must approve the organization before user credentials and MFA enrollment can be completed.</p><Link className="primary-link" to="/login">Return to Sign In</Link></div> :
          <form className="login-card register-card" onSubmit={handleSubmit}>
            <div className="auth-card-heading"><BrandLogo compact className="auth-card-logo" /><p className="eyebrow">SECURE REGISTRATION</p><h2>Request Your Account</h2><p className="muted">Workspace code is assigned automatically after submission.</p></div>
            {error && <div className="alert alert-error" role="alert">{error}</div>}
            <div className="register-grid">
              <label className="auth-field"><span>Full name</span><span className="input-with-icon"><UserRound size={17} /><input value={fullName} onChange={(event) => setFullName(event.target.value)} autoComplete="name" placeholder="Account owner" minLength={2} required /></span></label>
              <label className="auth-field"><span>Official email</span><span className="input-with-icon"><Mail size={17} /><input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" placeholder="name@organization.gov" required /></span></label>
              <label className="auth-field field-wide"><span>Organization name</span><span className="input-with-icon"><Building2 size={17} /><input value={organizationName} onChange={(event) => setOrganizationName(event.target.value)} autoComplete="organization" placeholder="Legal organization name" minLength={2} required /></span></label>
              <label className="auth-field"><span>Organization type</span><select value={organizationType} onChange={(event) => setOrganizationType(event.target.value)}>{organizationTypes.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
              <label className="auth-field"><span>Department or designation</span><input value={department} onChange={(event) => setDepartment(event.target.value)} placeholder="Digital Forensics Department" maxLength={120} required /></label>
              <label className="auth-field"><span>Official organization phone</span><span className="input-with-icon"><Phone size={17} /><input type="tel" value={officialPhone} onChange={(event) => setOfficialPhone(event.target.value)} autoComplete="organization-tel" placeholder="+91 44 0000 0000" maxLength={40} required /></span></label>
              <label className="auth-field"><span>Authorized contact phone</span><span className="input-with-icon"><Phone size={17} /><input type="tel" value={contactPhone} onChange={(event) => setContactPhone(event.target.value)} autoComplete="tel" placeholder="+91 90000 00000" maxLength={40} required /></span></label>
              <label className="auth-field"><span>Registration number <small>(optional)</small></span><input value={registrationNumber} onChange={(event) => setRegistrationNumber(event.target.value)} placeholder="Government or legal registration ID" maxLength={120} /></label>
              <label className="auth-field"><span>Official website <small>(optional)</small></span><input type="url" value={website} onChange={(event) => setWebsite(event.target.value)} placeholder="https://organization.example" maxLength={255} /></label>
              <label className="auth-field field-wide"><span>Official address <small>(optional)</small></span><input value={address} onChange={(event) => setAddress(event.target.value)} autoComplete="street-address" placeholder="Registered office address" maxLength={500} /></label>
              <label className="auth-field"><span>Estimated platform users <small>(optional)</small></span><input type="number" value={estimatedUsers} onChange={(event) => setEstimatedUsers(event.target.value)} placeholder="Example: 25" min={1} max={1000000} /></label>
              <label className="auth-field field-wide"><span>Reason for requesting access</span><textarea value={purpose} onChange={(event) => setPurpose(event.target.value)} placeholder="Describe the security, investigation, forensics, or organizational use case." minLength={20} maxLength={2000} rows={4} required /></label>
            </div>
            <label className="check-line terms-line"><input type="checkbox" checked={accepted} onChange={(event) => setAccepted(event.target.checked)} required /><span>I confirm these details are authorized and agree to the security policy.</span></label>
            <button className="primary button-full" type="submit" disabled={loading || !accepted}>{loading ? "Submitting securely…" : "Submit for Approval"}</button>
            <p className="form-footnote">Passwords are not collected before approval. This prevents unapproved credentials from being stored or activated.</p>
            <p className="auth-switch">Already have an approved account? <Link to="/login">Sign in</Link></p>
          </form>}
      </section>
      <footer className="auth-footer"><span>© 2026 Digital Defense Hub. All rights reserved.</span><span>Controlled Registration</span></footer>
    </main>
  );
}
