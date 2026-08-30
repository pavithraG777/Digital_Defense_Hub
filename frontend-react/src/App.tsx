import { useEffect, useState } from "react";
import { Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Layout } from "./components/Layout";
import { ChangePasswordPage } from "./pages/ChangePasswordPage";
import { AuditActivityPage } from "./pages/AuditActivityPage";
import { AttackStoriesPage } from "./pages/AttackStoriesPage";
import { DeceptionManagementPage } from "./pages/DeceptionManagementPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DeepfakeImageAnalysisPage } from "./pages/DeepfakeImageAnalysisPage";
import { DeepfakeAnalysisHistoryPage } from "./pages/DeepfakeAnalysisHistoryPage";
import { EvidenceVaultWorkspacePage } from "./pages/EvidenceVaultWorkspacePage";
import { ForensicReportsPage } from "./pages/ForensicReportsPage";
import { OrganizationManagementPage } from "./pages/OrganizationManagementPage";
import { IncidentResponsePage } from "./pages/IncidentResponsePage";
import { InvestigationCasesPage } from "./pages/InvestigationCasesPage";
import { LoginPage } from "./pages/LoginPage";
import { MfaPage } from "./pages/MfaPage";
import { MfaSetupPage } from "./pages/MfaSetupPage";
import { ModuleWorkspacePage } from "./pages/ModuleWorkspacePage";
import { ModulesPage } from "./pages/ModulesPage";
import { IamManagementPage } from "./pages/IamManagementPage";
import { NotificationsPage } from "./pages/NotificationsPage";
import { PasswordRecoveryPage } from "./pages/PasswordRecoveryPage";
import { ResetPasswordPage } from "./pages/ResetPasswordPage";
import { RegisterPage } from "./pages/RegisterPage";
import { ThreatCenterPage } from "./pages/ThreatCenterPage";
import { ThreatScorePage } from "./pages/ThreatScorePage";
import { session } from "./lib/api";
import type { AuthTokens, AuthUser } from "./types";

function ProtectedRoute({ children }: { children: JSX.Element }) {
  const location = useLocation();
  const [tokens, setTokens] = useState<AuthTokens | null>(() => session.getTokens());
  const [user, setUser] = useState<AuthUser | null>(() => session.getUser<AuthUser>());

  useEffect(() => {
    const sync = () => {
      setTokens(session.getTokens());
      setUser(session.getUser<AuthUser>());
    };
    window.addEventListener("ddh:session-changed", sync);
    return () => window.removeEventListener("ddh:session-changed", sync);
  }, []);

  if (!tokens) {
    return <Navigate to="/login" replace state={{ from: `${location.pathname}${location.search}` }} />;
  }

  if (user?.must_change_password && location.pathname !== "/change-password") {
    return <Navigate to="/change-password" replace />;
  }

  if (user && !user.must_change_password && !user.mfa_enabled && location.pathname !== "/mfa/setup") {
    return <Navigate to="/mfa/setup" replace />;
  }

  return children;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/password-recovery" element={<PasswordRecoveryPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/mfa" element={<MfaPage />} />
      <Route path="/mfa/setup" element={<ProtectedRoute><MfaSetupPage /></ProtectedRoute>} />
      <Route path="/change-password" element={<ProtectedRoute><ChangePasswordPage /></ProtectedRoute>} />
      <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/deepfake-image-analysis" element={<DeepfakeImageAnalysisPage />} />
        <Route path="/evidence-vault" element={<EvidenceVaultWorkspacePage />} />
        <Route path="/module/deepfake/reports" element={<ForensicReportsPage />} />
        <Route path="/honeytokens" element={<DeceptionManagementPage kind="honeytoken" />} />
        <Route path="/canary-files" element={<DeceptionManagementPage kind="canary" />} />
        <Route path="/audit-activity" element={<AuditActivityPage />} />
        <Route path="/notifications" element={<NotificationsPage />} />
        <Route path="/module/deepfake/media" element={<DeepfakeImageAnalysisPage />} />
        <Route path="/module/deepfake/analysis" element={<DeepfakeAnalysisHistoryPage />} />
        <Route path="/organizations" element={<OrganizationManagementPage />} />
        <Route path="/users" element={<IamManagementPage initialTab="users" />} />
        <Route path="/roles" element={<IamManagementPage initialTab="roles" />} />
        <Route path="/permissions" element={<IamManagementPage initialTab="permissions" />} />
        <Route path="/threats" element={<ThreatCenterPage />} />
        <Route path="/threat-score" element={<ThreatScorePage />} />
        <Route path="/incidents" element={<IncidentResponsePage />} />
        <Route path="/investigations" element={<InvestigationCasesPage />} />
        <Route path="/attack-stories" element={<AttackStoriesPage />} />
        <Route path="/module/investigations/:screenId" element={<Navigate to="/investigations" replace />} />
        <Route path="/module/intelligence/replay" element={<Navigate to="/attack-stories" replace />} />
        <Route path="/intelligence" element={<ModulesPage title="Intelligence Center" description="Threat correlation and enrichment insights" path="/intelligence/dashboard" emptyMessage="No intelligence data available yet." />} />
        <Route path="/reports" element={<ModulesPage title="Reports & Analytics" description="Executive and operational reporting" path="/reports" emptyMessage="No reports available yet." />} />
        <Route path="/settings" element={<div className="page"><div className="hero"><div><h1>Settings</h1><p>Enterprise configuration and governance controls</p></div></div></div>} />
        <Route path="/profile" element={<div className="page"><div className="hero"><div><h1>My Profile</h1><p>Identity, MFA, and account security control center</p></div></div><div className="card profile-security-card"><h3>Google Authenticator</h3><p className="muted">Generate and verify a replacement QR code without disabling your current authenticator first.</p><Link className="primary-link" to="/mfa/setup">Replace Authenticator</Link></div></div>} />
        <Route path="/module/:moduleId" element={<Navigate to="/dashboard" replace />} />
        <Route path="/module/:moduleId/:screenId" element={<ModuleWorkspacePage />} />
      </Route>
    </Routes>
  );
}
