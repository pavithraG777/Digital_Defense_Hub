export type ApiEnvelope<T> = {
  success: boolean;
  message?: string;
  data?: T;
  error?: unknown;
};

export type AuthUser = {
  id: string;
  username: string;
  official_email: string;
  display_name: string;
  user_type: string;
  account_status: string;
  must_change_password: boolean;
  mfa_enabled: boolean;
  roles: string[];
};

export type LoginResult = {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in_seconds: number;
  user: AuthUser;
};

export type MFAChallenge = {
  mfa_required: boolean;
  mfa_challenge_id: string;
  mfa_challenge_type?: "EMAIL" | "EMAIL_OR_TOTP";
  expires_in_seconds: number;
};

export type LoginMFAResponse = {
  mfa_challenge: MFAChallenge;
  risk?: {
    risk_score: number;
    risk_level: string;
    requires_step_up_mfa: boolean;
    risk_flags: string[];
    summary: string;
  };
};

export type AuthTokens = {
  accessToken: string;
  refreshToken?: string;
};

export type ApiSource = {
  id: string;
  label: string;
  path: string;
  description?: string;
  detailPath?: string;
  poll?: boolean;
};

export type ActionField = {
  name: string;
  label: string;
  type?: "text" | "email" | "password" | "number" | "textarea" | "select" | "json";
  required?: boolean;
  placeholder?: string;
  options?: Array<{ label: string; value: string }>;
};

export type ScreenAction = {
  label: string;
  method: "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  fields?: ActionField[];
  destructive?: boolean;
  description?: string;
};

export type ScreenDefinition = {
  id: string;
  title: string;
  shortTitle?: string;
  description: string;
  sources?: ApiSource[];
  actions?: ScreenAction[];
  unavailable?: string;
};

export type ModuleDefinition = {
  id: string;
  title: string;
  description: string;
  icon: string;
  screens: ScreenDefinition[];
};
