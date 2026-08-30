import type { ApiEnvelope, AuthTokens, LoginResult } from "../types";

const ACCESS_TOKEN_KEY = "ddh.access-token";
const REFRESH_TOKEN_KEY = "ddh.refresh-token";
const USER_KEY = "ddh.user";
const API_BASE = (import.meta.env.VITE_API_BASE_URL || "/api/v1").replace(/\/$/, "");

export class ApiError extends Error {
  status: number;
  details: unknown;

  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
  }
}

export const session = {
  getTokens(): AuthTokens | null {
    const accessToken = sessionStorage.getItem(ACCESS_TOKEN_KEY);
    if (!accessToken) return null;
    return { accessToken, refreshToken: sessionStorage.getItem(REFRESH_TOKEN_KEY) || undefined };
  },
  setTokens(tokens: AuthTokens) {
    sessionStorage.setItem(ACCESS_TOKEN_KEY, tokens.accessToken);
    if (tokens.refreshToken) sessionStorage.setItem(REFRESH_TOKEN_KEY, tokens.refreshToken);
    window.dispatchEvent(new Event("ddh:session-changed"));
  },
  setLogin(result: LoginResult) {
    this.setTokens({ accessToken: result.access_token, refreshToken: result.refresh_token });
    sessionStorage.setItem(USER_KEY, JSON.stringify(result.user));
    window.dispatchEvent(new Event("ddh:session-changed"));
  },
  getUser<T>() {
    const raw = sessionStorage.getItem(USER_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  },
  setUser(user: unknown) {
    sessionStorage.setItem(USER_KEY, JSON.stringify(user));
    window.dispatchEvent(new Event("ddh:session-changed"));
  },
  clear() {
    sessionStorage.removeItem(ACCESS_TOKEN_KEY);
    sessionStorage.removeItem(REFRESH_TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
    // Clear sessions created by older builds that persisted bearer credentials.
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    window.dispatchEvent(new Event("ddh:session-changed"));
  },
};

let refreshInFlight: Promise<boolean> | null = null;

async function parseResponse<T>(response: Response): Promise<T> {
  const contentType = response.headers.get("content-type") || "";
  const payload: ApiEnvelope<T> | T | null = contentType.includes("application/json")
    ? await response.json().catch(() => null)
    : null;

  if (!response.ok) {
    const envelope = payload as ApiEnvelope<T> | null;
    const message = envelope?.message || `Request failed (${response.status})`;
    throw new ApiError(message, response.status, envelope?.error);
  }

  if (payload && typeof payload === "object" && "success" in payload) {
    const envelope = payload as ApiEnvelope<T>;
    if (!envelope.success) throw new ApiError(envelope.message || "Request failed", response.status, envelope.error);
    return envelope.data as T;
  }
  return payload as T;
}

async function refreshAccessToken(): Promise<boolean> {
  const refreshToken = session.getTokens()?.refreshToken;
  if (!refreshToken) return false;

  try {
    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    const result = await parseResponse<{ access_token: string; refresh_token?: string }>(response);
    session.setTokens({ accessToken: result.access_token, refreshToken: result.refresh_token || refreshToken });
    return true;
  } catch {
    session.clear();
    return false;
  }
}

type RequestOptions = Omit<RequestInit, "body"> & {
  body?: unknown;
  skipRefresh?: boolean;
};

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, skipRefresh, headers, ...rest } = options;
  const tokens = session.getTokens();
  const requestHeaders = new Headers(headers || {});
  if (tokens?.accessToken) requestHeaders.set("Authorization", `Bearer ${tokens.accessToken}`);

  let requestBody: BodyInit | undefined;
  if (body instanceof FormData || body instanceof URLSearchParams || typeof body === "string") {
    requestBody = body;
  } else if (body !== undefined) {
    requestHeaders.set("Content-Type", "application/json");
    requestBody = JSON.stringify(body);
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...rest,
    headers: requestHeaders,
    body: requestBody,
  });

  const isPublicAuthRequest = /^\/auth\/(login|mfa\/verify|refresh|forgot-password|reset-password|revoke-refresh-token)$/.test(path);
  if (response.status === 401 && !skipRefresh && !isPublicAuthRequest && tokens?.refreshToken) {
    refreshInFlight ||= refreshAccessToken().finally(() => {
      refreshInFlight = null;
    });
    if (await refreshInFlight) return apiRequest<T>(path, { ...options, skipRefresh: true });
  }

  return parseResponse<T>(response);
}

export async function apiBlob(path: string, options: { method?: "GET" | "POST"; body?: unknown; skipRefresh?: boolean } = {}): Promise<Blob> {
  const { method = "GET", body, skipRefresh = false } = options;
  const tokens = session.getTokens();
  const headers = new Headers();
  if (tokens?.accessToken) headers.set("Authorization", `Bearer ${tokens.accessToken}`);
  if (body !== undefined) headers.set("Content-Type", "application/json");
  const response = await fetch(`${API_BASE}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });

  if (response.status === 401 && !skipRefresh && tokens?.refreshToken) {
    refreshInFlight ||= refreshAccessToken().finally(() => { refreshInFlight = null; });
    if (await refreshInFlight) return apiBlob(path, { ...options, skipRefresh: true });
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as ApiEnvelope<unknown> | null;
    throw new ApiError(payload?.message || `Request failed (${response.status})`, response.status, payload?.error);
  }
  return response.blob();
}

export const api = {
  get: <T>(path: string) => apiRequest<T>(path),
  post: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: "POST", body }),
  put: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: "PUT", body }),
  patch: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: "PATCH", body }),
  delete: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: "DELETE", body }),
};

export const apiBaseUrl = API_BASE;
