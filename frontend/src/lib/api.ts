/**
 * LogMorph Resilient Production API Client
 * Enterprise-grade client with Render free-tier cold-start resilience,
 * 502/503/504 backoff retry, normalized errors, and strict TypeScript types.
 */

export const API_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") ??
  (import.meta.env.DEV ? "" : "https://logmorph.onrender.com");

const TIMEOUT_MS = 70_000; // Render free tier can take up to 60s to wake from sleep
const RETRY_STATUSES = new Set([502, 503, 504]);
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public errorCode?: string,
    public details?: unknown
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// ---------------------------------------------------------------------------
// TypeScript Domain Interfaces (Derived from OpenAPI Contract)
// ---------------------------------------------------------------------------

export interface User {
  id: string;
  email: string;
  full_name?: string;
  is_verified?: boolean;
  created_at?: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user?: User;
}

export interface UniversalLogEvent {
  event_id: string;
  timestamp: string;
  raw_log: string;
  detected_format: "SYSLOG" | "CEF" | "LEEF" | "JSON" | "CLF" | "UNKNOWN" | string;
  severity: "CRITICAL" | "ERROR" | "WARNING" | "NOTICE" | "INFO" | "DEBUG" | string;
  source?: {
    ip?: string;
    hostname?: string;
    port?: number;
  };
  destination?: {
    ip?: string;
    hostname?: string;
    port?: number;
  };
  security?: {
    user?: string;
    process_name?: string;
    process_id?: number | string;
    auth_action?: string;
  } & Record<string, unknown>;
  action?: string;
  parsed_by?: "RULE" | "TEMPLATE" | "LLM" | string;
  enrichment?: {
    geoip?: {
      country?: string;
      city?: string;
      latitude?: number;
      longitude?: number;
    } | null;
    threat_match?: boolean;
    threat_intel?: {
      source?: string;
      confidence?: number;
    } | null;
    mitre_technique?: string | null;
    mitre_tactic?: string | null;
  };
  attributes?: Record<string, unknown>;
  parse_latency_ms?: number;
}

export interface SandboxParseResponse {
  detected_format: string;
  parsed_by: string;
  event: UniversalLogEvent;
  processing_ms: number;
}

export interface EventsResponse {
  events: UniversalLogEvent[];
  pagination: {
    page: number;
    total: number;
    total_pages: number;
    limit: number;
  };
}

export interface EventsFilterParams {
  page?: number;
  limit?: number;
  search?: string;
  severity?: string;
  format?: string;
  source?: string;
  from_date?: string;
  to_date?: string;
}

export interface ApiKeyItem {
  id: string;
  name: string;
  key_prefix: string;
  created_at: string;
  is_active: boolean;
  last_used_at?: string | null;
  project_id?: string;
}

export interface ApiKeyCreatedResponse extends ApiKeyItem {
  key: string; // Plaintext secret displayed ONCE at creation time
}

export interface LogSourceItem {
  id: string;
  name: string;
  collector_type: "SYSLOG" | "FLUENTBIT" | "FILEBEAT" | "API" | string;
  ip_cidr?: string;
  status: "ACTIVE" | "IDLE" | "INACTIVE" | string;
  event_count: number;
  last_active_at?: string | null;
  created_at: string;
}

export interface StatsOverview {
  total_events: number;
  events_today: number;
  avg_latency_ms: number;
  active_sources_count: number;
  threat_count: number;
  rule_percentage: number;
  template_percentage: number;
  llm_percentage: number;
}

export interface FormatStatItem {
  format: string;
  count: number;
  percentage: number;
}

export interface LatencyBucket {
  timestamp: string;
  avg_latency_ms: number;
  p95_latency_ms: number;
  count: number;
}

export interface HealthResponse {
  status: "healthy" | "unhealthy" | "degraded";
  components?: {
    database?: string;
    kafka?: string;
    redis?: string;
  };
  version?: string;
}

// ---------------------------------------------------------------------------
// Core HTTP Fetch Client with Retry & Token Injection
// ---------------------------------------------------------------------------

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem("logmorph_token");
  const url = `${API_URL}${path}`;
  const init: RequestInit = {
    ...options,
    mode: "cors",
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      Accept: "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  };

  let response: Response | undefined;
  let networkError: unknown;

  // Retry up to 3 times on Render 502/503/504 cold-starts
  for (let attempt = 0; attempt < 3; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      response = await fetch(url, { ...init, signal: controller.signal });
      networkError = undefined;
      if (!RETRY_STATUSES.has(response.status)) break;
    } catch (error) {
      networkError = error;
      response = undefined;
    } finally {
      clearTimeout(timer);
    }
    if (attempt < 2) await sleep(2000 * (attempt + 1));
  }

  if (!response) {
    const timedOut = networkError instanceof DOMException && networkError.name === "AbortError";
    throw new ApiError(
      0,
      timedOut
        ? "The LogMorph server took too long to respond. The free-tier compute instance may be waking up — please retry."
        : `Cannot connect to LogMorph API (${API_URL}). Please check your connection and retry.`
    );
  }

  // Handle 401 Unauthorized (session expired or invalid token)
  if (response.status === 401 && !path.startsWith("/auth/login") && !path.startsWith("/auth/signup")) {
    clearSession();
    // Dispatch event so auth context or listener can react
    window.dispatchEvent(new CustomEvent("logmorph:auth-expired"));
  }

  // WAF & Non-JSON Interceptor (FIX-P12): Handle HTML 403 blocks from CDN/WAF
  const contentType = response.headers.get("content-type") || "";
  let data: Record<string, unknown> = {};

  if (contentType.includes("application/json")) {
    data = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  } else {
    const rawText = await response.text().catch(() => "");
    const isWafBlock =
      response.status === 403 ||
      rawText.includes("Access Denied") ||
      rawText.includes("Cloudflare") ||
      rawText.includes("Render") ||
      rawText.includes("<!DOCTYPE");

    if (isWafBlock) {
      data = {
        message:
          "Request was blocked by the security edge filter (WAF). " +
          "If submitting payloads with SQL, script tags, or shell syntax, sanitize the input or use compressed ingestion.",
        error_code: "WAF_SECURITY_BLOCK",
        detail: "Edge WAF filter triggered.",
      };
    } else {
      data = {
        message: rawText.slice(0, 200) || `Request failed with status ${response.status}`,
      };
    }
  }

  if (!response.ok) {
    let message = (data.message as string) || `Request failed with status ${response.status}`;
    if (Array.isArray(data.detail)) {
      message = data.detail.map((item: { msg?: string }) => item.msg || JSON.stringify(item)).join(", ");
    } else if (typeof data.detail === "string") {
      message = data.detail;
    }
    throw new ApiError(response.status, message, data.error_code as string | undefined, data);
  }

  return data as T;
}

// ---------------------------------------------------------------------------
// Session & Storage Utilities
// ---------------------------------------------------------------------------

export function saveSession(data: { access_token: string; user?: User }) {
  localStorage.setItem("logmorph_token", data.access_token);
  if (data.user) {
    localStorage.setItem("logmorph_user", JSON.stringify(data.user));
  }
}

export function clearSession() {
  localStorage.removeItem("logmorph_token");
  localStorage.removeItem("logmorph_user");
}

export function getToken(): string | null {
  return localStorage.getItem("logmorph_token");
}

export function getUser(): User | null {
  const raw = localStorage.getItem("logmorph_user");
  if (!raw) return null;
  try {
    return JSON.parse(raw) as User;
  } catch {
    return null;
  }
}

export function isAuthenticated(): boolean {
  return Boolean(getToken());
}

/** Fire-and-forget background ping to warm up sleeping Render instance early */
export function warmUpApi() {
  fetch(`${API_URL}/health`, { mode: "cors" }).catch(() => {});
}

// ---------------------------------------------------------------------------
// Typed API Endpoints
// ---------------------------------------------------------------------------

export const authApi = {
  signup: (payload: { email: string; password: string; full_name?: string }) =>
    api<AuthResponse>("/auth/signup", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  login: (payload: { email: string; password: string }) =>
    api<AuthResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  me: () => api<User>("/auth/me", { method: "GET" }),

  verifyEmail: (token: string) =>
    api<{ message: string; email: string }>("/auth/verify-email", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),

  resendVerification: (email: string) =>
    api<{ message: string }>("/auth/resend-verification", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),

  forgotPassword: (email: string) =>
    api<{ message: string }>("/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),

  resetPassword: (payload: { token: string; new_password: string }) =>
    api<{ message: string }>("/auth/reset-password", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  changePassword: (payload: { current_password: string; new_password: string }) =>
    api<{ message: string }>("/auth/change-password", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
};

export const sandboxApi = {
  parse: (raw_log: string, format_hint?: string) =>
    api<UniversalLogEvent>("/api/v1/sandbox/parse", {
      method: "POST",
      body: JSON.stringify({ raw_log, format_hint }),
    }),
};

export const eventsApi = {
  list: (params: EventsFilterParams = {}) => {
    const query = new URLSearchParams();
    if (params.page) query.set("page", String(params.page));
    if (params.limit) query.set("limit", String(params.limit));
    if (params.search) query.set("search", params.search);
    if (params.severity && params.severity !== "ALL") query.set("severity", params.severity);
    if (params.format && params.format !== "ALL") query.set("format", params.format);
    if (params.source) query.set("source", params.source);
    const qs = query.toString();
    return api<EventsResponse>(`/api/v1/events${qs ? `?${qs}` : ""}`, { method: "GET" });
  },

  get: (eventId: string) =>
    api<UniversalLogEvent>(`/api/v1/events/${eventId}`, { method: "GET" }),
};

export const keysApi = {
  list: () => api<{ keys: ApiKeyItem[] }>("/api/v1/keys", { method: "GET" }),

  create: (name: string, project_id?: string) =>
    api<ApiKeyCreatedResponse>("/api/v1/keys", {
      method: "POST",
      body: JSON.stringify({ name, project_id }),
    }),

  revoke: (keyId: string) =>
    api<{ message: string; revoked_key_id: string }>(`/api/v1/keys/${keyId}`, {
      method: "DELETE",
    }),
};

export const sourcesApi = {
  list: () => api<{ sources: LogSourceItem[] }>("/api/v1/sources", { method: "GET" }),

  create: (name: string, collector_type: string, ip_cidr?: string) =>
    api<LogSourceItem>("/api/v1/sources", {
      method: "POST",
      body: JSON.stringify({ name, collector_type, ip_cidr }),
    }),

  delete: (sourceId: string) =>
    api<{ message: string }>(`/api/v1/sources/${sourceId}`, {
      method: "DELETE",
    }),
};

export const statsApi = {
  overview: () => api<StatsOverview>("/api/v1/stats", { method: "GET" }),
  formats: () => api<{ formats: FormatStatItem[] }>("/api/v1/stats/formats", { method: "GET" }),
  latency: () => api<{ buckets: LatencyBucket[] }>("/api/v1/stats/latency", { method: "GET" }),
};

export const healthApi = {
  check: () => api<HealthResponse>("/health", { method: "GET" }),
};
