// Single fetch wrapper for the backend API. The bearer token is pasted once
// into the header field of the UI and kept in localStorage, never baked into
// the build (a VITE_ env var would end up readable in the bundle).

import type {
  Alert,
  ExplainResponse,
  Host,
  HuntResponse,
  IncidentDetail,
  IncidentSummary,
  SummarizeResponse,
} from "./types";

const API_BASE = "http://localhost:8000";
const TOKEN_KEY = "edr_api_token";

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? "";
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export class ApiError extends Error {
  constructor(
    public status: number,
    detail: string,
  ) {
    super(detail);
  }
}

export function buildQuery(params: Record<string, string | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value) search.set(key, value);
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${getToken()}`,
  };
  if (init.body) headers["Content-Type"] = "application/json";

  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      // non-JSON error body, keep the generic detail
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  hosts: () => request<Host[]>("/hosts"),

  alerts: (params: { status?: string; severity?: string } = {}) =>
    request<Alert[]>(`/alerts${buildQuery(params)}`),

  updateAlertStatus: (id: number, status: string) =>
    request<Alert>(`/alerts/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  incidents: (params: { status?: string } = {}) =>
    request<IncidentSummary[]>(`/incidents${buildQuery(params)}`),

  incident: (id: number) => request<IncidentDetail>(`/incidents/${id}`),

  updateIncidentStatus: (id: number, status: string) =>
    request<IncidentSummary>(`/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  summarize: (incidentId: number) =>
    request<SummarizeResponse>(`/ai/summarize/${incidentId}`, { method: "POST" }),

  explain: (query: string) =>
    request<ExplainResponse>("/ai/explain", {
      method: "POST",
      body: JSON.stringify({ query }),
    }),

  hunt: (query: string, size = 50) =>
    request<HuntResponse>("/hunt", {
      method: "POST",
      body: JSON.stringify({ query, size }),
    }),
};
