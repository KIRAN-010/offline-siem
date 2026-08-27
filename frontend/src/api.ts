export type DashboardSummary = {
  events: number;
  alerts: number;
  new_alerts: number;
  alerts_by_severity: Record<string, number>;
  alerts_by_type: Record<string, number>;
};

export type Alert = {
  alert_uid: string;
  alert_type: string;
  severity: string;
  reason: string;
  description: string;
  timestamp: string;
  confidence: number;
  status: string;
  indicators: Record<string, unknown>;
  metadata: Record<string, unknown>;
};

export type Incident = {
  incident_uid: string;
  title: string;
  severity: string;
  status: string;
  alert_uids: string[];
  indicators: Record<string, unknown>;
  summary: string;
  risk_score: number;
  risk_level: string;
  attack_techniques: Array<{ tactic: string; technique_id: string; technique: string }>;
};

export type HuntEvent = {
  id: number;
  timestamp: string;
  source: string;
  host: string | null;
  username: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  event_id: string | null;
  process: string | null;
  command: string | null;
  severity: string;
  raw_data: Record<string, unknown>;
};

const API_BASE = import.meta.env.VITE_API_BASE ?? "";

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  dashboard: () => requestJson<DashboardSummary>("/api/v1/dashboard/summary"),
  alerts: (limit = 8) => requestJson<{ count: number; alerts: Alert[] }>(`/api/v1/alerts?limit=${limit}`),
  incidents: (limit = 6) => requestJson<{ count: number; incidents: Incident[] }>(`/api/v1/incidents?limit=${limit}`),
  correlate: () => requestJson<{ created: number; incidents: Incident[] }>("/api/v1/correlation/run", { method: "POST" }),
  hunt: (query: string) => requestJson<{ count: number; events: HuntEvent[]; summary: Record<string, number> }>(`/api/v1/hunting/search?q=${encodeURIComponent(query)}&limit=50`),
};
