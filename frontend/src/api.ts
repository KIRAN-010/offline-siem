export type DashboardSummary = { events: number; alerts: number; new_alerts: number; alerts_by_severity: Record<string, number>; alerts_by_type: Record<string, number> };
export type Alert = { alert_uid: string; severity: string; reason: string; timestamp: string; confidence: number; status: string };
export type Incident = { incident_uid: string; title: string; severity: string; status: string; summary: string; risk_score: number; risk_level: string; attack_techniques: Array<{ tactic: string; technique_id: string; technique: string }> };
export type HuntEvent = { id: number; event_uid: string; timestamp: string; source: string; source_ip: string | null; username: string | null; severity: string; command: string | null; process: string | null; raw_data: Record<string, unknown> };
export type CaseDetail = { incident: Incident; timeline: Array<{kind: string; timestamp: string; data: Record<string, unknown>}> };
export type CaseNote = { id: number; text: string; created_at?: string };
export type SavedSearch = { name: string; query: string };
const API_BASE = (import.meta.env.VITE_API_BASE ?? '').replace(/\/$/, '');
async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail ?? `${response.status} ${response.statusText}`));
  if (data.detection_errors?.length) throw new Error(`Events stored, but detection failed: ${data.detection_errors.join('; ')}`);
  return data as T;
}
const json = (value: unknown, method = 'POST'): RequestInit => ({method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(value)});
export const api = {
  dashboard: () => requestJson<DashboardSummary>('/api/v1/dashboard/summary'),
  alerts: () => requestJson<{alerts: Alert[]}>('/api/v1/alerts?limit=100'),
  incidents: () => requestJson<{incidents: Incident[]}>('/api/v1/incidents?limit=100'),
  correlate: () => requestJson<{created: number}>('/api/v1/correlation/run', {method: 'POST'}),
  hunt: (query: string) => requestJson<{events: HuntEvent[]}>(`/api/v1/hunting/search?q=${encodeURIComponent(query)}&limit=100`),
  importLogs: (filename: string, content: string) => requestJson<{accepted: number; alerts_generated: number}>('/api/v1/imports', json({filename, content})),
  alertStatus: (uid: string, status: string) => requestJson(`/api/v1/alerts/${encodeURIComponent(uid)}/status`, json({status}, 'PATCH')),
  incidentStatus: (uid: string, status: string) => requestJson(`/api/v1/incidents/${encodeURIComponent(uid)}/status`, json({status}, 'PATCH')),
  timeline: (uid: string) => requestJson<CaseDetail>(`/api/v1/investigation/${encodeURIComponent(uid)}/timeline`),
  notes: (uid: string) => requestJson<{notes: CaseNote[]}>(`/api/v1/incidents/${encodeURIComponent(uid)}/notes`),
  addNote: (uid: string, text: string) => requestJson(`/api/v1/incidents/${encodeURIComponent(uid)}/notes`, json({text})),
  evidence: (uid: string) => requestJson<{events: HuntEvent[]}>(`/api/v1/incidents/${encodeURIComponent(uid)}/evidence`),
  attachEvidence: (uid: string, event_uid: string) => requestJson(`/api/v1/incidents/${encodeURIComponent(uid)}/evidence`, json({event_uid})),
  saved: () => requestJson<{searches: SavedSearch[]}>('/api/v1/hunting/saved'),
  saveSearch: (name: string, query: string) => requestJson('/api/v1/hunting/saved', json({name, query})),
  reportUrl: (uid: string) => `${API_BASE}/api/v1/incidents/${encodeURIComponent(uid)}/report?format=html`,
};
