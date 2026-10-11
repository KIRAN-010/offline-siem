import { useEffect, useState, type ReactNode } from 'react';
import { api, type Alert, type DashboardSummary, type HuntEvent, type Incident, type CaseDetail, type CaseNote, type SavedSearch } from './api';
const emptySummary: DashboardSummary = {events: 0, alerts: 0, new_alerts: 0, alerts_by_severity: {}, alerts_by_type: {}};
const severityClass = (value: string) => `severity ${value.toLowerCase()}`;
function App() {
  const [summary, setSummary] = useState(emptySummary);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<HuntEvent[]>([]);
  const [searches, setSearches] = useState<SavedSearch[]>([]);
  const [searchName, setSearchName] = useState('');
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [notes, setNotes] = useState<CaseNote[]>([]);
  const [evidence, setEvidence] = useState<HuntEvent[]>([]);
  const [note, setNote] = useState('');
  const [eventUid, setEventUid] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  async function refresh() {
    const [dash, a, i, s] = await Promise.all([api.dashboard(), api.alerts(), api.incidents(), api.saved()]);
    setSummary(dash); setAlerts(a.alerts); setIncidents(i.incidents); setSearches(s.searches);
  }
  async function act(task: () => Promise<void>) {
    setBusy(true); setError(''); setMessage('');
    try { await task(); } catch (err) { setError(err instanceof Error ? err.message : 'Operation failed'); }
    finally { setBusy(false); }
  }
  async function openCase(uid: string) {
    const [d, n, e] = await Promise.all([api.timeline(uid), api.notes(uid), api.evidence(uid)]);
    setDetail(d); setNotes(n.notes); setEvidence(e.events);
  }
  useEffect(() => { void act(refresh); }, []);
  const techniques = Array.from(new Map(incidents.flatMap(i => i.attack_techniques).map(t => [t.technique_id, t])).values());
  return <div className="shell">
    <aside className="sidebar"><div className="brand"><span className="brand-mark">◈</span><div><strong>SentinelX</strong><small>SOC Console</small></div></div><nav>{['overview', 'ingestion', 'alerts', 'incidents', 'hunting', 'attack'].map(id => <a href={`#${id}`} key={id}>{id[0].toUpperCase() + id.slice(1)}</a>)}</nav><div className="sidebar-foot">Offline security operations</div></aside>
    <main className="content"><header className="topbar"><div><p className="eyebrow">Security Operations</p><h1>Analyst Overview</h1></div><div className="actions"><button disabled={busy} onClick={() => void act(refresh)}>Refresh</button><button disabled={busy} onClick={() => void act(async () => {const r = await api.correlate(); await refresh(); setMessage(`${r.created} correlated case(s) returned.`);})}>Run correlation</button></div></header>
    {error && <div className="error" role="alert">{error}</div>}{message && <p role="status">{message}</p>}
    <section id="overview" className="metrics">{[['Events', summary.events], ['Alerts', summary.alerts], ['New alerts', summary.new_alerts], ['Cases shown', incidents.length]].map(([label, value]) => <div className="metric" key={label}><span>{label}</span><strong>{value}</strong></div>)}</section>
    <section id="ingestion"><Panel title="Ingest logs" subtitle="Upload JSON, JSONL, CSV, TXT or LOG files; up to 2 MiB and 10,000 events."><form onSubmit={e => {e.preventDefault(); void act(async () => {if (!file) throw Error('Choose a log file'); if (file.size > 2 * 1024 * 1024) throw Error('File exceeds 2 MiB'); const r = await api.importLogs(file.name, await file.text()); await refresh(); setMessage(`${r.accepted} new events stored; ${r.alerts_generated} detections generated.`);});}}><label htmlFor="logs">Log file</label><input id="logs" type="file" accept=".json,.jsonl,.csv,.txt,.log" required onChange={e => setFile(e.target.files?.[0] ?? null)} /><button disabled={busy}>Ingest logs</button></form></Panel></section>
    <section id="alerts"><Panel title="Alert triage" subtitle="Review detections and update their status."><div className="alert-list">{alerts.map(a => <article className="alert-row" key={a.alert_uid}><div><span className={severityClass(a.severity)}>{a.severity}</span><strong>{a.reason}</strong><small>{new Date(a.timestamp).toLocaleString()} · confidence {(a.confidence * 100).toFixed(0)}%</small><p><code>{a.alert_uid}</code></p></div><select aria-label={`Status for ${a.alert_uid}`} value={a.status} disabled={busy} onChange={e => {const status=e.target.value; void act(async () => {await api.alertStatus(a.alert_uid, status); await refresh();});}}>{['new', 'acknowledged', 'resolved', 'false_positive'].map(s => <option key={s}>{s}</option>)}</select></article>)}{!alerts.length && <Empty text="Ingest logs to generate alerts" />}</div></Panel></section>
    <section id="incidents"><Panel title="Incidents" subtitle="Correlate alerts, investigate evidence and export reports."><div className="incident-grid">{incidents.map(i => <article className="incident-card" key={i.incident_uid}><div className="incident-top"><span className={severityClass(i.risk_level)}>{i.risk_level}</span><span>Risk {i.risk_score}/100</span></div><h3>{i.title}</h3><p>{i.summary}</p><small>{i.status}</small><p><button disabled={busy} onClick={() => void act(() => openCase(i.incident_uid))}>Investigate</button></p></article>)}{!incidents.length && <Empty text="Run correlation after detections are generated" />}</div></Panel></section>
    {detail && <Panel title={detail.incident.title} subtitle={detail.incident.incident_uid}><div className="actions"><select aria-label="Incident status" value={detail.incident.status} disabled={busy} onChange={e => {const status=e.target.value; void act(async () => {await api.incidentStatus(detail.incident.incident_uid, status); await openCase(detail.incident.incident_uid); await refresh();});}}>{['open', 'investigating', 'contained', 'resolved', 'closed'].map(s => <option key={s}>{s}</option>)}</select><a href={api.reportUrl(detail.incident.incident_uid)}>Download report</a><button onClick={() => setDetail(null)}>Close investigation</button></div><h3>Analyst notes</h3>{notes.map(n => <p key={n.id}>{n.text}</p>)}<form className="hunt-form" onSubmit={e => {e.preventDefault(); void act(async () => {await api.addNote(detail.incident.incident_uid, note); setNote(''); await openCase(detail.incident.incident_uid);});}}><input aria-label="Analyst note" value={note} onChange={e => setNote(e.target.value)} required maxLength={4000}/><button disabled={busy}>Add note</button></form><h3>Evidence ({evidence.length})</h3>{evidence.map(event => <p key={event.event_uid}><code>{event.event_uid}</code> · {event.source}</p>)}<form className="hunt-form" onSubmit={e => {e.preventDefault(); void act(async () => {await api.attachEvidence(detail.incident.incident_uid, eventUid); setEventUid(''); await openCase(detail.incident.incident_uid);});}}><input aria-label="Evidence event UID" placeholder="Event UID from hunt results" value={eventUid} onChange={e => setEventUid(e.target.value)} required maxLength={64}/><button disabled={busy}>Attach evidence</button></form><h3>Investigation timeline</h3><div className="timeline">{detail.timeline.map((item, index) => <p key={`${item.timestamp}-${index}`}><small>{new Date(item.timestamp).toLocaleString()} · {item.kind}</small><br/>{String(item.data.reason ?? (item.data.raw_data as Record<string, unknown> | undefined)?.message ?? item.data.source ?? 'Event')}</p>)}{!detail.timeline.length && <Empty text="No linked activity" />}</div></Panel>}
    <section id="hunting"><Panel title="Threat hunting" subtitle="Search messages, commands, IP addresses, users and hosts."><form className="hunt-form" onSubmit={e => {e.preventDefault(); void act(async () => {setResults((await api.hunt(query)).events);});}}><input aria-label="Hunt query" value={query} onChange={e => setQuery(e.target.value)} placeholder="failed password, powershell, 192.0.2.10" maxLength={300} required/><button disabled={busy}>Search</button></form><form className="hunt-form" onSubmit={e => {e.preventDefault(); void act(async () => {await api.saveSearch(searchName, query); await refresh(); setMessage('Search saved');});}}><input aria-label="Saved search name" value={searchName} onChange={e => setSearchName(e.target.value)} placeholder="Name this search" maxLength={100} required/><button disabled={busy || !query.trim()}>Save search</button></form><div className="actions">{searches.map(s => <button key={s.name} disabled={busy} onClick={() => void act(async () => {setQuery(s.query); setResults((await api.hunt(s.query)).events);})}>{s.name}</button>)}</div>{results.map(event => <article className="hunt-row" key={event.event_uid}><span className={severityClass(event.severity)}>{event.severity}</span><div><strong>{event.source}</strong><p>{String(event.raw_data.message ?? event.command ?? event.process ?? 'Event')}</p><small>{event.source_ip ?? 'no source IP'} · {event.username ?? 'no user'}</small><p><code>{event.event_uid}</code></p></div></article>)}{!results.length && <Empty text="No search results" />}</Panel></section>
    <section id="attack"><Panel title="MITRE ATT&CK context" subtitle="Deduplicated technique mappings from your cases."><div className="attack-strip">{techniques.map(t => <div className="attack-item" key={t.technique_id}><strong>{t.technique_id}</strong><span>{t.technique}</span><small>{t.tactic}</small></div>)}{!techniques.length && <Empty text="No technique mappings yet" />}</div></Panel></section>
    </main></div>;
}
function Panel({title, subtitle, children}: {title: string; subtitle: string; children: ReactNode}) {return <section className="panel"><div className="panel-head"><div><h2>{title}</h2><p>{subtitle}</p></div></div>{children}</section>;}
function Empty({text}: {text: string}) {return <div className="empty">{text}</div>;}
export default App;
