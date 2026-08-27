import { useEffect, useState, type ReactNode } from "react";
import { api, type Alert, type DashboardSummary, type Incident } from "./api";

const emptySummary: DashboardSummary = {
  events: 0,
  alerts: 0,
  new_alerts: 0,
  alerts_by_severity: {},
  alerts_by_type: {},
};

function severityClass(value: string): string {
  return `severity ${value.toLowerCase()}`;
}

function App() {
  const [summary, setSummary] = useState(emptySummary);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const [dashboard, alertData, incidentData] = await Promise.all([
        api.dashboard(),
        api.alerts(),
        api.incidents(),
      ]);
      setSummary(dashboard);
      setAlerts(alertData.alerts);
      setIncidents(incidentData.incidents);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to reach SentinelX API");
    } finally {
      setLoading(false);
    }
  }

  async function runCorrelation() {
    setWorking(true);
    setError(null);
    try {
      await api.correlate();
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Correlation failed");
    } finally {
      setWorking(false);
    }
  }

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 30000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">◈</span><div><strong>SentinelX</strong><small>SOC Console</small></div></div>
        <nav>
          <a className="active" href="#overview">Overview</a>
          <a href="#alerts">Alerts</a>
          <a href="#incidents">Incidents</a>
          <a href="#attack">ATT&amp;CK</a>
        </nav>
        <div className="sidebar-foot"><span className="dot" /> Offline-first core</div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div><p className="eyebrow">Security Operations</p><h1>Analyst Overview</h1></div>
          <div className="actions"><button onClick={() => void refresh()} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button><button className="primary" onClick={() => void runCorrelation()} disabled={working}>{working ? "Correlating…" : "Run correlation"}</button></div>
        </header>

        {error && <div className="error">API error: {error}. Start the FastAPI service on <code>127.0.0.1:8000</code>.</div>}

        <section id="overview" className="metrics">
          <Metric label="Events" value={summary.events} detail="Normalized events" />
          <Metric label="Alerts" value={summary.alerts} detail="All detected alerts" />
          <Metric label="New" value={summary.new_alerts} detail="Awaiting triage" />
          <Metric label="Incidents" value={incidents.length} detail="Current returned cases" />
        </section>

        <section className="grid two">
          <Panel title="Alert distribution" subtitle="Severity across stored detections">
            <div className="bar-list">
              {Object.entries(summary.alerts_by_severity).map(([name, count]) => <div className="bar-row" key={name}><span>{name}</span><div><i style={{ width: `${Math.min(100, count * 10)}%` }} /></div><b>{count}</b></div>)}
              {Object.keys(summary.alerts_by_severity).length === 0 && <Empty text="No alerts yet" />}
            </div>
          </Panel>
          <Panel title="Recent alerts" subtitle="Highest-signal items from the API">
            <div className="alert-list" id="alerts">
              {alerts.map((alert) => <article className="alert-row" key={alert.alert_uid}><div><span className={severityClass(alert.severity)}>{alert.severity}</span><strong>{alert.reason}</strong><small>{new Date(alert.timestamp).toLocaleString()} · confidence {(alert.confidence * 100).toFixed(0)}%</small></div><code>{alert.alert_uid}</code></article>)}
              {alerts.length === 0 && <Empty text="No alerts available" />}
            </div>
          </Panel>
        </section>

        <section id="incidents" className="panel incident-panel">
          <div className="panel-head"><div><h2>Incidents</h2><p>Correlated investigations with explainable risk</p></div><span className="pill">{incidents.length} shown</span></div>
          <div className="incident-grid">
            {incidents.map((incident) => <article className="incident-card" key={incident.incident_uid}><div className="incident-top"><span className={severityClass(incident.risk_level)}>{incident.risk_level}</span><span className="risk">Risk {incident.risk_score}/100</span></div><h3>{incident.title}</h3><p>{incident.summary}</p><div className="tags">{incident.attack_techniques.slice(0, 3).map((technique) => <span key={technique.technique_id}>{technique.technique_id}</span>)}</div></article>)}
            {incidents.length === 0 && <Empty text="Run correlation after alerts are generated" />}
          </div>
        </section>

        <section id="attack" className="panel">
          <div className="panel-head"><div><h2>MITRE ATT&amp;CK context</h2><p>Technique mappings exposed by correlated cases</p></div></div>
          <div className="attack-strip">{incidents.flatMap((incident) => incident.attack_techniques).slice(0, 8).map((technique) => <div className="attack-item" key={`${technique.technique_id}-${technique.tactic}`}><strong>{technique.technique_id}</strong><span>{technique.technique}</span><small>{technique.tactic}</small></div>)}{incidents.length === 0 && <Empty text="No ATT&amp;CK mappings yet" />}</div>
        </section>
      </main>
    </div>
  );
}

function Metric({ label, value, detail }: { label: string; value: number; detail: string }) {
  return <div className="metric"><span>{label}</span><strong>{value.toLocaleString()}</strong><small>{detail}</small></div>;
}

function Panel({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) {
  return <section className="panel"><div className="panel-head"><div><h2>{title}</h2><p>{subtitle}</p></div></div>{children}</section>;
}

function Empty({ text }: { text: string }) { return <div className="empty">{text}</div>; }

export default App;
