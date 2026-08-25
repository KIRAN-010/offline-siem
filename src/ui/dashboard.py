"""Streamlit dashboard for the Offline SIEM."""

from __future__ import annotations

from pathlib import Path

import streamlit as st


MAX_UPLOAD_BYTES = 25 * 1024 * 1024


def init_session_state() -> None:
    if "session_id" not in st.session_state:
        st.session_state.session_id = None
    if "current_tab" not in st.session_state:
        st.session_state.current_tab = "Dashboard"


def render_sidebar() -> None:
    with st.sidebar:
        st.title("🛡️ Offline SIEM")
        pages = {"Dashboard": "📊", "Logs": "📋", "Alerts": "⚠️", "Incidents": "🔴", "Timeline": "📈", "Reports": "📄", "Settings": "⚙️"}
        for page, icon in pages.items():
            if st.button(f"{icon} {page}", use_container_width=True):
                st.session_state.current_tab = page
        st.divider()
        if st.session_state.session_id:
            st.caption(f"Session: `{st.session_state.session_id[:8]}...`")
        else:
            st.caption("No active session")


def render_dashboard(summary: dict) -> None:
    st.title("📊 Security Dashboard")
    logs = summary.get("logs", {})
    alerts = summary.get("alerts", {})
    incidents = summary.get("incidents", {})
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Logs", logs.get("total", 0))
    c2.metric("Total Alerts", alerts.get("total", 0))
    c3.metric("Open Incidents", incidents.get("by_status", {}).get("open", 0))
    c4.metric("Critical Alerts", alerts.get("by_severity", {}).get("CRITICAL", 0))

    left, right = st.columns(2)
    with left:
        st.subheader("Alert Severity")
        st.bar_chart(alerts.get("by_severity", {})) if alerts.get("by_severity") else st.info("No alerts")
    with right:
        st.subheader("Log Levels")
        level_data = logs.get("by_level", {})
        values = {k: (v.get("count", 0) if isinstance(v, dict) else v) for k, v in level_data.items()}
        st.bar_chart(values) if values else st.info("No logs")


def render_logs_page(logs: list[dict]) -> None:
    st.title("📋 Log Explorer")
    ip_filter, event_filter = st.columns(2)
    ip = ip_filter.text_input("IP Address")
    event = event_filter.text_input("Event / Message")
    query = st.text_input("Search logs")

    filtered = logs
    if ip:
        filtered = [x for x in filtered if ip.lower() in x.get("ip", "").lower()]
    if event:
        filtered = [x for x in filtered if event.lower() in x.get("event", "").lower()]
    if query:
        filtered = [x for x in filtered if query.lower() in str(x).lower()]

    st.caption(f"Showing {min(len(filtered), 100)} of {len(filtered)} matching logs")
    for log in filtered[:100]:
        timestamp = str(log.get("timestamp", "N/A"))[:19]
        with st.expander(f"{timestamp} | {log.get('ip') or 'N/A'} | {str(log.get('event', 'N/A'))[:100]}"):
            st.write(f"**Timestamp:** {log.get('timestamp', 'N/A')}")
            st.write(f"**Level:** {log.get('level', 'UNKNOWN')}")
            st.write(f"**IP:** {log.get('ip', 'N/A')}")
            st.write(f"**Event:** {log.get('event', 'N/A')}")
            st.code(str(log.get("raw", "N/A"))[:4000])


def render_alerts_page(alerts: list[dict]) -> None:
    st.title("⚠️ Security Alerts")
    c1, c2 = st.columns(2)
    severity = c1.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    alert_type = c2.selectbox("Type", ["All", "BRUTE_FORCE", "FAILED_LOGIN", "SUSPICIOUS_KEYWORD", "SUSPICIOUS_IP", "ANOMALY", "CUSTOM"])
    filtered = [a for a in alerts if (severity == "All" or a.get("severity") == severity) and (alert_type == "All" or a.get("alert_type") == alert_type)]
    st.caption(f"Showing {len(filtered)} alerts")
    for alert in filtered:
        sev = alert.get("severity", "UNKNOWN")
        st.markdown(f"### {sev} — {alert.get('alert_type', 'N/A')}")
        st.write(f"**Reason:** {alert.get('reason', 'N/A')}")
        st.write(f"**Description:** {alert.get('description', 'N/A')}")
        st.write(f"**Confidence:** {float(alert.get('confidence', 0)):.0%}")
        if alert.get("indicators"):
            st.json(alert["indicators"])
        st.divider()


def render_incidents_page(incidents: list[dict]) -> None:
    st.title("🔴 Incident Management")
    st.caption(f"{len(incidents)} incidents")
    for inc in incidents:
        st.markdown(f"### {inc.get('incident_id', 'N/A')} — {inc.get('title', 'N/A')}")
        st.write(f"**Severity:** {inc.get('severity', 'N/A')} | **Status:** {inc.get('status', 'open')}")
        st.write(inc.get("description", ""))
        st.divider()


def render_timeline_page(timeline_data: dict) -> None:
    st.title("📈 Timeline Analysis")
    summary = timeline_data.get("summary", {})
    st.metric("Events", f"{summary.get('total_logs', 0)} logs / {summary.get('total_alerts', 0)} alerts")
    buckets = timeline_data.get("buckets", [])
    if not buckets:
        st.info("No timeline data available.")
        return
    import pandas as pd
    df = pd.DataFrame([{"Time": b.get("time", ""), "Logs": b.get("logs", 0), "Alerts": b.get("alerts", 0)} for b in buckets])
    if not df.empty:
        st.line_chart(df.set_index("Time"))


def render_reports_page(db, session_id: str) -> None:
    st.title("📄 Report Generation")
    fmt = st.selectbox("Format", ["HTML", "TXT"])
    if st.button("Generate Report"):
        try:
            from src.reporting import ReportGenerator
            path = ReportGenerator(db).generate_report(session_id, fmt.lower())
            data = path.read_bytes()
            mime = "text/html" if fmt == "HTML" else "text/plain"
            st.download_button("Download Report", data, path.name, mime)
            st.success(f"Generated {path.name}")
        except Exception as exc:
            st.error(f"Report generation failed: {exc}")


def render_settings_page() -> None:
    st.title("⚙️ Settings")
    st.info("Runtime security controls are configured through config.yaml and the security module.")
    st.caption("Offline SIEM — Security Operations Center")


def render_upload_section() -> None:
    st.subheader("📁 Ingest Logs")
    files = st.file_uploader("Choose log files", type=["log", "txt", "json", "jsonl", "csv", "syslog"], accept_multiple_files=True)
    if files and st.button("Process Files", type="primary"):
        process_uploaded_files(files)


def _decode_upload(uploaded_file) -> str:
    raw = uploaded_file.getvalue()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError(f"{uploaded_file.name} exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit")
    for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError(f"Unable to decode {uploaded_file.name}")


def _format_for_file(name: str) -> str:
    ext = Path(name).suffix.lower()
    return {".json": "json", ".jsonl": "json", ".csv": "csv", ".syslog": "syslog", ".log": "syslog", ".txt": "text"}.get(ext, "text")


def process_uploaded_files(uploaded_files) -> None:
    """Parse uploaded logs with the canonical parser/detection pipeline and persist results."""
    try:
        from src.detection import DetectionEngine
        from src.parsers import registry
        from src.storage import AlertStorage, LogStorage, SessionManager, get_database

        db = get_database()
        session_mgr = SessionManager(db)
        if not st.session_state.session_id:
            st.session_state.session_id = session_mgr.create_session(name="Analysis Session")
        session_id = st.session_state.session_id
        log_storage = LogStorage(db)
        alert_storage = AlertStorage(db)
        engine = DetectionEngine()

        total_logs = total_alerts = 0
        for uploaded_file in uploaded_files:
            with st.status(f"Processing {uploaded_file.name}...", expanded=False):
                content = _decode_upload(uploaded_file)
                fmt = _format_for_file(uploaded_file.name)
                logs = list(registry.parse_content(content, fmt))
                if not logs:
                    st.warning(f"No parseable log entries found in {uploaded_file.name}")
                    continue
                log_storage.save_logs(session_id, logs)
                alerts = engine.detect_batch(logs)
                if alerts:
                    alert_storage.save_alerts(session_id, alerts)
                total_logs += len(logs)
                total_alerts += len(alerts)
                st.write(f"Parsed {len(logs)} logs and generated {len(alerts)} alerts")

        st.success(f"Processing complete: {total_logs} logs, {total_alerts} alerts")
        st.rerun()
    except Exception as exc:
        st.error(f"Processing failed: {exc}")


def render_main() -> None:
    init_session_state()
    render_sidebar()
    from src.analytics import TimelineBuilder
    from src.storage import AlertStorage, IncidentManager, LogStorage, get_database

    db = get_database()
    from src.storage import SessionManager
    if not st.session_state.session_id:
        st.session_state.session_id = SessionManager(db).create_session(name="Analysis Session")
    session_id = st.session_state.session_id
    summary = TimelineBuilder(db).get_dashboard_summary(session_id)
    tab = st.session_state.current_tab

    if tab == "Dashboard":
        render_dashboard(summary)
        st.divider()
        render_upload_section()
    elif tab == "Logs":
        logs = LogStorage(db).get_logs(session_id, limit=1000)
        render_logs_page([{"timestamp": x.timestamp.isoformat(), "level": x.level.value, "ip": x.metadata.get("ip", ""), "event": x.message, "raw": x.raw_line} for x in logs])
    elif tab == "Alerts":
        render_alerts_page([x.to_dict() for x in AlertStorage(db).get_alerts(session_id, limit=1000)])
    elif tab == "Incidents":
        render_incidents_page(IncidentManager(db).list_incidents(session_id))
    elif tab == "Timeline":
        render_timeline_page(TimelineBuilder(db).build_combined_timeline(session_id))
    elif tab == "Reports":
        render_reports_page(db, session_id)
    elif tab == "Settings":
        render_settings_page()
