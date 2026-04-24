"""Streamlit dashboard pages and components."""

import streamlit as st
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="Offline SIEM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def init_session_state():
    """Initialize Streamlit session state."""
    if "session_id" not in st.session_state:
        st.session_state.session_id = None
    if "current_tab" not in st.session_state:
        st.session_state.current_tab = "Dashboard"
    if "filters" not in st.session_state:
        st.session_state.filters = {}


def render_sidebar():
    """Render the sidebar navigation."""
    with st.sidebar:
        st.title("🛡️ Offline SIEM")
        st.markdown("---")

        # Navigation
        pages = {
            "Dashboard": "📊",
            "Logs": "📋",
            "Alerts": "⚠️",
            "Incidents": "🔴",
            "Timeline": "📈",
            "Reports": "📄",
            "Settings": "⚙️",
        }

        for page, icon in pages.items():
            if st.button(f"{icon} {page}", use_container_width=True):
                st.session_state.current_tab = page

        st.markdown("---")

        # Session info
        if st.session_state.session_id:
            st.caption(f"Session: `{st.session_state.session_id[:8]}...`")
        else:
            st.caption("No active session")


def render_dashboard(summary: dict):
    """Render the dashboard page."""
    st.title("📊 Security Dashboard")

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Logs", summary.get("logs", {}).get("total", 0))
    with col2:
        st.metric("Total Alerts", summary.get("alerts", {}).get("total", 0))
    with col3:
        st.metric("Open Incidents", summary.get("incidents", {}).get("by_status", {}).get("open", 0))
    with col4:
        critical = summary.get("alerts", {}).get("by_severity", {}).get("CRITICAL", 0)
        st.metric("Critical Alerts", critical, delta_color="inverse")

    st.markdown("---")

    # Alert severity breakdown
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Alert Severity")
        severity_data = summary.get("alerts", {}).get("by_severity", {})
        if severity_data:
            for sev, count in severity_data.items():
                st.write(f"**{sev}**: {count}")
        else:
            st.info("No alerts")

    with col2:
        st.subheader("Log Levels")
        level_data = summary.get("logs", {}).get("by_level", {})
        if level_data:
            for level, stats in level_data.items():
                if isinstance(stats, dict):
                    st.write(f"**{level}**: {stats.get('count', 0)}")
                else:
                    st.write(f"**{level}**: {stats}")
        else:
            st.info("No logs")


def render_logs_page(logs: list, filters: dict):
    """Render the logs page."""
    st.title("📋 Log Explorer")

    # Filters
    with st.expander("Filters", expanded=True):
        col1, col2 = st.columns(2)
        with col1:
            ip_filter = st.text_input("IP Address")
        with col2:
            event_filter = st.text_input("Event/Message")

    # Search
    search_query = st.text_input("Search logs", placeholder="Enter search term...")

    # Display logs
    st.subheader(f"Showing {len(logs)} logs")

    if logs:
        # Apply filters
        filtered_logs = logs
        if ip_filter:
            filtered_logs = [l for l in filtered_logs if ip_filter.lower() in l.get('ip', '').lower()]
        if event_filter:
            filtered_logs = [l for l in filtered_logs if event_filter.lower() in l.get('event', '').lower()]
        if search_query:
            filtered_logs = [l for l in filtered_logs if search_query.lower() in str(l).lower()]

        st.subheader(f"Showing {len(filtered_logs)} filtered logs")

        for log in filtered_logs[:50]:
            timestamp = log.get('timestamp', '')[:19] if log.get('timestamp') else 'N/A'
            ip = log.get('ip', 'N/A')
            event = log.get('event', 'N/A')[:100]
            with st.expander(f"{timestamp} | {ip} | {event}"):
                st.write(f"**Timestamp:** {log.get('timestamp', 'N/A')}")
                st.write(f"**IP:** {log.get('ip', 'N/A')}")
                st.write(f"**Event:** {log.get('event', 'N/A')}")
                st.write(f"**Raw:** {log.get('raw', 'N/A')[:200]}{'...' if len(log.get('raw', '')) > 200 else ''}")
    else:
        st.info("No logs found. Upload log files to get started.")


def render_alerts_page(alerts: list):
    """Render the alerts page."""
    st.title("⚠️ Security Alerts")

    # Filters
    col1, col2 = st.columns(2)
    with col1:
        severity_filter = st.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with col2:
        type_filter = st.selectbox("Type", ["All", "BRUTE_FORCE", "FAILED_LOGIN", "SUSPICIOUS_KEYWORD", "SUSPICIOUS_IP", "ANOMALY"])

    # Display alerts
    st.subheader(f"Showing {len(alerts)} alerts")

    if alerts:
        for alert in alerts:
            severity = alert.get("severity", "UNKNOWN")
            color = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
            }.get(severity, "⚪")

            with st.container():
                st.markdown(f"### {color} {severity} - {alert.get('alert_type', 'N/A')}")
                st.write(f"**Reason:** {alert.get('reason', 'N/A')}")
                st.write(f"**Time:** {alert.get('timestamp', 'N/A')[:19]}")
                st.write(f"**Description:** {alert.get('description', 'N/A')}")
                st.markdown("---")
    else:
        st.info("No alerts found.")


def render_incidents_page(incidents: list):
    """Render the incidents page."""
    st.title("🔴 Incident Management")

    # Create incident button
    if st.button("Create New Incident"):
        st.session_state.current_tab = "Incidents"

    # Display incidents
    st.subheader(f"Showing {len(incidents)} incidents")

    if incidents:
        for inc in incidents:
            status_color = {
                "open": "🔴",
                "investigating": "🟡",
                "resolved": "🟢",
                "closed": "⚪",
            }.get(inc.get("status", "open"), "⚪")

            with st.container():
                st.markdown(f"### {status_color} {inc.get('incident_id', 'N/A')} - {inc.get('title', 'N/A')}")
                st.write(f"**Severity:** {inc.get('severity', 'N/A')}")
                st.write(f"**Status:** {inc.get('status', 'open')}")
                st.write(f"**Created:** {inc.get('created', 'N/A')[:19]}")
                if inc.get("resolved"):
                    st.write(f"**Resolved:** {inc.get('resolved')[:19]}")
                st.markdown("---")
    else:
        st.info("No incidents found.")


def render_timeline_page(timeline_data: dict):
    """Render the timeline page."""
    st.title("📈 Timeline Analysis")

    # Time range
    time_range = timeline_data.get("summary", {})
    st.metric("Time Range", f"{time_range.get('total_logs', 0)} logs, {time_range.get('total_alerts', 0)} alerts")

    # Timeline chart
    buckets = timeline_data.get("buckets", [])
    if buckets:
        # Prepare data for chart
        import pandas as pd

        chart_data = []
        for bucket in buckets:
            chart_data.append({
                "Time": bucket.get("time", ""),
                "Logs": bucket.get("logs", 0),
                "Alerts": bucket.get("alerts", 0),
            })

        df = pd.DataFrame(chart_data)

        # Line chart
        st.subheader("Activity Over Time")
        st.line_chart(df.set_index("Time"))

        # Bar chart
        st.subheader("Logs vs Alerts")
        st.bar_chart(df.set_index("Time"))
    else:
        st.info("No timeline data available.")


def render_reports_page():
    """Render the reports page."""
    st.title("📄 Report Generation")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Generate Report")
        report_format = st.selectbox("Format", ["HTML", "TXT"])
        if st.button("Generate Report"):
            st.success(f"Report generated: {report_format}")

    with col2:
        st.subheader("Recent Reports")
        st.info("No reports generated yet.")


def render_settings_page():
    """Render the settings page."""
    st.title("⚙️ Settings")

    # Security settings
    st.subheader("Security")

    col1, col2 = st.columns(2)
    with col1:
        st.checkbox("Password Protection", value=False, disabled=True)
    with col2:
        st.checkbox("Report Signing", value=True, disabled=True)

    # Display settings
    st.subheader("Display")
    st.slider("Items per page", 10, 100, 50)

    st.markdown("---")
    st.caption("Offline SIEM - Security Operations Center")


def render_upload_section():
    """Render the file upload section."""
    st.subheader("📁 Upload Log Files")

    uploaded_files = st.file_uploader(
        "Choose log files",
        type=["log", "txt", "json", "jsonl", "csv", "syslog"],
        accept_multiple_files=True,
    )

    if uploaded_files:
        st.write(f"**{len(uploaded_files)} file(s) uploaded**")
        for f in uploaded_files:
            st.write(f"- {f.name} ({f.size} bytes)")

        if st.button("Process Files"):
            process_uploaded_files(uploaded_files)

    return uploaded_files


def process_uploaded_files(uploaded_files):
    """Process uploaded files: parse, detect, save."""
    try:
        # Initialize components
        from src.parsers.robust_parser import parse_logs
        from src.detection.robust_detection import detect_alerts
        from src.storage import LogStorage, AlertStorage, get_database

        db = get_database()
        log_storage = LogStorage(db)
        alert_storage = AlertStorage(db)

        # Get current session
        from src.storage import SessionManager
        session_mgr = SessionManager(db)
        if not st.session_state.session_id:
            st.session_state.session_id = session_mgr.create_session(name="Analysis Session")
        session_id = st.session_state.session_id

        total_logs = 0
        total_alerts = 0
        all_raw_lines = []
        all_parsed_logs = []

        # Process each file
        for uploaded_file in uploaded_files:
            st.write(f"Processing {uploaded_file.name}...")

            # Read file content safely
            try:
                content = uploaded_file.read().decode("utf-8")
            except UnicodeDecodeError:
                try:
                    content = uploaded_file.read().decode("utf-8-sig")
                except UnicodeDecodeError:
                    content = uploaded_file.read().decode("latin-1", errors="replace")

            # Split into lines and show debug info
            lines = content.split("\n")
            st.write(f"  - Read {len(lines)} lines")
            if lines:
                st.write(f"  - First 5 lines preview:")
                for i, line in enumerate(lines[:5]):
                    st.write(f"    {i+1}: {line[:100]}{'...' if len(line) > 100 else ''}")

            all_raw_lines.extend(lines[:10])  # Keep first 10 for debug

            # Parse logs using robust parser
            try:
                parsed_logs = parse_logs(content)
                st.write(f"  - Parsed {len(parsed_logs)} log entries")
                all_parsed_logs.extend(parsed_logs[:10])  # Keep first 10 for debug

                if parsed_logs:
                    st.write("  - Parsed logs preview:")
                    for i, log in enumerate(parsed_logs[:3]):
                        st.write(f"    {i+1}: timestamp='{log.get('timestamp', '')}', ip='{log.get('ip', '')}', event='{log.get('event', '')[:50]}...'")

                # Convert to NormalizedLog for storage
                normalized_logs = []
                for log_dict in parsed_logs:
                    from src.schema import NormalizedLog, LogLevel
                    from datetime import datetime

                    # Parse timestamp
                    ts_str = log_dict.get("timestamp", "")
                    try:
                        timestamp = datetime.fromisoformat(ts_str) if ts_str else datetime.now()
                    except ValueError:
                        timestamp = datetime.now()

                    normalized_log = NormalizedLog(
                        timestamp=timestamp,
                        level=LogLevel.UNKNOWN,
                        message=log_dict.get("event", ""),
                        raw_line=log_dict.get("raw", ""),
                        format="robust",
                        metadata={"ip": log_dict.get("ip", "")}
                    )
                    normalized_logs.append(normalized_log)

                # Save logs
                if normalized_logs:
                    log_storage.save_logs(session_id, normalized_logs)
                    total_logs += len(normalized_logs)

                # Run detection
                alerts = detect_alerts(parsed_logs)
                st.write(f"  - Generated {len(alerts)} alerts")

                # Convert alerts to Alert objects for storage
                alert_objects = []
                for alert in alerts:
                    from src.detection.alert import Alert as AlertObj, AlertSeverity, AlertType
                    severity_map = {"CRITICAL": AlertSeverity.CRITICAL, "HIGH": AlertSeverity.HIGH,
                                  "MEDIUM": AlertSeverity.MEDIUM, "LOW": AlertSeverity.LOW}
                    type_map = {"BRUTE_FORCE": AlertType.BRUTE_FORCE}

                    alert_obj = AlertObj(
                        id=f"{alert.alert_type}_{alert.ip}_{alert.count}",
                        alert_type=type_map.get(alert.alert_type, AlertType.BRUTE_FORCE),
                        severity=severity_map.get(alert.severity, AlertSeverity.MEDIUM),
                        reason=alert.reason,
                        description=alert.description,
                        source_logs=[],  # Could add raw lines here
                        indicators={"ip": alert.ip, "count": alert.count},
                        matched_pattern=f"{alert.count} failures",
                        confidence=0.8,
                        metadata={}
                    )
                    alert_objects.append(alert_obj)

                # Save alerts
                if alert_objects:
                    alert_storage.save_alerts(session_id, alert_objects)
                    total_alerts += len(alert_objects)

            except Exception as parse_error:
                st.error(f"Error parsing {uploaded_file.name}: {str(parse_error)}")
                continue

        # Show summary
        st.success(f"Processing complete! Total: {total_logs} logs, {total_alerts} alerts")

        # Show debug info
        with st.expander("Debug Information", expanded=True):
            st.write(f"**Total lines read:** {len(all_raw_lines)}")
            st.write("**Raw lines preview:**")
            for i, line in enumerate(all_raw_lines[:10]):
                st.write(f"{i+1}: {line}")

            st.write(f"**Parsed logs count:** {len(all_parsed_logs)}")
            st.write("**Parsed logs preview:**")
            for i, log in enumerate(all_parsed_logs[:5]):
                st.write(f"{i+1}: {log}")

            st.write(f"**Alerts count:** {total_alerts}")

            if total_alerts == 0:
                st.warning("No alerts detected. This might indicate:")
                st.write("- Logs don't contain failure/error patterns")
                st.write("- IP addresses not extracted properly")
                st.write("- Detection thresholds not met")

        # Refresh the page to show updated data
        st.rerun()

    except Exception as e:
        st.error(f"Error processing files: {str(e)}")
        st.write("Full error details:")
        st.code(str(e))


def render_main():
    """Render the main application."""
    init_session_state()
    render_sidebar()

    # Get data based on current tab
    from src.storage import get_database
    from src.analytics import TimelineBuilder

    db = get_database()
    timeline = TimelineBuilder(db) if db else None

    # Get session ID or create new
    if not st.session_state.session_id:
        from src.storage import SessionManager
        mgr = SessionManager(db)
        st.session_state.session_id = mgr.create_session(name="Analysis Session")

    session_id = st.session_state.session_id

    # Get summary data
    summary = {}
    if timeline and session_id:
        summary = timeline.get_dashboard_summary(session_id)

    # Render current page
    current_tab = st.session_state.current_tab

    if current_tab == "Dashboard":
        render_dashboard(summary)
    elif current_tab == "Logs":
        from src.storage import LogStorage
        logs = LogStorage(db).get_logs(session_id, limit=100) if db else []
        # Convert NormalizedLog to dict format expected by UI
        log_dicts = []
        for log in logs:
            log_dict = {
                "timestamp": log.timestamp.isoformat(),
                "ip": log.metadata.get("ip", ""),
                "event": log.message,
                "raw": log.raw_line
            }
            log_dicts.append(log_dict)
        render_logs_page(log_dicts, {})
    elif current_tab == "Alerts":
        from src.storage import AlertStorage
        alerts = AlertStorage(db).get_alerts(session_id) if db else []
        render_alerts_page([a.to_dict() for a in alerts])
    elif current_tab == "Incidents":
        from src.storage import IncidentManager
        incidents = IncidentManager(db).list_incidents(session_id) if db else []
        render_incidents_page(incidents)
    elif current_tab == "Timeline":
        timeline_data = timeline.build_combined_timeline(session_id) if timeline else {}
        render_timeline_page(timeline_data)
    elif current_tab == "Reports":
        render_reports_page()
    elif current_tab == "Settings":
        render_settings_page()

    # Upload section in main area
    if current_tab == "Dashboard":
        st.markdown("---")
        render_upload_section()


# Entry point
if __name__ == "__main__":
    render_main()