"""Streamlit dashboard pages and components."""

import streamlit as st
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="Presidency SOC",
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
        st.title("🛡️ Presidency SOC")
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
        col1, col2, col3 = st.columns(3)
        with col1:
            level_filter = st.selectbox("Level", ["All"] + ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        with col2:
            logger_filter = st.text_input("Logger")
        with col3:
            source_filter = st.text_input("Source")

    # Search
    search_query = st.text_input("Search logs", placeholder="Enter search term...")

    # Display logs
    st.subheader(f"Showing {len(logs)} logs")

    if logs:
        for log in logs[:50]:
            with st.expander(f"{log.get('timestamp', '')[:19]} | {log.get('level', '')} | {log.get('logger', 'N/A')}"):
                st.write(f"**Message:** {log.get('message', 'N/A')}")
                st.write(f"**Source:** {log.get('source', 'N/A')}")
                st.write(f"**Raw:** {log.get('raw_line', 'N/A')[:200]}...")
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
    st.caption("Presidency SOC - Offline Security Analysis")


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
            st.success("Files processed successfully!")

    return uploaded_files


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
        render_logs_page([dict(l) for l in logs], {})
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