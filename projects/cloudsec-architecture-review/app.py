import json
from dataclasses import dataclass, asdict
from pathlib import Path

import streamlit as st


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    evidence: str
    recommendation: str
    nist_csf: str


RULES = [
    ("Public database exposure", "Critical", "Network Security", "database_public", "A database is reachable from the public network.", "Place the database in a private subnet and allow access only from the application tier.", "PR.AA / PR.IR"),
    ("Public object storage", "High", "Data Protection", "storage_public", "Object storage is configured as public.", "Disable public access and use identity-based access with explicit bucket policies.", "PR.DS"),
    ("Missing centralized logging", "High", "Monitoring", "central_logging", "No centralized security logging destination is defined.", "Centralize authentication, network, application, and administrative logs with retention and alerting.", "DE.CM / DE.AE"),
    ("Broad administrative access", "High", "Identity", "admin_broad", "Administrative access is described as unrestricted or shared.", "Use individual identities, MFA, least privilege, privileged access workflows, and time-bound elevation.", "PR.AA"),
    ("Missing network segmentation", "High", "Network Security", "segmentation", "Application, data, and management planes are not clearly segmented.", "Define trust zones and explicit allow-list paths between tiers.", "PR.IR"),
    ("Unencrypted sensitive traffic", "High", "Data Protection", "encryption", "Sensitive traffic is not explicitly protected in transit.", "Require TLS for external and internal sensitive communications and manage certificates centrally.", "PR.DS"),
    ("Secrets stored in application configuration", "Medium", "Secrets Management", "secrets", "Secrets appear to be stored directly in application configuration.", "Use a managed secrets vault and rotate credentials without redeploying application code.", "PR.DS / PR.AA"),
    ("No tested recovery process", "Medium", "Resilience", "recovery", "Backup or recovery testing is not defined.", "Document RPO/RTO, maintain isolated backups, and perform periodic restoration tests.", "PR.IR / RC.RP"),
]


def analyze(a):
    text = json.dumps(a).lower()
    findings = []
    for title, severity, category, key, evidence, recommendation, nist in RULES:
        hit = False
        if key == "database_public":
            hit = any(x in text for x in ["database public", "database: public", "public database", "db public"])
        elif key == "storage_public":
            hit = any(x in text for x in ["storage public", "bucket public", "public bucket", "object storage public"])
        elif key == "central_logging":
            hit = not any(x in text for x in ["central logging", "siem", "log aggregation", "centralized logging"])
        elif key == "admin_broad":
            hit = any(x in text for x in ["admin: broad", "admin broad", "shared admin", "unrestricted admin", "0.0.0.0/0"])
        elif key == "segmentation":
            hit = not any(x in text for x in ["segmented", "private subnet", "network segment", "trust zone"])
        elif key == "encryption":
            hit = any(x in text for x in ["unencrypted", "http only", "no tls", "plaintext traffic"])
        elif key == "secrets":
            hit = any(x in text for x in ["hardcoded secret", "password in config", "secret in config", "api key in code"])
        elif key == "recovery":
            hit = not any(x in text for x in ["tested recovery", "restore test", "rpo", "rto"])
        if hit:
            findings.append(Finding(title, severity, category, evidence, recommendation, nist))
    return findings


st.set_page_config(page_title="CloudSec Architecture Review", page_icon="🛡️", layout="wide")
st.title("🛡️ CloudSec Architecture Review")
st.caption("Defensive security architecture assessment • NIST CSF 2.0 aligned")

with st.sidebar:
    st.header("Architecture Input")
    uploaded = st.file_uploader("Upload JSON architecture", type=["json"])
    sample = st.button("Load sample architecture")

sample_arch = {
    "name": "Example Internet-Facing Application",
    "components": ["Internet", "Web App", "API", "Database", "Object Storage", "Admin Portal"],
    "controls": ["database public", "storage public", "admin broad", "no segmentation", "no central logging", "secret in config"],
    "traffic": "unencrypted internal traffic",
}

architecture = sample_arch if sample else None
if uploaded:
    try:
        architecture = json.load(uploaded)
    except Exception as exc:
        st.error(f"Invalid JSON: {exc}")

if architecture:
    findings = analyze(architecture)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ["Critical", "High", "Medium", "Low"]}

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Findings", len(findings))
    c2.metric("Critical", counts["Critical"])
    c3.metric("High", counts["High"])
    c4.metric("Medium", counts["Medium"])

    st.subheader("Architecture")
    st.json(architecture)

    st.subheader("Security Findings")
    if not findings:
        st.success("No rule-based gaps were identified from the supplied description. Perform manual review before approval.")
    for f in findings:
        with st.expander(f"{f.severity} — {f.title}"):
            st.write(f"**Category:** {f.category}")
            st.write(f"**Evidence:** {f.evidence}")
            st.write(f"**Recommendation:** {f.recommendation}")
            st.write(f"**NIST CSF 2.0:** {f.nist_csf}")

    report = {
        "architecture": architecture,
        "summary": counts,
        "findings": [asdict(f) for f in findings],
    }
    st.download_button("Download JSON assessment", json.dumps(report, indent=2), "architecture-review.json", "application/json")
else:
    st.info("Upload an architecture JSON file or load the sample to begin.")
    st.markdown("**Expected input:** components, controls, traffic, and access descriptions. The analyzer is intentionally non-invasive and performs no active scanning.")
