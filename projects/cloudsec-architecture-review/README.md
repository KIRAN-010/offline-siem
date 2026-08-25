# CloudSec Architecture Review

A defensive security architecture review tool for proposed cloud and network designs. It converts an architecture description into a structured security assessment with trust boundaries, risks, control recommendations, and NIST CSF 2.0 mappings.

## Why this project

Security architecture reviews are often delivered as static documents. This project demonstrates a repeatable workflow for identifying security gaps before deployment.

## Features

- Architecture component inventory
- Trust-boundary identification
- Internet exposure and segmentation checks
- Identity and least-privilege checks
- Encryption and secrets-management checks
- Logging, monitoring, backup, and recovery checks
- Risk scoring using likelihood x impact
- NIST CSF 2.0 function mapping
- Prioritized remediation plan
- JSON export for integration into GRC workflows
- Streamlit dashboard for analyst-friendly review

## Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Example

The included sample architecture describes a public web application, API tier, database, object storage, and administrative access path. The analyzer flags missing segmentation, overly broad administrative access, missing centralized logging, and public storage exposure.

## Security note

This is a defensive assessment aid. It does not perform active scanning or exploitation.

## Framework

Control mapping is aligned to the NIST Cybersecurity Framework (CSF) 2.0 at the function/category level.
