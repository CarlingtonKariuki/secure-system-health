# Secure Systems Health & Cyber Readiness Tool (SSHCR)

SSHCR is a modular assessment platform for system health, network readiness, and security baseline validation. It ships with a CLI and a Flask-powered dashboard.

## Current Capabilities

- System health checks:
  - OS/uptime
  - CPU and memory pressure
  - disk and inode usage
  - critical services
  - log growth
  - time sync signal

- Network checks:
  - active interfaces
  - listening ports
  - port-to-process mapping
  - allowed ports policy validation
  - firewall visibility
  - DNS/default route checks
  - network baseline drift detection

- Security checks:
  - identity and privilege controls
  - password and lockout policy checks
  - SSH hardening and crypto posture checks
  - patch backlog and auto-update posture
  - sudoers quality controls
  - host hardening sysctl baseline checks

- Reporting:
  - HTML, Markdown, and PDF output in `reports/`
  - status summary
  - priority remediation section
  - control IDs, confidence, and recommendations
  - downloadable exports via the dashboard (HTML/JSON/CSV)

## Project Layout

- `src/main.py`: CLI orchestration
- `src/system_checks.py`: system module
- `src/network_checks.py`: network module
- `src/security_checks.py`: security orchestration
- `src/security/collectors.py`: security evidence collection
- `src/security/evaluators.py`: security control evaluation
- `src/report_generator.py`: report rendering
- `app.py`: Flask backend (dashboard API)
- `dashboard/index.html`: dashboard UI
- `docs/security_policy.json`: policy thresholds and baseline values
- `docs/security_control_catalog.md`: control ID catalog
- `docs/allowed_ports.json`: network exposure baseline

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run one module:

```bash
python3 src/main.py --health --output md
python3 src/main.py --network --output md
python3 src/main.py --security --output md
```

Run full assessment:

```bash
python3 src/main.py --full-assessment --output html
```

Reports are generated as:

- `reports/sshcr_report_<YYYY-MM-DD>.html`
- `reports/sshcr_report_<YYYY-MM-DD>.md`
- `reports/sshcr_report_<YYYY-MM-DD>.pdf`

## Dashboard

Start the dashboard backend:

```bash
sudo python3 app.py
```

Then open:

- `http://localhost:5000`

## Smoke Testing

Run the built-in smoke tests:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

## Notes

- Running as root produces the most complete results.
- Some checks are privilege-sensitive and will report lower confidence without elevated permissions.
