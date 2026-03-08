"""Report generation for SSHCR."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Any
import html
import os
import shutil
import subprocess


def _status_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"OK": 0, "WARNING": 0, "RISK": 0}
    for item in findings:
        status = item.get("status", "OK")
        if status in counts:
            counts[status] += 1
    return counts


def _default_risk_score(status: str) -> int:
    if status == "RISK":
        return 85
    if status == "WARNING":
        return 55
    return 10


def _priority_findings(findings: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    actionable = [
        item
        for item in findings
        if item.get("status") in {"RISK", "WARNING"}
    ]
    sorted_items = sorted(
        actionable,
        key=lambda item: item.get("risk_score", _default_risk_score(item.get("status", "OK"))),
        reverse=True,
    )
    return sorted_items[:limit]


def _all_findings(results: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for group in results.values():
        findings.extend(group)
    return findings


def _render_markdown(results: Dict[str, List[Dict[str, Any]]]) -> str:
    all_findings = _all_findings(results)

    counts = _status_counts(all_findings)
    summary = (
        f"OK: {counts['OK']}, WARNING: {counts['WARNING']}, RISK: {counts['RISK']}"
    )

    lines = []
    lines.append("# System Health & Cyber Readiness Assessment")
    lines.append("")
    lines.append(f"**Assessment Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(summary)
    lines.append("")
    lines.append("## Priority Remediation")
    lines.append("")
    priorities = _priority_findings(all_findings, limit=5)
    if priorities:
        for item in priorities:
            control_id = item.get("control_id", "N/A")
            check = item.get("check", "")
            status = item.get("status", "")
            recommendation = item.get("recommendation", "Review and remediate.")
            lines.append(f"- `{control_id}` {check} [{status}]: {recommendation}")
    else:
        lines.append("- No WARNING/RISK findings detected.")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| Category | Control ID | Check | Status | Risk Score | Confidence | Details | Reason | Recommendation |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for item in all_findings:
        category = item.get("category", "")
        control_id = item.get("control_id", "")
        check = item.get("check", "")
        status = item.get("status", "")
        risk_score = item.get("risk_score", _default_risk_score(status))
        confidence = item.get("confidence", "medium")
        details = item.get("details", "")
        reason = item.get("reason", "Pending implementation detail")
        recommendation = item.get("recommendation", "Pending implementation detail")
        lines.append(
            f"| {category} | {control_id} | {check} | {status} | {risk_score} | {confidence} | {details} | {reason} | {recommendation} |"
        )

    return "\n".join(lines)


def _render_html(results: Dict[str, List[Dict[str, Any]]]) -> str:
    all_findings = _all_findings(results)
    counts = _status_counts(all_findings)
    priorities = _priority_findings(all_findings, limit=5)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    summary_cards = (
        f'<div class="card ok"><div class="label">OK</div><div class="value">{counts["OK"]}</div></div>'
        f'<div class="card warn"><div class="label">WARNING</div><div class="value">{counts["WARNING"]}</div></div>'
        f'<div class="card risk"><div class="label">RISK</div><div class="value">{counts["RISK"]}</div></div>'
    )

    priority_rows = ""
    if priorities:
        for item in priorities:
            control_id = html.escape(item.get("control_id", "N/A"))
            check = html.escape(item.get("check", ""))
            status = html.escape(item.get("status", ""))
            recommendation = html.escape(item.get("recommendation", "Review and remediate."))
            priority_rows += (
                f"<li><strong>{control_id}</strong> {check} "
                f'<span class="pill {status.lower()}">{status}</span><br>'
                f"{recommendation}</li>"
            )
    else:
        priority_rows = "<li>No WARNING/RISK findings detected.</li>"

    table_rows = ""
    for item in all_findings:
        category = html.escape(item.get("category", ""))
        control_id = html.escape(item.get("control_id", ""))
        check = html.escape(item.get("check", ""))
        status = html.escape(item.get("status", ""))
        risk_score = item.get("risk_score", _default_risk_score(item.get("status", "OK")))
        confidence = html.escape(item.get("confidence", "medium"))
        details = html.escape(item.get("details", ""))
        reason = html.escape(item.get("reason", "Pending implementation detail"))
        recommendation = html.escape(item.get("recommendation", "Pending implementation detail"))
        table_rows += (
            "<tr>"
            f"<td>{category}</td><td>{control_id}</td><td>{check}</td>"
            f'<td><span class="pill {status.lower()}">{status}</span></td>'
            f"<td>{risk_score}</td><td>{confidence}</td><td>{details}</td><td>{reason}</td><td>{recommendation}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>SSHCR Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 28px; color: #0f172a; }}
    h1 {{ margin-bottom: 6px; }}
    .muted {{ color: #475569; margin-top: 0; }}
    .summary {{ display: flex; gap: 12px; margin: 18px 0; }}
    .card {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 10px 14px; min-width: 120px; }}
    .card .label {{ font-size: 12px; color: #475569; }}
    .card .value {{ font-size: 24px; font-weight: 700; }}
    .ok {{ background: #ecfdf5; }}
    .warn {{ background: #fffbeb; }}
    .risk {{ background: #fef2f2; }}
    h2 {{ margin-top: 24px; margin-bottom: 8px; }}
    ul {{ margin-top: 0; }}
    li {{ margin-bottom: 8px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 6px 8px; vertical-align: top; }}
    th {{ background: #f8fafc; text-align: left; }}
    .pill {{ border-radius: 999px; padding: 2px 8px; font-weight: 700; font-size: 11px; display: inline-block; }}
    .pill.ok {{ background: #dcfce7; color: #166534; }}
    .pill.warning {{ background: #fef3c7; color: #92400e; }}
    .pill.risk {{ background: #fee2e2; color: #991b1b; }}
  </style>
</head>
<body>
  <h1>System Health & Cyber Readiness Assessment</h1>
  <p class="muted">Assessment Date: {date_str} (UTC)</p>
  <div class="summary">{summary_cards}</div>

  <h2>Priority Remediation</h2>
  <ul>{priority_rows}</ul>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Category</th><th>Control ID</th><th>Check</th><th>Status</th>
        <th>Risk Score</th><th>Confidence</th><th>Details</th><th>Reason</th><th>Recommendation</th>
      </tr>
    </thead>
    <tbody>
      {table_rows}
    </tbody>
  </table>
</body>
</html>"""


def _write_text(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _render_pdf_from_html(html_path: str, pdf_path: str) -> None:
    chrome_path = "/usr/bin/google-chrome"
    if not os.path.exists(chrome_path):
        raise ValueError("PDF rendering requires google-chrome in this environment.")
    html_url = f"file://{os.path.abspath(html_path)}"
    result = subprocess.run(
        [
            chrome_path,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            f"--print-to-pdf={pdf_path}",
            html_url,
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0 or not os.path.exists(pdf_path):
        raise ValueError("Failed to render PDF via headless Chrome.")


def _render_pdf_fallback(results: Dict[str, List[Dict[str, Any]]], pdf_path: str) -> None:
    if not shutil.which("ps2pdf"):
        raise ValueError("No PDF renderer available (google-chrome and ps2pdf unavailable).")

    markdown = _render_markdown(results)
    ps_path = os.path.splitext(pdf_path)[0] + ".ps"
    x = 40
    y = 780
    line_height = 11
    max_chars = 118

    lines = markdown.splitlines()
    ps_lines = [
        "%!PS-Adobe-3.0",
        "/Courier findfont 9 scalefont setfont",
    ]
    current_y = y
    for raw in lines:
        line = raw.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if not line:
            line = " "
        chunks = [line[i:i + max_chars] for i in range(0, len(line), max_chars)] or [" "]
        for chunk in chunks:
            ps_lines.append(f"{x} {current_y} moveto ({chunk}) show")
            current_y -= line_height
            if current_y < 45:
                ps_lines.append("showpage")
                ps_lines.append("/Courier findfont 9 scalefont setfont")
                current_y = y
    ps_lines.append("showpage")
    _write_text(ps_path, "\n".join(ps_lines) + "\n")

    result = subprocess.run(
        ["ps2pdf", ps_path, pdf_path],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0 or not os.path.exists(pdf_path):
        raise ValueError("Failed to render PDF via ps2pdf fallback.")


def generate_report(
    results: Dict[str, List[Dict[str, Any]]],
    output_format: str = "md",
    report_name: str = "sshcr_report",
) -> None:
    """Generate a report from findings."""
    output_format = output_format.lower()

    reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    reports_dir = os.path.abspath(reports_dir)
    os.makedirs(reports_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    base_path = os.path.join(reports_dir, f"{report_name}_{timestamp}")

    if output_format == "md":
        _write_text(f"{base_path}.md", _render_markdown(results))
        return

    if output_format == "pdf":
        html_path = f"{base_path}.html"
        pdf_path = f"{base_path}.pdf"
        _write_text(html_path, _render_html(results))
        try:
            _render_pdf_from_html(html_path, pdf_path)
        except ValueError:
            _render_pdf_fallback(results, pdf_path)
        return

    raise ValueError("Unsupported output format. Use 'md' or 'pdf'.")
