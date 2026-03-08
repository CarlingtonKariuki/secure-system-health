"""Report generation for SSHCR."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
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
    actionable = [item for item in findings if item.get("status") in {"RISK", "WARNING"}]
    return sorted(
        actionable,
        key=lambda item: item.get("risk_score", _default_risk_score(item.get("status", "OK"))),
        reverse=True,
    )[:limit]
def _all_findings(results: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for group in results.values():
        findings.extend(group)
    return findings
def _clean(value: Any, fallback: str = "-") -> str:
    """Return a clean string, using fallback for empty/placeholder values."""
    text = str(value).strip() if value is not None else ""
    if not text or text.lower() in {"pending implementation detail", "n/a", "none"}:
        return fallback
    return text
def _render_markdown(results: Dict[str, List[Dict[str, Any]]]) -> str:
    all_findings = _all_findings(results)
    counts = _status_counts(all_findings)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        "# System Health & Cyber Readiness Assessment",
        "",
        f"**Assessment Date:** {date_str} (UTC)",
        "",
        "## Summary",
        "",
        f"OK: {counts['OK']} | WARNING: {counts['WARNING']} | RISK: {counts['RISK']}",
        "",
        "## Priority Remediation",
        "",
    ]
    priorities = _priority_findings(all_findings, limit=5)
    if priorities:
        for item in priorities:
            control_id = _clean(item.get("control_id"), "N/A")
            check = _clean(item.get("check"), "")
            status = item.get("status", "")
            recommendation = _clean(item.get("recommendation"), "Review and remediate.")
            lines.append(f"- `{control_id}` **{check}** [{status}]: {recommendation}")
    else:
        lines.append("- No WARNING/RISK findings detected.")
    lines += ["", "## Findings", ""]
    lines.append(
        "| Category | Control ID | Check | Status | Risk Score | Confidence | Details | Reason | Recommendation |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for item in all_findings:
        row = [
            _clean(item.get("category")),
            _clean(item.get("control_id")),
            _clean(item.get("check")),
            item.get("status", ""),
            str(item.get("risk_score", _default_risk_score(item.get("status", "OK")))),
            _clean(item.get("confidence"), "medium"),
            _clean(item.get("details")),
            _clean(item.get("reason")),
            _clean(item.get("recommendation")),
        ]
        lines.append("| " + " | ".join(row) + " |")
    return "\\n".join(lines)
def _render_html(results: Dict[str, List[Dict[str, Any]]]) -> str:
    all_findings = _all_findings(results)
    counts = _status_counts(all_findings)
    priorities = _priority_findings(all_findings, limit=5)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    total = sum(counts.values())
    summary_cards = (
        f'<div class="card ok"><div class="label">OK</div><div class="value">{counts["OK"]}</div>'
        f'<div class="sub">{round(counts["OK"] / total * 100) if total else 0}%</div></div>'
        f'<div class="card warn"><div class="label">WARNING</div><div class="value">{counts["WARNING"]}</div>'
        f'<div class="sub">{round(counts["WARNING"] / total * 100) if total else 0}%</div></div>'
        f'<div class="card risk"><div class="label">RISK</div><div class="value">{counts["RISK"]}</div>'
        f'<div class="sub">{round(counts["RISK"] / total * 100) if total else 0}%</div></div>'
    )
    priority_rows = ""
    if priorities:
        for item in priorities:
            control_id = html.escape(_clean(item.get("control_id"), "N/A"))
            check = html.escape(_clean(item.get("check"), ""))
            status = html.escape(item.get("status", ""))
            recommendation = html.escape(_clean(item.get("recommendation"), "Review and remediate."))
            priority_rows += (
                f"<li><strong>{control_id}</strong> {check} "
                f'<span class="pill {status.lower()}">{status}</span><br>'
                f'<span class="rec">{recommendation}</span></li>'
            )
    else:
        priority_rows = "<li>No WARNING/RISK findings detected.</li>"
    table_rows = ""
    for item in all_findings:
        status = html.escape(item.get("status", ""))
        risk_score = item.get("risk_score", _default_risk_score(item.get("status", "OK")))
        row_cells = [
            html.escape(_clean(item.get("category"))),
            html.escape(_clean(item.get("control_id"))),
            html.escape(_clean(item.get("check"))),
            f'<span class="pill {status.lower()}">{status}</span>',
            f'<span class="score s{status.lower()}">{risk_score}</span>',
            html.escape(_clean(item.get("confidence"), "medium")),
            html.escape(_clean(item.get("details"))),
            html.escape(_clean(item.get("reason"))),
            f'<span class="rec-cell">{html.escape(_clean(item.get("recommendation")))}</span>',
        ]
        table_rows += "<tr>" + "".join(f"<td>{c}</td>" for c in row_cells) + "</tr>\\n"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>SSHCR Report - {date_str}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
           background: #f8fafc; color: #0f172a; padding: 32px 24px; }}
    .wrapper {{ max-width: 1400px; margin: 0 auto; }}
    h1 {{ font-size: 22px; font-weight: 700; margin-bottom: 4px; }}
    .muted {{ color: #64748b; font-size: 13px; margin-bottom: 20px; }}
    .summary {{ display: flex; gap: 14px; margin-bottom: 28px; flex-wrap: wrap; }}
    .card {{ border-radius: 10px; padding: 14px 20px; min-width: 130px; border: 1px solid transparent; }}
    .card .label {{ font-size: 11px; font-weight: 600; letter-spacing: .05em; text-transform: uppercase; }}
    .card .value {{ font-size: 32px; font-weight: 800; line-height: 1.1; }}
    .card .sub {{ font-size: 11px; color: #94a3b8; margin-top: 2px; }}
    .ok {{ background: #f0fdf4; border-color: #bbf7d0; }}
    .ok .value {{ color: #15803d; }}
    .warn {{ background: #fffbeb; border-color: #fde68a; }}
    .warn .value {{ color: #b45309; }}
    .risk {{ background: #fef2f2; border-color: #fecaca; }}
    .risk .value {{ color: #b91c1c; }}
    h2 {{ font-size: 16px; font-weight: 700; margin-bottom: 12px; padding-bottom: 6px;
          border-bottom: 2px solid #e2e8f0; }}
    section {{ margin-bottom: 32px; }}
    ul {{ list-style: none; padding: 0; }}
    ul li {{ padding: 10px 14px; background: #fff; border: 1px solid #e2e8f0;
             border-radius: 8px; margin-bottom: 8px; font-size: 13px; line-height: 1.5; }}
    .rec {{ color: #475569; font-size: 12px; display: block; margin-top: 3px; }}
    .table-wrap {{ overflow-x: auto; border-radius: 10px; border: 1px solid #e2e8f0; background: #fff; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
    th {{ background: #f1f5f9; text-align: left; padding: 9px 10px; font-weight: 600;
          font-size: 11px; letter-spacing: .03em; text-transform: uppercase;
          border-bottom: 1px solid #e2e8f0; white-space: nowrap; }}
    td {{ padding: 8px 10px; vertical-align: top; border-bottom: 1px solid #f1f5f9;
          line-height: 1.45; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #f8fafc; }}
    .pill {{ border-radius: 999px; padding: 2px 9px; font-weight: 700;
             font-size: 11px; display: inline-block; white-space: nowrap; }}
    .pill.ok {{ background: #dcfce7; color: #166534; }}
    .pill.warning {{ background: #fef3c7; color: #92400e; }}
    .pill.risk {{ background: #fee2e2; color: #991b1b; }}
    .score {{ font-weight: 700; font-size: 12px; }}
    .score.sok {{ color: #15803d; }}
    .score.swarning {{ color: #b45309; }}
    .score.srisk {{ color: #b91c1c; }}
    .rec-cell {{ color: #334155; font-size: 11px; display: block; }}
  </style>
</head>
<body>
<div class="wrapper">
  <h1>System Health &amp; Cyber Readiness Assessment</h1>
  <p class="muted">Assessment Date: {date_str} (UTC) &nbsp;|&nbsp; {total} checks evaluated</p>
  <div class="summary">{summary_cards}</div>
  <section>
    <h2>Priority Remediation</h2>
    <ul>{priority_rows}</ul>
  </section>
  <section>
    <h2>All Findings</h2>
    <div class="table-wrap">
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
    </div>
  </section>
</div>
</body>
</html>"""
def _write_text(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
def _find_chrome() -> Optional[str]:
    """Find a Chromium/Chrome binary for headless PDF rendering."""
    candidates = [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    # Also check PATH
    for name in ("google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None
def _render_pdf_from_html(html_path: str, pdf_path: str) -> None:
    chrome = _find_chrome()
    if not chrome:
        raise ValueError("No Chrome/Chromium found for PDF rendering.")
    html_url = f"file://{os.path.abspath(html_path)}"
    result = subprocess.run(
        [
            chrome,
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
        raise ValueError("Chrome headless PDF rendering failed.")
def _render_pdf_fallback(results: Dict[str, List[Dict[str, Any]]], pdf_path: str) -> None:
    if not shutil.which("ps2pdf"):
        raise ValueError("No PDF renderer available (Chrome and ps2pdf are both unavailable).")
    markdown = _render_markdown(results)
    ps_path = os.path.splitext(pdf_path)[0] + ".ps"
    x, y = 40, 780
    line_height, max_chars = 11, 118
    lines = markdown.splitlines()
    ps_lines = ["%!PS-Adobe-3.0", "/Courier findfont 9 scalefont setfont"]
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
    _write_text(ps_path, "\\n".join(ps_lines) + "\\n")
    result = subprocess.run(
        ["ps2pdf", ps_path, pdf_path],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0 or not os.path.exists(pdf_path):
        raise ValueError("ps2pdf fallback rendering failed.")
def generate_report(
    results: Dict[str, List[Dict[str, Any]]],
    output_format: str = "html",
    report_name: str = "sshcr_report",
) -> str:
    """Generate a report from findings. Returns the path to the generated report."""
    output_format = output_format.lower()
    reports_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "reports")
    )
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    base_path = os.path.join(reports_dir, f"{report_name}_{timestamp}")
    if output_format == "md":
        out_path = f"{base_path}.md"
        _write_text(out_path, _render_markdown(results))
        return out_path
    if output_format == "html":
        out_path = f"{base_path}.html"
        _write_text(out_path, _render_html(results))
        return out_path
    if output_format == "pdf":
        html_path = f"{base_path}.html"
        pdf_path = f"{base_path}.pdf"
        _write_text(html_path, _render_html(results))
        try:
            _render_pdf_from_html(html_path, pdf_path)
            return pdf_path
        except ValueError:
            try:
                _render_pdf_fallback(results, pdf_path)
                return pdf_path
            except ValueError:
                # Fall back gracefully to HTML if PDF rendering is unavailable
                print("[WARNING] PDF rendering unavailable - saved as HTML instead.")
                return html_path
    raise ValueError(f"Unsupported output format '{output_format}'. Use: md, html, pdf.")
