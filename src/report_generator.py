"""Report generation for SSHCR."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Any
import os


def _status_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"OK": 0, "WARNING": 0, "RISK": 0}
    for item in findings:
        status = item.get("status", "OK")
        if status in counts:
            counts[status] += 1
    return counts


def _render_markdown(results: Dict[str, List[Dict[str, Any]]]) -> str:
    all_findings: List[Dict[str, Any]] = []
    for group in results.values():
        all_findings.extend(group)

    counts = _status_counts(all_findings)
    summary = (
        f"OK: {counts['OK']}, WARNING: {counts['WARNING']}, RISK: {counts['RISK']}"
    )

    lines = []
    lines.append("# System Health & Cyber Readiness Assessment")
    lines.append("")
    lines.append(f"**Assessment Date:** {datetime.utcnow().strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(summary)
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| Category | Check | Status | Risk Score | Details | Reason |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for item in all_findings:
        category = item.get("category", "")
        check = item.get("check", "")
        status = item.get("status", "")
        risk_score = item.get("risk_score", "")
        details = item.get("details", "")
        reason = item.get("reason", "")
        lines.append(f"| {category} | {check} | {status} | {risk_score} | {details} | {reason} |")

    return "\n".join(lines)


def generate_report(
    results: Dict[str, List[Dict[str, Any]]],
    output_format: str = "md",
    report_name: str = "sshcr_report",
) -> None:
    """Generate a report from findings."""
    output_format = output_format.lower()
    if output_format != "md":
        raise ValueError("Only Markdown output is supported in this phase.")

    report_content = _render_markdown(results)
    reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    reports_dir = os.path.abspath(reports_dir)
    os.makedirs(reports_dir, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y-%m-%d")
    filename = f"{report_name}_{timestamp}.{output_format}"
    path = os.path.join(reports_dir, filename)

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(report_content)
