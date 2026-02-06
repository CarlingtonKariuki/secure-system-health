"""SSHCR CLI entry point."""

from __future__ import annotations

import argparse
from typing import Dict, List, Any

from system_checks import run_system_health_checks
from network_checks import run_network_checks
from security_checks import run_security_checks
from report_generator import generate_report


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for SSHCR."""
    parser = argparse.ArgumentParser(
        description="Secure Systems Health & Cyber Readiness Tool (SSHCR)"
    )
    parser.add_argument(
        "--health",
        action="store_true",
        help="Run system health checks",
    )
    parser.add_argument(
        "--network",
        action="store_true",
        help="Run network readiness checks",
    )
    parser.add_argument(
        "--security",
        action="store_true",
        help="Run security baseline checks",
    )
    parser.add_argument(
        "--full-assessment",
        action="store_true",
        help="Run all checks",
    )
    parser.add_argument(
        "--output",
        choices=["md", "pdf"],
        default="md",
        help="Report output format",
    )
    parser.add_argument(
        "--report-name",
        default="sshcr_report",
        help="Base filename for report output",
    )
    return parser.parse_args()


def main() -> None:
    """Orchestrate checks and generate report."""
    args = parse_args()

    run_health = args.full_assessment or args.health
    run_network = args.full_assessment or args.network
    run_security = args.full_assessment or args.security

    if not (run_health or run_network or run_security):
        raise SystemExit(
            "No checks selected. Use --full-assessment or a specific flag."
        )

    results: Dict[str, List[Dict[str, Any]]] = {
        "system_health": [],
        "network": [],
        "security": [],
    }

    if run_health:
        results["system_health"] = run_system_health_checks()
    if run_network:
        results["network"] = run_network_checks()
    if run_security:
        results["security"] = run_security_checks()

    generate_report(results, output_format=args.output, report_name=args.report_name)


if __name__ == "__main__":
    main()
