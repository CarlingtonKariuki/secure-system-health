"""SSHCR CLI entry point."""
from __future__ import annotations
import argparse
import os
import sys
from typing import Dict, List, Any
from system_checks import run_system_health_checks
from network_checks import run_network_checks
from security_checks import run_security_checks
from report_generator import generate_report
__version__ = "1.0.0"
def _check_privileges() -> None:
    """Warn if not running as root - some checks require elevated access."""
    if os.geteuid() != 0:
        print(
            "[WARNING] SSHCR is not running as root. "
            "Some checks (shadow file, iptables, sshd -T, process mapping) "
            "will be incomplete or skipped.\\n"
            "         Re-run with: sudo python3 src/main.py <flags>\\n",
            file=sys.stderr,
        )
def _count_by_status(results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
    counts = {"OK": 0, "WARNING": 0, "RISK": 0}
    for group in results.values():
        for item in group:
            status = item.get("status", "OK")
            if status in counts:
                counts[status] += 1
    return counts
def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for SSHCR."""
    parser = argparse.ArgumentParser(
        description="Secure Systems Health & Cyber Readiness Tool (SSHCR)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\\n"
            "  sudo python3 src/main.py --full-assessment --output html\\n"
            "  sudo python3 src/main.py --security --output md\\n"
            "  sudo python3 src/main.py --health --network --output pdf\\n"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"SSHCR {__version__}"
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
        help="Run all checks (health + network + security)",
    )
    parser.add_argument(
        "--output",
        choices=["md", "html", "pdf"],
        default="html",
        help="Report output format (default: html)",
    )
    parser.add_argument(
        "--report-name",
        default="sshcr_report",
        help="Base filename for report output (default: sshcr_report)",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Always exit 0 even when RISK findings are present",
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
            "No checks selected. Use --full-assessment or one of: --health, --network, --security"
        )
    _check_privileges()
    results: Dict[str, List[Dict[str, Any]]] = {
        "system_health": [],
        "network": [],
        "security": [],
    }
    print("[*] Starting SSHCR assessment...\\n")
    if run_health:
        print("[*] Running system health checks...")
        results["system_health"] = run_system_health_checks()
    if run_network:
        print("[*] Running network readiness checks...")
        results["network"] = run_network_checks()
    if run_security:
        print("[*] Running security baseline checks...")
        results["security"] = run_security_checks()
    print("[*] Generating report...\\n")
    report_path = generate_report(
        results,
        output_format=args.output,
        report_name=args.report_name,
    )
    counts = _count_by_status(results)
    total = sum(counts.values())
    print(
        f"[+] Assessment complete - {total} checks: "
        f"{counts['OK']} OK  {counts['WARNING']} WARNING  {counts['RISK']} RISK"
    )
    if report_path:
        print(f"[+] Report saved to: {report_path}")
    if not args.no_fail and counts["RISK"] > 0:
        sys.exit(2)
if __name__ == "__main__":
    main()
