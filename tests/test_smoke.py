"""Smoke tests for SSHCR module integration."""

from __future__ import annotations

import os
import sys
import unittest


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_ROOT = os.path.join(PROJECT_ROOT, "src")
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)

from network_checks import run_network_checks  # noqa: E402
from report_generator import generate_report  # noqa: E402
from security_checks import run_security_checks  # noqa: E402
from system_checks import run_system_health_checks  # noqa: E402


class TestSSHCRSmoke(unittest.TestCase):
    """Minimal runtime coverage for module outputs and report generation."""

    def _assert_findings_shape(self, findings):
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)
        for item in findings:
            self.assertIsInstance(item, dict)
            self.assertIn("category", item)
            self.assertIn("check", item)
            self.assertIn("status", item)
            self.assertIn("details", item)
            self.assertIn("reason", item)
            self.assertIn("risk_score", item)

    def test_system_checks_smoke(self):
        findings = run_system_health_checks()
        self._assert_findings_shape(findings)

    def test_network_checks_smoke(self):
        findings = run_network_checks()
        self._assert_findings_shape(findings)

    def test_security_checks_smoke(self):
        findings = run_security_checks()
        self._assert_findings_shape(findings)

    def test_report_generation_smoke(self):
        report_name = "smoke_test_report"
        results = {
            "system_health": run_system_health_checks(),
            "network": run_network_checks(),
            "security": run_security_checks(),
        }
        generate_report(results, output_format="md", report_name=report_name)
        reports_dir = os.path.join(PROJECT_ROOT, "reports")
        generated = [
            name
            for name in os.listdir(reports_dir)
            if name.startswith(report_name) and name.endswith(".md")
        ]
        self.assertTrue(generated)


if __name__ == "__main__":
    unittest.main()

