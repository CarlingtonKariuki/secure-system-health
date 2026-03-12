"""Security baseline checks for SSHCR."""

from __future__ import annotations

from typing import Dict, List, Any
import json
import os

from security.collectors import collect_security_evidence
from security.evaluators import evaluate_security


def _load_security_policy() -> Dict[str, Any]:
    defaults: Dict[str, Any] = {
        "max_sudo_users": 5,
        "max_nopasswd_rules": 0,
        "password_max_days": 90,
        "password_min_length": 12,
        "ssh_root_login_allowed_values": ["no", "prohibit-password"],
        "ssh_max_auth_tries": 4,
        "ssh_weak_algorithm_tokens": [
            "cbc",
            "hmac-md5",
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "ssh-rsa",
        ],
        "pending_updates_warning_threshold": 10,
        "pending_updates_risk_threshold": 30,
        "expected_sysctl": {
            "net.ipv4.conf.all.rp_filter": "1",
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.default.accept_redirects": "0",
            "net.ipv4.tcp_syncookies": "1",
            "kernel.kptr_restrict": "1",
            "kernel.dmesg_restrict": "1",
        },
    }
    policy_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "docs", "security_policy.json")
    )
    try:
        with open(policy_path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            defaults.update(loaded)
    except (OSError, json.JSONDecodeError):
        pass
    return defaults


def run_security_checks() -> List[Dict[str, Any]]:
    """Run security baseline checks and return structured findings."""
    policy = _load_security_policy()
    evidence = collect_security_evidence()
    return evaluate_security(evidence, policy)
