"""Evaluators for security evidence."""

from __future__ import annotations

from typing import Any, Dict, List


def _risk_score(status: str) -> int:
    if status == "RISK":
        return 85
    if status == "WARNING":
        return 55
    return 10


def _finding(
    control_id: str,
    check: str,
    status: str,
    details: str,
    reason: str,
    recommendation: str,
    confidence: str = "high",
) -> Dict[str, Any]:
    return {
        "category": "Security",
        "check": check,
        "status": status,
        "risk_score": _risk_score(status),
        "details": details,
        "reason": reason,
        "control_id": control_id,
        "recommendation": recommendation,
        "confidence": confidence,
    }


def evaluate_identity(identity: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    uid0_non_root = identity.get("uid0_non_root", [])
    if uid0_non_root:
        findings.append(
            _finding(
                "ID-001",
                "Privileged UID 0 accounts",
                "RISK",
                f"Non-root UID 0 accounts: {', '.join(uid0_non_root)}",
                "Multiple UID 0 accounts expand superuser attack surface.",
                "Remove or reassign non-root UID 0 accounts.",
            )
        )
    else:
        findings.append(
            _finding(
                "ID-001",
                "Privileged UID 0 accounts",
                "OK",
                "Only root account has UID 0",
                "Privileged identity scope is constrained.",
                "Keep UID 0 restricted to root only.",
            )
        )

    empty_password_accounts = identity.get("empty_password_accounts", [])
    shadow_readable = identity.get("shadow_readable", False)
    if not shadow_readable:
        findings.append(
            _finding(
                "ID-002",
                "Empty password accounts",
                "WARNING",
                "/etc/shadow not readable with current privileges",
                "Unable to validate password-less local accounts.",
                "Run SSHCR with elevated privileges for complete credential checks.",
                confidence="low",
            )
        )
    elif empty_password_accounts:
        findings.append(
            _finding(
                "ID-002",
                "Empty password accounts",
                "RISK",
                f"Accounts with empty password fields: {', '.join(empty_password_accounts)}",
                "Empty passwords allow trivial account compromise.",
                "Lock or disable affected accounts immediately.",
            )
        )
    else:
        findings.append(
            _finding(
                "ID-002",
                "Empty password accounts",
                "OK",
                "No empty password fields detected",
                "Account credential baseline appears sound.",
                "Continue periodic shadow-file audits.",
            )
        )

    sudo_users = identity.get("sudo_users", [])
    max_sudo_users = int(policy.get("max_sudo_users", 5))
    if len(sudo_users) > max_sudo_users:
        findings.append(
            _finding(
                "ID-003",
                "Privileged sudo membership",
                "WARNING",
                f"{len(sudo_users)} sudo-capable users: {', '.join(sudo_users)}",
                "Broad privileged access increases risk of misuse.",
                "Reduce sudo access to least-privilege set.",
            )
        )
    else:
        findings.append(
            _finding(
                "ID-003",
                "Privileged sudo membership",
                "OK",
                f"{len(sudo_users)} sudo-capable users detected",
                "Privileged user count is within policy threshold.",
                "Review sudo list regularly and remove stale access.",
            )
        )

    service_shell_accounts = identity.get("service_shell_accounts", [])
    if service_shell_accounts:
        findings.append(
            _finding(
                "ID-004",
                "Service account shell access",
                "WARNING",
                f"System accounts with interactive shells: {', '.join(service_shell_accounts[:8])}",
                "Interactive shells on service accounts increase abuse paths.",
                "Set non-interactive shells for service identities where possible.",
            )
        )
    else:
        findings.append(
            _finding(
                "ID-004",
                "Service account shell access",
                "OK",
                "No unexpected interactive service accounts detected",
                "Service identities appear hardened for non-interactive use.",
                "Keep system-account shell policy enforced.",
            )
        )

    return findings


def evaluate_sudoers(sudoers: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    max_nopasswd = int(policy.get("max_nopasswd_rules", 0))
    nopasswd_rules = sudoers.get("nopasswd_rules", [])
    wildcard_rules = sudoers.get("wildcard_rules", [])

    if len(nopasswd_rules) > max_nopasswd:
        findings.append(
            _finding(
                "ID-005",
                "Sudoers NOPASSWD policy",
                "RISK",
                f"{len(nopasswd_rules)} NOPASSWD rule(s) detected",
                "Passwordless privilege escalation increases abuse potential.",
                "Limit NOPASSWD to controlled automation identities only.",
            )
        )
    else:
        findings.append(
            _finding(
                "ID-005",
                "Sudoers NOPASSWD policy",
                "OK",
                f"{len(nopasswd_rules)} NOPASSWD rule(s) detected",
                "Sudo password challenge policy is within baseline.",
                "Keep privileged commands behind authentication where feasible.",
            )
        )

    if wildcard_rules:
        findings.append(
            _finding(
                "ID-006",
                "Sudoers wildcard scope",
                "WARNING",
                f"{len(wildcard_rules)} broad sudo rule(s) detected",
                "Overly broad sudo scope weakens least-privilege enforcement.",
                "Refine sudo rules to explicit command allowlists.",
                confidence="medium",
            )
        )
    else:
        findings.append(
            _finding(
                "ID-006",
                "Sudoers wildcard scope",
                "OK",
                "No broad wildcard sudo rules detected",
                "Sudo policy appears constrained.",
                "Continue periodic sudoers rule review.",
            )
        )
    return findings


def evaluate_auth_policy(auth_policy: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    pass_max_days_raw = auth_policy.get("pass_max_days", "")
    pass_min_len_raw = auth_policy.get("pass_min_len", "")

    max_days_threshold = int(policy.get("password_max_days", 90))
    min_len_threshold = int(policy.get("password_min_length", 12))

    try:
        pass_max_days = int(pass_max_days_raw)
    except ValueError:
        pass_max_days = -1
    try:
        pass_min_len = int(pass_min_len_raw)
    except ValueError:
        pass_min_len = -1

    if pass_max_days < 0:
        findings.append(
            _finding(
                "AUTH-001",
                "Password expiration policy",
                "WARNING",
                "PASS_MAX_DAYS not found in /etc/login.defs",
                "Password rotation policy could not be confirmed.",
                "Set PASS_MAX_DAYS to a compliant value (for example 90 days).",
            )
        )
    elif pass_max_days > max_days_threshold:
        findings.append(
            _finding(
                "AUTH-001",
                "Password expiration policy",
                "WARNING",
                f"PASS_MAX_DAYS={pass_max_days} (policy <= {max_days_threshold})",
                "Long password lifetime increases credential exposure window.",
                "Reduce PASS_MAX_DAYS to policy threshold.",
            )
        )
    else:
        findings.append(
            _finding(
                "AUTH-001",
                "Password expiration policy",
                "OK",
                f"PASS_MAX_DAYS={pass_max_days}",
                "Password expiry policy aligns with baseline.",
                "Maintain current password lifetime policy.",
            )
        )

    if pass_min_len < 0:
        findings.append(
            _finding(
                "AUTH-002",
                "Password minimum length",
                "WARNING",
                "PASS_MIN_LEN not found in /etc/login.defs",
                "Password complexity baseline could not be verified.",
                "Set PASS_MIN_LEN to policy minimum.",
            )
        )
    elif pass_min_len < min_len_threshold:
        findings.append(
            _finding(
                "AUTH-002",
                "Password minimum length",
                "WARNING",
                f"PASS_MIN_LEN={pass_min_len} (policy >= {min_len_threshold})",
                "Short passwords are easier to brute force.",
                "Increase PASS_MIN_LEN to baseline minimum.",
            )
        )
    else:
        findings.append(
            _finding(
                "AUTH-002",
                "Password minimum length",
                "OK",
                f"PASS_MIN_LEN={pass_min_len}",
                "Password minimum length meets policy.",
                "Keep complexity baseline enforced in PAM/login definitions.",
            )
        )

    lockout_configured = bool(auth_policy.get("lockout_configured", False))
    if lockout_configured:
        findings.append(
            _finding(
                "AUTH-003",
                "Account lockout controls",
                "OK",
                "PAM lockout module detected (faillock/tally)",
                "Brute-force resistance control appears configured.",
                "Validate lockout thresholds and unlock timers match policy.",
            )
        )
    else:
        findings.append(
            _finding(
                "AUTH-003",
                "Account lockout controls",
                "RISK",
                "No PAM lockout module detected",
                "Failed-login protection may be missing.",
                "Configure pam_faillock (or equivalent) for login failure controls.",
            )
        )

    return findings


def evaluate_ssh(ssh: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    permit_root_login = ssh.get("permit_root_login", "").lower()
    allowed_root = [item.lower() for item in policy.get("ssh_root_login_allowed_values", ["no", "prohibit-password"])]
    if permit_root_login and permit_root_login not in allowed_root:
        findings.append(
            _finding(
                "SSH-001",
                "SSH root login policy",
                "RISK",
                f"PermitRootLogin={ssh.get('permit_root_login', 'unset')}",
                "Direct root SSH access materially increases compromise impact.",
                "Set PermitRootLogin to no (or prohibit-password where justified).",
            )
        )
    else:
        findings.append(
            _finding(
                "SSH-001",
                "SSH root login policy",
                "OK",
                f"PermitRootLogin={ssh.get('permit_root_login', 'unset/default')}",
                "Root login policy aligns with hardened baseline.",
                "Keep root SSH disabled and use sudo-based admin workflows.",
            )
        )

    password_auth = ssh.get("password_authentication", "").lower()
    if password_auth in {"yes", "true"}:
        findings.append(
            _finding(
                "SSH-002",
                "SSH password authentication",
                "WARNING",
                f"PasswordAuthentication={ssh.get('password_authentication', 'unset')}",
                "Password-based SSH logins are more susceptible to brute-force attacks.",
                "Disable password authentication where key-based access is feasible.",
            )
        )
    else:
        findings.append(
            _finding(
                "SSH-002",
                "SSH password authentication",
                "OK",
                f"PasswordAuthentication={ssh.get('password_authentication', 'unset/default')}",
                "SSH is not explicitly relying on password authentication.",
                "Maintain key-based authentication controls.",
            )
        )

    pubkey_auth = ssh.get("pubkey_authentication", "").lower()
    if pubkey_auth in {"no", "false"}:
        findings.append(
            _finding(
                "SSH-003",
                "SSH public key authentication",
                "WARNING",
                f"PubkeyAuthentication={ssh.get('pubkey_authentication', 'unset')}",
                "Disabling key auth can force weaker authentication paths.",
                "Enable PubkeyAuthentication for stronger SSH access control.",
            )
        )
    else:
        findings.append(
            _finding(
                "SSH-003",
                "SSH public key authentication",
                "OK",
                f"PubkeyAuthentication={ssh.get('pubkey_authentication', 'unset/default')}",
                "Public-key authentication is available for hardened access.",
                "Keep SSH key lifecycle management in place.",
            )
        )

    max_auth_tries_raw = ssh.get("max_auth_tries", "")
    max_auth_tries_threshold = int(policy.get("ssh_max_auth_tries", 4))
    try:
        max_auth_tries = int(max_auth_tries_raw)
    except ValueError:
        max_auth_tries = -1
    if max_auth_tries < 0:
        findings.append(
            _finding(
                "SSH-004",
                "SSH MaxAuthTries setting",
                "WARNING",
                "MaxAuthTries not explicitly set",
                "Default retries may exceed hardened policy expectations.",
                f"Set MaxAuthTries to {max_auth_tries_threshold} or lower.",
            )
        )
    elif max_auth_tries > max_auth_tries_threshold:
        findings.append(
            _finding(
                "SSH-004",
                "SSH MaxAuthTries setting",
                "WARNING",
                f"MaxAuthTries={max_auth_tries} (policy <= {max_auth_tries_threshold})",
                "High retry limits increase brute-force opportunity.",
                f"Reduce MaxAuthTries to {max_auth_tries_threshold} or lower.",
            )
        )
    else:
        findings.append(
            _finding(
                "SSH-004",
                "SSH MaxAuthTries setting",
                "OK",
                f"MaxAuthTries={max_auth_tries}",
                "Authentication retry threshold aligns with baseline.",
                "Maintain limited SSH retry policy.",
            )
        )

    allow_users = ssh.get("allow_users", "")
    allow_groups = ssh.get("allow_groups", "")
    if not allow_users and not allow_groups:
        findings.append(
            _finding(
                "SSH-005",
                "SSH access allowlist",
                "WARNING",
                "AllowUsers/AllowGroups not explicitly configured",
                "SSH access scope may be broader than necessary.",
                "Define AllowUsers or AllowGroups to constrain SSH exposure.",
            )
        )
    else:
        findings.append(
            _finding(
                "SSH-005",
                "SSH access allowlist",
                "OK",
                "AllowUsers/AllowGroups restriction is configured",
                "SSH access scope is explicitly constrained.",
                "Review allowlist entries against active admin roster.",
            )
        )

    service_state = ssh.get("service_state", "unknown")
    service_status = "OK" if service_state == "active" else "WARNING"
    findings.append(
        _finding(
            "SSH-006",
            "SSH service state",
            service_status,
            f"sshd service state: {service_state}",
            "Service state visibility is required for support readiness.",
            "Confirm intended SSH service state for the environment.",
        )
    )

    weak_tokens = [token.lower() for token in policy.get("ssh_weak_algorithm_tokens", [])]
    runtime_ciphers = ssh.get("runtime_ciphers", "").lower()
    runtime_macs = ssh.get("runtime_macs", "").lower()
    runtime_kex = ssh.get("runtime_kex_algorithms", "").lower()
    crypto_surface = " ".join([runtime_ciphers, runtime_macs, runtime_kex])
    weak_present = sorted({token for token in weak_tokens if token and token in crypto_surface})
    if not runtime_ciphers and not runtime_macs and not runtime_kex:
        findings.append(
            _finding(
                "SSH-007",
                "SSH crypto posture",
                "WARNING",
                "Unable to inspect effective SSH crypto settings (sshd -T unavailable)",
                "Crypto baseline could not be verified.",
                "Run with SSH tooling installed and sufficient privileges.",
                confidence="low",
            )
        )
    elif weak_present:
        findings.append(
            _finding(
                "SSH-007",
                "SSH crypto posture",
                "RISK",
                f"Weak SSH algorithm tokens detected: {', '.join(weak_present)}",
                "Weak ciphers/MACs/KEX reduce transport security strength.",
                "Remove legacy algorithms and enforce modern SSH crypto baseline.",
            )
        )
    else:
        findings.append(
            _finding(
                "SSH-007",
                "SSH crypto posture",
                "OK",
                "No policy-defined weak algorithm tokens detected in sshd runtime config",
                "Effective SSH crypto profile aligns with baseline checks.",
                "Keep algorithm policy updated against current hardening guidance.",
                confidence="medium",
            )
        )

    return findings


def evaluate_patch(patch: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    manager = patch.get("manager", "unknown")
    pending_updates = int(patch.get("pending_updates", -1))
    warn_threshold = int(policy.get("pending_updates_warning_threshold", 10))
    risk_threshold = int(policy.get("pending_updates_risk_threshold", 30))

    if manager == "unknown":
        findings.append(
            _finding(
                "PATCH-001",
                "Package manager visibility",
                "WARNING",
                "No supported package manager detected (apt/dnf/yum)",
                "Patch backlog could not be assessed.",
                "Add package manager support for this distribution.",
            )
        )
    elif pending_updates < 0:
        findings.append(
            _finding(
                "PATCH-001",
                "Package update backlog",
                "WARNING",
                f"Unable to determine pending updates via {manager}",
                "Patch exposure is unknown.",
                "Run update inventory with elevated privileges and verify repositories.",
            )
        )
    elif pending_updates >= risk_threshold:
        findings.append(
            _finding(
                "PATCH-001",
                "Package update backlog",
                "RISK",
                f"{pending_updates} pending updates detected via {manager}",
                "Large update backlog increases exposure to known vulnerabilities.",
                "Apply high-priority and security updates before production rollout.",
            )
        )
    elif pending_updates >= warn_threshold:
        findings.append(
            _finding(
                "PATCH-001",
                "Package update backlog",
                "WARNING",
                f"{pending_updates} pending updates detected via {manager}",
                "Moderate patch backlog may include exploitable issues.",
                "Schedule patch cycle and verify service-impact windows.",
            )
        )
    else:
        findings.append(
            _finding(
                "PATCH-001",
                "Package update backlog",
                "OK",
                f"{pending_updates} pending updates detected via {manager}",
                "Patch posture is within baseline threshold.",
                "Continue regular update cadence.",
            )
        )

    unattended = bool(patch.get("unattended_upgrades", False))
    unattended_status = "OK" if unattended else "WARNING"
    findings.append(
        _finding(
            "PATCH-002",
            "Automatic security updates",
            unattended_status,
            "Unattended upgrades enabled" if unattended else "Unattended upgrades not enabled",
            "Automated patching reduces window of vulnerability.",
            "Enable unattended security updates where operationally safe.",
        )
    )
    return findings


def evaluate_hardening(hardening: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    auditd_state = hardening.get("auditd_state", "unknown")
    journald_state = hardening.get("journald_state", "unknown")
    journald_persistent = bool(hardening.get("journald_persistent", False))
    ntp_sync = hardening.get("ntp_sync", "")

    if auditd_state == "active":
        status = "OK"
        details = "auditd service is active"
        reason = "System audit trail collection is available."
    else:
        status = "WARNING"
        details = f"auditd service state: {auditd_state}"
        reason = "Audit event collection may be incomplete."
    findings.append(
        _finding(
            "HARD-001",
            "Audit daemon status",
            status,
            details,
            reason,
            "Enable and monitor auditd for high-value systems.",
        )
    )

    if journald_state == "active" and journald_persistent:
        status = "OK"
        details = "systemd-journald active with persistent log storage"
        reason = "Persistent logs support investigations and compliance evidence."
    elif journald_state == "active":
        status = "WARNING"
        details = "systemd-journald active but /var/log/journal missing"
        reason = "Logs may be volatile across reboots."
    else:
        status = "WARNING"
        details = f"systemd-journald service state: {journald_state}"
        reason = "Core system logging service is not confirmed active."
    findings.append(
        _finding(
            "HARD-002",
            "Logging persistence",
            status,
            details,
            reason,
            "Enable persistent journald storage for forensic continuity.",
        )
    )

    if ntp_sync == "yes":
        status = "OK"
        details = "NTP synchronized"
        reason = "Timestamp integrity supports incident analysis."
    elif ntp_sync == "no":
        status = "WARNING"
        details = "NTP not synchronized"
        reason = "Unsynchronized time weakens audit and correlation reliability."
    else:
        status = "WARNING"
        details = "NTP synchronization state unavailable"
        reason = "Time-sync posture cannot be verified."
    findings.append(
        _finding(
            "HARD-003",
            "Time synchronization",
            status,
            details,
            reason,
            "Configure and monitor reliable NTP synchronization.",
        )
    )

    expected_sysctl = policy.get(
        "expected_sysctl",
        {
            "net.ipv4.conf.all.rp_filter": "1",
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.default.accept_redirects": "0",
            "net.ipv4.tcp_syncookies": "1",
            "kernel.kptr_restrict": "1",
            "kernel.dmesg_restrict": "1",
        },
    )
    observed_sysctl = hardening.get("sysctl_values", {})
    mismatches: List[str] = []
    missing: List[str] = []
    for key, expected in expected_sysctl.items():
        if key not in observed_sysctl:
            missing.append(key)
            continue
        if str(observed_sysctl.get(key)) != str(expected):
            mismatches.append(f"{key}={observed_sysctl.get(key)} (expected {expected})")

    if mismatches:
        findings.append(
            _finding(
                "HARD-004",
                "Kernel/network sysctl baseline",
                "RISK",
                "; ".join(mismatches[:6]),
                "Kernel hardening baseline deviations increase attack surface.",
                "Align sysctl values with security policy and persist in sysctl.d.",
            )
        )
    elif missing:
        findings.append(
            _finding(
                "HARD-004",
                "Kernel/network sysctl baseline",
                "WARNING",
                f"Could not read: {', '.join(missing[:6])}",
                "Sysctl posture could not be fully verified.",
                "Run checks with sufficient privileges and confirm procfs access.",
                confidence="low",
            )
        )
    else:
        findings.append(
            _finding(
                "HARD-004",
                "Kernel/network sysctl baseline",
                "OK",
                "All monitored sysctl values match policy baseline",
                "Kernel/network hardening posture aligns with expected controls.",
                "Keep sysctl baseline enforced through configuration management.",
            )
        )

    return findings


def evaluate_security(evidence: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    findings.extend(evaluate_identity(evidence.get("identity", {}), policy))
    findings.extend(evaluate_sudoers(evidence.get("sudoers", {}), policy))
    findings.extend(evaluate_auth_policy(evidence.get("auth_policy", {}), policy))
    findings.extend(evaluate_ssh(evidence.get("ssh", {}), policy))
    findings.extend(evaluate_patch(evidence.get("patch", {}), policy))
    findings.extend(evaluate_hardening(evidence.get("hardening", {}), policy))
    return findings
