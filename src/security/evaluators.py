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
def _display_value(raw: str, default_label: str = "default (not explicitly set)") -> str:
    """Return a clean display string for a config value that may be empty."""
    return raw if raw else default_label
def evaluate_identity(identity: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    uid0_non_root = identity.get("uid0_non_root", [])
    if uid0_non_root:
        findings.append(_finding(
            "ID-001", "Privileged UID 0 accounts", "RISK",
            f"Non-root UID 0 accounts: {', '.join(uid0_non_root)}",
            "Multiple UID 0 accounts expand the superuser attack surface.",
            "Remove or reassign non-root UID 0 accounts immediately.",
        ))
    else:
        findings.append(_finding(
            "ID-001", "Privileged UID 0 accounts", "OK",
            "Only root account has UID 0",
            "Privileged identity scope is constrained.",
            "Keep UID 0 restricted to root only.",
        ))
    empty_password_accounts = identity.get("empty_password_accounts", [])
    shadow_readable = identity.get("shadow_readable", False)
    if not shadow_readable:
        findings.append(_finding(
            "ID-002", "Empty password accounts", "WARNING",
            "/etc/shadow not readable - re-run with sudo for complete check",
            "Unable to validate password-less local accounts without elevated privileges.",
            "Re-run SSHCR with `sudo` to enable full credential validation.",
            confidence="low",
        ))
    elif empty_password_accounts:
        findings.append(_finding(
            "ID-002", "Empty password accounts", "RISK",
            f"Accounts with empty passwords: {', '.join(empty_password_accounts)}",
            "Empty passwords allow trivial account compromise.",
            "Lock affected accounts with `passwd -l <user>` or set a strong password immediately.",
        ))
    else:
        findings.append(_finding(
            "ID-002", "Empty password accounts", "OK",
            "No empty password fields detected in /etc/shadow",
            "Account credential baseline appears sound.",
            "Continue periodic shadow-file audits.",
        ))
    sudo_users = identity.get("sudo_users", [])
    max_sudo_users = int(policy.get("max_sudo_users", 5))
    if len(sudo_users) > max_sudo_users:
        findings.append(_finding(
            "ID-003", "Privileged sudo membership", "WARNING",
            f"{len(sudo_users)} sudo-capable users: {', '.join(sudo_users)}",
            "Broad privileged access increases risk of misuse or lateral movement.",
            f"Reduce sudo membership to {max_sudo_users} or fewer. Review with `getent group sudo`.",
        ))
    else:
        findings.append(_finding(
            "ID-003", "Privileged sudo membership", "OK",
            f"{len(sudo_users)} sudo-capable user(s) detected",
            "Privileged user count is within the policy threshold.",
            "Review sudo list regularly and remove stale access.",
        ))
    service_shell_accounts = identity.get("service_shell_accounts", [])
    if service_shell_accounts:
        findings.append(_finding(
            "ID-004", "Service account shell access", "WARNING",
            f"System accounts with interactive shells: {', '.join(service_shell_accounts[:8])}",
            "Interactive shells on service accounts increase privilege abuse paths.",
            "Set non-interactive shells: `usermod -s /usr/sbin/nologin <user>` for each affected account.",
        ))
    else:
        findings.append(_finding(
            "ID-004", "Service account shell access", "OK",
            "No unexpected interactive service accounts detected",
            "Service identities appear hardened for non-interactive use.",
            "Keep system-account shell policy enforced.",
        ))
    return findings
def evaluate_sudoers(sudoers: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    max_nopasswd = int(policy.get("max_nopasswd_rules", 0))
    nopasswd_rules = sudoers.get("nopasswd_rules", [])
    wildcard_rules = sudoers.get("wildcard_rules", [])
    if len(nopasswd_rules) > max_nopasswd:
        findings.append(_finding(
            "ID-005", "Sudoers NOPASSWD policy", "RISK",
            f"{len(nopasswd_rules)} NOPASSWD rule(s) detected",
            "Passwordless privilege escalation increases misuse and compromise risk.",
            "Limit NOPASSWD to controlled automation identities only. Review with `sudo -l`.",
        ))
    else:
        findings.append(_finding(
            "ID-005", "Sudoers NOPASSWD policy", "OK",
            f"{len(nopasswd_rules)} NOPASSWD rule(s) - within policy",
            "Sudo password challenge policy is within baseline.",
            "Keep privileged commands behind authentication where feasible.",
        ))
    if wildcard_rules:
        findings.append(_finding(
            "ID-006", "Sudoers wildcard scope", "WARNING",
            f"{len(wildcard_rules)} broad sudo rule(s) detected",
            "Overly broad sudo scope weakens least-privilege enforcement.",
            "Refine sudo rules to explicit command allowlists in /etc/sudoers.d/.",
            confidence="medium",
        ))
    else:
        findings.append(_finding(
            "ID-006", "Sudoers wildcard scope", "OK",
            "No broad wildcard sudo rules detected",
            "Sudo policy appears constrained to specific commands.",
            "Continue periodic sudoers rule review with `visudo -c`.",
        ))
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
        findings.append(_finding(
            "AUTH-001", "Password expiration policy", "WARNING",
            "PASS_MAX_DAYS not found in /etc/login.defs",
            "Password rotation policy could not be confirmed.",
            f"Set `PASS_MAX_DAYS {max_days_threshold}` in /etc/login.defs and enforce via `chage`.",
        ))
    elif pass_max_days > max_days_threshold:
        findings.append(_finding(
            "AUTH-001", "Password expiration policy", "WARNING",
            f"PASS_MAX_DAYS={pass_max_days} (policy: <= {max_days_threshold})",
            "Long password lifetime increases the credential exposure window.",
            f"Set `PASS_MAX_DAYS {max_days_threshold}` in /etc/login.defs. Apply to existing accounts with `chage -M {max_days_threshold} <user>`.",
        ))
    else:
        findings.append(_finding(
            "AUTH-001", "Password expiration policy", "OK",
            f"PASS_MAX_DAYS={pass_max_days} (within policy threshold of {max_days_threshold})",
            "Password expiry policy aligns with baseline.",
            "Maintain current password lifetime policy.",
        ))
    if pass_min_len < 0:
        findings.append(_finding(
            "AUTH-002", "Password minimum length", "WARNING",
            "PASS_MIN_LEN not found in /etc/login.defs",
            "Password complexity baseline could not be verified.",
            f"Set `PASS_MIN_LEN {min_len_threshold}` in /etc/login.defs or configure via PAM pwquality.",
        ))
    elif pass_min_len < min_len_threshold:
        findings.append(_finding(
            "AUTH-002", "Password minimum length", "WARNING",
            f"PASS_MIN_LEN={pass_min_len} (policy: >= {min_len_threshold})",
            "Short passwords are more susceptible to brute-force attacks.",
            f"Increase `PASS_MIN_LEN` to {min_len_threshold} in /etc/login.defs.",
        ))
    else:
        findings.append(_finding(
            "AUTH-002", "Password minimum length", "OK",
            f"PASS_MIN_LEN={pass_min_len} (meets policy minimum of {min_len_threshold})",
            "Password minimum length meets policy.",
            "Keep complexity baseline enforced in PAM/login definitions.",
        ))
    lockout_configured = bool(auth_policy.get("lockout_configured", False))
    if lockout_configured:
        findings.append(_finding(
            "AUTH-003", "Account lockout controls", "OK",
            "PAM lockout module detected (pam_faillock or pam_tally)",
            "Brute-force resistance control is configured.",
            "Validate lockout thresholds and unlock timers with `faillock --user <user>` and review /etc/security/faillock.conf.",
        ))
    else:
        findings.append(_finding(
            "AUTH-003", "Account lockout controls", "RISK",
            "No PAM lockout module detected in common PAM configuration files",
            "Failed-login protection is missing - brute-force attacks on local accounts are unprotected.",
            "Configure pam_faillock: add `auth required pam_faillock.so` to /etc/pam.d/common-auth and set deny=5 in /etc/security/faillock.conf.",
        ))
    return findings
def evaluate_ssh(ssh: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    runtime_available = ssh.get("runtime_available", False)
    permit_root_login = ssh.get("permit_root_login", "").lower()
    allowed_root = [v.lower() for v in policy.get("ssh_root_login_allowed_values", ["no", "prohibit-password"])]
    if permit_root_login and permit_root_login not in allowed_root:
        findings.append(_finding(
            "SSH-001", "SSH root login policy", "RISK",
            f"PermitRootLogin={_display_value(ssh.get('permit_root_login', ''))}",
            "Direct root SSH access materially increases compromise impact.",
            "Set `PermitRootLogin no` in /etc/ssh/sshd_config and restart sshd.",
        ))
    else:
        findings.append(_finding(
            "SSH-001", "SSH root login policy", "OK",
            f"PermitRootLogin={_display_value(ssh.get('permit_root_login', ''))}",
            "Root login policy aligns with the hardened baseline.",
            "Keep root SSH disabled and use sudo-based admin workflows.",
        ))
    password_auth = ssh.get("password_authentication", "").lower()
    if password_auth in {"yes", "true"}:
        findings.append(_finding(
            "SSH-002", "SSH password authentication", "WARNING",
            f"PasswordAuthentication={_display_value(ssh.get('password_authentication', ''))}",
            "Password-based SSH logins are more susceptible to brute-force attacks.",
            "Set `PasswordAuthentication no` in /etc/ssh/sshd_config once key-based auth is confirmed.",
        ))
    else:
        findings.append(_finding(
            "SSH-002", "SSH password authentication", "OK",
            f"PasswordAuthentication={_display_value(ssh.get('password_authentication', ''))}",
            "SSH is not relying on password authentication.",
            "Maintain key-based authentication controls.",
        ))
    pubkey_auth = ssh.get("pubkey_authentication", "").lower()
    if pubkey_auth in {"no", "false"}:
        findings.append(_finding(
            "SSH-003", "SSH public key authentication", "WARNING",
            f"PubkeyAuthentication={_display_value(ssh.get('pubkey_authentication', ''))}",
            "Disabling key-based auth forces weaker authentication paths.",
            "Set `PubkeyAuthentication yes` in /etc/ssh/sshd_config.",
        ))
    else:
        findings.append(_finding(
            "SSH-003", "SSH public key authentication", "OK",
            f"PubkeyAuthentication={_display_value(ssh.get('pubkey_authentication', ''))}",
            "Public-key authentication is available for hardened access.",
            "Keep SSH key lifecycle management in place.",
        ))
    max_auth_tries_raw = ssh.get("max_auth_tries", "")
    max_auth_tries_threshold = int(policy.get("ssh_max_auth_tries", 4))
    try:
        max_auth_tries = int(max_auth_tries_raw)
    except ValueError:
        max_auth_tries = -1
    if max_auth_tries < 0:
        findings.append(_finding(
            "SSH-004", "SSH MaxAuthTries setting", "WARNING",
            "MaxAuthTries not explicitly set in sshd_config",
            "Default retry limit may exceed hardened policy expectations.",
            f"Add `MaxAuthTries {max_auth_tries_threshold}` to /etc/ssh/sshd_config.",
        ))
    elif max_auth_tries > max_auth_tries_threshold:
        findings.append(_finding(
            "SSH-004", "SSH MaxAuthTries setting", "WARNING",
            f"MaxAuthTries={max_auth_tries} (policy: <= {max_auth_tries_threshold})",
            "High retry limits increase brute-force opportunity.",
            f"Set `MaxAuthTries {max_auth_tries_threshold}` in /etc/ssh/sshd_config.",
        ))
    else:
        findings.append(_finding(
            "SSH-004", "SSH MaxAuthTries setting", "OK",
            f"MaxAuthTries={max_auth_tries} (within policy threshold)",
            "Authentication retry threshold aligns with baseline.",
            "Maintain limited SSH retry policy.",
        ))
    allow_users = ssh.get("allow_users", "")
    allow_groups = ssh.get("allow_groups", "")
    if not allow_users and not allow_groups:
        findings.append(_finding(
            "SSH-005", "SSH access allowlist", "WARNING",
            "AllowUsers and AllowGroups are not configured",
            "SSH access is open to all valid accounts on the system.",
            "Add `AllowUsers <user1> <user2>` or `AllowGroups sshusers` to /etc/ssh/sshd_config to limit SSH access scope.",
        ))
    else:
        configured = f"AllowUsers={allow_users}" if allow_users else f"AllowGroups={allow_groups}"
        findings.append(_finding(
            "SSH-005", "SSH access allowlist", "OK",
            f"SSH access restriction configured: {configured}",
            "SSH access scope is explicitly constrained.",
            "Review allowlist entries against the active admin roster each quarter.",
        ))
    service_state = ssh.get("service_state", "unknown")
    service_status = "OK" if service_state == "active" else "WARNING"
    findings.append(_finding(
        "SSH-006", "SSH service state", service_status,
        f"sshd service state: {service_state}",
        "Service state visibility is required for support readiness.",
        "Start the SSH service with `systemctl start ssh` and enable it with `systemctl enable ssh`."
        if service_status != "OK"
        else "SSH service is running. Confirm auto-start is enabled with `systemctl is-enabled ssh`.",
    ))
    weak_tokens = [token.lower() for token in policy.get("ssh_weak_algorithm_tokens", [])]
    runtime_ciphers = ssh.get("runtime_ciphers", "").lower()
    runtime_macs = ssh.get("runtime_macs", "").lower()
    runtime_kex = ssh.get("runtime_kex_algorithms", "").lower()
    crypto_surface = " ".join([runtime_ciphers, runtime_macs, runtime_kex])
    weak_present = sorted({token for token in weak_tokens if token and token in crypto_surface})
    if not runtime_available:
        findings.append(_finding(
            "SSH-007", "SSH crypto posture", "WARNING",
            "sshd -T output unavailable - re-run with sudo for full crypto inspection",
            "Effective crypto baseline cannot be verified without elevated privileges.",
            "Re-run SSHCR with `sudo` to enable `sshd -T` runtime inspection.",
            confidence="low",
        ))
    elif weak_present:
        findings.append(_finding(
            "SSH-007", "SSH crypto posture", "RISK",
            f"Weak algorithm tokens detected: {', '.join(weak_present)}",
            "Weak ciphers, MACs, or KEX algorithms reduce SSH transport security.",
            "Remove legacy algorithms from /etc/ssh/sshd_config. Use `ssh-audit` to validate the crypto baseline.",
        ))
    else:
        findings.append(_finding(
            "SSH-007", "SSH crypto posture", "OK",
            "No weak algorithm tokens detected in sshd runtime configuration",
            "Effective SSH crypto profile aligns with baseline checks.",
            "Keep algorithm policy updated against current hardening guidance (e.g. BSI, CIS, NIST).",
            confidence="medium",
        ))
    return findings
def evaluate_patch(patch: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    manager = patch.get("manager", "unknown")
    pending_updates = int(patch.get("pending_updates", -1))
    warn_threshold = int(policy.get("pending_updates_warning_threshold", 10))
    risk_threshold = int(policy.get("pending_updates_risk_threshold", 30))
    if manager == "unknown":
        findings.append(_finding(
            "PATCH-001", "Package manager visibility", "WARNING",
            "No supported package manager detected (apt/dnf/yum)",
            "Patch backlog could not be assessed.",
            "Add package manager support for this distribution in collectors.py.",
        ))
    elif pending_updates < 0:
        findings.append(_finding(
            "PATCH-001", "Package update backlog", "WARNING",
            f"Unable to determine pending updates via {manager}",
            "Patch exposure level is unknown.",
            f"Run `{manager} list --upgradable` manually and verify repository connectivity.",
        ))
    elif pending_updates >= risk_threshold:
        findings.append(_finding(
            "PATCH-001", "Package update backlog", "RISK",
            f"{pending_updates} pending updates detected via {manager}",
            "Large update backlog increases exposure to known vulnerabilities.",
            f"Run `sudo {manager} upgrade` to apply updates. Prioritise security updates: `sudo apt-get upgrade --with-new-pkgs -y`.",
        ))
    elif pending_updates >= warn_threshold:
        findings.append(_finding(
            "PATCH-001", "Package update backlog", "WARNING",
            f"{pending_updates} pending updates detected via {manager}",
            "Moderate patch backlog may include exploitable issues.",
            f"Schedule a patch cycle: `sudo {manager} upgrade`. Review changelogs for security-relevant updates.",
        ))
    else:
        findings.append(_finding(
            "PATCH-001", "Package update backlog", "OK",
            f"{pending_updates} pending updates - within policy threshold",
            "Patch posture is within the baseline threshold.",
            "Continue regular update cadence.",
        ))
    unattended = bool(patch.get("unattended_upgrades", False))
    findings.append(_finding(
        "PATCH-002", "Automatic security updates",
        "OK" if unattended else "WARNING",
        "Unattended security upgrades are enabled" if unattended else "Unattended upgrades are not enabled",
        "Automated patching reduces the window of vulnerability exposure.",
        "Automated patching is active - review /etc/apt/apt.conf.d/50unattended-upgrades for scope."
        if unattended
        else "Enable with: `sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades`.",
    ))
    return findings
def evaluate_hardening(hardening: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    auditd_state = hardening.get("auditd_state", "unknown")
    journald_state = hardening.get("journald_state", "unknown")
    journald_persistent = bool(hardening.get("journald_persistent", False))
    ntp_sync = hardening.get("ntp_sync", "")
    findings.append(_finding(
        "HARD-001", "Audit daemon status",
        "OK" if auditd_state == "active" else "WARNING",
        f"auditd service state: {auditd_state}",
        "System audit trail collection is required for forensic and compliance evidence."
        if auditd_state == "active"
        else "Audit event collection may be missing - this is a compliance gap in regulated environments.",
        "Monitor auditd with `auditctl -l` and review rules in /etc/audit/audit.rules."
        if auditd_state == "active"
        else "Install and enable auditd: `sudo apt install auditd && sudo systemctl enable --now auditd`.",
    ))
    if journald_state == "active" and journald_persistent:
        j_status, j_details, j_reason, j_rec = (
            "OK",
            "systemd-journald active with persistent log storage",
            "Persistent logs support forensic investigation and compliance evidence.",
            "Review retention limits in /etc/systemd/journald.conf (SystemMaxUse).",
        )
    elif journald_state == "active":
        j_status, j_details, j_reason, j_rec = (
            "WARNING",
            "systemd-journald active but /var/log/journal is missing (volatile logs)",
            "Logs are lost on reboot - forensic continuity is broken.",
            "Create persistent journal storage: `sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal`.",
        )
    else:
        j_status, j_details, j_reason, j_rec = (
            "WARNING",
            f"systemd-journald service state: {journald_state}",
            "Core system logging service is not confirmed active.",
            "Start journald: `sudo systemctl start systemd-journald`.",
        )
    findings.append(_finding("HARD-002", "Logging persistence", j_status, j_details, j_reason, j_rec))
    if ntp_sync == "yes":
        findings.append(_finding(
            "HARD-003", "Time synchronization", "OK",
            "NTP synchronized",
            "Timestamp integrity supports incident analysis and audit correlation.",
            "Confirm NTP servers with `timedatectl show-timesync` and ensure they are reliable.",
        ))
    elif ntp_sync == "no":
        findings.append(_finding(
            "HARD-003", "Time synchronization", "WARNING",
            "NTP is not synchronized",
            "Unsynchronized clocks weaken audit trails and incident correlation.",
            "Force sync: `sudo timedatectl set-ntp true` and verify with `timedatectl status`.",
        ))
    else:
        findings.append(_finding(
            "HARD-003", "Time synchronization", "WARNING",
            "NTP synchronization state could not be determined",
            "Time-sync posture cannot be verified.",
            "Install timesyncd or ntpd and enable: `sudo timedatectl set-ntp true`.",
        ))
    expected_sysctl = policy.get("expected_sysctl", {
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.default.accept_redirects": "0",
        "net.ipv4.tcp_syncookies": "1",
        "kernel.kptr_restrict": "1",
        "kernel.dmesg_restrict": "1",
    })
    observed_sysctl = hardening.get("sysctl_values", {})
    mismatches: List[str] = []
    missing: List[str] = []
    for key, expected in expected_sysctl.items():
        if key not in observed_sysctl:
            missing.append(key)
        elif str(observed_sysctl[key]) != str(expected):
            mismatches.append(f"{key}={observed_sysctl[key]} (expected {expected})")
    if mismatches:
        mismatch_fixes = "; ".join(
            f"sysctl -w {m.split('=')[0]}={m.split('expected ')[1].rstrip(')')}"
            for m in mismatches
            if "expected" in m
        )
        findings.append(_finding(
            "HARD-004", "Kernel/network sysctl baseline", "RISK",
            "; ".join(mismatches[:6]),
            "Kernel hardening baseline deviations increase network attack surface.",
            f"Apply fixes: `{mismatch_fixes}` - then persist in /etc/sysctl.d/99-sshcr-hardening.conf and run `sysctl --system`.",
        ))
    elif missing:
        findings.append(_finding(
            "HARD-004", "Kernel/network sysctl baseline", "WARNING",
            f"Could not read sysctl keys: {', '.join(missing[:6])}",
            "Sysctl posture could not be fully verified.",
            "Re-run with sufficient privileges to read /proc/sys entries.",
            confidence="low",
        ))
    else:
        findings.append(_finding(
            "HARD-004", "Kernel/network sysctl baseline", "OK",
            "All monitored sysctl values match the policy baseline",
            "Kernel and network hardening posture aligns with expected controls.",
            "Keep sysctl baseline enforced via /etc/sysctl.d/ and configuration management.",
        ))
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
