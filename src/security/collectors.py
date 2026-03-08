"""Evidence collectors for security checks."""

from __future__ import annotations

from typing import Any, Dict, List
import glob
import os
import shutil
import subprocess


def _run_command(args: List[str]) -> str:
    try:
        result = subprocess.run(
            args,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


def _load_login_defs() -> Dict[str, str]:
    values: Dict[str, str] = {}
    content = _read_text("/etc/login.defs")
    for line in content.splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        parts = clean.split()
        if len(parts) >= 2:
            values[parts[0]] = parts[1]
    return values


def _load_pam_content() -> str:
    paths = [
        "/etc/pam.d/common-auth",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
    ]
    chunks = []
    for path in paths:
        content = _read_text(path)
        if content:
            chunks.append(content)
    return "\n".join(chunks)


def _parse_sshd_config() -> Dict[str, str]:
    directives: Dict[str, str] = {}
    files = ["/etc/ssh/sshd_config"]
    files.extend(sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")))
    for path in files:
        content = _read_text(path)
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "#" in line:
                line = line.split("#", 1)[0].strip()
            parts = line.split(None, 1)
            if len(parts) == 2:
                directives[parts[0].lower()] = parts[1].strip()
    return directives


def collect_identity_evidence() -> Dict[str, Any]:
    uid0_non_root: List[str] = []
    service_shell_accounts: List[str] = []
    passwd_content = _read_text("/etc/passwd")
    for line in passwd_content.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user = parts[0]
        try:
            uid = int(parts[2])
        except ValueError:
            continue
        shell = parts[6]
        if uid == 0 and user != "root":
            uid0_non_root.append(user)
        if 0 < uid < 1000 and not shell.endswith(("nologin", "false", "sync")):
            service_shell_accounts.append(user)

    empty_password_accounts: List[str] = []
    shadow_readable = False
    shadow_content = _read_text("/etc/shadow")
    if shadow_content:
        shadow_readable = True
        for line in shadow_content.splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            if parts[1] == "":
                empty_password_accounts.append(parts[0])

    sudo_users: List[str] = []
    for group in ("sudo", "wheel"):
        output = _run_command(["getent", "group", group])
        if output and ":" in output:
            members = output.split(":")[-1].strip()
            if members:
                sudo_users.extend([member for member in members.split(",") if member])
    sudo_users = sorted(set(sudo_users))

    root_status = _run_command(["passwd", "-S", "root"])

    return {
        "uid0_non_root": sorted(uid0_non_root),
        "service_shell_accounts": sorted(set(service_shell_accounts)),
        "empty_password_accounts": sorted(empty_password_accounts),
        "shadow_readable": shadow_readable,
        "sudo_users": sudo_users,
        "root_status": root_status,
    }


def collect_sudoers_evidence() -> Dict[str, Any]:
    files = ["/etc/sudoers"]
    files.extend(sorted(glob.glob("/etc/sudoers.d/*")))
    entries: List[str] = []
    for path in files:
        content = _read_text(path)
        if not content:
            continue
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line)

    nopasswd_rules = [line for line in entries if "NOPASSWD" in line]
    wildcard_rules = [line for line in entries if " ALL" in line and "(" in line]
    return {
        "entries_count": len(entries),
        "nopasswd_rules": nopasswd_rules,
        "wildcard_rules": wildcard_rules,
    }


def collect_auth_policy_evidence() -> Dict[str, Any]:
    login_defs = _load_login_defs()
    pam_content = _load_pam_content().lower()
    lockout_configured = ("pam_faillock.so" in pam_content) or ("pam_tally2.so" in pam_content)
    return {
        "pass_max_days": login_defs.get("PASS_MAX_DAYS", ""),
        "pass_min_len": login_defs.get("PASS_MIN_LEN", ""),
        "lockout_configured": lockout_configured,
    }


def collect_ssh_evidence() -> Dict[str, Any]:
    directives = _parse_sshd_config()
    service_state = _run_command(["systemctl", "is-active", "sshd"]) or _run_command(
        ["systemctl", "is-active", "ssh"]
    )
    ssh_runtime = _run_command(["sshd", "-T"])
    runtime_map: Dict[str, str] = {}
    for line in ssh_runtime.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            runtime_map[parts[0].lower()] = parts[1].strip()

    return {
        "permit_root_login": directives.get("permitrootlogin", ""),
        "password_authentication": directives.get("passwordauthentication", ""),
        "pubkey_authentication": directives.get("pubkeyauthentication", ""),
        "max_auth_tries": directives.get("maxauthtries", ""),
        "allow_users": directives.get("allowusers", ""),
        "allow_groups": directives.get("allowgroups", ""),
        "service_state": service_state or "unknown",
        "runtime_ciphers": runtime_map.get("ciphers", ""),
        "runtime_macs": runtime_map.get("macs", ""),
        "runtime_kex_algorithms": runtime_map.get("kexalgorithms", ""),
    }


def collect_patch_evidence() -> Dict[str, Any]:
    manager = "unknown"
    pending_updates = -1
    if shutil.which("apt"):
        manager = "apt"
        output = _run_command(["apt", "list", "--upgradable"])
        if output:
            pending_updates = len(
                [
                    line
                    for line in output.splitlines()
                    if line and not line.startswith("Listing...")
                ]
            )
    elif shutil.which("dnf"):
        manager = "dnf"
        output = _run_command(["dnf", "check-update"])
        if output:
            pending_updates = len([line for line in output.splitlines() if "." in line and " " in line])
    elif shutil.which("yum"):
        manager = "yum"
        output = _run_command(["yum", "check-update"])
        if output:
            pending_updates = len([line for line in output.splitlines() if "." in line and " " in line])

    unattended_enabled = False
    auto_upgrades = _read_text("/etc/apt/apt.conf.d/20auto-upgrades")
    if "APT::Periodic::Unattended-Upgrade \"1\"" in auto_upgrades:
        unattended_enabled = True

    return {
        "manager": manager,
        "pending_updates": pending_updates,
        "unattended_upgrades": unattended_enabled,
    }


def collect_hardening_evidence() -> Dict[str, Any]:
    auditd_state = _run_command(["systemctl", "is-active", "auditd"]) or "unknown"
    journald_state = _run_command(["systemctl", "is-active", "systemd-journald"]) or "unknown"
    journald_persistent = os.path.isdir("/var/log/journal")
    ntp_sync = _run_command(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).lower()
    sysctl_keys = [
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.default.accept_redirects",
        "net.ipv4.tcp_syncookies",
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
    ]
    sysctl_values: Dict[str, str] = {}
    for key in sysctl_keys:
        proc_path = "/proc/sys/" + key.replace(".", "/")
        value = _read_text(proc_path).strip()
        if value:
            sysctl_values[key] = value

    return {
        "auditd_state": auditd_state,
        "journald_state": journald_state,
        "journald_persistent": journald_persistent,
        "ntp_sync": ntp_sync,
        "sysctl_values": sysctl_values,
    }


def collect_security_evidence() -> Dict[str, Any]:
    return {
        "identity": collect_identity_evidence(),
        "sudoers": collect_sudoers_evidence(),
        "auth_policy": collect_auth_policy_evidence(),
        "ssh": collect_ssh_evidence(),
        "patch": collect_patch_evidence(),
        "hardening": collect_hardening_evidence(),
    }
