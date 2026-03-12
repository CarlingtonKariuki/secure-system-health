"""System health checks for SSHCR."""
from __future__ import annotations
from typing import Dict, List, Any, Tuple
import json
import os
import platform
import shutil
import subprocess
def _status_from_threshold(value: float, warn: float, risk: float) -> str:
    if value >= risk:
        return "RISK"
    if value >= warn:
        return "WARNING"
    return "OK"
def _read_first_line(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.readline().strip()
    except OSError:
        return ""
def _get_os_pretty_name() -> str:
    line = _read_first_line("/etc/os-release")
    if line:
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as handle:
                for raw in handle:
                    if raw.startswith("PRETTY_NAME="):
                        return raw.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
    return platform.platform()
def _get_uptime_seconds() -> float:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as handle:
            return float(handle.read().split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0
def _format_uptime(seconds: float) -> str:
    if seconds <= 0:
        return "unknown"
    minutes = int(seconds // 60)
    hours = minutes // 60
    days = hours // 24
    if days > 0:
        return f"{days}d {hours % 24}h"
    if hours > 0:
        return f"{hours}h {minutes % 60}m"
    return f"{minutes}m"
def _get_load_1min() -> float:
    try:
        return os.getloadavg()[0]
    except OSError:
        return 0.0
def _get_cpu_count() -> int:
    return os.cpu_count() or 1
def _get_memory_info() -> Tuple[int, int, float]:
    total = 0
    available = 0
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) * 1024
                elif line.startswith("MemAvailable:"):
                    available = int(line.split()[1]) * 1024
        if total > 0:
            used = total - available
            percent_used = (used / total) * 100.0
            return total, available, percent_used
    except (OSError, ValueError):
        pass
    return 0, 0, 0.0
def _is_relevant_mount(device: str, mountpoint: str, fstype: str, options: str) -> bool:
    if not device.startswith("/dev/"):
        return False
    ignored_fs = {"tmpfs", "devtmpfs", "squashfs", "iso9660", "overlay", "aufs"}
    if fstype in ignored_fs:
        return False
    if mountpoint.startswith("/snap/"):
        return False
    if "ro" in set(options.split(",")):
        return False
    return True
def _get_disk_usages() -> List[Tuple[str, float, int, int]]:
    results: List[Tuple[str, float, int, int]] = []
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 4:
                    continue
                device, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]
                if not _is_relevant_mount(device, mountpoint, fstype, options):
                    continue
                try:
                    usage = shutil.disk_usage(mountpoint)
                except OSError:
                    continue
                percent = (usage.used / usage.total) * 100.0 if usage.total else 0.0
                results.append((mountpoint, percent, usage.used, usage.total))
    except OSError:
        pass
    return results
def _get_inode_usages() -> List[Tuple[str, float]]:
    results: List[Tuple[str, float]] = []
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 4:
                    continue
                device, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]
                if not _is_relevant_mount(device, mountpoint, fstype, options):
                    continue
                try:
                    stats = os.statvfs(mountpoint)
                except OSError:
                    continue
                total = stats.f_files
                free = stats.f_ffree
                if total > 0:
                    used = total - free
                    percent = (used / total) * 100.0
                    results.append((mountpoint, percent))
    except OSError:
        pass
    return results
def _systemctl_is_active(service: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return result.stdout.strip() == "active"
    except OSError:
        return False
def _check_services(services: List[str]) -> Tuple[str, str]:
    missing = [name for name in services if not _systemctl_is_active(name)]
    if missing:
        return "WARNING", f"Not active: {', '.join(missing)}"
    return "OK", "All critical services active"
def _check_log_growth(
    log_dir: str = "/var/log", warn_mb: int = 512, risk_mb: int = 2048
) -> Tuple[str, str]:
    try:
        total_bytes = 0
        for root, _, files in os.walk(log_dir):
            for name in files:
                path = os.path.join(root, name)
                try:
                    total_bytes += os.path.getsize(path)
                except OSError:
                    continue
        total_mb = total_bytes / (1024 * 1024)
        status = _status_from_threshold(total_mb, warn=warn_mb, risk=risk_mb)
        return status, f"{total_mb:.1f} MB in {log_dir}"
    except OSError:
        return "WARNING", "Unable to read log directory"
def _load_critical_services() -> List[str]:
    default_services = ["ssh", "systemd-journald"]
    config_path = os.path.join(
        os.path.dirname(__file__), "..", "docs", "critical_services.json"
    )
    try:
        with open(os.path.abspath(config_path), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        services = data.get("critical_services", [])
        if isinstance(services, list) and services:
            return [str(s).strip() for s in services if str(s).strip()]
    except (OSError, json.JSONDecodeError):
        pass
    return default_services
def _check_time_sync() -> Tuple[str, str]:
    try:
        result = subprocess.run(
            ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        value = result.stdout.strip().lower()
        if value == "yes":
            return "OK", "NTP synchronized"
        if value == "no":
            return "WARNING", "NTP not synchronized"
    except OSError:
        pass
    return "WARNING", "Unable to determine NTP sync status"
def _risk_score(status: str) -> int:
    if status == "RISK":
        return 85
    if status == "WARNING":
        return 55
    return 10
def _finding(
    category: str,
    control_id: str,
    check: str,
    status: str,
    details: str,
    reason: str,
    recommendation: str,
    confidence: str = "high",
) -> Dict[str, Any]:
    return {
        "category": category,
        "control_id": control_id,
        "check": check,
        "status": status,
        "risk_score": _risk_score(status),
        "details": details,
        "reason": reason,
        "recommendation": recommendation,
        "confidence": confidence,
    }
def run_system_health_checks() -> List[Dict[str, Any]]:
    """Run system health checks and return structured findings."""
    findings: List[Dict[str, Any]] = []
    os_name = _get_os_pretty_name()
    uptime_seconds = _get_uptime_seconds()
    uptime_str = _format_uptime(uptime_seconds)
    os_status = "OK" if uptime_seconds > 0 else "WARNING"
    findings.append(
        _finding(
            "System", "SYS-001", "OS version & uptime", os_status,
            f"{os_name}, uptime {uptime_str}",
            "Baseline host identification and uptime evidence.",
            "Document OS version and uptime in commissioning records." if os_status == "OK"
            else "Investigate why uptime could not be determined; check /proc/uptime.",
            confidence="medium",
        )
    )
    load_1 = _get_load_1min()
    cpu_count = _get_cpu_count()
    load_per_cpu = (load_1 / cpu_count) if cpu_count else load_1
    load_status = _status_from_threshold(load_per_cpu * 100, warn=70.0, risk=90.0)
    findings.append(
        _finding(
            "System", "SYS-002", "CPU load (1m)", load_status,
            f"Load {load_1:.2f} across {cpu_count} CPU(s)",
            "Sustained high load can degrade service availability.",
            "Identify high-CPU processes with `top` or `ps aux --sort=-%cpu`."
            if load_status != "OK"
            else "Monitor load trends during peak operating windows.",
            confidence="medium",
        )
    )
    mem_total, mem_available, mem_used_percent = _get_memory_info()
    mem_status = _status_from_threshold(mem_used_percent, warn=80.0, risk=90.0)
    if mem_total > 0:
        details = f"Used {mem_used_percent:.1f}% of {mem_total / (1024**3):.1f} GB"
        recommendation = (
            "Identify memory-heavy processes with `ps aux --sort=-%mem` and consider adding swap or RAM."
            if mem_status != "OK"
            else "Monitor memory usage trends; set alerting at 85% threshold."
        )
    else:
        details = "Memory stats unavailable"
        mem_status = "WARNING"
        recommendation = "Verify /proc/meminfo is accessible and re-run with sufficient privileges."
    findings.append(
        _finding(
            "System", "SYS-003", "Memory usage", mem_status,
            details,
            "Memory pressure impacts stability and response time.",
            recommendation,
            confidence="medium",
        )
    )
    disks = _get_disk_usages()
    if not disks:
        findings.append(
            _finding(
                "Storage", "STG-001", "Disk usage", "WARNING",
                "No disk usage data found",
                "Cannot confirm disk headroom for safe operation.",
                "Check /proc/mounts and verify disk devices are accessible.",
            )
        )
    else:
        for idx, (mountpoint, percent, used, total) in enumerate(disks, start=1):
            status = _status_from_threshold(percent, warn=80.0, risk=90.0)
            findings.append(
                _finding(
                    "Storage", f"STG-{idx:03d}", f"Disk usage {mountpoint}", status,
                    f"{percent:.1f}% used ({used / (1024**3):.1f} GB / {total / (1024**3):.1f} GB)",
                    "Low free space can cause service failures and logging gaps.",
                    f"Free space on {mountpoint}: remove unused files, rotate logs, or expand volume."
                    if status != "OK"
                    else f"Monitor {mountpoint} usage; alert at 80% threshold.",
                    confidence="high",
                )
            )
    inode_usages = _get_inode_usages()
    if inode_usages:
        for idx, (mountpoint, percent) in enumerate(inode_usages, start=1):
            status = _status_from_threshold(percent, warn=70.0, risk=90.0)
            findings.append(
                _finding(
                    "Storage", f"INO-{idx:03d}", f"Inode usage {mountpoint}", status,
                    f"{percent:.1f}% inode usage",
                    "Inode exhaustion breaks file creation and logging.",
                    f"Run `find {mountpoint} -xdev -printf '%h\\\\n' | sort | uniq -c | sort -rn | head` to locate inode-heavy directories."
                    if status != "OK"
                    else "Inode usage is healthy; no action required.",
                    confidence="high",
                )
            )
    services = _load_critical_services()
    svc_status, svc_details = _check_services(services)
    findings.append(
        _finding(
            "Services", "SVC-001", "Critical services", svc_status,
            svc_details,
            "Required services must be available before commissioning.",
            "Start missing services with `systemctl start <service>` and enable on boot with `systemctl enable <service>`."
            if svc_status != "OK"
            else "All critical services are running. Verify auto-start is configured with `systemctl is-enabled`.",
            confidence="high",
        )
    )
    log_status, log_details = _check_log_growth()
    findings.append(
        _finding(
            "Logs", "LOG-001", "Log growth", log_status,
            log_details,
            "Runaway logs can exhaust disk and reduce availability.",
            "Configure logrotate for /var/log and review journald retention in /etc/systemd/journald.conf."
            if log_status != "OK"
            else "Log volume is within normal range; ensure logrotate is scheduled.",
            confidence="medium",
        )
    )
    time_status, time_details = _check_time_sync()
    findings.append(
        _finding(
            "System", "SYS-004", "Time synchronization", time_status,
            time_details,
            "Accurate time is required for audit trails and incident response.",
            "Enable NTP with `timedatectl set-ntp true` and verify with `timedatectl status`."
            if time_status != "OK"
            else "NTP is synchronized. Confirm NTP servers are reachable and accurate.",
            confidence="high",
        )
    )
    return findings
