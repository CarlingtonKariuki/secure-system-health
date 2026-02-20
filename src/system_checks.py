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
        # First line is usually NAME or PRETTY_NAME; parse all for robustness.
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


def _get_disk_usages() -> List[Tuple[str, float, int, int]]:
    results: List[Tuple[str, float, int, int]] = []
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mountpoint, fstype = parts[0], parts[1], parts[2]
                if device.startswith("/dev/") and fstype not in {"tmpfs", "devtmpfs"}:
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
                if len(parts) < 3:
                    continue
                device, mountpoint, fstype = parts[0], parts[1], parts[2]
                if device.startswith("/dev/") and fstype not in {"tmpfs", "devtmpfs"}:
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


def _check_log_growth(log_dir: str = "/var/log", warn_mb: int = 512, risk_mb: int = 2048) -> Tuple[str, str]:
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


def run_system_health_checks() -> List[Dict[str, Any]]:
    """Run system health checks and return structured findings."""
    findings: List[Dict[str, Any]] = []

    os_name = _get_os_pretty_name()
    uptime_seconds = _get_uptime_seconds()
    uptime_str = _format_uptime(uptime_seconds)
    os_status = "OK" if uptime_seconds > 0 else "WARNING"
    findings.append(
        {
            "category": "System",
            "check": "OS version & uptime",
            "status": os_status,
            "details": f"{os_name}, uptime {uptime_str}",
            "risk_score": _risk_score(os_status),
            "reason": "Baseline host identification and uptime evidence",
        }
    )

    load_1 = _get_load_1min()
    cpu_count = _get_cpu_count()
    load_per_cpu = (load_1 / cpu_count) if cpu_count else load_1
    load_status = _status_from_threshold(load_per_cpu * 100, warn=70.0, risk=90.0)
    findings.append(
        {
            "category": "System",
            "check": "CPU load (1m)",
            "status": load_status,
            "details": f"Load {load_1:.2f} across {cpu_count} CPU(s)",
            "risk_score": _risk_score(load_status),
            "reason": "Sustained high load can degrade service availability",
        }
    )

    mem_total, mem_available, mem_used_percent = _get_memory_info()
    mem_status = _status_from_threshold(mem_used_percent, warn=80.0, risk=90.0)
    if mem_total > 0:
        details = f"Used {mem_used_percent:.1f}% of {mem_total / (1024**3):.1f} GB"
    else:
        details = "Memory stats unavailable"
        mem_status = "WARNING"
    findings.append(
        {
            "category": "System",
            "check": "Memory usage",
            "status": mem_status,
            "details": details,
            "risk_score": _risk_score(mem_status),
            "reason": "Memory pressure impacts stability and response time",
        }
    )

    disks = _get_disk_usages()
    if not disks:
        findings.append(
            {
                "category": "Storage",
                "check": "Disk usage",
                "status": "WARNING",
                "details": "No disk usage data found",
                "risk_score": _risk_score("WARNING"),
                "reason": "Cannot confirm disk headroom for safe operation",
            }
        )
    else:
        for mountpoint, percent, used, total in disks:
            status = _status_from_threshold(percent, warn=80.0, risk=90.0)
            findings.append(
                {
                    "category": "Storage",
                    "check": f"Disk usage {mountpoint}",
                    "status": status,
                    "details": f"{percent:.1f}% used ({used / (1024**3):.1f} GB / {total / (1024**3):.1f} GB)",
                    "risk_score": _risk_score(status),
                    "reason": "Low free space can cause service failures",
                }
            )

    inode_usages = _get_inode_usages()
    if inode_usages:
        for mountpoint, percent in inode_usages:
            status = _status_from_threshold(percent, warn=70.0, risk=90.0)
            findings.append(
                {
                    "category": "Storage",
                    "check": f"Inode usage {mountpoint}",
                    "status": status,
                    "details": f"{percent:.1f}% inode usage",
                    "risk_score": _risk_score(status),
                    "reason": "Inode exhaustion breaks file creation and logging",
                }
            )

    services = _load_critical_services()
    status, details = _check_services(services)
    findings.append(
        {
            "category": "Services",
            "check": "Critical services",
            "status": status,
            "details": details,
            "risk_score": _risk_score(status),
            "reason": "Required services must be available before commissioning",
        }
    )

    log_status, log_details = _check_log_growth()
    findings.append(
        {
            "category": "Logs",
            "check": "Log growth",
            "status": log_status,
            "details": log_details,
            "risk_score": _risk_score(log_status),
            "reason": "Runaway logs can exhaust disk and reduce availability",
        }
    )

    time_status, time_details = _check_time_sync()
    findings.append(
        {
            "category": "System",
            "check": "Time synchronization",
            "status": time_status,
            "details": time_details,
            "risk_score": _risk_score(time_status),
            "reason": "Accurate time is required for audit and incident response",
        }
    )

    return findings
