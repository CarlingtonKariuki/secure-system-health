"""Network readiness checks for SSHCR."""

from __future__ import annotations

from typing import Dict, List, Any, Set, Tuple
import json
import os
import shutil
import subprocess


def _risk_score(status: str) -> int:
    if status == "RISK":
        return 85
    if status == "WARNING":
        return 55
    return 10


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


def _parse_port(endpoint: str) -> int | None:
    value = endpoint.strip("[]")
    if ":" not in value:
        return None
    port_text = value.rsplit(":", 1)[1]
    if port_text.isdigit():
        return int(port_text)
    return None


def _collect_port_entries() -> Tuple[str, List[Dict[str, str]]]:
    ss_output = _run_command(["ss", "-tulpn"])
    if ss_output:
        entries: List[Dict[str, str]] = []
        for line in ss_output.splitlines():
            if line.startswith("Netid") or not line.strip():
                continue
            parts = line.split(None, 6)
            if len(parts) < 6:
                continue
            proto = parts[0]
            state = parts[1]
            if proto.startswith("tcp") and state != "LISTEN":
                continue
            if not (proto.startswith("tcp") or proto.startswith("udp")):
                continue
            local = parts[4]
            process = parts[6] if len(parts) > 6 else "-"
            entries.append({"proto": proto, "local": local, "process": process})
        return "ss", entries

    netstat_output = _run_command(["netstat", "-tulnp"])
    if netstat_output:
        entries = []
        for line in netstat_output.splitlines():
            if line.startswith("Proto") or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            proto = parts[0]
            if not (proto.startswith("tcp") or proto.startswith("udp")):
                continue
            local = parts[3]
            process = parts[6] if len(parts) > 6 else "-"
            entries.append({"proto": proto, "local": local, "process": process})
        return "netstat", entries

    return "none", []


def _is_loopback_endpoint(endpoint: str) -> bool:
    return endpoint.startswith("127.") or endpoint.startswith("[::1]") or endpoint.startswith("::1")


def _check_interfaces() -> Dict[str, Any]:
    output = _run_command(["ip", "-brief", "address"])
    if output:
        active = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            iface = parts[0]
            state = parts[1]
            if iface == "lo":
                continue
            has_ip = any(token.count(".") == 3 or ":" in token for token in parts[2:])
            if state.upper() == "UP" and has_ip:
                active.append(iface)
        if active:
            details = f"Active interfaces with IP: {', '.join(sorted(active))}"
            return {
                "status": "OK",
                "details": details,
                "reason": "Host has routable interfaces ready for communication",
                "data": {"interfaces": sorted(active)},
            }
        return {
            "status": "RISK",
            "details": "No non-loopback interface is UP with an IP address",
            "reason": "System may be unreachable for commissioning or support",
            "data": {"interfaces": []},
        }

    try:
        ifaces = [name for name in os.listdir("/sys/class/net") if name != "lo"]
    except OSError:
        ifaces = []
    if ifaces:
        return {
            "status": "WARNING",
            "details": f"`ip` command unavailable; detected interfaces: {', '.join(sorted(ifaces))}",
            "reason": "Interface state/IP verification incomplete due to missing primary tooling",
            "data": {"interfaces": sorted(ifaces)},
        }
    return {
        "status": "RISK",
        "details": "Unable to detect network interfaces",
        "reason": "Network readiness cannot be established",
        "data": {"interfaces": []},
    }


def _check_open_ports() -> Dict[str, Any]:
    tool, entries = _collect_port_entries()
    if tool == "none":
        return {
            "status": "WARNING",
            "details": "Unable to enumerate listening ports (`ss`/`netstat` unavailable)",
            "reason": "Service exposure validation is incomplete",
            "data": {"entries": [], "ports": []},
        }

    if not entries:
        return {
            "status": "WARNING",
            "details": f"No listening TCP/UDP ports detected via `{tool}`",
            "reason": "No exposed services may indicate incomplete commissioning",
            "data": {"entries": [], "ports": []},
        }

    endpoints = [entry["local"] for entry in entries]
    sample = ", ".join(endpoints[:5])
    ports = sorted(
        {
            port
            for port in (_parse_port(entry["local"]) for entry in entries)
            if port is not None
        }
    )
    return {
        "status": "OK",
        "details": f"{len(entries)} listening entries via `{tool}` (sample: {sample})",
        "reason": "Port visibility confirms active network service bindings",
        "data": {"entries": entries, "ports": ports},
    }


def _check_port_process_mapping(entries: List[Dict[str, str]]) -> Dict[str, Any]:
    if not entries:
        return {
            "status": "WARNING",
            "details": "No listening entries available for process mapping",
            "reason": "Cannot attribute network exposure to specific services",
        }

    mapped = [entry for entry in entries if entry.get("process") and entry["process"] != "-"]
    if not mapped:
        return {
            "status": "WARNING",
            "details": "Process owner info unavailable (permissions or tooling limitation)",
            "reason": "Exposure ownership cannot be fully validated",
        }

    sample = ", ".join(f"{entry['local']}->{entry['process']}" for entry in mapped[:4])
    if len(mapped) < len(entries):
        return {
            "status": "WARNING",
            "details": f"Mapped {len(mapped)}/{len(entries)} listeners (sample: {sample})",
            "reason": "Some open ports are missing owning process details",
        }
    return {
        "status": "OK",
        "details": f"Mapped all listening ports to owning process (sample: {sample})",
        "reason": "Service ownership is traceable for operational accountability",
    }


def _load_allowed_ports() -> Set[int]:
    default_ports = {22, 53, 67, 68, 80, 123, 443}
    config_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "docs", "allowed_ports.json")
    )
    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        ports = data.get("allowed_ports", [])
        if isinstance(ports, list):
            allowed = {int(port) for port in ports if str(port).isdigit()}
            return allowed or default_ports
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return default_ports


def _check_allowed_ports_policy(entries: List[Dict[str, str]]) -> Dict[str, Any]:
    allowed_ports = _load_allowed_ports()
    exposed: Set[int] = set()
    unexpected: Set[int] = set()
    for entry in entries:
        port = _parse_port(entry["local"])
        if port is None:
            continue
        exposed.add(port)
        if _is_loopback_endpoint(entry["local"]):
            continue
        if port not in allowed_ports:
            unexpected.add(port)

    if not exposed:
        return {
            "status": "WARNING",
            "details": "No parseable listening ports found for policy validation",
            "reason": "Allowed-port policy could not be evaluated",
            "data": {"exposed_ports": []},
        }

    if unexpected:
        unexpected_text = ", ".join(str(port) for port in sorted(unexpected))
        return {
            "status": "RISK",
            "details": f"Unexpected exposed ports: {unexpected_text}",
            "reason": "Open ports outside approved baseline increase attack surface",
            "data": {"exposed_ports": sorted(exposed)},
        }

    return {
        "status": "OK",
        "details": "All non-loopback listening ports are within allowed policy",
        "reason": "Service exposure aligns with network baseline",
        "data": {"exposed_ports": sorted(exposed)},
    }


def _check_firewall() -> Dict[str, Any]:
    if shutil.which("ufw"):
        ufw_out = _run_command(["ufw", "status"])
        if "Status: active" in ufw_out:
            return {
                "status": "OK",
                "details": "UFW is active",
                "reason": "Host-level ingress filtering is enabled",
                "data": {"firewall": "active"},
            }
        if "Status: inactive" in ufw_out:
            return {
                "status": "RISK",
                "details": "UFW is inactive",
                "reason": "No local firewall policy is currently enforced",
                "data": {"firewall": "inactive"},
            }

    if shutil.which("nft"):
        nft_out = _run_command(["nft", "list", "ruleset"])
        if nft_out:
            return {
                "status": "OK",
                "details": "nftables ruleset detected",
                "reason": "Packet filtering rules are present",
                "data": {"firewall": "active"},
            }

    if shutil.which("iptables"):
        ipt_out = _run_command(["iptables", "-S"])
        if ipt_out:
            return {
                "status": "OK",
                "details": "iptables rules detected",
                "reason": "Packet filtering rules are present",
                "data": {"firewall": "active"},
            }

    return {
        "status": "WARNING",
        "details": "No firewall state confirmed (ufw/nft/iptables checks inconclusive)",
        "reason": "Firewall control could not be verified on this host",
        "data": {"firewall": "unknown"},
    }


def _check_dns_gateway() -> Dict[str, Any]:
    nameservers: List[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("nameserver "):
                    parts = line.split()
                    if len(parts) >= 2:
                        nameservers.append(parts[1])
    except OSError:
        pass

    route_out = _run_command(["ip", "route"])
    default_route = ""
    if route_out:
        for line in route_out.splitlines():
            if line.startswith("default "):
                default_route = line
                break

    if not nameservers and not default_route:
        return {
            "status": "RISK",
            "details": "No DNS nameserver and no default route detected",
            "reason": "External service resolution and routing are unavailable",
            "data": {"nameservers": [], "default_route": ""},
        }
    if not nameservers or not default_route:
        missing = "DNS nameserver" if not nameservers else "default route"
        return {
            "status": "WARNING",
            "details": f"Missing {missing}",
            "reason": "Partial network configuration may break dependency connectivity",
            "data": {"nameservers": nameservers, "default_route": default_route},
        }

    return {
        "status": "OK",
        "details": f"DNS: {', '.join(nameservers[:2])}; Gateway: {default_route}",
        "reason": "Name resolution and default routing are configured",
        "data": {"nameservers": nameservers, "default_route": default_route},
    }


def _network_baseline_path() -> str:
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "reports", "network_baseline.json")
    )


def _load_network_baseline() -> Dict[str, Any]:
    path = _network_baseline_path()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _save_network_baseline(snapshot: Dict[str, Any]) -> None:
    path = _network_baseline_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=2, sort_keys=True)


def _check_network_baseline_drift(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    previous = _load_network_baseline()
    if not previous:
        _save_network_baseline(snapshot)
        return {
            "status": "OK",
            "details": "Baseline created (first run)",
            "reason": "Future runs will detect interface/port/DNS/gateway drift",
        }

    changes: List[str] = []
    keys = ["interfaces", "exposed_ports", "nameservers", "default_route"]
    for key in keys:
        if previous.get(key) != snapshot.get(key):
            changes.append(key)

    if changes:
        _save_network_baseline(snapshot)
        changed_text = ", ".join(changes)
        return {
            "status": "WARNING",
            "details": f"Network baseline drift detected in: {changed_text}",
            "reason": "Unexpected network changes can indicate misconfiguration or exposure drift",
        }

    _save_network_baseline(snapshot)
    return {
        "status": "OK",
        "details": "No network baseline drift detected",
        "reason": "Current network state matches previous assessment baseline",
    }


def run_network_checks() -> List[Dict[str, Any]]:
    """Run network checks and return structured findings."""
    findings: List[Dict[str, Any]] = []

    interfaces = _check_interfaces()
    findings.append(
        {
            "category": "Network",
            "check": "Active interfaces",
            "status": interfaces["status"],
            "risk_score": _risk_score(interfaces["status"]),
            "details": interfaces["details"],
            "reason": interfaces["reason"],
        }
    )

    ports = _check_open_ports()
    entries = ports.get("data", {}).get("entries", [])
    findings.append(
        {
            "category": "Network",
            "check": "Open ports",
            "status": ports["status"],
            "risk_score": _risk_score(ports["status"]),
            "details": ports["details"],
            "reason": ports["reason"],
        }
    )

    mapping = _check_port_process_mapping(entries)
    findings.append(
        {
            "category": "Network",
            "check": "Port-to-process mapping",
            "status": mapping["status"],
            "risk_score": _risk_score(mapping["status"]),
            "details": mapping["details"],
            "reason": mapping["reason"],
        }
    )

    allowed = _check_allowed_ports_policy(entries)
    findings.append(
        {
            "category": "Network",
            "check": "Allowed ports policy",
            "status": allowed["status"],
            "risk_score": _risk_score(allowed["status"]),
            "details": allowed["details"],
            "reason": allowed["reason"],
        }
    )

    firewall = _check_firewall()
    findings.append(
        {
            "category": "Network",
            "check": "Firewall status",
            "status": firewall["status"],
            "risk_score": _risk_score(firewall["status"]),
            "details": firewall["details"],
            "reason": firewall["reason"],
        }
    )

    dns_gateway = _check_dns_gateway()
    findings.append(
        {
            "category": "Network",
            "check": "DNS & gateway",
            "status": dns_gateway["status"],
            "risk_score": _risk_score(dns_gateway["status"]),
            "details": dns_gateway["details"],
            "reason": dns_gateway["reason"],
        }
    )

    snapshot = {
        "interfaces": interfaces.get("data", {}).get("interfaces", []),
        "exposed_ports": allowed.get("data", {}).get("exposed_ports", []),
        "nameservers": dns_gateway.get("data", {}).get("nameservers", []),
        "default_route": dns_gateway.get("data", {}).get("default_route", ""),
        "firewall": firewall.get("data", {}).get("firewall", "unknown"),
    }
    drift = _check_network_baseline_drift(snapshot)
    findings.append(
        {
            "category": "Network",
            "check": "Network baseline drift",
            "status": drift["status"],
            "risk_score": _risk_score(drift["status"]),
            "details": drift["details"],
            "reason": drift["reason"],
        }
    )

    return findings
