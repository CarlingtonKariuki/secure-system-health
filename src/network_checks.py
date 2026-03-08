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
def _is_loopback_or_local_only(endpoint: str) -> bool:
    """Return True for endpoints that are loopback-only and not externally reachable."""
    local = endpoint.strip("[]").split("%")[0]
    # IPv4 loopback
    if local.startswith("127."):
        return True
    # IPv6 loopback
    if local in {"::1", "[::1]"}:
        return True
    return False
def _is_wildcard_bind(endpoint: str) -> bool:
    """Return True for 0.0.0.0 and :: wildcard binds (exposed on all interfaces)."""
    local = endpoint.strip("[]").split(":")[0] if ":" not in endpoint.replace("[", "").replace("]", "") else endpoint.split("]")[0].strip("[")
    addr = endpoint.split("%")[0]
    if addr.startswith("0.0.0.0") or addr.startswith("*"):
        return True
    stripped = endpoint.strip("[]").rsplit(":", 1)[0].strip("[]")
    if stripped in {"", "::", "0.0.0.0", "*"}:
        return True
    return False
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
            return {
                "status": "OK",
                "details": f"Active interfaces with IP: {', '.join(sorted(active))}",
                "reason": "Host has routable interfaces ready for communication.",
                "recommendation": "Document active interfaces and IP assignments in network inventory.",
                "data": {"interfaces": sorted(active)},
            }
        return {
            "status": "RISK",
            "details": "No non-loopback interface is UP with an IP address",
            "reason": "System may be unreachable for commissioning or support.",
            "recommendation": "Bring up the required network interface with `ip link set <iface> up` and assign an IP.",
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
            "reason": "Interface state/IP verification incomplete due to missing tooling.",
            "recommendation": "Install `iproute2` package to enable full interface inspection.",
            "data": {"interfaces": sorted(ifaces)},
        }
    return {
        "status": "RISK",
        "details": "Unable to detect network interfaces",
        "reason": "Network readiness cannot be established.",
        "recommendation": "Verify network hardware is present and drivers are loaded.",
        "data": {"interfaces": []},
    }
def _check_open_ports() -> Dict[str, Any]:
    tool, entries = _collect_port_entries()
    if tool == "none":
        return {
            "status": "WARNING",
            "details": "Unable to enumerate listening ports (`ss`/`netstat` unavailable)",
            "reason": "Service exposure validation is incomplete.",
            "recommendation": "Install `iproute2` (for `ss`) or `net-tools` (for `netstat`) and re-run.",
            "data": {"entries": [], "ports": []},
        }
    if not entries:
        return {
            "status": "WARNING",
            "details": f"No listening TCP/UDP ports detected via `{tool}`",
            "reason": "No exposed services may indicate incomplete commissioning.",
            "recommendation": "Verify expected services are started and listening on correct ports.",
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
        "reason": "Port visibility confirms active network service bindings.",
        "recommendation": "Review all listening ports against the approved service inventory.",
        "data": {"entries": entries, "ports": ports},
    }
def _check_port_process_mapping(entries: List[Dict[str, str]]) -> Dict[str, Any]:
    if not entries:
        return {
            "status": "WARNING",
            "details": "No listening entries available for process mapping",
            "reason": "Cannot attribute network exposure to specific services.",
            "recommendation": "Ensure port scan was successful and re-run with elevated privileges.",
        }
    mapped = [entry for entry in entries if entry.get("process") and entry["process"] != "-"]
    if not mapped:
        return {
            "status": "WARNING",
            "details": "Process owner info unavailable - re-run with sudo for full mapping",
            "reason": "Exposure ownership cannot be fully validated without elevated privileges.",
            "recommendation": "Re-run SSHCR with `sudo` to enable full port-to-process attribution.",
        }
    sample = ", ".join(f"{entry['local']}->{entry['process']}" for entry in mapped[:4])
    unmapped_count = len(entries) - len(mapped)
    if unmapped_count > 0:
        return {
            "status": "WARNING",
            "details": f"Mapped {len(mapped)}/{len(entries)} listeners (sample: {sample})",
            "reason": f"{unmapped_count} open port(s) have no owning process - elevated privileges required.",
            "recommendation": "Re-run with `sudo` to resolve all listener-to-process mappings.",
        }
    return {
        "status": "OK",
        "details": f"Mapped all {len(entries)} listening ports to owning processes (sample: {sample})",
        "reason": "Service ownership is fully traceable for operational accountability.",
        "recommendation": "Review the process list and remove any unexpected listeners.",
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
        # Only flag externally reachable binds - skip pure loopback
        if _is_loopback_or_local_only(entry["local"]):
            continue
        if port not in allowed_ports:
            unexpected.add(port)
    if not exposed:
        return {
            "status": "WARNING",
            "details": "No parseable listening ports found for policy validation",
            "reason": "Allowed-port policy could not be evaluated.",
            "recommendation": "Verify port scanning completed successfully and re-run.",
            "data": {"exposed_ports": []},
        }
    if unexpected:
        unexpected_text = ", ".join(str(port) for port in sorted(unexpected))
        return {
            "status": "RISK",
            "details": f"Unexpected exposed ports: {unexpected_text}",
            "reason": "Open ports outside the approved baseline increase attack surface.",
            "recommendation": (
                f"For each unexpected port ({unexpected_text}): identify the owning process, "
                "determine if it is required, and either add it to docs/allowed_ports.json "
                "or stop the service. Port 179 (BGP) is only expected on routing infrastructure."
            ),
            "data": {"exposed_ports": sorted(exposed)},
        }
    return {
        "status": "OK",
        "details": "All non-loopback listening ports are within the allowed policy",
        "reason": "Service exposure aligns with the network baseline.",
        "recommendation": "Review allowed_ports.json periodically and remove stale entries.",
        "data": {"exposed_ports": sorted(exposed)},
    }
def _check_firewall() -> Dict[str, Any]:
    # UFW
    if shutil.which("ufw"):
        ufw_out = _run_command(["ufw", "status"])
        if "Status: active" in ufw_out:
            return {
                "status": "OK",
                "details": "UFW firewall is active",
                "reason": "Host-level ingress filtering is enabled.",
                "recommendation": "Review UFW rules with `ufw status verbose` and ensure only required ports are open.",
                "data": {"firewall": "active", "tool": "ufw"},
            }
        if "Status: inactive" in ufw_out:
            return {
                "status": "RISK",
                "details": "UFW is installed but inactive",
                "reason": "No local firewall policy is currently enforced.",
                "recommendation": "Enable UFW with `ufw enable` and define ingress rules before production deployment.",
                "data": {"firewall": "inactive", "tool": "ufw"},
            }
    # nftables
    if shutil.which("nft"):
        nft_out = _run_command(["nft", "list", "ruleset"])
        if nft_out and len(nft_out.strip().splitlines()) > 2:
            return {
                "status": "OK",
                "details": "nftables ruleset is active",
                "reason": "Packet filtering rules are present and enforced.",
                "recommendation": "Audit nftables rules with `nft list ruleset` and verify rule intent.",
                "data": {"firewall": "active", "tool": "nftables"},
            }
    # iptables - check for non-default (non-ACCEPT policy) rules
    if shutil.which("iptables"):
        ipt_out = _run_command(["iptables", "-S"])
        if ipt_out:
            non_default = [
                line for line in ipt_out.splitlines()
                if line.startswith("-A") or "DROP" in line or "REJECT" in line
            ]
            if non_default:
                return {
                    "status": "OK",
                    "details": f"iptables rules active ({len(non_default)} non-default rule(s))",
                    "reason": "Packet filtering rules are present and enforced.",
                    "recommendation": "Review iptables rules with `iptables -L -v -n` and ensure rules are persisted across reboots.",
                    "data": {"firewall": "active", "tool": "iptables"},
                }
            return {
                "status": "WARNING",
                "details": "iptables present but only default ACCEPT policies detected",
                "reason": "No meaningful filtering rules are in place.",
                "recommendation": "Define iptables INPUT/OUTPUT rules or switch to ufw/nftables for easier management.",
                "data": {"firewall": "default-accept", "tool": "iptables"},
            }
    return {
        "status": "WARNING",
        "details": "No firewall state confirmed (ufw/nft/iptables checks inconclusive)",
        "reason": "Firewall control could not be verified on this host.",
        "recommendation": "Install and enable a firewall: `apt install ufw && ufw enable` on Debian/Ubuntu/Kali.",
        "data": {"firewall": "unknown", "tool": "none"},
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
            "reason": "External service resolution and routing are unavailable.",
            "recommendation": "Configure DNS in /etc/resolv.conf and set a default gateway with `ip route add default via <gateway>`.",
            "data": {"nameservers": [], "default_route": ""},
        }
    if not nameservers or not default_route:
        missing = "DNS nameserver" if not nameservers else "default route"
        return {
            "status": "WARNING",
            "details": f"Missing {missing}",
            "reason": "Partial network configuration may break dependency connectivity.",
            "recommendation": f"Configure the missing {missing} before production deployment.",
            "data": {"nameservers": nameservers, "default_route": default_route},
        }
    return {
        "status": "OK",
        "details": f"DNS: {', '.join(nameservers[:2])}; Gateway: {default_route}",
        "reason": "Name resolution and default routing are configured.",
        "recommendation": "Verify DNS servers are internal or trusted resolvers; avoid using public DNS in regulated environments.",
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
            "details": "Network baseline established (first run)",
            "reason": "Future assessments will detect interface, port, DNS, and gateway drift.",
            "recommendation": "Re-run periodically to track network state changes over time.",
        }
    changes: List[str] = []
    keys = ["interfaces", "exposed_ports", "nameservers", "default_route"]
    for key in keys:
        if previous.get(key) != snapshot.get(key):
            changes.append(key)
    _save_network_baseline(snapshot)
    if changes:
        changed_text = ", ".join(changes)
        return {
            "status": "WARNING",
            "details": f"Network baseline drift detected in: {changed_text}",
            "reason": "Unexpected network changes can indicate misconfiguration or exposure drift.",
            "recommendation": f"Review changes to: {changed_text}. If intentional, the baseline has been updated. If unexpected, investigate immediately.",
        }
    return {
        "status": "OK",
        "details": "No network baseline drift detected",
        "reason": "Current network state matches the previous assessment baseline.",
        "recommendation": "Continue periodic assessments to maintain drift detection coverage.",
    }
def _finding(
    control_id: str,
    check: str,
    status: str,
    details: str,
    reason: str,
    recommendation: str,
    confidence: str = "medium",
) -> Dict[str, Any]:
    return {
        "category": "Network",
        "control_id": control_id,
        "check": check,
        "status": status,
        "risk_score": _risk_score(status),
        "details": details,
        "reason": reason,
        "recommendation": recommendation,
        "confidence": confidence,
    }
def run_network_checks() -> List[Dict[str, Any]]:
    """Run network checks and return structured findings."""
    findings: List[Dict[str, Any]] = []
    interfaces = _check_interfaces()
    findings.append(_finding(
        "NET-001", "Active interfaces",
        interfaces["status"], interfaces["details"],
        interfaces["reason"], interfaces["recommendation"],
    ))
    ports = _check_open_ports()
    entries = ports.get("data", {}).get("entries", [])
    findings.append(_finding(
        "NET-002", "Open ports",
        ports["status"], ports["details"],
        ports["reason"], ports["recommendation"],
    ))
    mapping = _check_port_process_mapping(entries)
    findings.append(_finding(
        "NET-003", "Port-to-process mapping",
        mapping["status"], mapping["details"],
        mapping["reason"], mapping["recommendation"],
    ))
    allowed = _check_allowed_ports_policy(entries)
    findings.append(_finding(
        "NET-004", "Allowed ports policy",
        allowed["status"], allowed["details"],
        allowed["reason"], allowed["recommendation"],
    ))
    firewall = _check_firewall()
    findings.append(_finding(
        "NET-005", "Firewall status",
        firewall["status"], firewall["details"],
        firewall["reason"], firewall["recommendation"],
    ))
    dns_gateway = _check_dns_gateway()
    findings.append(_finding(
        "NET-006", "DNS & gateway",
        dns_gateway["status"], dns_gateway["details"],
        dns_gateway["reason"], dns_gateway["recommendation"],
    ))
    snapshot = {
        "interfaces": interfaces.get("data", {}).get("interfaces", []),
        "exposed_ports": allowed.get("data", {}).get("exposed_ports", []),
        "nameservers": dns_gateway.get("data", {}).get("nameservers", []),
        "default_route": dns_gateway.get("data", {}).get("default_route", ""),
        "firewall": firewall.get("data", {}).get("firewall", "unknown"),
    }
    drift = _check_network_baseline_drift(snapshot)
    findings.append(_finding(
        "NET-007", "Network baseline drift",
        drift["status"], drift["details"],
        drift["reason"], drift["recommendation"],
    ))
    return findings
