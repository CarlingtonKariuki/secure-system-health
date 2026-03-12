# Network Checks Update Report

Project: Secure System Health & Cyber Readiness Tool (SSHCR)  
Date: 2026-03-08  
Module: `src/network_checks.py`

## 1) Upgrade Scope

This update replaced placeholder network checks with production-style readiness and risk checks. The module now collects live network evidence, normalizes results into structured findings, and supports policy and baseline controls.

Implemented outcomes:
- Real command-driven network inspection.
- Status + risk scoring + rationale on each finding.
- Linux fallback behavior for tool variability.
- New controls: port/process attribution, allowed-port policy enforcement, baseline drift detection.

## 2) Files Added / Updated

- Updated: `src/network_checks.py`
- Added: `docs/allowed_ports.json`
- Runtime baseline artifact: `reports/network_baseline.json`

## 3) Finding Schema

Each check emits:
- `category`
- `check`
- `status` (`OK`, `WARNING`, `RISK`)
- `risk_score`
- `details`
- `reason`

Risk score mapping:
- `OK -> 10`
- `WARNING -> 55`
- `RISK -> 85`

## 4) Implemented Checks

### 4.1 Active Interfaces

Primary method:
- `ip -brief address`

Fallback:
- `/sys/class/net`

Decision logic:
- `OK`: at least one non-loopback interface is UP and has IP.
- `RISK`: no usable non-loopback interface with IP.
- `WARNING`: only fallback visibility available (primary tool missing).

### 4.2 Open Ports

Primary method:
- `ss -tulpn`

Fallback:
- `netstat -tulnp`

Decision logic:
- `OK`: listening entries detected.
- `WARNING`: no listeners found, or no viable port tool.

Output includes:
- listener count
- sample endpoints
- parsed port list for downstream checks

### 4.3 Port-to-Process Mapping (New)

Purpose:
- Attribute listening ports to owning process/PID.

Decision logic:
- `OK`: all listeners mapped.
- `WARNING`: partial or missing process attribution.

Value:
- Improves operational accountability and triage quality.

### 4.4 Allowed Ports Policy (New)

Config:
- `docs/allowed_ports.json`

Current baseline list:
- `22, 53, 67, 68, 80, 123, 443`

Decision logic:
- `RISK`: non-loopback exposed port not in approved list.
- `OK`: exposed ports align with policy.
- `WARNING`: no parseable ports for policy evaluation.

Value:
- Converts discovery into enforceable exposure policy.

### 4.5 Firewall Status

Detection sequence:
1. `ufw status`
2. `nft list ruleset`
3. `iptables -S`

Decision logic:
- `OK`: active or detectable ruleset present.
- `RISK`: explicitly inactive firewall state.
- `WARNING`: unable to conclusively confirm firewall state.

### 4.6 DNS and Default Gateway

Sources:
- DNS: `/etc/resolv.conf`
- Gateway: `ip route` default route

Decision logic:
- `RISK`: missing both DNS and default route.
- `WARNING`: missing one of the two.
- `OK`: both present.

### 4.7 Network Baseline Drift (New)

Baseline file:
- `reports/network_baseline.json`

Tracked fields:
- `interfaces`
- `exposed_ports`
- `nameservers`
- `default_route`
- `firewall`

Behavior:
- First run creates baseline.
- Later runs compare current snapshot to baseline.
- `WARNING` on drift in tracked fields.
- `OK` when unchanged.

Value:
- Detects unplanned network-state changes over time.

## 5) Runtime Execution Order

`run_network_checks()` executes:
1. Active interfaces
2. Open ports
3. Port-to-process mapping
4. Allowed ports policy
5. Firewall status
6. DNS & gateway
7. Network baseline drift

## 6) Fallback Strategy

To avoid assessment failure across environments:
- Missing `ip` -> fallback interface discovery from `/sys/class/net`
- Missing `ss` -> fallback to `netstat`
- Missing firewall frontend -> fallback sequence `ufw -> nft -> iptables`

If tooling is missing, module returns structured `WARNING` findings instead of crashing.

## 7) Reporting Integration

The module output is consumed by `src/report_generator.py` and appears in Markdown reports with:
- Category
- Check
- Status
- Risk Score
- Details
- Reason

Example run:
`python src/main.py --network --output md`

## 8) Operational Impact

This upgrade shifts network assessment from basic visibility to controlled readiness by adding:
- Exposure ownership (`port -> process`)
- Exposure governance (`allowed ports policy`)
- Change awareness (`baseline drift`)

This makes SSHCR more aligned with service engineering, maintenance validation, and pre-commissioning risk assessment workflows.

## 9) Recommended Next Network Enhancements

1. Protocol-aware policy (`tcp/udp + port`) in config.
2. Interface subnet and route-metric drift tracking.
3. Endpoint reachability matrix (gateway/DNS/NTP/service hosts).
4. Optional JSON export for dashboard ingestion.
5. Rule-level firewall posture checks (default policy + explicit allows/denies).
