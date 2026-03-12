# SSHCR Security Phase Implementation Report

Project: Secure System Health & Cyber Readiness Tool (SSHCR)  
Date: 2026-03-08  
Repository: `git@github.com:CarlingtonKariuki/secure-system-health.git`  
Branch: `main`

## 1) Objective

This phase upgraded SSHCR security checks from placeholders to a modular, policy-driven assessment engine designed for service engineering and cybersecurity readiness workflows.

## 2) Architecture Implemented

Security logic was separated into clear layers:

1. Orchestration layer
- File: `src/security_checks.py`
- Responsibilities:
  - load security policy
  - trigger evidence collection
  - run evaluators
  - return normalized findings

2. Evidence collection layer
- File: `src/security/collectors.py`
- Responsibilities:
  - read host evidence from OS files and commands
  - return raw structured evidence
  - avoid scoring/risk decisions in collector functions

3. Evaluation and risk layer
- File: `src/security/evaluators.py`
- Responsibilities:
  - evaluate evidence against policy
  - emit findings with:
    - `control_id`
    - `status`
    - `risk_score`
    - `details`
    - `reason`
    - `recommendation`
    - `confidence`

4. Policy/config layer
- File: `docs/security_policy.json`
- Purpose:
  - define thresholds and acceptable values without code edits

5. Control catalog layer
- File: `docs/security_control_catalog.md`
- Purpose:
  - provide stable control IDs for report traceability

## 3) Security Controls Implemented

### Identity and Privilege
- `ID-001`: Privileged UID 0 accounts
- `ID-002`: Empty password accounts
- `ID-003`: Privileged sudo membership
- `ID-004`: Service account shell access
- `ID-005`: Sudoers NOPASSWD policy
- `ID-006`: Sudoers wildcard scope

### Authentication Policy
- `AUTH-001`: Password expiration policy (`PASS_MAX_DAYS`)
- `AUTH-002`: Password minimum length (`PASS_MIN_LEN`)
- `AUTH-003`: Account lockout controls (`pam_faillock`/`pam_tally2`)

### SSH Hardening
- `SSH-001`: Root login policy
- `SSH-002`: Password authentication
- `SSH-003`: Public-key authentication
- `SSH-004`: `MaxAuthTries`
- `SSH-005`: Access allowlist (`AllowUsers`/`AllowGroups`)
- `SSH-006`: SSH service state
- `SSH-007`: SSH crypto posture (`sshd -T` runtime ciphers/MACs/KEX)

### Patch Readiness
- `PATCH-001`: Package update backlog
- `PATCH-002`: Automatic security updates

### Host Hardening
- `HARD-001`: Audit daemon status
- `HARD-002`: Logging persistence
- `HARD-003`: Time synchronization
- `HARD-004`: Kernel/network sysctl baseline

## 4) Evidence Sources and Runtime Methods

Implemented collectors read from:
- `/etc/passwd`, `/etc/shadow`
- `/etc/login.defs`
- `/etc/pam.d/*` auth files
- `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*.conf`
- `/etc/sudoers`, `/etc/sudoers.d/*`
- `/proc/sys/*` for hardening sysctls
- `/etc/apt/apt.conf.d/20auto-upgrades`

Commands used:
- `systemctl is-active`
- `passwd -S root`
- `getent group`
- `sshd -T` (when available)
- package manager checks (`apt`/`dnf`/`yum`)
- `timedatectl`

## 5) Policy-Driven Parameters Added

`docs/security_policy.json` now controls:
- max sudo users
- max `NOPASSWD` rules
- password max days
- password min length
- allowed `PermitRootLogin` values
- SSH max auth tries
- weak SSH algorithm token list
- patch warning/risk thresholds
- expected sysctl hardening values

## 6) Reporting Enhancements

Updated report engine in `src/report_generator.py`:

1. Added `Priority Remediation` section
- auto-selects top 5 actionable `RISK/WARNING` findings by risk score

2. Expanded findings table columns:
- `Category`
- `Control ID`
- `Check`
- `Status`
- `Risk Score`
- `Confidence`
- `Details`
- `Reason`
- `Recommendation`

This changed report output from informational to directly actionable.

## 7) Validation Performed

Executed successfully:
- `python3 src/main.py --security --output md`
- `python3 src/main.py --full-assessment --output md`

Observed outcomes confirmed:
- control IDs present
- recommendations present
- confidence levels present
- priority remediation generated
- integration with full assessment report working

## 8) Git Changes and Push

Committed and pushed to `main`:
- Commit: `6419ec5`
- Message: `Build advanced security module with policy controls and prioritized remediation`

Files in commit:
- `src/security_checks.py`
- `src/security/__init__.py`
- `src/security/collectors.py`
- `src/security/evaluators.py`
- `src/report_generator.py`
- `docs/security_policy.json`
- `docs/security_control_catalog.md`

Push destination:
- `origin/main`

## 9) Engineering Outcome

Security checks now operate as a structured subsystem rather than a monolithic script. The implementation supports:
- reproducible evidence collection
- policy-based decisions
- control-level traceability
- prioritized remediation output

This establishes a professional baseline for future extensions (CVE-aware update checks, deeper SSH crypto validation, file integrity checks, and compliance mappings).
