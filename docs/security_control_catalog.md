# Security Control Catalog

## Identity
- `ID-001`: Privileged UID 0 accounts
- `ID-002`: Empty password accounts
- `ID-003`: Privileged sudo membership
- `ID-004`: Service account shell access
- `ID-005`: Sudoers NOPASSWD policy
- `ID-006`: Sudoers wildcard scope

## Authentication
- `AUTH-001`: Password expiration policy
- `AUTH-002`: Password minimum length
- `AUTH-003`: Account lockout controls

## SSH
- `SSH-001`: SSH root login policy
- `SSH-002`: SSH password authentication
- `SSH-003`: SSH public key authentication
- `SSH-004`: SSH MaxAuthTries setting
- `SSH-005`: SSH access allowlist
- `SSH-006`: SSH service state
- `SSH-007`: SSH crypto posture

## Patch Management
- `PATCH-001`: Package update backlog
- `PATCH-002`: Automatic security updates

## Host Hardening
- `HARD-001`: Audit daemon status
- `HARD-002`: Logging persistence
- `HARD-003`: Time synchronization
- `HARD-004`: Kernel/network sysctl baseline
