"""Canonical test entrypoint for SSHCR CI.

This file mirrors the existing smoke tests and keeps the structure
aligned with documentation expectations.
"""

from test_smoke import TestSSHCRSmoke  # re-export for unittest discovery

__all__ = ["TestSSHCRSmoke"]
