"""Default `must_deny` invariants per fix type (architecture doc 6.4)."""

from __future__ import annotations

# Adapted from postura-backend/app/aws/remediation/ip_safe.py (sensitive-port list).
SG_SENSITIVE_PORTS: tuple[int, ...] = (22, 3389, 3306, 5432, 1433, 6379, 9200, 27017)
WORLD_CIDRS: tuple[str, ...] = ("0.0.0.0/0", "::/0")
