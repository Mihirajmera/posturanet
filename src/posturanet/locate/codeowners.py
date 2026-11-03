"""CODEOWNERS lookup (FR-8). The last matching rule wins, as on GitHub."""

from __future__ import annotations

import re
from pathlib import Path

CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")


def find_codeowners(repo: Path) -> Path | None:
    for rel in CODEOWNERS_LOCATIONS:
        p = repo / rel
        if p.is_file():
            return p
    return None


def owners_for(codeowners: Path, rel_path: str) -> list[str]:
    owners: list[str] = []
    for raw in codeowners.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        pattern, *rule_owners = line.split()
        if _pattern_regex(pattern).match(rel_path):
            owners = rule_owners
    return owners


def _pattern_regex(pattern: str) -> re.Pattern[str]:
    anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
    pat = pattern.lstrip("/")
    dir_only = pat.endswith("/")
    pat = pat.rstrip("/")
    out = []
    i = 0
    while i < len(pat):
        if pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    body = "".join(out)
    prefix = "^" if anchored else "^(?:.*/)?"
    suffix = "/.*$" if dir_only else "(?:/.*)?$"
    return re.compile(prefix + body + suffix)
