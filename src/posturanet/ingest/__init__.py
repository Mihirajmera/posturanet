"""Ingest stage: turn an ASFF finding or a manual target into a `Finding` (FR-1..FR-4)."""

from __future__ import annotations

from pathlib import Path

from posturanet.ingest.asff import parse_asff_file
from posturanet.ingest.manual import finding_from_resource_id
from posturanet.models import Finding


def ingest(target: str) -> Finding:
    """`target` is a path to an ASFF JSON file, or a resource id such as `sg-0a91f3c2`."""
    path = Path(target)
    if path.suffix.lower() == ".json" or path.is_file():
        return parse_asff_file(path)
    return finding_from_resource_id(target)


__all__ = ["finding_from_resource_id", "ingest", "parse_asff_file"]
