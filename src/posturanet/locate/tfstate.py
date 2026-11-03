"""Read Terraform state (format version 4) and match resources by id or ARN (FR-6).

State can contain secrets. Only `id`, `arn` and (for security groups) `ingress` attributes are
read here, and nothing from state is ever logged or printed (NFR-3).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from posturanet.errors import StageStop

_MODULE_SEGMENT = re.compile(r"module\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?")


@dataclass(frozen=True)
class StateMatch:
    address: str
    module: str  # e.g. "module.bastion" or "" for root
    type: str
    name: str
    # Security groups only: the ingress rules recorded in state, for drift detection (FR-9).
    ingress: list[dict[str, Any]] | None = field(default=None, compare=False)

    @property
    def module_names(self) -> list[str]:
        return _MODULE_SEGMENT.findall(self.module)


def load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageStop(
            "locate",
            f"Terraform state not found at {path.as_posix()}",
            ["check terraform.state_path in .posturanet.yml, or pass --state"],
        )
    return parse_state(path.read_bytes())


def parse_state(raw: bytes) -> dict[str, Any]:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise StageStop("locate", "Terraform state could not be parsed") from exc
    if not isinstance(doc, dict) or doc.get("version") != 4:
        raise StageStop(
            "locate",
            "unsupported Terraform state format (expected version 4)",
            ["use Terraform 0.12 or later"],
        )
    return doc


def find_resource(
    state: dict[str, Any], resource_id: str, arn: str | None = None
) -> list[StateMatch]:
    matches: list[StateMatch] = []
    for res in state.get("resources", []):
        if not isinstance(res, dict) or res.get("mode") != "managed":
            continue
        for inst in res.get("instances", []):
            attrs = inst.get("attributes") or {}
            if attrs.get("id") == resource_id or (arn and attrs.get("arn") == arn):
                matches.append(
                    StateMatch(
                        address=_address(res, inst.get("index_key")),
                        module=str(res.get("module", "")),
                        type=str(res["type"]),
                        name=str(res["name"]),
                        ingress=_ingress(res, attrs),
                    )
                )
    return sorted(matches, key=lambda m: m.address)


def find_by_type(state: dict[str, Any], rtype: str) -> list[StateMatch]:
    """Every managed instance of `rtype`. For account-wide settings with no resource id."""
    matches = [
        StateMatch(
            address=_address(res, inst.get("index_key")),
            module=str(res.get("module", "")),
            type=rtype,
            name=str(res["name"]),
        )
        for res in state.get("resources", [])
        if isinstance(res, dict) and res.get("mode") == "managed" and res.get("type") == rtype
        for inst in res.get("instances", [])
    ]
    return sorted(matches, key=lambda m: m.address)


def _address(res: dict[str, Any], index_key: Any) -> str:
    base = f"{res['type']}.{res['name']}"
    if res.get("module"):
        base = f"{res['module']}.{base}"
    if isinstance(index_key, int):
        return f"{base}[{index_key}]"
    if isinstance(index_key, str):
        return f'{base}["{index_key}"]'
    return base


def _ingress(res: dict[str, Any], attrs: dict[str, Any]) -> list[dict[str, Any]] | None:
    if res.get("type") != "aws_security_group" or not isinstance(attrs.get("ingress"), list):
        return None
    return [r for r in attrs["ingress"] if isinstance(r, dict)]
