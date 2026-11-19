"""Catalog of attribute fixes: Security Hub control -> Terraform attribute change (FR-48).

Each row changes literal attributes on one resource, in place. Nothing in the catalog can
remove a rule, a principal or a route, so these fixes need no usage evidence.
"""

from __future__ import annotations

import json
from functools import cache
from importlib.resources import files
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Literal_ = bool | int | str | list[str]
Op = Literal["set", "at_least", "one_of", "includes"]

# In `when`, null means "attribute absent" and PRESENT means "attribute or block exists".
PRESENT = "present"


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str  # dotted: nested block names, then the attribute
    # CloudFormation property path under Properties; `List[key]` at the end means the Value
    # of the {Key, Value} item with that Key (load balancer attributes)
    cfn: str | None = None
    cfn_value: Literal_ | None = None  # the CloudFormation value, when it isn't `value`
    op: Op
    value: Literal_
    allowed: list[str] = Field(default_factory=list)  # one_of only

    @model_validator(mode="after")
    def _shape(self) -> Change:
        if self.op == "at_least" and (
            isinstance(self.value, bool) or not isinstance(self.value, int)
        ):
            raise ValueError(f"{self.path}: at_least needs an integer")
        if self.op == "includes" and not isinstance(self.value, list):
            raise ValueError(f"{self.path}: includes needs a list")
        if self.op == "one_of" and self.value not in self.allowed:
            raise ValueError(f"{self.path}: one_of default must be in allowed")
        return self

    @property
    def parents(self) -> list[str]:
        return self.path.split(".")[:-1]

    @property
    def name(self) -> str:
        return self.path.rsplit(".", 1)[-1]

    def satisfied_by(self, current: object) -> bool:
        if self.op == "set":
            return current == self.value
        if self.op == "at_least":
            return (
                isinstance(current, int)
                and not isinstance(current, bool)
                and (
                    current >= self.value  # type: ignore[operator]
                )
            )
        if self.op == "one_of":
            return current in self.allowed
        return isinstance(current, list) and all(
            v in current
            for v in self.value  # type: ignore[union-attr]
        )

    def describe(self) -> str:
        return {
            "set": f"{self.path} = {_show(self.value)}",
            "at_least": f"{self.path} >= {self.value}",
            "one_of": f"{self.path} in {', '.join(self.allowed)} (default {_show(self.value)})",
            "includes": f"{self.path} includes {_show(self.value)}",
        }[self.op]


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    path: str
    cfn: str | None = None
    in_: list[str | None] = Field(alias="in")


class ConfigFix(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control: str
    title: str
    resource_type: str
    changes: list[Change]
    when: list[Condition] = Field(default_factory=list)
    scope: Literal["resource", "account"] = "resource"
    why: str
    note: str | None = None
    risk: Literal["low", "medium"] = "low"
    cfn_type: str | None = None  # the CloudFormation resource type, when the row maps to one

    def for_cfn(self) -> ConfigFix | None:
        """This row with CloudFormation types and property paths, or None if it has no
        complete mapping (every change and condition needs one)."""
        if self.cfn_type is None or self.scope != "resource":
            return None
        if any(c.cfn is None for c in self.changes) or any(w.cfn is None for w in self.when):
            return None
        return self.model_copy(
            update={
                "resource_type": self.cfn_type,
                "changes": [
                    c.model_copy(
                        update={
                            "path": c.cfn,
                            "value": c.value if c.cfn_value is None else c.cfn_value,
                        }
                    )
                    for c in self.changes
                ],
                "when": [w.model_copy(update={"path": w.cfn}) for w in self.when],
            }
        )

    @property
    def service(self) -> str:
        return self.control.split(".", 1)[0].lower()

    @property
    def change_summary(self) -> str:
        return "; ".join(c.describe() for c in self.changes)


def _show(value: object) -> str:
    return json.dumps(value)


@cache
def catalog() -> tuple[ConfigFix, ...]:
    raw = json.loads(files("posturanet.configfix").joinpath("catalog.json").read_text("utf-8"))
    return tuple(ConfigFix.model_validate(row) for row in raw["fixes"])


def fixes_for(control_id: str) -> list[ConfigFix]:
    """Catalog rows for a control, in preference order (first matching resource type wins).

    `RDS.2+RDS.8` is several controls on one resource: one merged row per resource type
    every part can fix, so they land as one change and one PR.
    """
    if "+" in control_id:
        return list(_combined(tuple(control_id.split("+"))))
    return [f for f in catalog() if f.control == control_id]


@cache
def _combined(parts: tuple[str, ...]) -> tuple[ConfigFix, ...]:
    per_part = [fixes_for(p) for p in parts]
    if len(parts) < 2 or not all(per_part):
        return ()
    merged: list[ConfigFix] = []
    for rtype in dict.fromkeys(f.resource_type for f in per_part[0]):
        rows = [next((f for f in rows if f.resource_type == rtype), None) for rows in per_part]
        picked = [r for r in rows if r is not None]
        if len(picked) == len(parts):
            row = merge(picked)
            if row is not None:
                merged.append(row)
    return tuple(merged)


def merge(rows: list[ConfigFix]) -> ConfigFix | None:
    """One row making every row's changes, or None if two rows want different values."""
    changes: dict[str, Change] = {}
    for c in (c for r in rows for c in r.changes):
        if c.path in changes and changes[c.path] != c:
            return None
        changes[c.path] = c
    when = list(
        {
            json.dumps(w.model_dump(by_alias=True), sort_keys=True): w for r in rows for w in r.when
        }.values()
    )
    scopes = {r.scope for r in rows}
    if len(scopes) != 1:
        return None
    cfn_types = {r.cfn_type for r in rows}
    return ConfigFix(
        control="+".join(r.control for r in rows),
        title="; ".join(dict.fromkeys(r.title for r in rows)),
        resource_type=rows[0].resource_type,
        changes=list(changes.values()),
        when=when,
        scope=rows[0].scope,
        why=" ".join(dict.fromkeys(r.why for r in rows)),
        note=" ".join(dict.fromkeys(r.note for r in rows if r.note)) or None,
        risk="medium" if any(r.risk == "medium" for r in rows) else "low",
        cfn_type=cfn_types.pop() if len(cfn_types) == 1 else None,
    )


def same_fix(control_ids: list[str], resource_type: str | None = None) -> bool:
    """True when every control makes the identical change (on `resource_type`, if given).

    Security Hub has twin controls for one setting (ES.1 and OpenSearch.1); a scanner check
    mapped to both can then use either one without asking which.
    """

    def shape(control_id: str) -> tuple[str, ...]:
        rows = [
            f
            for f in fixes_for(control_id)
            if resource_type is None or f.resource_type == resource_type
        ]
        return tuple(
            sorted(
                json.dumps(
                    [
                        f.resource_type,
                        f.scope,
                        [c.model_dump() for c in f.changes],
                        [w.model_dump(by_alias=True) for w in f.when],
                    ],
                    sort_keys=True,
                )
                for f in rows
            )
        )

    shapes = {shape(c) for c in control_ids}
    return len(control_ids) > 1 and len(shapes) == 1 and () not in shapes


def controls() -> list[str]:
    return sorted({f.control for f in catalog()}, key=_control_order)


def _control_order(control: str) -> tuple[str, int]:
    service, _, num = control.partition(".")
    return service.lower(), int(num) if num.isdigit() else 0
