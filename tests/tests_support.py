from __future__ import annotations

from datetime import date

from posturanet.configfix.catalog import PRESENT, Change, ConfigFix
from posturanet.configfix.hcl_attrs import apply_changes
from posturanet.models import BehaviorContract, Confidence, NetRule
from posturanet.models.contract import ObservedMeta, ObservedWindow


def contract_for(allow: list[NetRule], deny: list[NetRule] | None = None) -> BehaviorContract:
    return BehaviorContract(
        resource="aws_security_group.x",
        observed=ObservedMeta(
            source="test",
            window=ObservedWindow(start=date(2026, 8, 1), end=date(2026, 10, 29), days=89),
            confidence=Confidence.HIGH,
        ),
        must_allow=allow,
        must_deny=deny or [],
    )


def config_fixture(fix: ConfigFix) -> str:
    """A minimal resource the fix applies to, built with the editor itself."""
    text = f'resource "{fix.resource_type}" "this" {{\n  name = "example"\n}}\n'
    for cond in fix.when:
        wanted = next((v for v in cond.in_ if v is not None), None)
        if wanted is None:
            continue
        if wanted == PRESENT:
            text = apply_changes(
                text, 1, [Change(path=cond.path + ".placeholder", op="set", value="x")]
            ).text
        else:
            text = apply_changes(text, 1, [Change(path=cond.path, op="set", value=wanted)]).text
    return text
