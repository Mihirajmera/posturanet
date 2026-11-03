from __future__ import annotations

from datetime import date

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
