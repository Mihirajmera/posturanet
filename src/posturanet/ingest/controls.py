from __future__ import annotations

import json
from functools import cache
from importlib.resources import files

from posturanet.models import FixType


@cache
def _control_map() -> dict[str, FixType]:
    raw = json.loads(files("posturanet.ingest").joinpath("controls.json").read_text("utf-8"))
    return {k: FixType(v) for k, v in raw.items() if not k.startswith("_")}


def fix_type_for(control_id: str) -> FixType:
    found = _control_map().get(control_id)
    if found is not None:
        return found
    from posturanet.configfix.catalog import fixes_for

    return FixType.CONFIG_ATTRIBUTE if fixes_for(control_id) else FixType.UNSUPPORTED
