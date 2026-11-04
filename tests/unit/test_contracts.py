from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ruamel.yaml import YAML

from posturanet.contracts import (
    build_contract,
    contract_path,
    dump_contract,
    load_contract,
    merge_human_fields,
    write_contract,
)
from posturanet.contracts.store import HEADER, contract_filename
from posturanet.evidence import FileSource, aggregate
from posturanet.models import BehaviorContract
from posturanet.synth.sg_rules import Rule

OPEN_22 = Rule("0.0.0.0/0", 22, 22, "tcp")
ADDRESS = "module.bastion.aws_security_group.this"


def _contract(flows_path: Path) -> BehaviorContract:
    now = datetime.now(UTC)
    obs = aggregate(FileSource(flows_path).fetch("sg", now, now), ADDRESS)
    return build_contract(obs, [OPEN_22], account="123456789012", region="us-east-1")


def test_build_contract(flows_path: Path) -> None:
    c = _contract(flows_path)
    assert c.status == "draft"
    assert [r.cidr for r in c.must_allow] == [
        "10.0.4.12/32",
        "10.0.4.37/32",
        "10.0.5.9/32",
    ]
    # Internet sources: daily use is kept but needs a human; a one-day visitor is left out.
    assert [r.cidr for r in c.needs_review] == ["203.0.113.7/32"]
    assert [r.cidr for r in c.not_kept] == ["198.51.100.23/32"]
    assert "likely a scanner" in (c.not_kept[0].reason or "")
    assert {(d.cidr, d.port) for d in c.must_deny} == {("0.0.0.0/0", 22), ("::/0", 22)}
    partner = next(r for r in c.needs_review if r.cidr == "203.0.113.7/32")
    assert partner.period == "daily@02:00Z"
    assert c.unknown_risk == "behavior rarer than once per 89 days is not observed"


def test_yaml_format(flows_path: Path) -> None:
    text = dump_contract(_contract(flows_path))
    lines = text.splitlines()
    assert lines[0] == f"# {HEADER}"
    keys = [ln.split(":")[0] for ln in lines if ln and not ln.startswith((" ", "#"))]
    assert keys == [
        "schema", "resource", "account", "region", "kind", "observed", "must_allow",
        "must_deny", "needs_review", "not_kept", "unknown_risk", "status", "approved_by", "approved_at",
        "generated_by",
    ]  # fmt: skip
    assert 'account: "123456789012"' in text
    assert "  - {cidr: 10.0.4.12/32, port: 22, proto: tcp, period: daily, count: 6002}" in text
    assert "window: {from: 2026-08-01, to: 2026-10-29, days: 89}" in text


def test_round_trip(flows_path: Path, tmp_path: Path) -> None:
    c = _contract(flows_path)
    path = contract_path(tmp_path, "posturanet/contracts", ADDRESS)
    write_contract(path, c)
    assert load_contract(path) == c
    raw = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    assert raw["account"] == "123456789012"  # a string, not an int


def test_human_fields_survive_regeneration(flows_path: Path) -> None:
    old = _contract(flows_path)
    edited = old.model_copy(
        update={
            "needs_review": [
                r.model_copy(update={"owner": "partner-sftp", "ref": "SEC-412"})
                if r.cidr == "203.0.113.7/32"
                else r
                for r in old.needs_review
            ]
        }
    )
    merged = merge_human_fields(_contract(flows_path), edited)
    partner = next(r for r in merged.needs_review if r.cidr == "203.0.113.7/32")
    assert (partner.owner, partner.ref) == ("partner-sftp", "SEC-412")


def test_human_can_keep_a_dropped_source(flows_path: Path) -> None:
    old = _contract(flows_path)
    edited = old.model_copy(update={"must_allow": [*old.must_allow, *old.not_kept], "not_kept": []})
    merged = merge_human_fields(_contract(flows_path), edited)
    assert "198.51.100.23/32" in [r.cidr for r in merged.must_allow]
    assert merged.not_kept == []


def test_filename_sanitized() -> None:
    assert contract_filename('module.a["x"].aws_security_group.b[0]') == (
        "module.a__x__.aws_security_group.b_0_.yaml"
    )


def _flow(cidr: str, *, days: int, review: bool, count: int = 100, nbytes: int | None = None):  # type: ignore[no-untyped-def]
    from datetime import UTC, datetime

    from posturanet.models import ObservedFlow, Period

    t = datetime(2026, 8, 1, tzinfo=UTC)
    return ObservedFlow(
        cidr=cidr, port=22, proto="tcp", count=count, bytes=nbytes, first_seen=t, last_seen=t,
        days_seen=days, period=Period.ONE_OFF if review else Period.DAILY, needs_review=review,
    )  # fmt: skip


def test_place_sources() -> None:
    from posturanet.contracts import place

    assert place(_flow("10.0.4.12/32", days=80, review=False)) == ("allow", None)
    assert place(_flow("10.0.30.8/32", days=1, review=True))[0] == "review"
    assert place(_flow("203.0.113.10/32", days=60, review=False))[0] == "review"
    assert place(_flow("198.51.100.23/32", days=1, review=True))[0] == "not_kept"
    scan = _flow("198.51.100.99/32", days=90, review=False, count=900, nbytes=900 * 180)
    assert place(scan)[0] == "not_kept"
    real = _flow("203.0.113.10/32", days=60, review=False, count=900, nbytes=900 * 40_000)
    assert place(real)[0] == "review"
