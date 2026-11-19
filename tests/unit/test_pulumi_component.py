"""Pulumi components used exactly once: finding the class, counting uses, picking the call."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from posturanet.cdk.source import mask
from posturanet.pulumi import component
from posturanet.pulumi.source import InComponent

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from bench import pulumi as bench  # noqa: E402

TS = """import * as aws from "@pulumi/aws";
class Bastion extends pulumi.ComponentResource {
    constructor(name: string, opts?: pulumi.ComponentResourceOptions) {
        super("acme:net:Bastion", name, {}, opts);
        new aws.ec2.SecurityGroup(`${name}-sg`, { description: "b" }, { parent: this });
    }
}
// new Bastion("in a comment") is not a use
const b = new Bastion("bastion");
"""

PY = """import pulumi
import pulumi_aws as aws


class Assets(pulumi.ComponentResource):
    def __init__(self, name, opts=None):
        super(Assets, self).__init__("acme:storage:Assets", name, None, opts)
        aws.s3.BucketPublicAccessBlock("assets-pab", bucket="b", block_public_acls=False)


aws.s3.BucketPublicAccessBlock("other-pab", bucket="c")
Assets("assets")
"""


def _write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.write_text(text, "utf-8", newline="")
    return p


def test_typescript_class_found_used_once_and_computed_name_picked(tmp_path: Path) -> None:
    f = _write(tmp_path, "index.ts", TS)
    (comp,) = component.find([f], "acme:net:Bastion")
    assert (comp.name, comp.line) == ("Bastion", 2)
    assert component.uses([f], comp) == 1
    calls = component.children(comp, TS, "SecurityGroup", "ec2", "acme:net:Bastion")
    hit = component.pick(calls, "bastion-sg")
    assert isinstance(hit, InComponent) and hit.construct_id == ""
    # The edited file is read back to the same call.
    again = component.rescan(hit, TS.replace('"b"', '"bastion"'))
    assert again.start == hit.start


def test_python_body_ends_at_dedent_and_super_with_args_is_not_a_use(tmp_path: Path) -> None:
    f = _write(tmp_path, "__main__.py", PY)
    (comp,) = component.find([f], "acme:storage:Assets")
    assert component.uses([f], comp) == 1
    calls = component.children(comp, PY, "BucketPublicAccessBlock", "s3", "acme:storage:Assets")
    assert [c.construct_id for c in calls] == ["assets-pab"]  # other-pab is outside the class


def test_other_token_or_second_use_is_seen(tmp_path: Path) -> None:
    f = _write(tmp_path, "index.ts", TS + 'new Bastion("spare");\n')
    assert component.find([f], "acme:net:Other") == []
    (comp,) = component.find([f], "acme:net:Bastion")
    assert component.uses([f], comp) == 2


def test_go_function_registers_the_type() -> None:
    text = (FIX_GO := bench.FIX / "pulumi" / "go-program" / "storage.go").read_text("utf-8")
    for old, new in bench.GO_COMP:
        text = text.replace(old, new, 1)
    masked = component._mask(FIX_GO, text)
    (comp,) = component.registered(FIX_GO, text, masked, "acme:iam:App")
    assert comp.name == "NewApp"
    assert "func NewApp" not in mask(text, "ts")[comp.body[0] : comp.body[1]]


@pytest.mark.parametrize(
    ("names", "want"),
    [(["app"], 0), (["", "app"], 1), (["x"], "named 'app'"), (["", ""], "2 calls"), ([""], 0)],
)
def test_pick(names: list[str], want: int | str) -> None:
    calls = [InComponent(**_blank(n)) for n in names]
    hit = component.pick(calls, "app")
    if isinstance(want, int):
        assert hit is calls[want]
    else:
        assert isinstance(hit, str) and want in hit


def _blank(name: str) -> dict[str, object]:
    from dataclasses import fields

    from posturanet.cdk.source import Construct

    out: dict[str, object] = {f.name: None for f in fields(Construct)}
    out["construct_id"] = name
    return out


@pytest.mark.parametrize("cid", [c.id for c in bench.CASES if "component" in c.id])
def test_bench_component_case(cid: str) -> None:
    case = next(c for c in bench.CASES if c.id == cid)
    result, code = bench.run_case(case)
    assert result.verdict == ("CORRECT" if case.expect == "fix" else "STOPPED"), result.note
    assert code == case.exit_code
