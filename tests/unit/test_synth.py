from __future__ import annotations

import ipaddress
import shutil
from datetime import date
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from posturanet.contracts import default_must_deny
from posturanet.errors import StageStop
from posturanet.models import BehaviorContract, Confidence, NetRule
from posturanet.models.config import SynthesisConfig
from posturanet.models.contract import ObservedMeta, ObservedWindow
from posturanet.synth import make_diff, parse_security_group, render, synthesize
from posturanet.synth.sg_rules import Rule
from posturanet.validate.invariants import allow_holds, check_contract, deny_holds

OPEN_22 = Rule("0.0.0.0/0", 22, 22, "tcp")


def contract(allow: list[NetRule], deny: list[NetRule] | None = None) -> BehaviorContract:
    return BehaviorContract(
        resource="aws_security_group.x",
        observed=ObservedMeta(
            source="test",
            window=ObservedWindow(start=date(2026, 8, 1), end=date(2026, 10, 29), days=89),
            confidence=Confidence.HIGH,
        ),
        must_allow=allow,
        must_deny=deny if deny is not None else default_must_deny([OPEN_22], {22}),
    )


def nr(cidr: str, port: int = 22) -> NetRule:
    return NetRule(cidr=cidr, port=port, proto="tcp")


def write_sg(tmp_path: Path, body: str, extra: str = "") -> Path:
    tf = tmp_path / "main.tf"
    tf.write_text(f'resource "aws_security_group" "web" {{\n  name = "web"\n{body}}}\n{extra}')
    return tf


def test_exact_sources_when_quota_allows() -> None:
    c = contract([nr("10.0.4.12/32"), nr("203.0.113.7/32")])
    s = synthesize(c, [OPEN_22], SynthesisConfig())
    assert [r.cidr for r in s.added] == ["10.0.4.12/32", "203.0.113.7/32"]
    assert s.removed == [OPEN_22]


def test_quota_forces_minimal_supernet() -> None:
    c = contract([nr("10.0.4.12/32"), nr("10.0.4.37/32"), nr("10.0.5.9/32")])
    s = synthesize(c, [OPEN_22], SynthesisConfig(rules_quota=1))
    assert [r.cidr for r in s.added] == ["10.0.4.0/23"]


def test_public_sources_never_widen_past_limit() -> None:
    c = contract([nr("203.0.113.7/32"), nr("198.51.100.23/32")])
    with pytest.raises(StageStop, match="within the quota"):
        synthesize(c, [OPEN_22], SynthesisConfig(rules_quota=1))


def test_kept_rules_count_against_quota_and_cover_traffic() -> None:
    kept = Rule("10.0.0.0/16", 22, 22, "tcp")
    c = contract([nr("10.0.4.12/32"), nr("203.0.113.7/32")])
    s = synthesize(c, [OPEN_22, kept], SynthesisConfig(rules_quota=2))
    assert s.kept == [kept]
    assert [r.cidr for r in s.added] == ["203.0.113.7/32"]
    assert [a.cidr for a in s.already_allowed] == ["10.0.4.12/32"]


def test_no_traffic_means_remove() -> None:
    s = synthesize(contract([]), [OPEN_22], SynthesisConfig())
    assert s.added == [] and s.removed == [OPEN_22]


def test_ipv6_sources_stop() -> None:
    c = contract([nr("2001:db8::1/128")])
    with pytest.raises(StageStop, match="IPv6"):
        synthesize(c, [Rule("::/0", 22, 22, "tcp")], SynthesisConfig())


def test_narrow_must_deny_is_respected() -> None:
    c = contract(
        [nr("10.0.4.12/32"), nr("10.0.4.37/32")],
        deny=[nr("10.0.4.32/28")],
    )
    with pytest.raises(StageStop, match="violate must_deny"):
        synthesize(c, [OPEN_22], SynthesisConfig(rules_quota=1))


def test_all_traffic_rule_narrows_to_observed_ports() -> None:
    c = contract([nr("10.0.4.12/32", 22), nr("10.0.4.12/32", 443)])
    s = synthesize(c, [Rule("0.0.0.0/0", 0, 0, "-1")], SynthesisConfig())
    assert sorted((r.cidr, r.from_port) for r in s.added) == [
        ("10.0.4.12/32", 22),
        ("10.0.4.12/32", 443),
    ]


# --- HCL parsing and rendering ----------------------------------------------------------


def test_parse_and_render_fixture(basic_repo: Path, tmp_path: Path) -> None:
    repo = tmp_path / "r"
    shutil.copytree(basic_repo, repo)
    sg = parse_security_group(repo / "modules/bastion/main.tf", 5, "aws_security_group", "this")
    assert sg.rules() == [OPEN_22]
    s = synthesize(contract([nr("10.0.4.12/32")]), sg.rules(), SynthesisConfig())
    diff = make_diff(repo, sg, s, "module.bastion.aws_security_group.this")
    assert diff.files[0].path == "modules/bastion/main.tf"
    assert '-    cidr_blocks = ["0.0.0.0/0"]' in diff.files[0].unified_diff
    assert '+    cidr_blocks = ["10.0.4.12/32"]' in diff.files[0].unified_diff
    assert 'description = "ssh"' in diff.files[0].new_content
    assert diff.summary == "0.0.0.0/0:22/tcp → 10.0.4.12/32:22/tcp (1 rule)"


def test_mixed_block_keeps_private_cidrs(tmp_path: Path) -> None:
    tf = write_sg(
        tmp_path,
        '  ingress {\n    from_port   = 443\n    to_port     = 443\n    protocol    = "tcp"\n'
        '    cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"] # public and vpc\n  }\n',
    )
    sg = parse_security_group(tf, 1, "aws_security_group", "web")
    c = contract([nr("203.0.113.9/32", 443)], deny=[])
    s = synthesize(c, sg.rules(), SynthesisConfig())
    new = render(sg, s)
    assert '"0.0.0.0/0"' not in new
    assert 'cidr_blocks = ["10.0.0.0/8"]' in new
    assert 'cidr_blocks = ["203.0.113.9/32"]' in new


def test_remove_only_deletes_block(tmp_path: Path) -> None:
    tf = write_sg(
        tmp_path,
        '\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n  }\n',
    )
    sg = parse_security_group(tf, 1, "aws_security_group", "web")
    new = render(sg, synthesize(contract([]), sg.rules(), SynthesisConfig()))
    assert "ingress" not in new
    assert new == 'resource "aws_security_group" "web" {\n  name = "web"\n}\n'


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ('  dynamic "ingress" {\n    for_each = var.rules\n    content {}\n  }\n', "dynamic"),
        (
            '  ingress {\n    from_port = var.port\n    to_port = 22\n    protocol = "tcp"\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n  }\n',
            "not a literal",
        ),
        (
            '  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n'
            "    cidr_blocks = var.cidrs\n  }\n",
            "not a literal",
        ),
    ],
)
def test_unsupported_hcl_stops(tmp_path: Path, body: str, match: str) -> None:
    tf = write_sg(tmp_path, body)
    with pytest.raises(StageStop, match=match):
        parse_security_group(tf, 1, "aws_security_group", "web")


def test_separate_rule_resources_stop(tmp_path: Path) -> None:
    extra = (
        'resource "aws_vpc_security_group_ingress_rule" "ssh" {\n'
        "  security_group_id = aws_security_group.web.id\n}\n"
    )
    tf = write_sg(tmp_path, "", extra)
    with pytest.raises(StageStop, match="separate|resources"):
        parse_security_group(tf, 1, "aws_security_group", "web")


def test_crlf_files_keep_crlf(basic_repo: Path, tmp_path: Path) -> None:
    repo = tmp_path / "r"
    shutil.copytree(basic_repo, repo)
    tf = repo / "modules/bastion/main.tf"
    tf.write_bytes(tf.read_bytes().replace(b"\n", b"\r\n"))
    sg = parse_security_group(tf, 5, "aws_security_group", "this")
    s = synthesize(contract([nr("10.0.4.12/32")]), sg.rules(), SynthesisConfig())
    new = make_diff(repo, sg, s, "x").files[0].new_content
    assert "\r\n" in new and "\r\r" not in new and new.count("\n") == new.count("\r\n")


# --- properties: zero wrongly-reported-safe ----------------------------------------------

_octet = st.integers(0, 255)
_private = st.tuples(st.just(10), st.integers(0, 3), _octet, _octet).map(lambda t: ".".join(map(str, t)))  # fmt: skip
_public = st.tuples(st.just(203), st.just(0), st.integers(113, 114), _octet).map(lambda t: ".".join(map(str, t)))  # fmt: skip


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    sources=st.lists(st.one_of(_private, _public), min_size=1, max_size=25, unique=True),
    quota=st.integers(1, 30),
)
def test_synthesis_properties(sources: list[str], quota: int) -> None:
    c = contract([nr(f"{s}/32") for s in sources])
    cfg = SynthesisConfig(rules_quota=quota)
    try:
        s = synthesize(c, [OPEN_22], cfg)
    except StageStop:
        return  # fail closed is always acceptable
    assert len(s.added) <= quota
    for r in s.added:
        net = ipaddress.ip_network(r.cidr)
        assert net.prefixlen >= (16 if net.is_private and str(net).startswith("10.") else 24)
    # Every contract source stays allowed, and the world rule is gone.
    for src in c.must_allow:
        assert allow_holds(s.added, src)
    for d in c.must_deny:
        assert deny_holds(s.added, d)
    assert all(r.holds for r in check_contract(s.added, c))


@settings(max_examples=60, deadline=None)
@given(
    rules=st.lists(
        st.tuples(_private, st.integers(8, 32)).map(
            lambda t: Rule(str(ipaddress.ip_network(f"{t[0]}/{t[1]}", strict=False)), 22, 22, "tcp")
        ),
        max_size=6,
    ),
    probe=_private,
)
def test_allow_invariant_agrees_with_brute_force(rules: list[Rule], probe: str) -> None:
    """If the Z3 check says a /32 is allowed, an exact evaluation agrees (and vice versa)."""
    src = nr(f"{probe}/32")
    exact = any(ipaddress.ip_address(probe) in r.net for r in rules)
    assert allow_holds(rules, src) == exact
