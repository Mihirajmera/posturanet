"""What a Pulumi resource's literals say, in one shape for the source and the stack export.

Ingress rules, Block Public Access flags and policy documents are read from the program's
literals (`read`) and from the export's `inputs` and `outputs`, then compared: the literals
must explain the deployed inputs exactly (`explains`) and the inputs must equal the outputs
(`drift`). The literals also become a one-resource CloudFormation template (`resource`), so
the CloudFormation re-check, contract and invariant checks run on Pulumi code unchanged.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from posturanet.cdk.source import BY_HAND, Construct, norm
from posturanet.cfn.edit import BUCKET_TYPE, PAB, POLICY_TYPE, SG_TYPE
from posturanet.cfn.locate import CfnResource
from posturanet.cfn.template import parse
from posturanet.errors import StageStop
from posturanet.pulumi.source import Computed, Lit, Props, camel, has_computed, props, rescan
from posturanet.synth.sg_rules import WORLD, Rule, norm_proto

if TYPE_CHECKING:
    from posturanet.pulumi.stack import Part

FLAGS = ("blockPublicAcls", "blockPublicPolicy", "ignorePublicAcls", "restrictPublicBuckets")
_CFN_FLAG = {f: f[0].upper() + f[1:] for f in FLAGS}
_FOREIGN = ("securityGroups", "prefixListIds", "sourceSecurityGroupId", "prefixListId",
            "referencedSecurityGroupId")  # fmt: skip
_COMPUTED_REF = {"Ref": "PulumiComputedValue"}  # how a non-literal reads in the template


def _stop(why: str) -> StageStop:
    return StageStop("locate", why, [BY_HAND], unknown=True)


# --- security group rules


def entry_rules(d: dict[str, Any], what: str) -> list[Rule]:
    """Rules of one Pulumi ingress entry or standalone rule (camelCase keys, plain values)."""
    if d.get("type", "ingress") != "ingress":
        raise _stop(f"{what} is not a literal ingress rule")
    keys = ("protocol", "ipProtocol", "fromPort", "toPort", "cidrBlocks", "ipv6CidrBlocks",
            "cidrIpv4", "cidrIpv6", "self", *_FOREIGN)  # fmt: skip
    if any(has_computed(d.get(k)) for k in keys):
        raise _stop(f"{what} has a value that is not a literal")
    if d.get("self") is True or any(d.get(k) for k in _FOREIGN):
        raise _stop(
            f"{what} allows a security group or prefix list; PosturaNet edits CIDR rules only"
        )
    proto = norm_proto(d.get("protocol", d.get("ipProtocol", "")))
    if proto == "-1":
        lo = hi = -1
    elif isinstance(d.get("fromPort"), int) and isinstance(d.get("toPort"), int):
        lo, hi = d["fromPort"], d["toPort"]
    else:
        raise _stop(f"{what} has no literal fromPort and toPort")
    cidrs = [*(d.get("cidrBlocks") or []), *(d.get("ipv6CidrBlocks") or [])]
    cidrs += [d[k] for k in ("cidrIpv4", "cidrIpv6") if d.get(k)]
    if not all(isinstance(x, str) for x in cidrs):
        raise _stop(f"{what} has CIDRs that are not literal strings")
    try:
        return [
            norm(Rule(str(ipaddress.ip_network(c, strict=False)), lo, hi, proto)) for c in cidrs
        ]
    except ValueError as exc:
        raise _stop(f"{what} has a CIDR PosturaNet can't read") from exc


def is_open(rules: list[Rule]) -> bool:
    return any(str(r.net) in WORLD for r in rules)


@dataclass
class Entry:
    """One place ingress is written: an inline `ingress` item, or a standalone rule resource."""

    index: int  # which part (0 is the group itself)
    lit: Lit | None  # the inline item; None for a standalone resource
    rules: list[Rule]
    description: str | None
    quote: str


@dataclass
class View:
    constructs: list[Construct]  # one per part, from the text read
    props: list[Props]
    entries: list[Entry] = field(default_factory=list)
    ingress: Lit | None = None  # the group's inline list
    flags: dict[str, Lit | None] = field(default_factory=dict)
    doc: Any = None  # the policy document, normalized
    statements: list[Lit] = field(default_factory=list)  # each statement object

    @property
    def rules(self) -> list[Rule]:
        return sorted({r for e in self.entries for r in e.rules})


def _quote(lit: Lit) -> str:
    """The quote character the entry already uses."""
    if lit.kind == "str":
        return lit.quote
    vals = lit.value.values() if lit.kind == "obj" else lit.value if lit.kind == "list" else []
    return next((q for q in (_quote(v) for v in vals) if q), "")


def _read_sg(v: View, parts: list[Part]) -> None:
    group = v.props[0].values
    ing = group.get("ingress")
    if ing is not None:
        if ing.kind != "list":
            raise _stop(f"the ingress of '{parts[0].state.name}' is not a literal list")
        v.ingress = ing
        for i, item in enumerate(ing.value):
            what = f"ingress entry {i + 1} of '{parts[0].state.name}'"
            if item.kind != "obj":
                raise _stop(f"{what} is not a literal object")
            d = {camel(k): x for k, x in item.plain().items()}
            desc = d.get("description")
            v.entries.append(
                Entry(
                    0,
                    item,
                    entry_rules(d, what),
                    desc if isinstance(desc, str) else None,
                    _quote(item),
                )  # fmt: skip
            )
    for idx, p in enumerate(parts[1:], start=1):
        d = v.props[idx].plain()
        desc = d.get("description")
        v.entries.append(
            Entry(
                idx,
                None,
                entry_rules(d, f"ingress rule '{p.state.name}'"),
                desc if isinstance(desc, str) else None,
                next((_quote(x) for x in v.props[idx].values.values() if _quote(x)), ""),
            )
        )


def norm_doc(doc: Any) -> Any:
    """A policy document with one-item shorthands spelled out, for comparison."""
    if not isinstance(doc, dict):
        return doc
    out = dict(doc)
    st = out.get("Statement")
    sts = st if isinstance(st, list) else [st] if isinstance(st, dict) else st
    if isinstance(sts, list):
        fixed = []
        for s in sts:
            if isinstance(s, dict):
                s = dict(s)
                for k in ("Action", "NotAction", "Resource", "NotResource"):
                    if isinstance(s.get(k), str):
                        s[k] = [s[k]]
            fixed.append(s)
        out["Statement"] = fixed
    return out


def _read_policy(v: View, parts: list[Part]) -> None:
    name = parts[0].state.name
    lit = v.props[0].values.get("policy")
    doc = lit.value if lit is not None and lit.kind == "json" else lit
    if doc is None or doc.kind != "obj" or has_computed(doc.plain()):
        raise _stop(
            f"the policy of '{name}' is not a literal document (an object, or "
            "JSON.stringify / json.dumps of one); PosturaNet won't guess"
        )
    st = doc.value.get("Statement")
    sts = [st] if st is not None and st.kind == "obj" else st.value if st is not None else None
    if sts is None or st is None or st.kind not in ("obj", "list"):
        raise _stop(f"the Statement of '{name}' is not a literal list")
    if any(s.kind != "obj" for s in sts):
        raise _stop(f"a statement of '{name}' is not a literal object")
    v.statements = sts
    v.doc = norm_doc(doc.plain())


def read(rtype: str, parts: list[Part], texts: dict[Path, str]) -> View:
    from posturanet.pulumi.stack import BPA, POLICY, SG

    constructs = [
        rescan(p.construct, texts[p.construct.file]) if p.construct.file in texts else p.construct
        for p in parts
    ]
    v = View(constructs, [props(c) for c in constructs])
    if rtype == SG:
        _read_sg(v, parts)
    elif rtype == BPA:
        v.flags = {f: v.props[0].values.get(f) for f in FLAGS}
        bad = [f for f, x in v.flags.items() if x is not None and x.kind != "bool"]
        if bad:
            raise _stop(f"{', '.join(bad)} of '{parts[0].state.name}' is not a literal boolean")
    elif rtype == POLICY:
        _read_policy(v, parts)
    return v


# --- the same values from the export


def _state_doc(v: Any) -> Any:
    if isinstance(v, str):
        try:
            return norm_doc(json.loads(v))
        except ValueError:
            return Computed(v)
    return norm_doc(v)


def explains(rtype: str, v: View, parts: list[Part]) -> str | None:
    """None when the literals give exactly the export's inputs, else why not."""
    from posturanet.pulumi.stack import BPA, POLICY, SG

    st = parts[0].state
    if rtype == SG:
        try:
            deployed = sorted(
                {r for i, e in enumerate(st.inputs.get("ingress") or [])
                 for r in entry_rules(e, f"deployed ingress entry {i + 1}")}
                | {r for p in parts[1:] for r in entry_rules(p.state.inputs, p.state.name)}
            )  # fmt: skip
        except StageStop as exc:
            return f"in the stack export: {exc.reason}"
        if deployed != v.rules:
            return (
                f"'{st.name}' has {len(deployed)} ingress rule(s) in the stack export but "
                f"{len(v.rules)} in the literals of the program"
            )
        return None
    if rtype == BPA:
        diff = [
            f
            for f, lit in v.flags.items()
            if (lit.value if lit is not None else False) != bool(st.inputs.get(f, False))
        ]
        return (
            f"{', '.join(diff)} of '{st.name}' differ between the program and the stack export"
            if diff
            else None
        )
    if rtype == POLICY:
        if _state_doc(st.inputs.get("policy")) != v.doc:
            return f"the policy of '{st.name}' in the program differs from the stack export"
        return None
    return f"{st.type} is not a type PosturaNet edits"


def drift(rtype: str, parts: list[Part]) -> str | None:
    """None when the export's outputs (the deployed state) match its inputs, else why not."""
    from posturanet.pulumi.stack import BPA, POLICY, SG

    st = parts[0].state
    if not st.outputs:
        return f"the stack export has no outputs for '{st.name}'"
    try:
        if rtype == SG:
            inline = {r for e in st.inputs.get("ingress") or [] for r in entry_rules(e, st.name)}
            extra = {r for p in parts[1:] for r in entry_rules(p.state.inputs, p.state.name)}
            live = {r for e in st.outputs.get("ingress") or [] for r in entry_rules(e, st.name)}
            # outputs list standalone rules only after a refresh; both states are consistent
            if live not in (inline, inline | extra):
                return f"'{st.name}' has different ingress in its outputs than its inputs"
            for p in parts[1:]:
                if set(entry_rules(p.state.outputs, p.state.name)) != set(
                    entry_rules(p.state.inputs, p.state.name)
                ):
                    return f"ingress rule '{p.state.name}' differs between outputs and inputs"
            return None
    except StageStop as exc:
        return exc.reason
    if rtype == BPA:
        diff = [f for f in FLAGS if bool(st.inputs.get(f)) != bool(st.outputs.get(f))]
        return f"{', '.join(diff)} of '{st.name}' differ from its outputs" if diff else None
    if rtype == POLICY:
        same = _state_doc(st.inputs.get("policy")) == _state_doc(st.outputs.get("policy"))
        return None if same else f"the policy of '{st.name}' differs from its outputs"
    return None


# --- as a CloudFormation resource, for the shared checks


def _cfn_props(rtype: str, v: View) -> tuple[str, dict[str, Any]]:
    from posturanet.pulumi.stack import BPA, POLICY

    if rtype == BPA:
        pab = {_CFN_FLAG[f]: lit.value for f, lit in v.flags.items() if lit is not None}
        return BUCKET_TYPE, {PAB: pab}
    if rtype == POLICY:
        return POLICY_TYPE, {"PolicyDocument": v.doc}
    ingress = [
        {
            "IpProtocol": r.proto,
            "FromPort": r.from_port,
            "ToPort": r.to_port,
            ("CidrIp" if r.net.version == 4 else "CidrIpv6"): r.cidr,
        }
        for r in v.rules
    ]
    return SG_TYPE, {"SecurityGroupIngress": ingress}


def resource(rtype: str, v: View, stack: str, name: str, c: Construct) -> CfnResource:
    cfn_type, cfn_props = _cfn_props(rtype, v)
    text = json.dumps({"Resources": {name: {"Type": cfn_type, "Properties": cfn_props}}})
    t = parse(text, c.file)
    return CfnResource(stack, name, cfn_type, t, t.resources[name], c.line)
