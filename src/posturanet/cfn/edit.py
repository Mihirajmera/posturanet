"""Minimal edits to CloudFormation templates for the three evidence-backed fix types.

Each edit replaces one node's span (or inserts after one) and leaves every other character as
the customer wrote it. Block YAML gets block YAML, flow YAML and JSON get JSON-style flow, in
the indentation already used around the change. Values PosturaNet can't read literally
(`!If`, `!FindInMap`, parameters) stop the run instead of being guessed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ruamel.yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from posturanet.cfn.locate import CfnResource
from posturanet.cfn.template import (
    Template,
    block_mapping,
    end,
    get,
    indent_of,
    is_intrinsic,
    json_mapping,
    key_node,
    line_end,
    line_start,
    scalar_text,
    start,
    value,
)
from posturanet.errors import StageStop
from posturanet.iamfix.doc import Statement
from posturanet.synth.hcl_render import DEFAULT_DESCRIPTION
from posturanet.synth.sg_rules import WORLD, Rule, norm_proto
from posturanet.synth.sg_z3 import Synthesis

SG_TYPE = "AWS::EC2::SecurityGroup"
SG_INGRESS_TYPE = "AWS::EC2::SecurityGroupIngress"
BUCKET_TYPE = "AWS::S3::Bucket"
POLICY_TYPE = "AWS::IAM::ManagedPolicy"
PAB = "PublicAccessBlockConfiguration"
# Terraform flag name -> CloudFormation property name.
PAB_FLAGS = {
    "block_public_acls": "BlockPublicAcls",
    "block_public_policy": "BlockPublicPolicy",
    "ignore_public_acls": "IgnorePublicAcls",
    "restrict_public_buckets": "RestrictPublicBuckets",
}
_BY_HAND = "fix this resource by hand, or make the value a literal and re-run"

Edit = tuple[int, int, str]  # replace text[start:end] with the string


def apply(text: str, edits: list[Edit]) -> str:
    # At one offset a removal goes before an insertion, so it never eats the inserted text.
    for s, e, new in sorted(edits, key=lambda x: (-x[0], -x[1])):
        text = text[:s] + new + text[e:]
    return text


def _step(res: CfnResource) -> str:
    """The template's indent step, read from how the resource is nested under its key."""
    key_line = res.template.text.split("\n")[res.line - 1]
    width = res.node.start_mark.column - (len(key_line) - len(key_line.lstrip()))
    return " " * width if not res.node.flow_style and width > 0 else "  "


def _unsupported(what: str, *, unknown: bool = False) -> StageStop:
    return StageStop(
        "fix",
        f"{what} is not a literal value; PosturaNet won't guess it",
        [_BY_HAND],
        unknown=unknown,
    )


def remove_pair(text: str, mapping: MappingNode, key: str) -> Edit:
    """An edit that deletes `key` and its value from `mapping`, comments around it kept."""
    keys = [k.value for k, _ in mapping.value]
    i = keys.index(key)
    k, v = mapping.value[i]
    if not mapping.flow_style:
        s, e = line_start(text, start(k)), line_end(text, end(v))
        if text[e : e + 1] == "\n" and (s == 0 or text[:s].endswith("\n\n")):
            e += 1  # don't leave two blank lines where one block was
        return s, e, ""
    if i + 1 < len(keys):
        return start(k), start(mapping.value[i + 1][0]), ""
    return (end(mapping.value[i - 1][1]) if i else start(k)), end(v), ""


def insert_pairs(text: str, mapping: MappingNode, pairs: list[tuple[str, Any]], step: str) -> Edit:
    """An edit that adds `pairs` (nested pairs allowed) at the end of `mapping`."""
    if not mapping.flow_style:
        if not mapping.value:
            raise _unsupported("an empty block mapping")
        indent = " " * mapping.value[0][0].start_mark.column
        pos = line_end(text, end(mapping))
        lead = "" if text[:pos].endswith("\n") else "\n"
        return pos, pos, lead + "\n".join(block_mapping(pairs, indent, step)) + "\n"
    close = int(mapping.end_mark.index) - 1  # the "}"
    raw = text[start(mapping) : close + 1]
    multiline = "\n" in raw
    if not mapping.value:
        key_ind = indent_of(text, start(mapping)) + step
        pos = close
    else:
        key_ind = " " * mapping.value[0][0].start_mark.column
        pos = end(mapping.value[-1][1])
    items = [
        f'"{k}": '
        + (
            json_mapping(v, key_ind, step, multiline=multiline)
            if isinstance(v, list)
            else scalar_text(v, as_json=True)
        )
        for k, v in pairs
    ]
    sep = ",\n" + key_ind if multiline else ", "
    lead = "" if not mapping.value else ","
    body = (("\n" + key_ind) if multiline else " ") if not mapping.value else sep[1:]
    return pos, pos, lead + body + sep.join(items)


# --- security groups


@dataclass
class IngressEntry:
    node: MappingNode  # the inline entry, or the standalone resource's Properties
    rules: list[Rule]
    is_open: bool
    description: str | None
    resource: str | None = None  # logical id of a standalone SecurityGroupIngress


@dataclass
class CfnSecurityGroup:
    res: CfnResource
    seq: SequenceNode | None
    entries: list[IngressEntry] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.res.template.text

    def rules(self) -> list[Rule]:
        return sorted({r for e in self.entries for r in e.rules})


def _group_target(v: Any) -> tuple[str, str] | None:
    """(logical id, "Ref" or attribute) for a plain `Ref` / `Fn::GetAtt` GroupId, else None."""
    if not isinstance(v, dict) or len(v) != 1:
        return None
    if isinstance(v.get("Ref"), str):
        return v["Ref"], "Ref"
    att = v.get("Fn::GetAtt")
    if isinstance(att, str):
        att = att.split(".", 1)
    if isinstance(att, list) and len(att) == 2 and all(isinstance(a, str) for a in att):
        return att[0], att[1]
    return None


def owned_ingress(resources: dict[str, Any], sg_id: str, *, strict: bool = False) -> list[str]:
    """Logical ids of the SecurityGroupIngress resources that add rules to `sg_id`.

    `resources` is the plain Resources dict. With `strict`, one whose GroupId might point at
    `sg_id` but isn't a plain `!Ref`/`!GetAtt .GroupId` to a resource here stops UNKNOWN.
    """
    out = []
    for lid, r in resources.items():
        if not isinstance(r, dict) or r.get("Type") != SG_INGRESS_TYPE:
            continue
        props = r.get("Properties")
        target = _group_target(props.get("GroupId") if isinstance(props, dict) else None)
        if target in ((sg_id, "Ref"), (sg_id, "GroupId")):
            out.append(lid)
        elif strict and (target is None or target[0] == sg_id or target[0] not in resources):
            raise StageStop(
                "fix",
                f"{lid} ({SG_INGRESS_TYPE}) has a GroupId PosturaNet can't tie to a resource "
                f"in this template, so it may add rules to {sg_id}",
                [
                    "fix this group by hand, or set GroupId to !Ref or !GetAtt <group>.GroupId",
                ],
                unknown=True,
            )
    return out


def _entry(node: Node | None, what: str, resource: str | None = None) -> IngressEntry:
    v = value(node)
    if not isinstance(node, MappingNode) or not isinstance(v, dict):
        raise _unsupported(what, unknown=True)
    for k in ("IpProtocol", "FromPort", "ToPort", "CidrIp", "CidrIpv6"):
        if is_intrinsic(v.get(k)):
            raise _unsupported(f"{what} {k}", unknown=True)
    proto = norm_proto(v.get("IpProtocol", ""))
    lo, hi = int(v.get("FromPort", -1)), int(v.get("ToPort", -1))
    cidrs = [str(v[k]) for k in ("CidrIp", "CidrIpv6") if k in v]
    desc = v.get("Description")
    return IngressEntry(
        node,
        [Rule(c, lo, hi, proto) for c in cidrs],
        any(c in WORLD for c in cidrs),
        desc if isinstance(desc, str) else None,
        resource,
    )


def parse_sg(res: CfnResource) -> CfnSecurityGroup:
    """Inline SecurityGroupIngress entries, then standalone SecurityGroupIngress resources."""
    t = res.template
    props = res.properties
    if props is not None and not isinstance(props, MappingNode):
        raise _unsupported(f"{res.logical_id} Properties")
    seq = get(props, "SecurityGroupIngress")
    if seq is not None and not isinstance(seq, SequenceNode):
        raise _unsupported(f"{res.logical_id} SecurityGroupIngress")
    items = seq.value if seq is not None else []
    entries = [_entry(item, f"an ingress entry of {res.logical_id}") for item in items]
    plain = value(get(t.root, "Resources"))
    for lid in owned_ingress(plain, res.logical_id, strict=True):
        entries.append(_entry(get(t.resources[lid], "Properties"), lid, lid))
    return CfnSecurityGroup(res, seq, entries)


def _rule_pairs(r: Rule, desc: str) -> list[tuple[str, Any]]:
    return [
        ("IpProtocol", r.proto),
        ("FromPort", r.from_port),
        ("ToPort", r.to_port),
        ("CidrIp" if r.net.version == 4 else "CidrIpv6", r.cidr),
        ("Description", desc),
    ]


def _description(sg: CfnSecurityGroup, r: Rule) -> str:
    for e in sg.entries:
        if (
            e.is_open
            and e.description
            and any(o.proto == "-1" or o.from_port <= r.from_port <= o.to_port for o in e.rules)
        ):
            return e.description
    return DEFAULT_DESCRIPTION


def render_sg(sg: CfnSecurityGroup, synth: Synthesis) -> str:
    """New template text: open entries removed, synthesized rules where the first one was.

    An open standalone SecurityGroupIngress is deleted, or, when it is the first open entry,
    edited to carry the first new rule, with copies of it for the rest.
    """
    open_entries = [e for e in sg.entries if e.is_open]
    if not open_entries:
        return sg.text
    new_items = [_rule_pairs(r, _description(sg, r)) for r in synth.added]
    host = open_entries[0]
    edits: list[Edit] = []
    for e in open_entries:
        if e.resource is None:
            continue
        if e is host and new_items:
            edits += _standalone_edits(sg, e, new_items)
        else:
            edits.append(remove_pair(sg.text, _resources(sg), e.resource))
    inline_open = [e for e in open_entries if e.resource is None]
    if inline_open:
        assert sg.seq is not None
        edits += _inline_edits(sg, sg.seq, inline_open, new_items if host.resource is None else [])
    return apply(sg.text, edits)


def _resources(sg: CfnSecurityGroup) -> MappingNode:
    node = get(sg.res.template.root, "Resources")
    assert isinstance(node, MappingNode)
    return node


def _set_pairs(
    sg: CfnSecurityGroup, props: MappingNode, pairs: list[tuple[str, Any]]
) -> list[Edit]:
    """Edits that make the rule fields of a standalone resource's Properties equal `pairs`."""
    t, text = sg.res.template, sg.text
    edits: list[Edit] = []
    missing = []
    for k, v in pairs:
        node = get(props, k)
        if node is None:
            missing.append((k, v))
        elif value(node) != v:
            quoted = t.is_json or (isinstance(node, ScalarNode) and node.style == '"')
            edits.append((start(node), end(node), scalar_text(v, as_json=quoted)))
    wanted = {k for k, _ in pairs}
    edits += [
        remove_pair(text, props, k)
        for k in ("CidrIp", "CidrIpv6")
        if k not in wanted and get(props, k) is not None
    ]
    if missing:
        edits.append(insert_pairs(text, props, missing, _step(sg.res)))
    return edits


def _standalone_edits(
    sg: CfnSecurityGroup, host: IngressEntry, new_items: list[list[tuple[str, Any]]]
) -> list[Edit]:
    """The host resource carries the first new rule; copies of it, renamed, carry the rest."""
    assert host.resource is not None
    t, text, rs = sg.res.template, sg.text, _resources(sg)
    key = key_node(rs, host.resource)
    assert key is not None
    node = t.resources[host.resource]
    if rs.flow_style:
        s, e = start(key), end(node)
    else:
        s, e = line_start(text, start(key)), line_end(text, end(node))
    blank = not rs.flow_style and (text[e : e + 1] == "\n" or text[:s].endswith("\n\n"))
    taken = set(t.resources)
    copies = []
    for pairs in new_items[1:]:
        n = 2
        while f"{host.resource}{n}" in taken:
            n += 1
        name = f"{host.resource}{n}"
        taken.add(name)
        body = apply(text[s:e], [(a - s, b - s, x) for a, b, x in _set_pairs(sg, host.node, pairs)])
        new_key = json.dumps(name) if key.style == '"' else name
        body = body[: start(key) - s] + new_key + body[end(key) - s :]
        copies.append(
            (",\n" + indent_of(text, s) if rs.flow_style else "\n" if blank else "") + body
        )
    lead = "" if rs.flow_style or text[:e].endswith("\n") else "\n"
    # The copies go in before the host's own inserted fields so those stay inside the host.
    out: list[Edit] = [(e, e, lead + "".join(copies))] if copies else []
    return out + _set_pairs(sg, host.node, new_items[0])


def _inline_edits(
    sg: CfnSecurityGroup,
    seq: SequenceNode,
    open_entries: list[IngressEntry],
    new_items: list[list[tuple[str, Any]]],
) -> list[Edit]:
    text = sg.text
    inline = [e for e in sg.entries if e.resource is None]
    if seq.flow_style:
        return [_render_flow(sg, seq, inline, open_entries, new_items)]
    edits: list[Edit] = []
    for idx, e in enumerate(open_entries):
        s = line_start(text, start(e.node))
        prefix = text[s : start(e.node)]
        m = re.fullmatch(r"([ \t]*)-[ \t]+", prefix)
        if m is None:
            raise StageStop(
                "fix",
                f"an ingress entry of {sg.res.logical_id} doesn't start on its `-` line",
                ["fix this group by hand"],
            )
        dash, key_ind = m.group(1), " " * len(prefix)
        lines: list[str] = []
        for pairs in new_items if idx == 0 else []:
            if e.node.flow_style:  # `- {IpProtocol: tcp, …}`: keep one line per entry
                flow = ", ".join(f"{k}: {scalar_text(v, as_json=False)}" for k, v in pairs)
                lines.append(f"{dash}- {{{flow}}}")
                continue
            block = block_mapping(pairs, key_ind, "  ")
            lines += [dash + "- " + block[0].lstrip(), *block[1:]]
        edits.append((s, line_end(text, end(e.node)), "".join(f"{ln}\n" for ln in lines)))
    if len(open_entries) == len(inline) and not new_items:
        props = sg.res.properties
        assert isinstance(props, MappingNode)
        key = key_node(props, "SecurityGroupIngress")
        assert key is not None
        edits = [(line_start(text, start(key)), line_end(text, end(seq)), "")]
    return edits


def _render_flow(
    sg: CfnSecurityGroup,
    seq: SequenceNode,
    inline: list[IngressEntry],
    open_entries: list[IngressEntry],
    new_items: list[list[tuple[str, Any]]],
) -> Edit:
    text = sg.text
    raw_seq = text[start(seq) : end(seq)]
    multiline = "\n" in raw_seq
    first = open_entries[0].node
    item_ind = " " * first.start_mark.column
    key_col = first.value[0][0].start_mark.column if first.value else first.start_mark.column + 2
    step = " " * max(key_col - first.start_mark.column, 2)
    obj_multi = "\n" in text[start(first) : end(first)]
    items: list[str] = []
    for e in inline:
        if e is open_entries[0]:
            items += [json_mapping(p, item_ind, step, multiline=obj_multi) for p in new_items]
        elif not e.is_open:
            items.append(text[start(e.node) : end(e.node)])
    if multiline and items:
        close = indent_of(text, end(seq) - 1)
        body = "[\n" + ",\n".join(item_ind + i for i in items) + "\n" + close + "]"
    else:
        body = "[" + ", ".join(items) + "]"
    return start(seq), end(seq), body


# --- S3 Block Public Access


def s3_block_public_access(res: CfnResource) -> tuple[str, list[str], list[str]]:
    """(new text, settings changed, settings already on) for the bucket's four BPA flags."""
    text, step = res.template.text, _step(res)
    names = list(PAB_FLAGS.values())
    props = res.properties
    if props is None:
        pairs: list[tuple[str, Any]] = [("Properties", [(PAB, [(n, True) for n in names])])]
        return apply(text, [insert_pairs(text, res.node, pairs, step)]), names, []
    if not isinstance(props, MappingNode):
        raise _unsupported(f"{res.logical_id} Properties")
    pab = get(props, PAB)
    if pab is None:
        edit = insert_pairs(text, props, [(PAB, [(n, True) for n in names])], step)
        return apply(text, [edit]), names, []
    if not isinstance(pab, MappingNode):
        raise _unsupported(f"{res.logical_id} {PAB}")
    edits: list[Edit] = []
    changed, already, missing = [], [], []
    for n in names:
        node = get(pab, n)
        v = value(node)
        if node is None:
            missing.append(n)
        elif v is True or v == "true":
            already.append(n)
        elif isinstance(node, ScalarNode) and (v is False or v == "false"):
            edits.append((start(node), end(node), "true"))
            changed.append(n)
        else:
            raise _unsupported(f"{res.logical_id} {PAB}.{n}")
    if missing:
        edits.append(insert_pairs(text, pab, [(n, True) for n in missing], step))
        changed += missing
    return apply(text, edits), changed, already


def s3_flags(res: CfnResource) -> dict[str, Any]:
    """Terraform-named flags as set in the template (None when unset, '<unknown>' when not
    literal), for the S3 gate and re-check."""
    pab = value(get(res.properties, PAB))
    out: dict[str, Any] = {}
    for tf_name, cfn_name in PAB_FLAGS.items():
        v = pab.get(cfn_name) if isinstance(pab, dict) else None
        out[tf_name] = "<unknown>" if is_intrinsic(v) or is_intrinsic(pab) else v
    return out


# --- IAM managed policies


@dataclass
class CfnPolicy:
    res: CfnResource
    statements: list[Statement]
    action_nodes: dict[int, Node]


def _strs(v: Any, what: str) -> list[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return list(v)
    raise _unsupported(what)


def parse_policy(res: CfnResource) -> CfnPolicy:
    doc = get(res.properties, "PolicyDocument")
    if not isinstance(doc, MappingNode):
        raise _unsupported(f"{res.logical_id} PolicyDocument")
    st = get(doc, "Statement")
    nodes = (
        st.value if isinstance(st, SequenceNode) else [st] if isinstance(st, MappingNode) else None
    )
    if nodes is None:
        raise _unsupported(f"{res.logical_id} Statement")
    statements: list[Statement] = []
    action_nodes: dict[int, Node] = {}
    text = res.template.text
    for idx, s in enumerate(nodes):
        v = value(s)
        if not isinstance(s, MappingNode) or not isinstance(v, dict):
            raise _unsupported(f"statement {idx + 1}")
        if not isinstance(v.get("Effect"), str):
            raise _unsupported(f"statement {idx + 1} Effect")
        action = get(s, "Action")
        actions = None
        if action is not None:
            actions = _strs(value(action), f"statement {idx + 1} Action")
            action_nodes[idx] = action
        res_v = v.get("Resource")
        resources = (
            ["<NotResource>"]
            if "NotResource" in v
            else [r if isinstance(r, str) else "<expression>" for r in res_v]
            if isinstance(res_v, list)
            else [res_v if isinstance(res_v, str) else "<expression>"]
            if res_v is not None
            else []
        )
        sid = v.get("Sid")
        statements.append(
            Statement(
                index=idx,
                sid=sid if isinstance(sid, str) else None,
                effect=v["Effect"],
                actions=actions,
                not_action="NotAction" in v,
                resources=resources,
                span=(start(action), end(action)) if action is not None else None,
                indent=indent_of(text, start(action)) if action is not None else "",
                container=(start(s), end(s)),
            )
        )
    return CfnPolicy(res, statements, action_nodes)


def render_actions(t: Template, node: Node, actions: list[str], step: str) -> str:
    text = t.text
    if isinstance(node, SequenceNode) and not node.flow_style:
        ind: str = " " * int(node.start_mark.column)
        return ("\n" + ind).join(f"- {scalar_text(a, as_json=False)}" for a in actions)
    quoted = [scalar_text(a, as_json=True) for a in actions]
    raw = text[start(node) : end(node)]
    if isinstance(node, SequenceNode) and "\n" in raw and node.value:
        ind = " " * node.value[0].start_mark.column
        close = indent_of(text, end(node) - 1)
        return "[\n" + ",\n".join(ind + q for q in quoted) + "\n" + close + "]"
    if not t.is_json and isinstance(node, ScalarNode) and len(actions) > 3:
        ind = indent_of(text, start(node)) + step
        return "\n" + "\n".join(f"{ind}- {scalar_text(a, as_json=False)}" for a in actions)
    if t.is_json and len(actions) > 3:
        ind = indent_of(text, start(node))
        return "[\n" + ",\n".join(ind + step + q for q in quoted) + "\n" + ind + "]"
    return "[" + ", ".join(quoted) + "]"


def iam_edit(policy: CfnPolicy, after: dict[int, list[str]]) -> str:
    """New text with each statement's Action list replaced (statement index -> actions)."""
    t, step = policy.res.template, _step(policy.res)
    edits: list[Edit] = []
    for i, node in policy.action_nodes.items():
        if i not in after:
            continue
        new, s = render_actions(t, node, after[i], step), start(node)
        if new.startswith("\n"):  # a block list after `Action:` leaves no trailing space
            s = len(t.text[:s].rstrip(" "))
        edits.append((s, end(node), new))
    return apply(t.text, edits)
