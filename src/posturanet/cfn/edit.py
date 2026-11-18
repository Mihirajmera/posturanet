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
    Raw,
    Template,
    TemplateError,
    block_mapping,
    end,
    get,
    indent_of,
    is_intrinsic,
    json_mapping,
    key_node,
    line_end,
    line_of,
    line_start,
    parse,
    scalar_text,
    start,
    value,
)
from posturanet.configfix.catalog import PRESENT, Change, ConfigFix
from posturanet.errors import StageStop
from posturanet.iamfix.doc import Statement
from posturanet.iamfix.shrink import targeted
from posturanet.synth.hcl_render import DEFAULT_DESCRIPTION
from posturanet.synth.sg_rules import WORLD, Rule, norm_proto
from posturanet.synth.sg_z3 import Synthesis

SG_TYPE = "AWS::EC2::SecurityGroup"
SG_INGRESS_TYPE = "AWS::EC2::SecurityGroupIngress"
BUCKET_TYPE = "AWS::S3::Bucket"
POLICY_TYPE = "AWS::IAM::ManagedPolicy"
STANDALONE_POLICY_TYPE = "AWS::IAM::Policy"
SAM_FUNCTION_TYPE = "AWS::Serverless::Function"
# Resources an IAM finding can name: the managed policy, or the principal holding inline policies.
IAM_TYPES = [POLICY_TYPE, "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"]
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
            if isinstance(v, list) and v and isinstance(v[0], tuple)
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


# --- IAM policy documents


@dataclass
class CfnPolicy:
    res: CfnResource  # the resource whose text holds the document
    statements: list[Statement]
    action_nodes: dict[int, Node]
    doc: MappingNode | None = None
    name: str | None = None  # inline PolicyName (SAM: the generated one); None = whole resource

    @property
    def address(self) -> str:
        """`cfn.<stack>.<LogicalId>`, plus `.<PolicyName>` for an inline document."""
        return self.res.address + (f".{self.name}" if self.name else "")

    @property
    def where(self) -> str:
        return f"{self.name} in {self.res.logical_id}" if self.name else self.res.logical_id


def _iam_unknown(why: str, *steps: str) -> StageStop:
    return StageStop("fix", why, list(steps) or ["shrink this policy by hand"], unknown=True)


def _strs(v: Any, what: str) -> list[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return list(v)
    raise _iam_unknown(f"{what} is not a literal value; PosturaNet won't guess it", _BY_HAND)


def _sam_policies(res: CfnResource) -> list[Node]:
    pols = get(res.properties, "Policies")
    return [] if pols is None else pols.value if isinstance(pols, SequenceNode) else [pols]


def _inline_doc(res: CfnResource, name: str) -> MappingNode:
    """The document named `name` inside `res` (Role/User/Group `Policies`, SAM `Policies`)."""
    if res.type == SAM_FUNCTION_TYPE:
        prefix = f"{res.logical_id}RolePolicy"
        idx = name[len(prefix) :]
        entries = _sam_policies(res)
        if not name.startswith(prefix) or not idx.isdigit() or int(idx) >= len(entries):
            raise _iam_unknown(f"{res.logical_id} has no SAM policy {name}")
        entry = entries[int(idx)]
        if not isinstance(entry, MappingNode) or get(entry, "Statement") is None:
            raise _iam_unknown(
                f"{name} ({_sam_label(entry)}) is not an inline statement document",
                "SAM policy templates and managed policies are fixed by hand",
            )
        return entry
    for entry in _entries(res):
        if value(get(entry, "PolicyName")) == name:
            doc = get(entry, "PolicyDocument")
            if not isinstance(doc, MappingNode):
                raise _iam_unknown(f"PolicyDocument of {name} in {res.logical_id} is not literal")
            return doc
    raise _iam_unknown(f"{res.logical_id} has no inline policy named {name}")


def _entries(res: CfnResource) -> list[MappingNode]:
    pols = get(res.properties, "Policies")
    if pols is None:
        return []
    if not isinstance(pols, SequenceNode) or not all(
        isinstance(e, MappingNode) and isinstance(value(get(e, "PolicyName")), str)
        for e in pols.value
    ):
        raise _iam_unknown(f"{res.logical_id} Policies is not a literal list of named policies")
    return list(pols.value)


def _sam_label(entry: Node) -> str:
    v = value(entry)
    if is_intrinsic(v):
        return "an intrinsic function"
    if isinstance(v, str):
        return f"managed policy {v}"
    if isinstance(v, dict) and len(v) == 1:
        return f"SAM policy template {next(iter(v))}"
    return "an intrinsic function"


def _refs(v: Any, logical_id: str) -> bool:
    if isinstance(v, dict):
        if v.get("Ref") == logical_id:
            return True
        att = v.get("Fn::GetAtt")
        if isinstance(att, list) and att and att[0] == logical_id:
            return True
        return any(_refs(x, logical_id) for x in v.values())
    return isinstance(v, list) and any(_refs(x, logical_id) for x in v)


def _attached(lid: str, node: MappingNode, logical_id: str) -> list[Any] | None:
    """Every principal an `AWS::IAM::Policy` attaches to, if `logical_id` is one of them."""
    props = value(get(node, "Properties"))
    lists = [props.get(k) for k in ("Roles", "Users", "Groups")] if isinstance(props, dict) else []
    if not any(_refs(v, logical_id) for v in lists):
        return None
    if not all(v is None or isinstance(v, list) for v in lists):
        raise _iam_unknown(f"{lid} lists its principals with an intrinsic function")
    return [p for v in lists for p in v or []]


def documents(res: CfnResource) -> tuple[list[CfnPolicy], list[str]]:
    """(the readable policy documents that apply to `res`, labels of the ones that can't be read).

    Role/User/Group: inline `Policies` entries plus `AWS::IAM::Policy` resources in the same
    template that attach to it. SAM function: its `Policies` statement documents."""
    if res.type == POLICY_TYPE:
        return [parse_policy(res)], []
    if res.type == SAM_FUNCTION_TYPE:
        if get(res.properties, "Role") is not None:
            raise _iam_unknown(f"{res.logical_id} uses its own Role; SAM generates no policy")
        found, opaque = [], []
        for i, entry in enumerate(_sam_policies(res)):
            if isinstance(entry, MappingNode) and get(entry, "Statement") is not None:
                found.append(parse_policy(res, f"{res.logical_id}RolePolicy{i}"))
            else:
                opaque.append(_sam_label(entry))
        return found, opaque
    found = [parse_policy(res, str(value(get(e, "PolicyName")))) for e in _entries(res)]
    for lid, node in res.template.resources.items():
        if value(get(node, "Type")) != STANDALONE_POLICY_TYPE:
            continue
        principals = _attached(lid, node, res.logical_id)
        if principals is None:
            continue
        if len(principals) != 1:
            # the evidence is this principal's use only; the others would lose access
            raise _iam_unknown(
                f"{lid} also attaches to other principals; the evidence covers {res.logical_id} "
                "only",
                f"shrink {lid} by hand, or give {res.logical_id} its own policy",
            )
        key = key_node(get(res.template.root, "Resources"), lid)  # type: ignore[arg-type]
        line = line_of(key) if key is not None else res.line
        other = CfnResource(res.stack, lid, STANDALONE_POLICY_TYPE, res.template, node, line)
        found.append(parse_policy(other))
    return found, []


def select_policy(res: CfnResource, control: str) -> CfnPolicy:
    """The one document behind the finding: the managed policy itself, or the single
    inline document on the role/user/group/function that has the wildcard `control` flags."""
    found, opaque = documents(res)
    if res.type == POLICY_TYPE:
        return found[0]
    hits = [
        p
        for p in found
        if any(
            s.effect == "Allow" and any(targeted(control, a) for a in s.actions or [])
            for s in p.statements
        )
    ]
    if len(hits) == 1:
        return hits[0]
    if hits:
        raise _iam_unknown(
            f"{len(hits)} policies on {res.logical_id} have the {control} wildcard: "
            + ", ".join(p.where for p in hits),
            "shrink these policies by hand, or split the role",
        )
    why = f"no inline policy document on {res.logical_id} has the {control} wildcard"
    if opaque:
        why += "; " + ", ".join(opaque) + " can't be read as statements"
    raise _iam_unknown(
        why,
        "SAM policy templates and managed policies are fixed by hand",
        "a managed policy with the wildcard has its own finding",
    )


def parse_policy(res: CfnResource, name: str | None = None) -> CfnPolicy:
    doc = (
        _inline_doc(res, name)
        if name is not None
        else get(res.properties, "PolicyDocument")
        if res.type in (POLICY_TYPE, STANDALONE_POLICY_TYPE)
        else None
    )
    if not isinstance(doc, MappingNode):
        raise _iam_unknown(f"{res.logical_id} PolicyDocument is not a literal document")
    st = get(doc, "Statement")
    nodes = (
        st.value if isinstance(st, SequenceNode) else [st] if isinstance(st, MappingNode) else None
    )
    where = f"{name} in {res.logical_id}" if name else res.logical_id
    if nodes is None:
        raise _iam_unknown(f"{where} Statement is not a literal list")
    statements: list[Statement] = []
    action_nodes: dict[int, Node] = {}
    text = res.template.text
    for idx, s in enumerate(nodes):
        v = value(s)
        what = f"{where} statement {idx + 1}"
        if not isinstance(s, MappingNode) or not isinstance(v, dict):
            raise _iam_unknown(f"{what} is not a literal mapping")
        if not isinstance(v.get("Effect"), str):
            raise _iam_unknown(f"{what} Effect is not a literal value")
        action = get(s, "Action")
        actions = None
        if action is not None:
            actions = _strs(value(action), f"{what} Action")
            action_nodes[idx] = action
        res_v = v.get("Resource")
        resources = (
            ["<NotResource>"]
            if "NotResource" in v
            else _strs(res_v, f"{what} Resource")
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
    return CfnPolicy(res, statements, action_nodes, doc, name)


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


# --- attribute fixes (configfix catalog rows mapped with ConfigFix.for_cfn)


def _kv_path(path: str) -> tuple[str, str] | None:
    """`Attrs[some.key]` → ("Attrs", "some.key"): the Value of a {Key, Value} list item."""
    if not path.endswith("]") or "[" not in path:
        return None
    head, key = path[:-1].split("[", 1)
    return head, key


def _kv_index(res: CfnResource, path: str, items: Any, key: str) -> int | None:
    if is_intrinsic(items) or not isinstance(items, list):
        raise _unsupported(f"{res.logical_id} {path}")
    for i, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("Key"), str):
            raise _unsupported(f"{res.logical_id} {path}")
        if item["Key"] == key:
            return i
    return None


def _prop(res: CfnResource, path: str) -> tuple[bool, Any]:
    """(present, value) of a property path under Properties; stops on an intrinsic on the way."""
    kv = _kv_path(path)
    if kv is not None:
        present, items = _prop(res, kv[0])
        if not present:
            return False, None
        i = _kv_index(res, path, items, kv[1])
        return (False, None) if i is None else (True, items[i].get("Value"))
    cur: Any = value(res.properties) if res.properties is not None else {}
    for part in path.split("."):
        if is_intrinsic(cur) or not isinstance(cur, dict):
            raise _unsupported(f"{res.logical_id} {path}")
        if part not in cur:
            return False, None
        cur = cur[part]
    return True, cur


def _literal(res: CfnResource, c: Change, v: Any) -> Any:
    """The property as a plain value the change can compare; CloudFormation often writes
    booleans and numbers as strings."""
    what = f"{res.logical_id} {c.path}"
    if v is None or isinstance(v, dict):
        raise _unsupported(what)
    if isinstance(v, list):
        if not all(isinstance(x, str) for x in v):
            raise _unsupported(what)
        return v
    if isinstance(v, str) and isinstance(c.value, bool) and v.lower() in ("true", "false"):
        return v.lower() == "true"
    if isinstance(v, str) and c.op == "at_least" and v.isdigit():
        return int(v)
    return v


def attr_applies(res: CfnResource, fix: ConfigFix) -> tuple[bool, str]:
    for w in fix.when:
        present, v = _prop(res, w.path)
        if is_intrinsic(v):
            raise _unsupported(f"{res.logical_id} {w.path}")
        if not present and None in w.in_:
            continue
        if present and (PRESENT in w.in_ or v in w.in_):
            continue
        shown = "not set" if not present else repr(v)
        return False, f"{w.path} is {shown}"
    return True, ""


def attr_unmet(res: CfnResource, fix: ConfigFix) -> list[str]:
    """The changes the resource doesn't meet yet."""
    unmet = []
    for c in fix.changes:
        present, v = _prop(res, c.path)
        if not present or not c.satisfied_by(_literal(res, c, v)):
            unmet.append(c.describe())
    return unmet


def _nest(parts: list[str], v: Any) -> list[tuple[str, Any]]:
    return [(parts[0], _nest(parts[1:], v) if len(parts) > 1 else v)]


def _append_items(t: Template, seq: SequenceNode, items: list[str]) -> Edit:
    text = t.text
    if not seq.flow_style:
        ind = indent_of(text, start(seq.value[-1]))
        pos = line_end(text, end(seq))
        lead = "" if text[:pos].endswith("\n") else "\n"
        return pos, pos, lead + "".join(f"{ind}- {scalar_text(i, as_json=False)}\n" for i in items)
    rendered = [scalar_text(i, as_json=t.is_json) for i in items]
    if not seq.value:
        return end(seq) - 1, end(seq) - 1, ", ".join(rendered)
    last = seq.value[-1]
    sep = ",\n" + indent_of(text, start(last)) if "\n" in text[start(seq) : end(seq)] else ", "
    return end(last), end(last), "".join(sep + r for r in rendered)


def _attr_edit(res: CfnResource, c: Change) -> Edit | None:
    """One edit that makes the resource meet `c`, or None if it already does."""
    present, cur = _prop(res, c.path)
    if present and c.satisfied_by(_literal(res, c, cur)):
        return None
    t, step, parts = res.template, _step(res), c.path.split(".")
    want: Any = list(c.value) if isinstance(c.value, list) else c.value
    if _kv_path(c.path) is not None:
        return _kv_edit(res, c.path, want)
    node = res.properties
    if node is None:
        return insert_pairs(t.text, res.node, [("Properties", _nest(parts, want))], step)
    for i, part in enumerate(parts):
        if not isinstance(node, MappingNode) or str(node.tag).startswith("!"):
            raise _unsupported(f"{res.logical_id} {'.'.join(parts[:i]) or 'Properties'}")
        child = get(node, part)
        if child is None:
            return insert_pairs(t.text, node, _nest(parts[i:], want), step)
        node = child
    if str(node.tag).startswith("!"):
        raise _unsupported(f"{res.logical_id} {c.path}")
    if c.op == "includes":
        if not isinstance(node, SequenceNode):
            raise _unsupported(f"{res.logical_id} {c.path}")
        return _append_items(t, node, [v for v in want if v not in cur])
    if not isinstance(node, ScalarNode):
        raise _unsupported(f"{res.logical_id} {c.path}")
    return start(node), end(node), scalar_text(want, as_json=t.is_json)


def _kv_edit(res: CfnResource, path: str, want: Any) -> Edit:
    """Set the Value of the {Key, Value} item, adding the item (or the list) if missing."""
    kv = _kv_path(path)
    assert kv is not None
    head, key = kv
    t, step = res.template, _step(res)
    val = _kv_text(want)
    present, items = _prop(res, head)
    seq = _node_at(res, head) if present else None
    if seq is not None:
        if not isinstance(seq, SequenceNode) or str(seq.tag).startswith("!"):
            raise _unsupported(f"{res.logical_id} {head}")
        i = _kv_index(res, path, items, key)
        if i is not None:
            v = get(seq.value[i], "Value")
            if not isinstance(v, ScalarNode) or str(v.tag).startswith("!"):
                raise _unsupported(f"{res.logical_id} {path}")
            return start(v), end(v), scalar_text(val, as_json=t.is_json)
        if not seq.flow_style and seq.value:
            pos = line_end(t.text, end(seq))
            ind = indent_of(t.text, start(seq.value[-1]))
            return pos, pos, _lead(t.text, pos) + _kv_block(key, val, ind)
        flow = _kv_flow(key, val, as_json=t.is_json)
        if not seq.value:
            return end(seq) - 1, end(seq) - 1, flow
        last = seq.value[-1]
        multiline = "\n" in t.text[start(seq) : end(seq)]
        sep = ",\n" + indent_of(t.text, start(last)) if multiline else ", "
        return end(last), end(last), sep + flow
    # No list yet: add it to the mapping that should hold it.
    *parents, name = head.split(".")
    parent = _node_at(res, ".".join(parents)) if parents else res.properties
    if not isinstance(parent, MappingNode) or str(parent.tag).startswith("!"):
        raise _unsupported(f"{res.logical_id} {head}")
    if parent.flow_style or not parent.value:
        flow = "[" + _kv_flow(key, val, as_json=t.is_json) + "]"
        return insert_pairs(t.text, parent, [(name, Raw(flow))], step)
    ind = " " * parent.value[0][0].start_mark.column
    pos = line_end(t.text, end(parent))
    return pos, pos, _lead(t.text, pos) + f"{ind}{name}:\n" + _kv_block(key, val, ind + step)


def _lead(text: str, pos: int) -> str:
    return "" if text[:pos].endswith("\n") else "\n"


def _kv_text(v: Any) -> str:
    """CloudFormation takes these Values as strings."""
    return ("true" if v else "false") if isinstance(v, bool) else str(v)


def _kv_block(key: str, val: str, ind: str) -> str:
    k, v = scalar_text(key, as_json=False), scalar_text(val, as_json=False)
    return f"{ind}- Key: {k}\n{ind}  Value: {v}\n"


def _kv_flow(key: str, val: str, *, as_json: bool) -> str:
    k, v = ('"Key"', '"Value"') if as_json else ("Key", "Value")
    return f"{{{k}: {scalar_text(key, as_json=as_json)}, {v}: {scalar_text(val, as_json=as_json)}}}"


def _node_at(res: CfnResource, path: str) -> Node | None:
    node: Node | None = res.properties
    for part in path.split("."):
        if not isinstance(node, MappingNode) or str(node.tag).startswith("!"):
            raise _unsupported(f"{res.logical_id} {path}")
        node = get(node, part)
        if node is None:
            return None
    return node


def attr_edit(res: CfnResource, fix: ConfigFix) -> tuple[str, list[str], list[str]]:
    """(new text, changes made, changes already met). `fix` carries CloudFormation paths."""
    ok, why = attr_applies(res, fix)
    if not ok:
        raise StageStop(
            "fix", f"the {fix.control} fix doesn't apply here: {why}", ["fix this resource by hand"]
        )
    text, changed, already = res.template.text, [], []
    for c in fix.changes:
        # Re-read after each edit: two changes can share a parent that the first one adds.
        try:
            t = parse(text, res.template.path)
        except TemplateError as exc:
            raise StageStop("fix", f"the edited template doesn't parse: {exc}") from exc
        cur = CfnResource(
            res.stack, res.logical_id, res.type, t, t.resources[res.logical_id], res.line
        )
        e = _attr_edit(cur, c)
        if e is None:
            already.append(c.describe())
        else:
            text = apply(text, [e])
            changed.append(c.describe())
    return text, changed, already
