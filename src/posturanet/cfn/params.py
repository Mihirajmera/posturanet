"""Parameters and conditions: read `!Ref <Param>` and `Fn::If` only when the value is known.

Values come from the deployed stack (`cloudformation:DescribeStacks`) or, offline, from each
parameter's `Default` (and the values a parent template passes to a nested stack). NoEcho
parameters are never read, so their values can't reach a log, a contract or a PR. Anything
else (pseudo parameters, `!GetAtt`, `!Sub`, a condition that depends on an unknown value) is
`Unresolved`, and the caller stops with UNKNOWN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from posturanet.aws.session import ClientFactory
from posturanet.cfn.template import Template, get, is_intrinsic, value
from posturanet.errors import StageStop

NO_VALUE = object()  # `!Ref AWS::NoValue`: the property or list item is absent


class Unresolved(Exception):
    """A value PosturaNet can't know from the template and the stack's parameters."""


def _norm(v: Any, ptype: str) -> Any:
    """Parameter values are strings to CloudFormation; list types split on commas."""
    if ptype.startswith("List<") or ptype == "CommaDelimitedList":
        return [str(x).strip() for x in v] if isinstance(v, list) else str(v).split(",")
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


@dataclass
class Scope:
    """The parameter values and conditions of one stack. `Scope()` knows nothing."""

    template: Template | None = None
    stack: str = ""
    aws: ClientFactory | None = None
    # Offline nested stacks: values the parent passes; `blocked` ones the parent can't resolve.
    passed: dict[str, Any] = field(default_factory=dict)
    blocked: set[str] = field(default_factory=set)
    _params: dict[str, Any] | None = None
    _conds: dict[str, bool | None] = field(default_factory=dict)

    @property
    def source(self) -> str:
        return "cloudformation:DescribeStacks" if self.aws is not None else "template defaults"

    def _decl(self) -> dict[str, Any]:
        d = value(get(self.template.root, "Parameters")) if self.template else None
        return {k: v for k, v in d.items() if isinstance(v, dict)} if isinstance(d, dict) else {}

    def params(self) -> dict[str, Any]:
        if self._params is not None:
            return self._params
        decl = self._decl()
        raw: dict[str, Any] = {}
        if decl and self.aws is not None:
            try:
                stacks = self.aws("cloudformation").describe_stacks(StackName=self.stack)["Stacks"]
            except Exception as exc:  # botocore ClientError; boto3 is only imported in aws/
                raise StageStop(
                    "locate", f"cloudformation:DescribeStacks failed for {self.stack}: {exc}"
                ) from exc
            for p in stacks[0].get("Parameters", []) if stacks else []:
                v = p.get("ResolvedValue", p.get("ParameterValue"))
                if v is not None:
                    raw[str(p.get("ParameterKey"))] = v
        elif decl:
            raw = {k: d["Default"] for k, d in decl.items() if "Default" in d}
            raw.update(self.passed)
            for k, d in decl.items():  # offline, an SSM parameter's Default is its path
                if str(d.get("Type", "")).startswith("AWS::SSM::Parameter::Value"):
                    raw.pop(k, None)
        self._params = {
            k: _norm(v, str(decl[k].get("Type", "String")))
            for k, v in raw.items()
            if k in decl
            and k not in self.blocked
            and str(decl[k].get("NoEcho", "")).lower() != "true"
        }
        return self._params

    def _why_ref(self, name: str) -> str:
        decl = self._decl().get(name)
        if decl is None:
            return f"Ref {name} is not a parameter"
        if str(decl.get("NoEcho", "")).lower() == "true":
            return f"parameter {name} is NoEcho, so PosturaNet doesn't read it"
        return f"parameter {name} has no known value"

    def condition(self, name: str) -> bool | None:
        """True or False when every input is known; None otherwise."""
        if name in self._conds:
            return self._conds[name]
        self._conds[name] = None  # a cycle reads as unknown
        conds = value(get(self.template.root, "Conditions")) if self.template else None
        expr = conds.get(name) if isinstance(conds, dict) else None
        self._conds[name] = None if expr is None else self._eval(expr)
        return self._conds[name]

    def _eval(self, expr: Any) -> bool | None:
        if not isinstance(expr, dict) or len(expr) != 1:
            return None
        ((fn, arg),) = expr.items()
        if fn == "Condition" and isinstance(arg, str):
            return self.condition(arg)
        if not isinstance(arg, list):
            return None
        if fn == "Fn::Equals" and len(arg) == 2:
            try:
                a, b = (self.resolve(x)[0] for x in arg)
            except Unresolved:
                return None
            return bool(_norm(a, "String") == _norm(b, "String"))
        parts = [self._eval(x) for x in arg]
        if fn == "Fn::Not" and len(parts) == 1:
            return None if parts[0] is None else not parts[0]
        if fn == "Fn::And":
            return False if False in parts else None if None in parts else True
        if fn == "Fn::Or":
            return True if True in parts else None if None in parts else False
        return None

    def resolve(self, v: Any) -> tuple[Any, list[str]]:
        """(the literal value, the parameters and conditions it came from) or `Unresolved`."""
        if is_intrinsic(v):
            ((fn, arg),) = v.items()
            if fn == "Ref" and arg == "AWS::NoValue":
                return NO_VALUE, []
            if fn == "Ref" and isinstance(arg, str):
                params = self.params()
                if arg in params:
                    return params[arg], [f"parameter {arg}"]
                raise Unresolved(self._why_ref(arg))
            if fn == "Fn::If" and isinstance(arg, list) and len(arg) == 3:
                cond = arg[0]
                picked = self.condition(cond) if isinstance(cond, str) else None
                if picked is None:
                    raise Unresolved(f"condition {cond} can't be resolved from known parameters")
                out, src = self.resolve(arg[1] if picked else arg[2])
                return out, [f"condition {cond}", *src]
            raise Unresolved(f"{fn} is not a literal value")
        sources: list[str] = []
        if isinstance(v, dict):
            out_d = {}
            for k, x in v.items():
                r, s = self.resolve(x)
                sources += s
                if r is not NO_VALUE:
                    out_d[k] = r
            return out_d, sources
        if isinstance(v, list):
            out_l = []
            for x in v:
                r, s = self.resolve(x)
                sources += s
                if r is not NO_VALUE:
                    out_l.append(r)
            return out_l, sources
        return v, []


def param_stop(what: str, sources: list[str]) -> StageStop:
    """The fix would have to rewrite a value that comes from a parameter or condition."""
    via = ", ".join(dict.fromkeys(sources))
    return StageStop(
        "fix",
        f"the fix must change {what}, which comes from {via}; "
        "PosturaNet never rewrites a parameterised value",
        [
            f"change {via} where the stack is deployed, or make the value a literal and re-run",
            "fix this resource by hand",
        ],
        unknown=True,
    )


def unresolved_stop(what: str, why: Unresolved) -> StageStop:
    return StageStop(
        "fix",
        f"{what}: {why}; PosturaNet won't guess it",
        ["fix this resource by hand, or make the value a literal and re-run"],
        unknown=True,
    )
