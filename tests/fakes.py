"""Test doubles: Terraform without providers, and a recording GitHub API."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx

from posturanet.locate.hcl_index import find_resource_block
from posturanet.synth.sg_rules import Rule, parse_security_group
from posturanet.validate.tf import TfResult

TARGET = "module.bastion.aws_security_group.this"


def ingress_json(rules: list[Rule]) -> list[dict[str, Any]]:
    out = []
    for r in rules:
        v6 = ":" in r.cidr
        out.append(
            {
                "cidr_blocks": [] if v6 else [r.cidr],
                "ipv6_cidr_blocks": [r.cidr] if v6 else [],
                "from_port": r.from_port,
                "to_port": r.to_port,
                "protocol": r.proto,
                "description": "",
                "prefix_list_ids": [],
                "security_groups": [],
                "self": False,
            }
        )
    return out


def plan_for(
    before: list[Rule],
    after: list[Rule],
    *,
    address: str = TARGET,
    actions: list[str] | None = None,
    extra: list[dict[str, Any]] | None = None,
    after_unknown: bool = False,
) -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": address,
                "mode": "managed",
                "type": "aws_security_group",
                "change": {
                    "actions": actions or ["update"],
                    "before": {"ingress": ingress_json(before)},
                    "after": {"ingress": ingress_json(after)},
                    "after_unknown": {"ingress": True} if after_unknown else {},
                },
            },
            *(extra or []),
        ],
    }


class FakeTerraform:
    """Plans by parsing the patched HCL in the work dir, like a provider-less `terraform plan`."""

    def __init__(
        self,
        *,
        available: bool = True,
        fmt_ok: bool = True,
        live_before: list[Rule] | None = None,
        extra_changes: list[dict[str, Any]] | None = None,
    ) -> None:
        self._available = available
        self.fmt_ok = fmt_ok
        self.live_before = live_before
        self.extra_changes = extra_changes
        self.calls: list[str] = []

    def available(self) -> bool:
        return self._available

    def fmt_check(self, workdir: Path, files: list[str]) -> TfResult:
        self.calls.append("fmt")
        return TfResult(self.fmt_ok, "" if self.fmt_ok else files[0])

    def init(self, workdir: Path, *, backend: bool) -> TfResult:
        self.calls.append("init")
        return TfResult(True, "")

    def validate(self, workdir: Path) -> TfResult:
        self.calls.append("validate")
        return TfResult(True, "Success!")

    def plan_json(self, workdir: Path, state: Path | None) -> tuple[TfResult, dict[str, Any]]:
        self.calls.append("plan")
        module = workdir / "modules" / "bastion"
        block = find_resource_block(module, "aws_security_group", "this")
        assert block is not None
        after = parse_security_group(block.file, block.line, "aws_security_group", "this").rules()
        before = self.live_before
        if before is None:
            before = [Rule("0.0.0.0/0", 22, 22, "tcp")]
        return TfResult(True, ""), plan_for(before, after, extra=self.extra_changes)


class ConfigTerraform(FakeTerraform):
    """Plans an attribute fix: `after` is read from the patched HCL, `before` is given."""

    def __init__(
        self,
        address: str,
        rtype: str,
        paths: list[str],
        *,
        before: dict[str, Any] | None = None,
        extra_after: dict[str, Any] | None = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.address, self.rtype, self.paths = address, rtype, paths
        self.before = before or {}
        self.extra_after = extra_after or {}

    def plan_json(self, workdir: Path, state: Path | None) -> tuple[TfResult, dict[str, Any]]:
        from posturanet.configfix.hcl_attrs import ABSENT, BLOCK, lookup

        self.calls.append("plan")
        name = self.address.rsplit(".", 1)[-1]
        block = find_resource_block(workdir, self.rtype, name)
        assert block is not None
        text = block.file.read_text(encoding="utf-8")
        after: dict[str, Any] = {**self.before, **self.extra_after}
        for path in self.paths:
            value = lookup(text, block.line, path)
            if value is ABSENT or value is BLOCK:
                continue
            *parents, leaf = path.split(".")
            node: Any = {leaf: value}
            for p in reversed(parents):
                node = {p: [node]}
            after.update(node)
        change = {"actions": ["update"], "before": self.before, "after": after}
        rc = {"address": self.address, "mode": "managed", "type": self.rtype, "change": change}
        return TfResult(True, ""), {
            "format_version": "1.2",
            "resource_changes": [rc, *(self.extra_changes or [])],
        }


class FakeGitHub:
    """In-memory GitHub REST API behind httpx.MockTransport. Records every write."""

    def __init__(self, files: dict[str, str], open_prs: list[dict[str, Any]] | None = None):
        self.files = {("main", k): v for k, v in files.items()}
        self.prs = open_prs or []
        self.writes: list[tuple[str, str]] = []
        self.refs: dict[str, str] = {"main": "basesha"}
        self.parents: dict[str, str] = {}
        self.pr_files: dict[int, list[dict[str, Any]]] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content else {}
        repo = "/repos/acme/infra"
        if method == "GET" and path == f"{repo}/pulls":
            return httpx.Response(200, json=[p for p in self.prs if p.get("state") != "closed"])
        if method == "GET" and path.startswith(f"{repo}/pulls/"):
            rest = path.removeprefix(f"{repo}/pulls/")
            if rest.endswith("/files"):
                return httpx.Response(200, json=self.pr_files.get(int(rest.split("/")[0]), []))
            pr = next((p for p in self.prs if p["number"] == int(rest)), None)
            return httpx.Response(200, json=pr) if pr else httpx.Response(404, json={})
        if method == "GET" and path.startswith(f"{repo}/commits/"):
            sha = path.removeprefix(f"{repo}/commits/")
            return httpx.Response(200, json={"parents": [{"sha": self.parents[sha]}]})
        if method == "GET" and path.startswith(f"{repo}/git/ref/heads/"):
            name = path.removeprefix(f"{repo}/git/ref/heads/")
            return httpx.Response(200, json={"object": {"sha": self.refs[name]}})
        if method == "GET" and path.startswith(f"{repo}/contents/"):
            fpath = path.removeprefix(f"{repo}/contents/")
            ref = request.url.params.get("ref", "main")
            if (ref, fpath) not in self.files:
                return httpx.Response(404, json={})
            content = base64.b64encode(self.files[(ref, fpath)].encode()).decode()
            return httpx.Response(200, json={"content": content, "sha": f"sha-{fpath}"})
        self.writes.append((method, path))
        if method == "POST" and path == f"{repo}/git/refs":
            name = body["ref"].removeprefix("refs/heads/")
            self.refs[name] = body["sha"]
            for (ref, fpath), text in list(self.files.items()):
                if ref == "main":
                    self.files[(name, fpath)] = text
            return httpx.Response(201, json={})
        if method == "PATCH" and path.startswith(f"{repo}/git/refs/heads/"):
            return httpx.Response(200, json={})
        if method == "DELETE" and path.startswith(f"{repo}/contents/"):
            self.files.pop((body["branch"], path.removeprefix(f"{repo}/contents/")), None)
            return httpx.Response(200, json={})
        if method == "PUT" and path.startswith(f"{repo}/contents/"):
            fpath = path.removeprefix(f"{repo}/contents/")
            self.files[(body["branch"], fpath)] = base64.b64decode(body["content"]).decode()
            return httpx.Response(201, json={})
        if method == "POST" and path == f"{repo}/pulls":
            number = 412 + len(self.prs)
            pr = {
                "number": number,
                "html_url": f"https://github.com/acme/infra/pull/{number}",
                "state": "open",
                "head": {"ref": body["head"]},
                "body": body["body"],
                "title": body["title"],
                "labels": [],
            }
            self.prs.append(pr)
            return httpx.Response(201, json=pr)
        if method == "PATCH" and path.startswith(f"{repo}/pulls/"):
            return httpx.Response(200, json={})
        if method == "POST" and path.endswith("/labels"):
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={"message": f"unexpected {method} {path}"})

    def merge(self, number: int, merged_at: str = "2026-10-30T12:00:00Z") -> str:
        """Merge PR `number` into main like GitHub would; returns the merge sha."""
        pr = next(p for p in self.prs if p["number"] == number)
        branch, sha = pr["head"]["ref"], f"merge{number}"
        self.parents[sha] = f"parent{number}"
        main = {f: t for (ref, f), t in self.files.items() if ref == "main"}
        for f, t in main.items():
            self.files[(f"parent{number}", f)] = t
        changed = []
        for (ref, f), t in list(self.files.items()):
            if ref == branch and main.get(f) != t:
                changed.append({"filename": f, "status": "added" if f not in main else "modified"})
                self.files[("main", f)] = t
        for (ref, f), t in list(self.files.items()):
            if ref == "main":
                self.files[(sha, f)] = t
        self.pr_files[number] = changed
        pr.update(state="closed", merged_at=merged_at, merge_commit_sha=sha)
        return sha

    def client(self) -> httpx.Client:
        return httpx.Client(
            base_url="https://api.github.com", transport=httpx.MockTransport(self.handler)
        )
