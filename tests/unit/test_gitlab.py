"""GitLab merge-request delivery (FR-27, FR-28) against a fake GitLab API."""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import unquote

import httpx
import pytest

from posturanet.deliver.github import PullRequest, push_pr
from posturanet.deliver.gitlab import GitLab
from posturanet.deliver.idempotency import markers
from posturanet.errors import StageStop


class FakeGitLab:
    def __init__(self) -> None:
        self.files: dict[tuple[str, str], str] = {("main.tf", "main"): "old\n"}
        self.branches: dict[str, str] = {"main": "sha-main"}
        self.mrs: list[dict[str, Any]] = []
        self.calls: list[str] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        path = unquote(req.url.raw_path.decode().split("?")[0])
        assert path.startswith("/api/v4/projects/team/infra/"), path
        assert req.headers["Authorization"] == "Bearer t0k"
        rest = path.removeprefix("/api/v4/projects/team/infra")
        body = json.loads(req.content) if req.content else {}
        q = req.url.params
        self.calls.append(f"{req.method} {rest}")
        if rest == "/merge_requests" and req.method == "GET":
            return httpx.Response(200, json=[m for m in self.mrs if m["state"] == "opened"])
        if rest == "/merge_requests" and req.method == "POST":
            mr = {
                "iid": len(self.mrs) + 1,
                "web_url": f"https://gitlab.example/team/infra/-/merge_requests/{len(self.mrs) + 1}",
                "description": body["description"],
                "title": body["title"],
                "source_branch": body["source_branch"],
                "target_branch": body["target_branch"],
                "labels": [],
                "state": "opened",
            }
            self.mrs.append(mr)
            return httpx.Response(201, json=mr)
        if rest.startswith("/merge_requests/") and req.method == "PUT":
            mr = self.mrs[int(rest.rsplit("/", 1)[1]) - 1]
            if "add_labels" in body:
                mr["labels"] += body["add_labels"].split(",")
            mr.update({k: v for k, v in body.items() if k in ("title", "description")})
            return httpx.Response(200, json=mr)
        if rest.startswith("/repository/branches/"):
            name = rest.removeprefix("/repository/branches/")
            if req.method == "DELETE":
                return httpx.Response(204 if self.branches.pop(name, None) else 404)
            if name not in self.branches:
                return httpx.Response(404)
            return httpx.Response(200, json={"commit": {"id": self.branches[name]}})
        if rest == "/repository/branches" and req.method == "POST":
            if q["branch"] in self.branches:
                return httpx.Response(400)
            self.branches[q["branch"]] = q["ref"]
            return httpx.Response(201, json={})
        if rest.startswith("/repository/files/"):
            name = rest.removeprefix("/repository/files/")
            if req.method == "GET":
                text = self.files.get((name, q["ref"]))
                if text is None:
                    return httpx.Response(404)
                content = base64.b64encode(text.encode()).decode()
                return httpx.Response(200, json={"content": content, "blob_id": "b1"})
            branch = body["branch"]
            if req.method == "DELETE":
                self.files.pop((name, branch))
                return httpx.Response(204)
            exists = (name, branch) in self.files
            if (req.method == "POST") == exists:
                return httpx.Response(400)
            self.files[(name, branch)] = base64.b64decode(body["content"]).decode()
            return httpx.Response(201, json={})
        return httpx.Response(500)


def _gl(fake: FakeGitLab) -> GitLab:
    client = httpx.Client(
        base_url="https://gitlab.example/api/v4", transport=httpx.MockTransport(fake)
    )
    return GitLab("t0k", "team/infra", "https://gitlab.example", client=client)


def _pr(key: str = "a" * 64, content: str = "new\n") -> PullRequest:
    return PullRequest(
        finding_id="f-1",
        key=key,
        branch="posturanet/sg/web-12345678",
        title="fix: close SSH",
        body="Fix.\n" + markers(key, "f-1"),
        labels=["posturanet", "security"],
        writes=[("main.tf", content, "fix(security): close SSH [posturanet]")],
    )


def test_opens_then_updates_one_merge_request() -> None:
    fake = FakeGitLab()
    gl = _gl(fake)
    local = {"main.tf": "old\n"}

    first = push_pr(gl, _pr(), base="main", max_open=5, local_originals=local)
    assert (first.action, first.number) == ("opened", 1)
    assert first.url.endswith("/merge_requests/1")
    assert fake.files[("main.tf", "posturanet/sg/web-12345678")] == "new\n"
    assert fake.mrs[0]["labels"] == ["posturanet", "security"]
    assert fake.mrs[0]["target_branch"] == "main"

    same = push_pr(gl, _pr(), base="main", max_open=5, local_originals=local)
    assert same.action == "unchanged"

    changed = push_pr(gl, _pr("j" * 64, "newer\n"), base="main", max_open=5, local_originals=local)
    assert (changed.action, changed.number) == ("updated", 1)
    assert len(fake.mrs) == 1
    assert fake.files[("main.tf", "posturanet/sg/web-12345678")] == "newer\n"
    assert not any("merge" in c and "/merge_requests/1/merge" in c for c in fake.calls)


def test_refuses_other_branches_and_stale_base() -> None:
    fake = FakeGitLab()
    gl = _gl(fake)
    with pytest.raises(StageStop, match="not a PosturaNet branch"):
        gl.set_branch("main", "sha", exists=True)
    with pytest.raises(StageStop, match="differs from the local checkout"):
        push_pr(gl, _pr(), base="main", max_open=5, local_originals={"main.tf": "edited\n"})
    assert fake.branches == {"main": "sha-main"}


def test_auth_error_stops_with_next_step() -> None:
    gl = GitLab(
        "bad",
        "team/infra",
        client=httpx.Client(
            base_url="https://gitlab.com/api/v4",
            transport=httpx.MockTransport(lambda r: httpx.Response(401)),
        ),
    )
    with pytest.raises(StageStop) as err:
        gl.open_prs()
    assert "api scope" in " ".join(err.value.next_steps)


def test_forge_selection_from_config() -> None:
    from posturanet.models.config import Config
    from posturanet.pipeline import Context, _base, _forge

    config = Config.model_validate(
        {"delivery": {"provider": "gitlab", "gitlab": {"base": "trunk"}}}
    )
    ctx = Context(env={"GITLAB_TOKEN": "x", "CI_PROJECT_PATH": "g/p"})
    forge = _forge(config, ctx)
    assert isinstance(forge, GitLab) and forge.project == "g/p"
    assert _base(config) == "trunk"
    with pytest.raises(StageStop, match="GITLAB_TOKEN"):
        _forge(config, Context(env={}))
