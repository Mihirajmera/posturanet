"""Open or update the fix PR through the GitHub REST API (FR-27, FR-28, FR-30; architecture doc 10).

Writes only to a `posturanet/...` branch and the PR itself. Never merges, approves or pushes
to the base branch.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import httpx

from posturanet.deliver import pr_body
from posturanet.deliver.idempotency import finding_in, finding_tag, key_in
from posturanet.errors import StageStop
from posturanet.proposal import Proposal

API = "https://api.github.com"


@dataclass
class Delivery:
    url: str
    number: int
    action: str  # "opened" | "updated" | "unchanged"
    branch: str


class GitHub:
    def __init__(self, token: str, repo: str, client: httpx.Client | None = None) -> None:
        self.repo = repo
        self.http = client or httpx.Client(base_url=API, timeout=30.0)
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "posturanet",
        }

    def _req(
        self,
        method: str,
        path: str,
        *,
        need: str = "contents:write and pull-requests:write",
        **kw: Any,
    ) -> httpx.Response:
        try:
            resp = self.http.request(method, path, headers=self.headers, **kw)
        except httpx.HTTPError as exc:
            raise StageStop("deliver", f"GitHub request failed: {exc.__class__.__name__}") from exc
        if resp.status_code in (401, 403):
            raise StageStop(
                "deliver",
                f"GitHub refused {method} {path.split('?')[0]} ({resp.status_code})",
                [f"the token needs {need} on this repo"],
            )
        return resp

    def _ok(self, resp: httpx.Response, what: str) -> Any:
        if resp.status_code >= 300:
            raise StageStop("deliver", f"GitHub could not {what} ({resp.status_code})")
        return resp.json() if resp.content else None

    def open_prs(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            data = self._ok(
                self._req("GET", f"/repos/{self.repo}/pulls?state=open&per_page=100&page={page}"),
                "list pull requests",
            )
            out += data
            if len(data) < 100:
                return out
            page += 1

    def ref_sha(self, branch: str) -> str:
        data = self._ok(
            self._req("GET", f"/repos/{self.repo}/git/ref/heads/{branch}"), f"read {branch}"
        )
        return str(data["object"]["sha"])

    def set_branch(self, branch: str, sha: str, *, exists: bool) -> None:
        if not branch.startswith("posturanet/"):
            raise StageStop("deliver", f"refusing to write to {branch}: not a PosturaNet branch")
        if exists:
            self._ok(
                self._req(
                    "PATCH",
                    f"/repos/{self.repo}/git/refs/heads/{branch}",
                    json={"sha": sha, "force": True},
                ),
                f"reset {branch}",
            )
        else:
            resp = self._req(
                "POST",
                f"/repos/{self.repo}/git/refs",
                json={"ref": f"refs/heads/{branch}", "sha": sha},
            )
            if resp.status_code == 422:  # left over from an earlier run
                self.set_branch(branch, sha, exists=True)
                return
            self._ok(resp, f"create {branch}")

    def get_file(self, path: str, ref: str) -> tuple[str | None, str | None]:
        resp = self._req("GET", f"/repos/{self.repo}/contents/{path}?ref={ref}")
        if resp.status_code == 404:
            return None, None
        data = self._ok(resp, f"read {path}")
        content = base64.b64decode(data["content"]).decode("utf-8")
        return content, str(data["sha"])

    def put_file(self, path: str, branch: str, content: str, message: str) -> None:
        _, sha = self.get_file(path, branch)
        payload: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        self._ok(
            self._req("PUT", f"/repos/{self.repo}/contents/{path}", json=payload), f"write {path}"
        )

    def create_pr(self, title: str, body: str, head: str, base: str) -> dict[str, Any]:
        data: dict[str, Any] = self._ok(
            self._req(
                "POST",
                f"/repos/{self.repo}/pulls",
                json={"title": title, "body": body, "head": head, "base": base},
            ),
            "open the pull request",
        )
        return data

    def update_pr(self, number: int, title: str, body: str) -> None:
        self._ok(
            self._req(
                "PATCH", f"/repos/{self.repo}/pulls/{number}", json={"title": title, "body": body}
            ),
            "update the pull request",
        )

    def create_check_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        data: dict[str, Any] = self._ok(
            self._req("POST", f"/repos/{self.repo}/check-runs", need="checks:write", json=payload),
            "publish the check run",
        )
        return data

    def add_labels(self, number: int, labels: list[str]) -> None:
        self._ok(
            self._req(
                "POST", f"/repos/{self.repo}/issues/{number}/labels", json={"labels": labels}
            ),
            "label the pull request",
        )


def _norm(text: str | None) -> str | None:
    return None if text is None else text.replace("\r\n", "\n")


def branch_name(p: Proposal) -> str:
    short = pr_body.short_name(p).replace("_", "-").lower()
    return f"posturanet/{p.finding.fix_type.value}/{short}-{p.idempotency_key[:8]}"


def deliver(
    gh: GitHub,
    p: Proposal,
    *,
    base: str,
    labels: list[str],
    max_open: int,
    local_originals: dict[str, str | None],
    run_id: str,
) -> Delivery:
    message = f"fix(security): {p.finding.control_id} {p.location.address} [posturanet]"
    writes = [(fc.path, fc.new_content, message) for fc in p.diff.files]
    if p.contract_text is not None:
        writes.append((p.contract_file, p.contract_text, f"docs(contract): {p.location.address}"))
    return push_pr(
        gh,
        PullRequest(
            finding_id=p.finding.finding_id,
            key=p.idempotency_key,
            branch=branch_name(p),
            title=pr_body.title(p),
            body=pr_body.body(p, run_id=run_id),
            labels=pr_body.labels(p, labels),
            writes=writes,
        ),
        base=base,
        max_open=max_open,
        local_originals=local_originals,
    )


@dataclass
class PullRequest:
    """Everything a fix PR needs, independent of the fix type."""

    finding_id: str
    key: str  # idempotency key (FR-28)
    branch: str  # used only when no PR exists for this finding yet
    title: str
    body: str  # must contain idempotency.markers(key, finding_id)
    labels: list[str]
    writes: list[tuple[str, str, str]]  # (path, content, commit message)


def push_pr(
    gh: GitHub,
    pr_in: PullRequest,
    *,
    base: str,
    max_open: int,
    local_originals: dict[str, str | None],
) -> Delivery:
    prs = gh.open_prs()
    ours = [
        pr for pr in prs if any(lbl.get("name") == "posturanet" for lbl in pr.get("labels", []))
    ]
    tag = finding_tag(pr_in.finding_id)
    existing = next((pr for pr in prs if finding_in(pr.get("body")) == tag), None)

    if existing is not None and key_in(existing.get("body")) == pr_in.key:
        return Delivery(
            existing["html_url"], int(existing["number"]), "unchanged", existing["head"]["ref"]
        )
    if existing is None and len(ours) >= max_open:
        raise StageStop(
            "deliver",
            f"{len(ours)} PosturaNet PRs are already open (limit {max_open})",
            ["merge or close open PosturaNet PRs, or raise delivery.max_open_prs"],
        )

    # The PR must change only what we validated: the base must match the local checkout.
    for path, local in local_originals.items():
        remote, _ = gh.get_file(path, base)
        if _norm(remote) != _norm(local):
            raise StageStop(
                "deliver",
                f"{path} on {base} differs from the local checkout",
                [f"pull the latest {base} and re-run, so the PR is validated on the same code"],
            )

    base_sha = gh.ref_sha(base)
    branch = existing["head"]["ref"] if existing is not None else pr_in.branch
    gh.set_branch(branch, base_sha, exists=existing is not None)

    for path, content, message in pr_in.writes:
        gh.put_file(path, branch, content, message)

    if existing is not None:
        gh.update_pr(int(existing["number"]), pr_in.title, pr_in.body)
        gh.add_labels(int(existing["number"]), pr_in.labels)
        return Delivery(existing["html_url"], int(existing["number"]), "updated", branch)
    pr = gh.create_pr(pr_in.title, pr_in.body, branch, base)
    gh.add_labels(int(pr["number"]), pr_in.labels)
    return Delivery(pr["html_url"], int(pr["number"]), "opened", branch)
