"""Open or update the fix as a GitLab merge request (FR-27, FR-28, FR-30), for `fix --open-pr`.

The same calls as `github.GitHub` that `push_pr` makes, against the GitLab REST API (v4,
gitlab.com or self-managed). Merge requests come back in GitHub's shape (`number`,
`html_url`, `body`, `head.ref`, `labels[].name`), so idempotency and the open-MR limit work
unchanged. Writes only to `posturanet/...` branches and the MR itself; never merges, approves
or pushes to the base branch.

Not on GitLab yet: `verify`, the contract-check status and the sticky comment (GitHub only).
"""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import quote

import httpx

from posturanet.errors import StageStop

DEFAULT_URL = "https://gitlab.com"


def _q(text: str) -> str:
    return quote(text, safe="")


class GitLab:
    def __init__(
        self, token: str, project: str, url: str = DEFAULT_URL, client: httpx.Client | None = None
    ) -> None:
        self.project = project
        self.base = f"/projects/{_q(project)}"
        self.http = client or httpx.Client(base_url=url.rstrip("/") + "/api/v4", timeout=30.0)
        self.headers = {"Authorization": f"Bearer {token}", "User-Agent": "posturanet"}

    def _req(self, method: str, path: str, **kw: Any) -> httpx.Response:
        try:
            resp = self.http.request(method, self.base + path, headers=self.headers, **kw)
        except httpx.HTTPError as exc:
            raise StageStop("deliver", f"GitLab request failed: {exc.__class__.__name__}") from exc
        if resp.status_code in (401, 403):
            raise StageStop(
                "deliver",
                f"GitLab refused {method} {path.split('?')[0]} ({resp.status_code})",
                ["the token needs the api scope and the Developer role on this project"],
            )
        return resp

    def _ok(self, resp: httpx.Response, what: str) -> Any:
        if resp.status_code >= 300:
            raise StageStop("deliver", f"GitLab could not {what} ({resp.status_code})")
        return resp.json() if resp.content else None

    @staticmethod
    def _as_pr(mr: dict[str, Any]) -> dict[str, Any]:
        return {
            "number": mr["iid"],
            "html_url": mr["web_url"],
            "body": mr.get("description") or "",
            "head": {"ref": mr["source_branch"]},
            "labels": [{"name": name} for name in mr.get("labels", [])],
        }

    def open_prs(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            data = self._ok(
                self._req("GET", f"/merge_requests?state=opened&per_page=100&page={page}"),
                "list merge requests",
            )
            out += [self._as_pr(mr) for mr in data]
            if len(data) < 100:
                return out
            page += 1

    def ref_sha(self, branch: str) -> str:
        data = self._ok(self._req("GET", f"/repository/branches/{_q(branch)}"), f"read {branch}")
        return str(data["commit"]["id"])

    def set_branch(self, branch: str, sha: str, *, exists: bool) -> None:
        if not branch.startswith("posturanet/"):
            raise StageStop("deliver", f"refusing to write to {branch}: not a PosturaNet branch")
        if exists:  # GitLab has no force-update of a ref: recreate our own branch
            resp = self._req("DELETE", f"/repository/branches/{_q(branch)}")
            if resp.status_code not in (204, 404):
                self._ok(resp, f"reset {branch}")
        resp = self._req("POST", "/repository/branches", params={"branch": branch, "ref": sha})
        if resp.status_code == 400 and not exists:  # left over from an earlier run
            self.set_branch(branch, sha, exists=True)
            return
        self._ok(resp, f"create {branch}")

    def get_file(self, path: str, ref: str) -> tuple[str | None, str | None]:
        resp = self._req("GET", f"/repository/files/{_q(path)}", params={"ref": ref})
        if resp.status_code == 404:
            return None, None
        data = self._ok(resp, f"read {path}")
        return base64.b64decode(data["content"]).decode("utf-8"), str(data["blob_id"])

    def put_file(self, path: str, branch: str, content: str, message: str) -> None:
        existing, _ = self.get_file(path, branch)
        payload = {
            "branch": branch,
            "commit_message": message,
            "encoding": "base64",
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        }
        method = "POST" if existing is None else "PUT"
        self._ok(self._req(method, f"/repository/files/{_q(path)}", json=payload), f"write {path}")

    def delete_file(self, path: str, branch: str, message: str) -> None:
        existing, _ = self.get_file(path, branch)
        if existing is None:
            return
        self._ok(
            self._req(
                "DELETE",
                f"/repository/files/{_q(path)}",
                json={"branch": branch, "commit_message": message},
            ),
            f"delete {path}",
        )

    def create_pr(self, title: str, body: str, head: str, base: str) -> dict[str, Any]:
        mr = self._ok(
            self._req(
                "POST",
                "/merge_requests",
                json={
                    "source_branch": head,
                    "target_branch": base,
                    "title": title,
                    "description": body,
                    "remove_source_branch": True,
                },
            ),
            "open the merge request",
        )
        return self._as_pr(mr)

    def update_pr(self, number: int, title: str, body: str) -> None:
        self._ok(
            self._req(
                "PUT", f"/merge_requests/{number}", json={"title": title, "description": body}
            ),
            "update the merge request",
        )

    def add_labels(self, number: int, labels: list[str]) -> None:
        if labels:
            self._ok(
                self._req(
                    "PUT", f"/merge_requests/{number}", json={"add_labels": ",".join(labels)}
                ),
                "label the merge request",
            )
