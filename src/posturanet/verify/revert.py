"""Revert PR for a regressed fix (FR-33, architecture doc 11).

Restores every file the fix PR changed to its content before the merge, on a new
`posturanet/revert/...` branch. If any file changed on the base branch since the merge, it
stops: restoring it would also undo someone else's work.
"""

from __future__ import annotations

import hashlib
from typing import Any

from posturanet import __version__
from posturanet.deliver.github import Delivery, GitHub, PullRequest, push_pr
from posturanet.deliver.idempotency import markers
from posturanet.errors import StageStop
from posturanet.models import VerifySpec

_NO_LIMIT = 10**6  # a revert must never wait behind the open-PR limit


def _norm(text: str | None) -> str | None:
    return None if text is None else text.replace("\r\n", "\n")


def open_revert(
    gh: GitHub, pr: dict[str, Any], spec: VerifySpec, regressions: list[str], *, base: str
) -> Delivery:
    number = int(pr["number"])
    merge_sha = str(pr.get("merge_commit_sha") or "")
    if not merge_sha:
        raise StageStop("revert", f"#{number} has no merge commit to revert")
    parent = gh.first_parent(merge_sha)
    message = f"revert: #{number} {spec.control} {spec.address} [posturanet]"

    writes: list[tuple[str, str, str]] = []
    deletes: list[tuple[str, str]] = []
    for f in gh.pr_files(number):
        path = str(f["filename"])
        if f.get("status") == "renamed":
            raise StageStop(
                "revert",
                f"#{number} renamed {path}; PosturaNet doesn't revert renames",
                [f"revert by hand: git revert -m 1 {merge_sha[:12]}"],
            )
        before, _ = gh.get_file(path, parent)
        merged, _ = gh.get_file(path, merge_sha)
        now, _ = gh.get_file(path, base)
        if _norm(now) != _norm(merged):
            raise StageStop(
                "revert",
                f"{path} changed on {base} after #{number} merged",
                [f"revert by hand: git revert -m 1 {merge_sha[:12]}, then resolve the conflict"],
                why="restoring the old file would also undo later changes",
            )
        if before is None:
            deletes.append((path, message))
        else:
            writes.append((path, before, message))

    key = hashlib.sha256(f"revert:{spec.key}:{merge_sha}".encode()).hexdigest()
    short = spec.address.rsplit(".", 1)[-1].split("[", 1)[0]
    title = f"↩️ PosturaNet: revert #{number} ({spec.control} regression on {short})"
    if len(title) > 72:
        title = f"↩️ PosturaNet: revert #{number} ({spec.control} regression)"
    body = "\n".join(
        [
            markers(key, f"revert:{spec.finding_id}"),
            f"**PosturaNet** saw a regression after #{number} was applied and is reverting it.",
            "",
            "| | |",
            "|---|---|",
            f"| Fix PR | #{number} · merge `{merge_sha[:12]}` |",
            f"| Resource | `{spec.address}` |",
            f"| Control | {spec.control} (it will fail again after this revert) |",
            "",
            "### What regressed",
            *[f"- {r}" for r in regressions],
            "",
            "### What changes",
            f"Restores {len(writes) + len(deletes)} file(s) to their content before #{number}:",
            *[f"- `{p}`" for p, _, _ in writes],
            *[f"- `{p}` (added by #{number}; removed)" for p, _ in deletes],
            "",
            "### Before you merge",
            "- [ ] Confirm the blocked traffic above is legitimate.",
            "- [ ] Merge to apply through your normal pipeline. PosturaNet never applies changes.",
            "- [ ] Afterwards, re-run `posturanet fix` with a longer evidence window so the "
            "contract includes these sources.",
            "",
            f"<sub>PosturaNet {__version__} · checks describe the observed signals; they are not a "
            "guarantee of production behavior.</sub>",
        ]
    )
    return push_pr(
        gh,
        PullRequest(
            finding_id=f"revert:{spec.finding_id}",
            key=key,
            branch=f"posturanet/revert/{spec.key[:8]}",
            title=title,
            body=body + "\n",
            labels=["posturanet", "regression", "risk:high"],
            writes=writes,
            deletes=deletes,
        ),
        base=base,
        max_open=_NO_LIMIT,
        local_originals={},
    )
