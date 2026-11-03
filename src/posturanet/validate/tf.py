"""Terraform subprocess calls for validation (architecture doc 9).

Arguments are always a list (never a shell string). Plans run with `-lock=false` and
`-input=false`: a plan only reads, and a state lock would be a write to the backend.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass
class TfResult:
    ok: bool
    output: str
    missing: bool = False  # binary not found
    timed_out: bool = False


class TerraformRunner(Protocol):
    def available(self) -> bool: ...
    def fmt_check(self, workdir: Path, files: list[str]) -> TfResult: ...
    def init(self, workdir: Path, *, backend: bool) -> TfResult: ...
    def validate(self, workdir: Path) -> TfResult: ...
    def plan_json(
        self, workdir: Path, state: Path | None
    ) -> tuple[TfResult, dict[str, Any] | None]: ...


class SubprocessTerraform:
    def __init__(self, binary: str = "terraform", timeout_s: int = 300) -> None:
        self.binary = binary
        self.timeout_s = timeout_s

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def _run(self, workdir: Path, args: list[str]) -> TfResult:
        exe = shutil.which(self.binary)
        if exe is None:
            return TfResult(False, f"{self.binary} not found on PATH", missing=True)
        env = {**os.environ, "TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "CHECKPOINT_DISABLE": "1"}
        try:
            proc = subprocess.run(  # noqa: S603 - fixed binary, list args
                [exe, *args],
                cwd=workdir,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return TfResult(
                False, f"terraform {args[0]} timed out after {self.timeout_s}s", timed_out=True
            )
        return TfResult(proc.returncode == 0, (proc.stdout + proc.stderr).strip())

    def fmt_check(self, workdir: Path, files: list[str]) -> TfResult:
        return self._run(workdir, ["fmt", "-check", "-list=true", *files])

    def init(self, workdir: Path, *, backend: bool) -> TfResult:
        args = ["init", "-input=false", "-no-color", f"-backend={'true' if backend else 'false'}"]
        return self._run(workdir, args)

    def validate(self, workdir: Path) -> TfResult:
        return self._run(workdir, ["validate", "-no-color"])

    def plan_json(
        self, workdir: Path, state: Path | None
    ) -> tuple[TfResult, dict[str, Any] | None]:
        args = ["plan", "-input=false", "-lock=false", "-no-color", "-out=posturanet.tfplan"]
        if state is not None:
            args.append(f"-state={state}")
        res = self._run(workdir, args)
        if not res.ok:
            return res, None
        show = self._run(workdir, ["show", "-json", "posturanet.tfplan"])
        if not show.ok:
            return show, None
        try:
            return show, json.loads(show.output)
        except json.JSONDecodeError:
            return TfResult(False, "terraform show -json returned invalid JSON"), None
