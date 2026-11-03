"""Domain errors. Exit codes follow docs/02_ARCHITECTURE_AND_DATA.md section 12."""

from __future__ import annotations


class PosturaNetError(Exception):
    exit_code = 10


class UsageError(PosturaNetError):
    """Bad arguments or configuration."""

    exit_code = 2


class StageStop(PosturaNetError):
    """A pipeline stage stopped on purpose (fail closed). No PR is opened (NFR-1)."""

    exit_code = 3

    def __init__(
        self,
        stage: str,
        reason: str,
        next_steps: list[str] | None = None,
        *,
        why: str | None = None,
        unknown: bool = False,
        exit_code: int | None = None,
    ) -> None:
        super().__init__(reason)
        self.stage = stage
        self.reason = reason
        self.why = why
        self.next_steps = next_steps or []
        # "Unknown" (e.g. no evidence) renders as ? instead of a failure.
        self.unknown = unknown
        if exit_code is not None:
            self.exit_code = exit_code
