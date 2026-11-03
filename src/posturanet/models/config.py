"""`.posturanet.yml` (architecture doc section 5). Only the R1 subset is modeled so far.

Unknown keys are errors, not ignored (FR-46).
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from posturanet.errors import UsageError

CONFIG_FILENAME = ".posturanet.yml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AwsConfig(_Strict):
    role_arn: str | None = None  # optional; else ambient credentials
    region: str | None = None


class TerraformConfig(_Strict):
    root: str = "."
    backend: Literal["s3", "local"] = "local"
    # Local backend only: path to the state file, relative to the repo root.
    state_path: str | None = None
    binary: str = "terraform"


class FlowLogsConfig(_Strict):
    mode: Literal["logs_insights"] = "logs_insights"
    log_group: str | None = None


class EvidenceConfig(_Strict):
    flow_logs: FlowLogsConfig = Field(default_factory=FlowLogsConfig)
    window_days: int = Field(default=90, ge=1, le=400)
    min_confidence_for_pr: Literal["high", "medium"] = "medium"


class ContractsConfig(_Strict):
    dir: str = "posturanet/contracts"


class SynthesisConfig(_Strict):
    rules_quota: int = Field(default=60, ge=1)
    max_prefix_private: int = Field(default=16, ge=8, le=32)
    max_prefix_public: int = Field(default=24, ge=16, le=32)


class ValidationConfig(_Strict):
    timeout_s: int = Field(default=300, ge=10)
    # Terraform plan needs read access to the backend and providers. "required" fails
    # closed without it; "skip" is only for local experiments and never opens a PR.
    plan: Literal["required", "skip"] = "required"
    optional: list[str] = Field(default_factory=lambda: ["tflint", "checkov"])
    allowed_paths: list[str] = Field(default_factory=lambda: ["**"])


class GithubConfig(_Strict):
    repo: str | None = None
    base: str = "main"


class DeliveryConfig(_Strict):
    github: GithubConfig = Field(default_factory=GithubConfig)
    labels: list[str] = Field(default_factory=lambda: ["posturanet", "security"])
    max_open_prs: int = Field(default=5, ge=1)


class Config(_Strict):
    version: Literal[1] = 1
    aws: AwsConfig = Field(default_factory=AwsConfig)
    terraform: TerraformConfig = Field(default_factory=TerraformConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    contracts: ContractsConfig = Field(default_factory=ContractsConfig)
    synthesis: SynthesisConfig = Field(default_factory=SynthesisConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    delivery: DeliveryConfig = Field(default_factory=DeliveryConfig)


def load_config(repo: Path) -> tuple[Config, Path | None]:
    """Load `.posturanet.yml` from the repo root, or defaults when it's absent."""
    path = repo / CONFIG_FILENAME
    if not path.is_file():
        return Config(), None
    try:
        data = YAML(typ="safe").load(path.read_text(encoding="utf-8")) or {}
    except YAMLError as exc:
        raise UsageError(f"{CONFIG_FILENAME} is not valid YAML: {exc}") from exc
    try:
        return Config.model_validate(data), path
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        raise UsageError(f"{CONFIG_FILENAME} is invalid: {problems}") from exc
