"""`.posturanet.yml` (architecture doc section 5). Only the R1 subset is modeled so far.

Unknown keys are errors, not ignored (FR-46).
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
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


class ChangeSetPreviewConfig(_Strict):
    # Opt-in control-plane write (NFR-2 exception, docs/design/cfn-changeset-preview.md):
    # create, read and delete a change set, never execute it, under its own role.
    enabled: bool = False
    role_arn: str | None = None


class CloudFormationConfig(_Strict):
    # Offline stack mapping: an `aws cloudformation describe-stack-resources` export.
    stack_resources: str | None = None
    # stack name -> template path, when a logical id appears in more than one template.
    templates: dict[str, str] = Field(default_factory=dict)
    changeset_preview: ChangeSetPreviewConfig = Field(default_factory=ChangeSetPreviewConfig)


class CdkConfig(_Strict):
    # The CDK app directory (holds cdk.json), relative to the repo root; found when unset.
    app: str | None = None
    # A cloud assembly your CI already synthesized from this commit (`cdk synth -o …`).
    # Unset: PosturaNet runs `cdk synth --no-lookups` itself, outside dry runs.
    assembly: str | None = None
    binary: str = "cdk"


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
    # auto: CDK when the repo has a cdk.json and no .tf files; else CloudFormation when a
    # stack-resources export is given, or the repo has templates and no .tf files.
    iac: Literal["auto", "terraform", "cloudformation", "cdk"] = "auto"
    terraform: TerraformConfig = Field(default_factory=TerraformConfig)
    cloudformation: CloudFormationConfig = Field(default_factory=CloudFormationConfig)
    cdk: CdkConfig = Field(default_factory=CdkConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    contracts: ContractsConfig = Field(default_factory=ContractsConfig)
    synthesis: SynthesisConfig = Field(default_factory=SynthesisConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    delivery: DeliveryConfig = Field(default_factory=DeliveryConfig)

    @model_validator(mode="after")
    def _changeset_role(self) -> Config:
        preview = self.cloudformation.changeset_preview
        if preview.enabled and not preview.role_arn:
            raise ValueError("cloudformation.changeset_preview.enabled needs its own role_arn")
        if preview.enabled and preview.role_arn == self.aws.role_arn:
            raise ValueError(
                "cloudformation.changeset_preview.role_arn must differ from aws.role_arn; "
                "the read-only role stays read-only"
            )
        return self


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
