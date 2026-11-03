"""Build read-only clients from ambient credentials or an assumed role."""

from __future__ import annotations

from typing import Any, Protocol

from posturanet.aws.readonly import ReadOnlyClient
from posturanet.errors import StageStop
from posturanet.models.config import AwsConfig


class ClientFactory(Protocol):
    def __call__(self, service: str) -> ReadOnlyClient: ...


def boto3_factory(cfg: AwsConfig, region: str | None = None) -> ClientFactory:
    """Return a factory of read-only clients. Credentials are resolved lazily on first use."""
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as exc:  # pragma: no cover - boto3 is a hard dependency
        raise StageStop("evidence", "boto3 is not installed") from exc

    session_cache: dict[str, Any] = {}

    def _session() -> Any:
        if "s" in session_cache:
            return session_cache["s"]
        base = boto3.session.Session(region_name=region or cfg.region)
        if cfg.role_arn:
            sts = ReadOnlyClient(base.client("sts"), "sts")
            try:
                creds = sts.assume_role(RoleArn=cfg.role_arn, RoleSessionName="posturanet")[
                    "Credentials"
                ]
            except (BotoCoreError, ClientError) as exc:
                raise StageStop(
                    "evidence",
                    f"could not assume {cfg.role_arn}",
                    ["check the role trust policy and that this runner may assume it"],
                    why=str(exc),
                ) from exc
            base = boto3.session.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region or cfg.region,
            )
        session_cache["s"] = base
        return base

    def factory(service: str) -> ReadOnlyClient:
        return ReadOnlyClient(_session().client(service), service)

    return factory
