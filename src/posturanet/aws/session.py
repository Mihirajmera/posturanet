"""Build read-only clients from ambient credentials or an assumed role."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from posturanet.aws.changeset import ChangeSetClient
from posturanet.aws.readonly import ReadOnlyClient
from posturanet.errors import StageStop
from posturanet.models.config import AwsConfig, Config


class ClientFactory(Protocol):
    def __call__(self, service: str) -> ReadOnlyClient: ...


def _lazy_session(role_arn: str | None, region: str | None) -> Callable[[], Any]:
    """A boto3 session for `role_arn` (or ambient credentials), built on first use."""
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as exc:  # pragma: no cover - boto3 is a hard dependency
        raise StageStop("evidence", "boto3 is not installed") from exc

    session_cache: dict[str, Any] = {}

    def _session() -> Any:
        if "s" in session_cache:
            return session_cache["s"]
        base = boto3.session.Session(region_name=region)
        if role_arn:
            sts = ReadOnlyClient(base.client("sts"), "sts")
            try:
                creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="posturanet")[
                    "Credentials"
                ]
            except (BotoCoreError, ClientError) as exc:
                raise StageStop(
                    "evidence",
                    f"could not assume {role_arn}",
                    ["check the role trust policy and that this runner may assume it"],
                    why=str(exc),
                ) from exc
            base = boto3.session.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        session_cache["s"] = base
        return base

    return _session


def boto3_factory(cfg: AwsConfig, region: str | None = None) -> ClientFactory:
    """Return a factory of read-only clients. Credentials are resolved lazily on first use."""
    session = _lazy_session(cfg.role_arn, region or cfg.region)

    def factory(service: str) -> ReadOnlyClient:
        return ReadOnlyClient(session().client(service), service)

    return factory


def changeset_client(config: Config) -> ChangeSetClient | None:
    """The opt-in change-set client, under its own role; None unless opted in."""
    preview = config.cloudformation.changeset_preview
    if not preview.enabled:
        return None
    session = _lazy_session(preview.role_arn, config.aws.region)
    return ChangeSetClient(lambda: session().client("cloudformation"))
