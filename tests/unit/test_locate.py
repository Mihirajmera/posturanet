from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from posturanet.errors import StageStop
from posturanet.ingest import ingest
from posturanet.locate import locate
from posturanet.locate.codeowners import owners_for
from posturanet.locate.tfstate import find_resource
from posturanet.models import Confidence, Config
from posturanet.models.config import load_config

S3_BACKEND = """\
terraform {
  backend "s3" {
    bucket = "acme-tfstate"
    key    = "infra/terraform.tfstate"
    region = "us-east-1"
  }
}
"""


def test_locates_module_resource(sg_finding_path: Path, basic_repo: Path) -> None:
    config, _ = load_config(basic_repo)
    loc = locate(ingest(str(sg_finding_path)), basic_repo, config)
    assert loc.address == "module.bastion.aws_security_group.this"
    assert loc.file == "modules/bastion/main.tf"
    assert loc.line == 5
    assert loc.module_path == ["bastion"]
    assert loc.owners == ["@example-org/platform-network"]
    assert loc.drift is None
    assert loc.confidence is Confidence.HIGH


def test_resource_not_in_state(basic_repo: Path) -> None:
    config, _ = load_config(basic_repo)
    with pytest.raises(StageStop, match="not in the Terraform state"):
        locate(ingest("sg-ffffffff"), basic_repo, config)


def test_s3_backend_without_block_stops(basic_repo: Path) -> None:
    config = Config.model_validate({"terraform": {"backend": "s3"}})
    with pytest.raises(StageStop, match='no backend "s3" block'):
        locate(ingest("sg-0a91f3c2"), basic_repo, config)


def test_s3_backend_reads_state_through_fetch(basic_repo: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(basic_repo, repo)
    state_bytes = (repo / "state.fixture.json").read_bytes()
    (repo / "state.fixture.json").unlink()
    (repo / "backend.tf").write_text(S3_BACKEND, encoding="utf-8")
    calls: list[tuple[str, str, str | None]] = []

    def fetch(bucket: str, key: str, region: str | None) -> bytes:
        calls.append((bucket, key, region))
        return state_bytes

    config = Config.model_validate({"terraform": {"backend": "s3"}})
    loc = locate(ingest("sg-0a91f3c2"), repo, config, s3_fetch=fetch)
    assert calls == [("acme-tfstate", "infra/terraform.tfstate", "us-east-1")]
    assert loc.state_source == "s3://acme-tfstate/infra/terraform.tfstate"
    assert loc.address == "module.bastion.aws_security_group.this"


def test_s3_backend_needs_aws_outside_dry_run(basic_repo: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(basic_repo, repo)
    (repo / "backend.tf").write_text(S3_BACKEND, encoding="utf-8")
    config = Config.model_validate({"terraform": {"backend": "s3"}})
    with pytest.raises(StageStop, match="needs AWS access"):
        locate(ingest("sg-0a91f3c2"), repo, config)


def test_state_override(basic_repo: Path) -> None:
    config = Config()  # default path would not exist
    loc = locate(
        ingest("sg-0a91f3c2"), basic_repo, config, state_path=basic_repo / "state.fixture.json"
    )
    assert loc.state_source == "state.fixture.json"


def test_remote_module_stops(tmp_path: Path, basic_repo: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(basic_repo, repo)
    (repo / "main.tf").write_text(
        'module "bastion" {\n  source = "terraform-aws-modules/security-group/aws"\n}\n',
        encoding="utf-8",
    )
    config, _ = load_config(repo)
    with pytest.raises(StageStop, match="remote source"):
        locate(ingest("sg-0a91f3c2"), repo, config)


def test_duplicate_state_entries_stop(tmp_path: Path, basic_repo: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(basic_repo, repo)
    state_file = repo / "state.fixture.json"
    state = json.loads(state_file.read_text(encoding="utf-8"))
    dup = json.loads(json.dumps(state["resources"][0]))
    dup["name"] = "other"
    state["resources"].append(dup)
    state_file.write_text(json.dumps(state), encoding="utf-8")
    config, _ = load_config(repo)
    with pytest.raises(StageStop, match="2 state entries"):
        locate(ingest("sg-0a91f3c2"), repo, config)


def test_index_keys_in_address() -> None:
    state = {
        "resources": [
            {
                "mode": "managed",
                "type": "aws_security_group",
                "name": "sg",
                "instances": [
                    {"index_key": 0, "attributes": {"id": "sg-a"}},
                    {"index_key": "web", "attributes": {"id": "sg-b"}},
                ],
            }
        ]
    }
    assert find_resource(state, "sg-a")[0].address == "aws_security_group.sg[0]"
    assert find_resource(state, "sg-b")[0].address == 'aws_security_group.sg["web"]'


def test_data_sources_ignored(basic_repo: Path) -> None:
    state = json.loads((basic_repo / "state.fixture.json").read_text(encoding="utf-8"))
    assert len(find_resource(state, "sg-0a91f3c2")) == 1


def test_bad_state_version(tmp_path: Path, basic_repo: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(basic_repo, repo)
    (repo / "state.fixture.json").write_text('{"version": 3}', encoding="utf-8")
    config, _ = load_config(repo)
    with pytest.raises(StageStop, match="version 4"):
        locate(ingest("sg-0a91f3c2"), repo, config)


@pytest.mark.parametrize(
    ("rules", "path", "expected"),
    [
        ("* @all\n", "a/b.tf", ["@all"]),
        ("* @all\n/modules/ @net\n", "modules/x/main.tf", ["@net"]),
        ("/modules/ @net\n* @all\n", "modules/x/main.tf", ["@all"]),  # last match wins
        ("*.tf @tf\n", "deep/dir/main.tf", ["@tf"]),
        ("/main.tf @root\n", "sub/main.tf", []),  # anchored
        ("docs/** @docs\n", "docs/a/b.md", ["@docs"]),
        ("# only a comment\n", "main.tf", []),
    ],
)
def test_codeowners(tmp_path: Path, rules: str, path: str, expected: list[str]) -> None:
    co = tmp_path / "CODEOWNERS"
    co.write_text(rules, encoding="utf-8")
    assert owners_for(co, path) == expected
