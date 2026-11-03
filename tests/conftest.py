from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(Path(__file__).parent))


@pytest.fixture
def sg_finding_path() -> Path:
    return FIXTURES / "findings" / "sg_ssh_open.json"


@pytest.fixture
def basic_repo() -> Path:
    return FIXTURES / "tf" / "basic"


@pytest.fixture
def flows_path() -> Path:
    return FIXTURES / "flows" / "bastion_90d.json"


@pytest.fixture
def tmp_repo(basic_repo: Path, tmp_path: Path) -> Path:
    """A writable copy of the basic repo (check and open-pr modes write the contract)."""
    repo = tmp_path / "repo"
    shutil.copytree(basic_repo, repo)
    return repo
