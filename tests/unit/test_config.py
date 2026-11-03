from __future__ import annotations

from pathlib import Path

import pytest

from posturanet.errors import UsageError
from posturanet.models.config import load_config


def test_defaults_without_file(tmp_path: Path) -> None:
    config, path = load_config(tmp_path)
    assert path is None
    assert config.terraform.backend == "local"


def test_unknown_key_is_error(tmp_path: Path) -> None:
    (tmp_path / ".posturanet.yml").write_text("version: 1\nterrafrom: {}\n", encoding="utf-8")
    with pytest.raises(UsageError, match="terrafrom"):
        load_config(tmp_path)


def test_invalid_yaml(tmp_path: Path) -> None:
    (tmp_path / ".posturanet.yml").write_text("version: [1\n", encoding="utf-8")
    with pytest.raises(UsageError, match="not valid YAML"):
        load_config(tmp_path)


def test_fixture_config(basic_repo: Path) -> None:
    config, path = load_config(basic_repo)
    assert path is not None
    assert config.terraform.state_path == "state.fixture.json"
