"""The sample `.posturanet.yml` in the architecture doc must be a valid config."""

from __future__ import annotations

from pathlib import Path

from ruamel.yaml import YAML

from posturanet.models.config import Config

DOC = Path(__file__).resolve().parents[2] / "docs" / "02_ARCHITECTURE_AND_DATA.md"


def test_architecture_config_example_validates() -> None:
    text = DOC.read_text(encoding="utf-8")
    start = text.index("## 5. Configuration")
    block = text[text.index("```yaml\n", start) + len("```yaml\n") :]
    Config.model_validate(YAML(typ="safe").load(block[: block.index("```")]))
