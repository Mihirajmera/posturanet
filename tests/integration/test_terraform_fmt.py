"""Rendered HCL must pass the real `terraform fmt -check` (skipped without terraform)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from posturanet.models import NetRule
from posturanet.models.config import SynthesisConfig
from posturanet.synth import parse_security_group, render, synthesize
from posturanet.validate.tf import SubprocessTerraform
from tests_support import contract_for

pytestmark = pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not installed")

MIXED = """\
resource "aws_security_group" "web" {
  name = "web"

  ingress {
    description = "https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


@pytest.mark.parametrize(
    "sources",
    [
        [],
        [("203.0.113.9/32", 443)],
        [("10.0.4.12/32", 22), ("10.0.4.37/32", 22), ("203.0.113.7/32", 5432)],
    ],
)
def test_rendered_hcl_is_fmt_clean(tmp_path: Path, sources: list[tuple[str, int]]) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text(MIXED, encoding="utf-8")
    runner = SubprocessTerraform()
    assert runner.fmt_check(tmp_path, ["main.tf"]).ok, "fixture itself must be fmt-clean"

    sg = parse_security_group(tf, 1, "aws_security_group", "web")
    c = contract_for([NetRule(cidr=c, port=p, proto="tcp") for c, p in sources])
    tf.write_text(render(sg, synthesize(c, sg.rules(), SynthesisConfig())), encoding="utf-8")
    result = runner.fmt_check(tmp_path, ["main.tf"])
    assert result.ok, tf.read_text(encoding="utf-8")
    assert '"0.0.0.0/0"' in tf.read_text(encoding="utf-8")  # egress untouched
