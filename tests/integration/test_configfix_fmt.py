"""Every attribute fix must leave a fmt-clean file fmt-clean (skipped without terraform)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from posturanet.configfix.catalog import ConfigFix, catalog
from posturanet.configfix.hcl_attrs import apply_changes
from posturanet.validate.tf import SubprocessTerraform
from tests_support import config_fixture as _fixture_for

pytestmark = pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not installed")

DENSE = """\
resource "{rtype}" "this" {{
  name        = "example"
  description = "has {{braces}} and # hashes"

  tags = {{
    team = "platform"
  }}
}}
"""


def _fmt_ok(tmp_path: Path, text: str) -> bool:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    return SubprocessTerraform("terraform", 60).fmt_check(tmp_path, ["main.tf"]).ok


@pytest.mark.parametrize("fix", catalog(), ids=lambda f: f"{f.control}:{f.resource_type}")
def test_fix_output_is_fmt_clean(tmp_path: Path, fix: ConfigFix) -> None:
    before = _fixture_for(fix)
    assert _fmt_ok(tmp_path, before), before
    after = apply_changes(before, 1, fix.changes).text
    assert _fmt_ok(tmp_path, after), after


@pytest.mark.parametrize("fix", catalog()[:12], ids=lambda f: f"{f.control}:{f.resource_type}")
def test_fix_output_is_fmt_clean_next_to_maps(tmp_path: Path, fix: ConfigFix) -> None:
    if fix.when:
        pytest.skip("covered above")
    before = DENSE.format(rtype=fix.resource_type)
    assert _fmt_ok(tmp_path, before)
    assert _fmt_ok(tmp_path, apply_changes(before, 1, fix.changes).text)
