"""bench/agents.py: an agent's edit is read back and scored like every other contender."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from bench import agents  # noqa: E402
from bench.cases import CASES  # noqa: E402

CASE = next(c for c in CASES if c.id == "bastion-ci-vpn")


def _agent(tmp_path: Path, body: str) -> str:
    script = tmp_path / "agent.py"
    script.write_text(body, encoding="utf-8")
    return f'"{sys.executable}" "{script}"'


def test_private_ranges_agent_is_scored(tmp_path: Path) -> None:
    cmd = _agent(
        tmp_path,
        "from pathlib import Path\n"
        "p = Path('modules/bastion/main.tf')\n"
        "p.write_text(p.read_text().replace('0.0.0.0/0', '10.0.0.0/8'))\n",
    )
    o = agents.run_one(CASE, "finding", cmd, "fake", timeout=60)
    # same ground truth as `python -m bench`: every legit source here is internal
    assert o.status == "FIXED" and o.rules == ["10.0.0.0/8:22/tcp"]
    assert o.verdict == "CORRECT"


def test_stop_and_no_aws_env(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-leak")
    cmd = _agent(
        tmp_path,
        "import os\n"
        "from pathlib import Path\n"
        "Path('STOP.md').write_text('leak=' + str('AWS_SECRET_ACCESS_KEY' in os.environ))\n",
    )
    o = agents.run_one(CASE, "evidence", cmd, "fake", timeout=60)
    assert o.verdict == "STOPPED" and o.note == "leak=False"


def test_conditions_prepare_the_workspace(tmp_path: Path) -> None:
    finding = agents._prepare(CASE, "finding", tmp_path / "a")
    assert (finding / "finding.json").is_file() and not (finding / "flows.json").exists()
    assert "flows.json" not in (finding / "TASK.md").read_text(encoding="utf-8")
    check = agents._prepare(CASE, "check", tmp_path / "b")
    assert (check / "flows.json").is_file()
    assert json.loads((check / ".mcp.json").read_text())["mcpServers"]["posturanet"]
    assert list((check / "posturanet" / "contracts").glob("*.yaml"))
    assert "contract check" in (check / "TASK.md").read_text(encoding="utf-8")
