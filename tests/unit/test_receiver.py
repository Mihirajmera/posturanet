"""The outcome-share receiver (receiver/api/outcomes.py) keeps counters of exactly what the
client sends, and refuses anything more (FR-45a, golden rule 6)."""

from __future__ import annotations

import importlib.util
import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import HTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from posturanet import outcome_share
from posturanet.outcome_share import SharedOutcome

_PATH = Path(__file__).resolve().parents[2] / "receiver" / "api" / "outcomes.py"
_spec = importlib.util.spec_from_file_location("receiver_outcomes", _PATH)
assert _spec is not None and _spec.loader is not None
rx: ModuleType = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rx)

GOOD = {
    "control": "EC2.19",
    "fix_type": "sg_ingress",
    "outcome": "held",
    "evidence_days": 3,
    "agent_version": "0.5.1",
}


class FakeRedis:
    def __init__(self) -> None:
        self.h: dict[str, dict[str, int]] = {}

    def __call__(self, commands: list[list[str]]) -> list[Any]:
        out: list[Any] = []
        for cmd in commands:
            if cmd[0] == "HINCRBY":
                h = self.h.setdefault(cmd[1], {})
                h[cmd[2]] = h.get(cmd[2], 0) + int(cmd[3])
                out.append({"result": h[cmd[2]]})
            elif cmd[0] == "HGETALL":
                flat: list[Any] = []
                for k, v in self.h.get(cmd[1], {}).items():
                    flat += [k, str(v)]
                out.append({"result": flat})
        return out


def test_schema_is_in_step_with_the_client() -> None:
    assert set(SharedOutcome.model_fields) == rx.FIELDS
    assert rx.CONTROL.pattern == outcome_share._CONTROL.pattern
    assert rx.FIX_TYPES == outcome_share._FIX_TYPES
    sent = SharedOutcome(**GOOD).model_dump_json().encode()
    assert rx.parse(sent) == GOOD


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"resource_id": "sg-0a91f3c2"}, "exactly the fields"),
        ({"control": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1"}, "control"),
        ({"fix_type": "unsupported"}, "fix_type"),
        ({"outcome": "maybe"}, "outcome"),
        ({"evidence_days": -1}, "evidence_days"),
        ({"evidence_days": True}, "evidence_days"),
        ({"evidence_days": 2.5}, "evidence_days"),
        ({"agent_version": "acme-corp internal build"}, "agent_version"),
    ],
)
def test_refuses_anything_more_or_different(change: dict[str, Any], why: str) -> None:
    assert why in str(rx.parse(json.dumps({**GOOD, **change}).encode()))


def test_refuses_big_or_broken_bodies() -> None:
    assert rx.parse(b"{" + b" " * 2000 + b"}") == "body too large"
    assert rx.parse(b"not json") == "not JSON"
    assert "exactly the fields" in str(rx.parse(b"[1, 2]"))


def test_counts_and_summary() -> None:
    redis = FakeRedis()
    rx.record(GOOD, redis)
    rx.record({**GOOD, "evidence_days": 5}, redis)
    rx.record({**GOOD, "outcome": "reverted", "evidence_days": 2}, redis)
    rx.record({**GOOD, "control": "RDS.13", "fix_type": "config_attribute"}, redis)
    s = rx.summary(redis)
    assert s["rows"] == [
        {"control": "EC2.19", "fix_type": "sg_ingress", "held": 2, "reverted": 1,
         "mean_evidence_days": 3.3},
        {"control": "RDS.13", "fix_type": "config_attribute", "held": 1, "reverted": 0,
         "mean_evidence_days": 3.0},
    ]  # fmt: skip
    assert s["agent_versions"] == {"0.5.1": 4}
    # only counters are stored: no record, no time, no client address
    assert set(redis.h) == {rx.COUNTS, rx.DAYS, rx.VERSIONS}


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, FakeRedis]]:
    redis = FakeRedis()
    monkeypatch.setattr(rx, "upstash", lambda: redis)
    srv = HTTPServer(("127.0.0.1", 0), rx.handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_port}/api/outcomes", redis
    srv.shutdown()


def _post(url: str, body: bytes) -> int:
    req = urllib.request.Request(url, data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return exc.code


def test_http_round_trip(server: tuple[str, FakeRedis]) -> None:
    url, redis = server
    assert _post(url, json.dumps(GOOD).encode()) == 204
    assert _post(url, json.dumps({**GOOD, "account": "123456789012"}).encode()) == 400
    assert _post(url, b"x" * 2000) == 413
    with urllib.request.urlopen(url, timeout=5) as resp:
        doc = json.loads(resp.read())
    assert doc["rows"][0]["held"] == 1
    assert redis.h[rx.COUNTS] == {"EC2.19|sg_ingress|held": 1}


def test_storage_down_is_503_and_says_nothing_more(
    server: tuple[str, FakeRedis], monkeypatch: pytest.MonkeyPatch
) -> None:
    url, _ = server

    def broken() -> Any:
        raise RuntimeError("KV_REST_API_TOKEN=secret")

    monkeypatch.setattr(rx, "upstash", broken)
    req = urllib.request.Request(url, data=json.dumps(GOOD).encode(), method="POST")
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(req, timeout=5)
    assert err.value.code == 503 and b"secret" not in err.value.read()
