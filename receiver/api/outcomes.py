"""PosturaNet outcome-share receiver (FR-45a, R9): a Vercel Python function.

POST /api/outcomes takes exactly the five fields `posturanet verify` sends when a customer turns
the outcome share on, and adds one to a counter. It keeps counters only: no record, no request
headers, no IP address, no time of arrival. GET /api/outcomes returns the counters.

Storage: Upstash Redis through its REST API (env KV_REST_API_URL and KV_REST_API_TOKEN, which
the Vercel Upstash integration sets). Standard library only.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler
from typing import Any

# In step with posturanet.outcome_share.SharedOutcome (a test checks).
FIELDS = {"control", "fix_type", "outcome", "evidence_days", "agent_version"}
CONTROL = re.compile(r"[A-Za-z][A-Za-z0-9]{0,23}\.[0-9]{1,4}")
FIX_TYPES = {"sg_ingress", "s3_public", "iam_least_privilege", "config_attribute"}
OUTCOMES = {"held", "reverted"}
VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}([.+-]?[A-Za-z0-9.]{1,16})?")
MAX_BODY = 1024
MAX_DAYS = 3660

COUNTS = "posturanet:outcomes:v1"  # "<control>|<fix_type>|<outcome>" -> count
DAYS = "posturanet:outcome_days:v1"  # same key -> sum of evidence_days
VERSIONS = "posturanet:versions:v1"  # agent_version -> count

Redis = Callable[[list[list[str]]], list[Any]]


def parse(body: bytes) -> dict[str, Any] | str:
    """The record, or why it's refused. Anything beyond the five fields is refused, so a
    client can't make the receiver keep more than golden rule 6 allows."""
    if len(body) > MAX_BODY:
        return "body too large"
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return "not JSON"
    if not isinstance(doc, dict) or set(doc) != FIELDS:
        return f"expected exactly the fields {sorted(FIELDS)}"
    control, fix_type = doc["control"], doc["fix_type"]
    days, version = doc["evidence_days"], doc["agent_version"]
    if not isinstance(control, str) or not CONTROL.fullmatch(control):
        return "control must look like EC2.19"
    if fix_type not in FIX_TYPES:
        return f"fix_type must be one of {sorted(FIX_TYPES)}"
    if doc["outcome"] not in OUTCOMES:
        return "outcome must be held or reverted"
    if type(days) is not int or not 0 <= days <= MAX_DAYS:
        return f"evidence_days must be a whole number 0-{MAX_DAYS}"
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        return "agent_version must look like 0.5.1"
    return doc


def record(doc: dict[str, Any], redis: Redis) -> None:
    key = f"{doc['control']}|{doc['fix_type']}|{doc['outcome']}"
    redis(
        [
            ["HINCRBY", COUNTS, key, "1"],
            ["HINCRBY", DAYS, key, str(doc["evidence_days"])],
            ["HINCRBY", VERSIONS, doc["agent_version"], "1"],
        ]
    )


def _pairs(flat: Any) -> dict[str, int]:
    items = flat if isinstance(flat, list) else []
    return {str(items[i]): int(items[i + 1]) for i in range(0, len(items) - 1, 2)}


def summary(redis: Redis) -> dict[str, Any]:
    counts, days, versions = (
        _pairs(r.get("result")) for r in redis([["HGETALL", h] for h in (COUNTS, DAYS, VERSIONS)])
    )
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for key, n in counts.items():
        control, fix_type, outcome = key.split("|")
        row = rows.setdefault(
            (control, fix_type),
            {"control": control, "fix_type": fix_type, "held": 0, "reverted": 0, "days": 0},
        )
        row[outcome] += n
        row["days"] += days.get(key, 0)
    out = []
    for row in sorted(rows.values(), key=lambda r: (r["control"], r["fix_type"])):
        total = row["held"] + row["reverted"]
        out.append(
            {
                "control": row["control"],
                "fix_type": row["fix_type"],
                "held": row["held"],
                "reverted": row["reverted"],
                "mean_evidence_days": round(row.pop("days") / total, 1) if total else 0,
            }
        )
    return {"schema": "posturanet.outcomes/v1", "rows": out, "agent_versions": versions}


def upstash() -> Redis:
    url = os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL", "")
    token = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN", "")
    if not url.startswith("https://") or not token:
        raise RuntimeError("storage not configured")

    def call(commands: list[list[str]]) -> list[Any]:
        req = urllib.request.Request(
            url.rstrip("/") + "/pipeline",
            data=json.dumps(commands).encode(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (https only, above)
            result: list[Any] = json.loads(resp.read())
        if any(isinstance(r, dict) and "error" in r for r in result):
            raise RuntimeError("storage error")
        return result

    return call


class handler(BaseHTTPRequestHandler):  # noqa: N801 (the name Vercel's Python runtime loads)
    def _send(self, status: int, doc: dict[str, Any] | None = None) -> None:
        body = json.dumps(doc).encode() if doc is not None else b""
        self.send_response(status)
        if doc is not None:
            self.send_header("Content-Type", "application/json")
        if status == 200:
            self.send_header("Cache-Control", "public, max-age=300")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BODY:
            self._send(413 if length > MAX_BODY else 400, {"error": "body size"})
            return
        doc = parse(self.rfile.read(length))
        if isinstance(doc, str):
            self._send(400, {"error": doc})
            return
        try:
            record(doc, upstash())
        except Exception:  # noqa: BLE001 (the client is best-effort; never echo internals)
            self._send(503, {"error": "not stored"})
            return
        self._send(204)

    def do_GET(self) -> None:  # noqa: N802
        try:
            self._send(200, summary(upstash()))
        except Exception:  # noqa: BLE001
            self._send(503, {"error": "unavailable"})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """No access log: it would hold client addresses."""
