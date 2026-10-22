import json
from pathlib import Path

import pytest

from token_trap.php2shell.detector import detect_php2shell, scan_multipart
from token_trap.php2shell.types import RequestInfo

FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "php2shell" / "cases.json"
CASES = json.loads(FIXTURES.read_text(encoding="utf-8"))


def _request(case):
    headers = {k.lower(): str(v) for k, v in case["request"]["headers"].items()}
    path = case["request"]["path"]
    path_only, _, query = path.partition("?")
    content_type = headers.get("content-type", "")
    body = case["request"]["bodyPrefix"]
    return RequestInfo(
        method=case["request"]["method"],
        path=path_only,
        query=query,
        headers=headers,
        body_prefix=body,
        body_bytes=case["request"]["contentLength"]
        if case["request"]["contentLength"] is not None
        else len(body.encode()),
        body_truncated=False,
        body_sha256="",
        content_type=content_type,
        content_length=case["request"]["contentLength"],
        transfer_encoding=headers.get("transfer-encoding", ""),
        user_agent=headers.get("user-agent", ""),
        client_ip=case["session"]["clientIp"],
        multipart=scan_multipart(body, content_type),
    )


def _prior(case):
    phases = case["session"].get("priorPhases", [])
    if not phases:
        return None
    pressure = any(p in {"pressure", "stale_reuse", "post_exploit"} for p in phases)
    return {
        "sessionId": "fixture-session",
        "createdAt": 0,
        "lastSeen": 0,
        "requestCount": case["session"].get("requestCount", 0),
        "maxScore": 0,
        "phase": phases[-1],
        "pressureSeen": pressure,
        "uploadProgressSeen": pressure,
        "issuedCanaries": tuple(case["session"].get("issuedCanaries", [])),
        "canaryEchoed": False,
    }


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_detection_fixtures(case):
    result = detect_php2shell(
        _request(case),
        _prior(case),
        case["profile"],
        pressure_bytes=1024 * 1024,
        canaries=(),
    )
    assert list(result.signals) == case["expect"]["signals"]
    assert result.score == case["expect"]["score"]
    assert result.phase == case["expect"]["phase"]
    assert result.response_phase == case["expect"]["responsePhase"]
    assert result.canary_echo is case["expect"]["canaryEcho"]
