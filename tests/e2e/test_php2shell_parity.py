import json
import subprocess
from pathlib import Path

import pytest

from token_trap.php2shell.detector import detect_php2shell, scan_multipart
from token_trap.php2shell.types import RequestInfo

ROOT = Path(__file__).resolve().parents[2]
DUMP = ROOT / "tests" / "e2e" / "php2shell_dump.mjs"
ENGINE_JS = ROOT / "packages" / "widget" / "dist" / "php2shell.js"
CASES = json.loads(
    (ROOT / "tests" / "fixtures" / "php2shell" / "cases.json").read_text(encoding="utf-8")
)


@pytest.fixture(scope="module")
def ts_results():
    if not ENGINE_JS.exists():
        pytest.skip("widget not built yet - run: npm run build -w tokentrap-ai")
    result = subprocess.run(
        ["node", str(DUMP)], capture_output=True, text=True, cwd=ROOT, check=True
    )
    return json.loads(result.stdout)


def _prior(c):
    phases = c["session"].get("priorPhases", [])
    if not phases:
        return None
    pressure = any(p in {"pressure", "stale_reuse", "post_exploit"} for p in phases)
    return {
        "sessionId": "fixture-session",
        "createdAt": 0,
        "lastSeen": 0,
        "requestCount": c["session"].get("requestCount", 0),
        "maxScore": 0,
        "phase": phases[-1],
        "pressureSeen": pressure,
        "uploadProgressSeen": pressure,
        "issuedCanaries": tuple(c["session"].get("issuedCanaries", [])),
        "canaryEchoed": False,
    }


def _request(c):
    headers = {k.lower(): str(v) for k, v in c["request"]["headers"].items()}
    path, _, query = c["request"]["path"].partition("?")
    content_type = headers.get("content-type", "")
    body = c["request"]["bodyPrefix"]
    return RequestInfo(
        method=c["request"]["method"],
        path=path,
        query=query,
        headers=headers,
        body_prefix=body,
        body_bytes=c["request"]["contentLength"]
        if c["request"]["contentLength"] is not None
        else len(body.encode()),
        body_truncated=False,
        body_sha256="",
        content_type=content_type,
        content_length=c["request"]["contentLength"],
        transfer_encoding=headers.get("transfer-encoding", ""),
        user_agent=headers.get("user-agent", ""),
        client_ip=c["session"]["clientIp"],
        multipart=scan_multipart(body, content_type),
    )


def test_php2shell_detection_parity(ts_results):
    py_results = []
    for case in CASES:
        result = detect_php2shell(
            _request(case), _prior(case), case["profile"], 1024 * 1024, ()
        )
        py_results.append(
            {
                "name": case["name"],
                "signals": list(result.signals),
                "score": result.score,
                "phase": result.phase,
                "responsePhase": result.response_phase,
                "canaryEcho": result.canary_echo,
            }
        )
    assert py_results == ts_results
