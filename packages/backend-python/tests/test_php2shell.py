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


def _multipart_body(boundary="----trap", upload_progress=True, empty_parts=0):
    parts = []
    if upload_progress:
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; "
            'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        )
    for i in range(empty_parts):
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; "
            f'name="files[a][b][{i}]"; filename=""\r\n\r\n\r\n'
        )
    parts.append(f"--{boundary}--\r\n")
    return "".join(parts)


def test_decoy_app_serves_page_and_pressure():
    from fastapi.testclient import TestClient

    from token_trap.config import TrapConfig
    from token_trap.php2shell.router import create_php2shell_app

    app = create_php2shell_app(TrapConfig(php2shell_enabled=True))
    client = TestClient(app)
    page = client.get("/", headers={"user-agent": "curl/8"})
    assert page.status_code == 200
    assert page.headers["x-powered-by"] == "PHP/8.3.14"
    assert "PHPSESSID" in page.headers["set-cookie"]

    boundary = "----trap"
    body = _multipart_body(boundary, upload_progress=True, empty_parts=4)
    res = client.post(
        "/index.php",
        content=body,
        headers={
            "content-type": f"multipart/form-data; boundary={boundary}",
            "user-agent": "python-requests/2.32",
        },
    )
    assert res.status_code == 500
    assert "PHP Fatal error" in res.text


def test_decoy_stale_reuse_emits_canary_cookie():
    from fastapi.testclient import TestClient

    from token_trap.config import TrapConfig
    from token_trap.php2shell.router import create_php2shell_app

    app = create_php2shell_app(TrapConfig(php2shell_enabled=True))
    client = TestClient(app)
    boundary = "----trap"
    headers = {
        "content-type": f"multipart/form-data; boundary={boundary}",
        "user-agent": "python-requests/2.32",
    }
    client.post(
        "/index.php",
        content=_multipart_body(boundary, upload_progress=True, empty_parts=4),
        headers=headers,
    )
    second = client.post(
        "/index.php",
        content=_multipart_body(boundary, upload_progress=True, empty_parts=0),
        headers=headers,
    )
    assert second.status_code == 500
    assert "TRAPCANARY" in second.headers["set-cookie"]


def test_embedded_app_keeps_chat_route():
    from fastapi.testclient import TestClient

    from token_trap.app import create_app
    from token_trap.config import TrapConfig

    app = create_app(TrapConfig(php2shell_enabled=True))
    client = TestClient(app)
    chat = client.post("/api/chat", json={"sessionId": "p", "message": "hello"})
    assert chat.status_code == 200
    decoy = client.get("/index.php", headers={"user-agent": "curl/8"})
    assert decoy.status_code == 200


def test_config_env_flags():
    from token_trap.config import TrapConfig

    cfg = TrapConfig.from_env_prefix(
        {
            "TOKENTRAP_PHP2SHELL": "1",
            "TOKENTRAP_PHP2SHELL_PROFILE": "wordpress",
            "TOKENTRAP_PHP2SHELL_MODE": "scanner",
            "TOKENTRAP_PHP2SHELL_SCAN_BYTES": "1048576",
        }
    )
    assert cfg.php2shell_enabled is True
    assert cfg.php2shell_profile == "wordpress"
    assert cfg.php2shell_mode == "scanner"
    assert cfg.php2shell_max_scan_bytes == 1048576


def test_scanner_mode_opens_fake_shell_and_answers_commands():
    from fastapi.testclient import TestClient

    from token_trap.config import TrapConfig
    from token_trap.php2shell.router import create_php2shell_app

    app = create_php2shell_app(
        TrapConfig(php2shell_enabled=True, php2shell_mode="scanner")
    )
    client = TestClient(app)
    boundary = "----trap"
    headers = {
        "content-type": f"multipart/form-data; boundary={boundary}",
        "user-agent": "python-requests/2.32",
    }
    first = client.post(
        "/index.php",
        content=_multipart_body(boundary, upload_progress=True, empty_parts=4),
        headers=headers,
    )
    assert first.status_code == 500

    shell = client.post(
        "/index.php",
        content=_multipart_body(boundary, upload_progress=True, empty_parts=0),
        headers=headers,
    )
    assert shell.status_code == 200
    assert "PHP2Shell chain accepted" in shell.text
    assert "uid=33(www-data)" in shell.text
    assert "ENGAGEMENT EVIDENCE NOTICE" in shell.text

    command = client.post(
        "/index.php?cmd=cat%20wp-config.php",
        content="",
        headers={"user-agent": "python-requests/2.32", "content-type": "text/plain"},
    )
    assert command.status_code == 200
    assert "DB_PASSWORD" in command.text
    assert "TRAPCANARY" in command.text

    listing = client.post(
        "/index.php?cmd=ls%20-la",
        content="",
        headers={"user-agent": "python-requests/2.32"},
    )
    assert "wp-config.php" in listing.text
