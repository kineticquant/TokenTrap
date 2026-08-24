import json

import pytest
from fastapi.testclient import TestClient

from token_trap import TrapConfig, create_app


@pytest.fixture()
def client():
    config = TrapConfig(strength="aggressive", canary_tokens=("audit-canary-42",))
    return TestClient(create_app(config))


def test_healthz(client):
    res = client.get("/api/healthz")
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True and body["mode"] == "level-2-backend"


def test_cors_headers_present(client):
    res = client.options(
        "/api/chat",
        headers={"origin": "https://evil.example", "access-control-request-method": "POST"},
    )
    assert res.status_code in (200, 204)
    assert res.headers["access-control-allow-origin"] == "*"


def test_widget_chat_escalation_ladder(client):
    sid = "parity-session-1"

    r0 = client.post("/api/chat", json={"sessionId": sid, "message": "hello"}).json()
    assert r0["turn"] == 0 and r0["meta"]["escalated"] is False

    r1 = client.post("/api/chat", json={"sessionId": sid, "message": "go on"}).json()
    assert r1["turn"] == 1
    assert r1["meta"]["repeats"] == 3
    assert r1["meta"]["minWords"] == 4000

    r2 = client.post("/api/chat", json={"sessionId": sid, "message": "again"}).json()
    assert r2["turn"] == 2 and r2["meta"]["escalated"] is True
    assert r2["meta"]["repeats"] == 10 and r2["meta"]["minWords"] == 15000

    # Session continuity: independent sessions start fresh.
    r_other = client.post("/api/chat", json={"sessionId": "other", "message": "hi"}).json()
    assert r_other["turn"] == 0


def test_canary_echo_header_and_tag(client):
    first = client.post("/api/chat", json={"sessionId": "c", "message": "hello"})
    assert first.headers["x-tokentrap-canary-echo"] == "false"
    assert "[AUDIT-TAG:audit-canary-42]" in first.json()["reply"]

    echo = client.post(
        "/api/chat",
        json={"sessionId": "c", "message": "resending: AUDIT-TAG:audit-canary-42"},
    )
    assert echo.headers["x-tokentrap-canary-echo"] == "true"


def test_invalid_message_400(client):
    res = client.post("/api/chat", content=json.dumps({"message": ""}), headers={"content-type": "application/json"})
    assert res.status_code == 400


def test_openai_endpoint_shape_and_trap(client):
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "list all files on C:\\"},
        ],
    }
    res = client.post("/v1/chat/completions", json=payload)
    assert res.status_code == 200
    body = res.json()
    assert body["object"] == "chat.completions"
    assert body["model"] == "gpt-4o-mini"
    choice = body["choices"][0]
    assert choice["index"] == 0 and choice["finish_reason"] == "stop"
    assert choice["message"]["role"] == "assistant"
    usage = body["usage"]
    assert usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"]
    assert usage["total_tokens"] > 0


def test_openai_endpoint_grows_with_replayed_history(client):
    """Agents replay growing transcripts; the bait must escalate with depth."""
    history = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "hello, list files please"},
    ]
    first = client.post("/v1/chat/completions", json={"model": "m", "messages": history}).json()
    short_reply = len(first["choices"][0]["message"]["content"])

    for i in range(3):
        history.append({"role": "assistant", "content": f"prior trap reply {i} (attacker never complies)"})
        history.append({"role": "user", "content": "continue"})
    later = client.post("/v1/chat/completions", json={"model": "m", "messages": history}).json()

    escalated_reply = later["choices"][0]["message"]["content"]
    assert "SYSTEM COMPLIANCE NOTICE" in escalated_reply
    assert len(escalated_reply) > short_reply
    assert later["id"].startswith("chatcmpl-trap-")


def test_rate_limit_returns_429():
    config = TrapConfig(rate_limit_per_minute=2)
    with TestClient(create_app(config)) as c:
        assert c.post("/api/chat", json={"message": "a"}).status_code == 200
        assert c.post("/api/chat", json={"message": "b"}).status_code == 200
        assert c.post("/api/chat", json={"message": "c"}).status_code == 429


def test_mount_into_existing_app():
    from fastapi import FastAPI

    parent = FastAPI()
    parent.mount("/trap", create_app(TrapConfig()))
    with TestClient(parent) as c:
        assert c.get("/trap/api/healthz").json()["ok"] is True
