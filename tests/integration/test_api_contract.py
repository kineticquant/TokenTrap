"""Cross-package wire contract: what tokentrap-ai expects from a backend.

The widget's ApiChatResponse type (packages/widget/src/types.ts) is:

    { sessionId: string, reply: string, turn: number,
      meta: { turn, strength, repeats, minWords, injectionDetected,
              matchedKeywords, escalated, ref } }

These tests pin the Python backend to exactly that shape so the shipped
widget can always talk to the shipped server.
"""

import json
import re

import pytest
from fastapi.testclient import TestClient

from token_trap import TrapConfig, create_app

META_KEYS = {
    "turn",
    "strength",
    "repeats",
    "minWords",
    "injectionDetected",
    "matchedKeywords",
    "escalated",
    "ref",
}

SESSION_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


@pytest.fixture()
def client():
    return TestClient(create_app(TrapConfig(strength="aggressive")))


def _post_chat(client, **body):
    return client.post("/api/chat", json=body or {"message": "hello"})


def test_chat_response_keys_match_widget_types(client):
    res = _post_chat(client)
    assert res.status_code == 200
    body = res.json()
    assert set(body.keys()) >= {"sessionId", "reply", "turn", "meta"}
    assert isinstance(body["sessionId"], str) and body["sessionId"]
    assert isinstance(body["reply"], str) and body["reply"]
    assert body["turn"] == 0 and isinstance(body["turn"], int)
    assert META_KEYS.issubset(set(body["meta"].keys()))
    assert isinstance(body["meta"]["matchedKeywords"], list)


def test_client_generated_session_id_is_adopted_verbatim(client):
    sid = "12345678-90ab-4cde-8f01-234567890abc"
    body = _post_chat(client, sessionId=sid, message="hello").json()
    assert body["sessionId"] == sid


def test_server_mints_uuid_session_id_when_absent(client):
    body = _post_chat(client).json()
    assert SESSION_ID_RE.match(body["sessionId"])


def test_meta_types_are_json_stable(client):
    """Everything must survive JSON round-trips with JS-safe types."""
    payload = json.loads(json.dumps(_post_chat(client).json()["meta"]))
    for key in ("repeats", "minWords", "turn"):
        assert isinstance(payload[key], int)
    for key in ("injectionDetected", "escalated"):
        assert isinstance(payload[key], bool)
    assert payload["ref"] == "" or re.match(r"^TR-\d{6}$", payload["ref"])


def test_error_shape_is_simple_json(client):
    res = client.post(
        "/api/chat",
        content=b"{not json",
        headers={"content-type": "application/json"},
    )
    assert res.status_code == 400
    assert set(res.json().keys()) == {"error"}


def test_openai_bait_matches_minimal_schema(client):
    res = client.post(
        "/v1/chat/completions",
        json={"model": "m", "messages": [{"role": "user", "content": "hi"}]},
    )
    body = res.json()
    for key in ("id", "object", "created", "model", "choices", "usage"):
        assert key in body
    assert body["object"] == "chat.completions"
    choice = body["choices"][0]
    assert set(choice.keys()) >= {"index", "message", "finish_reason"}
