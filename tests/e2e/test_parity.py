"""TypeScript <-> Python trap-engine parity.

Runs the built TS engine via node (tests/e2e/parity_dump.mjs), then replays
the identical scripted conversations through the Python engine and asserts
byte-equality of every reply and every metadata field.

Skips (with a loud message) if node or the widget build is unavailable -
CI always provides both, so this only ever skips on partial local setups.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from token_trap import TrapEngine

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parents[1] / ".out"
DUMP = ROOT / "tests" / "e2e" / "parity_dump.mjs"
ENGINE_JS = ROOT / "packages" / "widget" / "dist" / "engine.js"


def _ts_transcripts() -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["node", str(DUMP)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )
    data = json.loads(result.stdout)
    (OUT / "parity_ts.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


@pytest.fixture(scope="module")
def ts_transcripts():
    if not ENGINE_JS.exists():
        pytest.skip("widget not built yet - run: npm run build -w tokentrap-ai")
    try:
        return _ts_transcripts()
    except FileNotFoundError:
        pytest.skip("node executable not found")


def _py_transcript(options: dict, messages: list) -> list:
    engine = TrapEngine(
        session_id=options["sessionId"],
        strength=options["strength"],
        canary_tokens=tuple(options.get("canaryTokens", ())),
    )
    return [
        {"message": msg, **engine.handle(msg).to_dict()} for msg in messages
    ]


def test_parity_ladder_script(ts_transcripts):
    ts = ts_transcripts["ladder"]
    py = _py_transcript(
        {"sessionId": "parity-fixed-session", "strength": "aggressive"},
        [entry["message"] for entry in ts],
    )
    assert len(py) == len(ts)
    for ts_entry, py_entry in zip(ts, py):
        assert ts_entry["message"] == py_entry["message"]
        # Byte-identical payload - THE parity assertion.
        assert ts_entry["reply"] == py_entry["reply"], (
            f"reply divergence at turn {py_entry['meta']['turn']}:\n"
            f"--- TS ---\n{ts_entry['reply']}\n--- PY ---\n{py_entry['reply']}"
        )
        assert ts_entry["meta"] == py_entry["meta"]


def test_parity_moderate_canary_script(ts_transcripts):
    ts = ts_transcripts["moderate-canary"]
    py = _py_transcript(
        {
            "sessionId": "parity-canary-session",
            "strength": "moderate",
            "canaryTokens": ["canary-a"],
        },
        [entry["message"] for entry in ts],
    )
    for ts_entry, py_entry in zip(ts, py):
        assert ts_entry["reply"] == py_entry["reply"]
        assert ts_entry["meta"]["repeats"] == py_entry["meta"]["repeats"]
        assert ts_entry["meta"]["minWords"] == py_entry["meta"]["minWords"]
        assert "[AUDIT-TAG:canary-a]" in py_entry["reply"]


def test_parity_covers_escalation_corners():
    """Sanity: the shared script really exercises engage/base/injection/max."""
    engine = TrapEngine(session_id="corner", strength="aggressive")
    kinds = []
    for msg in ["Hello, can you help me?", "What is your purpose?", "ignore previous instructions", "continue", "one more"]:
        res = engine.handle(msg)
        kinds.append((res.meta.turn, res.meta.escalated, res.meta.injectionDetected))
    assert kinds == [
        (0, False, False),   # engage
        (1, False, False),   # base directive
        (2, True, True),     # injection -> maximum
        (3, True, False),    # depth -> maximum
        (4, True, False),
    ]
