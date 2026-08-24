# tokentrap (Python backend)

Level-2 TokenTrap backend: full FastAPI service with persistent sessions,
structured logging, canary tokens, an OpenAI-compatible bait endpoint, and a
one-command CLI.

> **Defensive only.** Traps fire on connections the attacker initiates — no
> exploits, no outbound traffic, no human deception. Operators are solely
> responsible for lawful use in their jurisdiction. See
> <https://github.com/kineticquant/TokenTrap/blob/main/docs/ethics-and-legal.md>.

## Install

```bash
pip install "tokentrap"            # published package
# or from this monorepo:
pip install -e "packages/backend-python[test]"
```

## 60-second start

```bash
tokentrap serve --port 8787 --strength aggressive --canary-tokens audit-777
# then point the widget at it:
#   TokenTrap.init({ apiEndpoint: "http://127.0.0.1:8787", ... })
```

Environment variables (all optional): `TOKENTRAP_PERSONA`, `TOKENTRAP_STRENGTH`,
`TOKENTRAP_CANARY_TOKENS`, `TOKENTRAP_EXTRA_KEYWORDS`, `TOKENTRAP_RATE_LIMIT`,
`TOKENTRAP_LOG_WEBHOOK`, `TOKENTRAP_LLM_MODEL`.

## Endpoints

| Route | Purpose |
| --- | --- |
| `POST /api/chat` | Widget protocol (`{sessionId?, message}` -> `{reply, turn, meta}`) |
| `POST /v1/chat/completions` | OpenAI-compatible bait for agents scanning for exposed API endpoints |
| `GET /api/healthz` | Liveness |

`/v1/chat/completions` is fully stateless: the turn index is derived from the
replayed message list, so agents that grow their transcript each iteration
walk straight up the escalation ladder.

## Embed in an existing FastAPI app

```python
from fastapi import FastAPI
from token_trap import create_app, TrapConfig

app = FastAPI()
app.mount("/trap", create_app(TrapConfig(strength="maximum")))
```

## Optional real-LLM dressing

With `pip install "tokentrap[llm]"`, set `llm_model` / `--llm-model` and turn-0
messages get answered by a real model before the trap engages. Failures fall
back to the static engagement payload.

## Tests

```bash
pytest
```
