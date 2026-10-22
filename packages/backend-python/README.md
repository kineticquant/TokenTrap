# tokentrap (Python backend)

Level-2 TokenTrap backend: full FastAPI service with persistent sessions,
structured logging, canary tokens, an OpenAI-compatible bait endpoint, and a
one-command CLI.

> **Defensive only.** Traps fire on connections the attacker initiates — no
> exploits, no outbound traffic, no human deception. Operators are solely
> responsible for lawful use in their jurisdiction. See
> <https://github.com/kineticquant/TokenTrap/blob/main/docs/ethics-and-legal.md>.
>
> **Release notes:** <https://github.com/kineticquant/TokenTrap/blob/main/docs/releases/1.1.0.md>

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
`TOKENTRAP_LOG_WEBHOOK`, `TOKENTRAP_LLM_MODEL`, `TOKENTRAP_PHP2SHELL`,
`TOKENTRAP_PHP2SHELL_PROFILE`, `TOKENTRAP_PHP2SHELL_MODE`, and the other
`TOKENTRAP_PHP2SHELL_*` settings.

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

## PHP2Shell decoy

```bash
tokentrap php2shell --port 8080 --profile wordpress
tokentrap php2shell --php2shell-mode scanner --port 8080 --profile generic
# or add it to the existing backend:
tokentrap serve --php2shell --php2shell-profile generic
```

```python
from token_trap import TrapConfig, create_php2shell_app

app = create_php2shell_app(TrapConfig(php2shell_enabled=True))
```

The decoy is synthetic: no PHP execution, uploads, shell commands, or proxying.
See <https://github.com/kineticquant/TokenTrap/blob/main/docs/php2shell.md> for the
signal table, event schema, and limitations.

## Optional real-LLM dressing

With `pip install "tokentrap[llm]"`, set `llm_model` / `--llm-model` and turn-0
messages get answered by a real model before the trap engages. Failures fall
back to the static engagement payload.

## Tests

```bash
pytest
```
