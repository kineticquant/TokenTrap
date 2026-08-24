# Deployment: Python FastAPI backend (level 2)

Full-featured backend: persistent sessions, OpenAI-compatible bait endpoint,
structured JSON logs, CLI, optional real-LLM dressing.

## Install & run

```bash
pip install "tokentrap"          # or: pip install -e "packages/backend-python[test]"

tokentrap serve --host 0.0.0.0 --port 8787 \
  --strength aggressive \
  --canary-tokens prod-canary-1,prod-canary-2
```

## Embed in an existing FastAPI app

```python
from fastapi import FastAPI
from token_trap import create_app, TrapConfig

app = FastAPI()
app.mount("/trap", create_app(TrapConfig(strength="maximum")))
# POST /trap/api/chat and /trap/v1/chat/completions are now live.
```

## Endpoints

| Route | Purpose |
| --- | --- |
| `POST /api/chat` | widget protocol |
| `POST /v1/chat/completions` | OpenAI-compatible bait; stateless turn derivation from replayed transcripts |
| `GET /api/healthz`, `/healthz` | liveness |

## Configuration

Constructor args on `TrapConfig` mirror the Worker's env vars:
`persona`, `strength`, `canary_tokens`, `extra_keywords`,
`override_keywords`, `rate_limit_per_minute`, `session_ttl_seconds`,
`log_webhook`, `llm_model`. Every field can also come from `TOKENTRAP_*`
environment variables (`TrapConfig.from_env_prefix(None)`).

## Scaling notes

- The default session store is per-process memory with TTL. For multiple
  workers/replicas, implement a Redis-backed store against the same tiny
  interface (`get_or_create`, `increment_turns`, `set_last_meta`) in
  `token_trap/session.py`.
- Rate limiting is likewise per-process; put a limiter at your edge for
  strict global limits.

## Optional LLM dressing

```bash
pip install "tokentrap[llm]"
TOKENTRAP_LLM_MODEL=gpt-4o-mini tokentrap serve
```

Turn-0 messages get a genuine model reply before the trap engages, making the
early conversation more convincing. Any failure falls back to the static
engagement payload - the honeypot never breaks because its dressing did.

## Upgrade path recap

static -> worker -> python is always just the one `apiEndpoint` value on the
widget. Nothing else changes.
