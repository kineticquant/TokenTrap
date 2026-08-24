# Deployment: Cloudflare Workers (level 1)

Server-side traps with sessions, logging, canaries and rate limiting - no
servers to manage, free tier friendly.

## Deploy

```bash
cd packages/worker
npm install
npx wrangler login        # first time only
npx wrangler deploy       # prints your https://tokentrap-worker.<you>.workers.dev
```

## Recommended: bind KV

```bash
npx wrangler kv namespace create TRAP_SESSIONS
```

Uncomment the `[[kv_namespaces]]` block in `wrangler.toml` and paste the id.
Without KV the worker still works; sessions then live per-isolate and
escalation may reset between PoPs.

## Configuration (wrangler.toml `[vars]`)

| Var | Default | Meaning |
| --- | --- | --- |
| `PERSONA` | Internal AI Assistant | displayed persona |
| `TRAP_STRENGTH` | aggressive | moderate / aggressive / maximum |
| `RATE_LIMIT` | 30 | POST /api/chat per minute per IP |
| `EXTRA_KEYWORDS` | - | comma-separated extra triggers |
| `CANARY_TOKENS` | - | comma-separated tokens embedded in payloads |
| `LOG_WEBHOOK` | - | receives one JSON line per interaction |

## Point the widget at it

```js
TokenTrap.init({ container: "#trap", apiEndpoint: "https://tokentrap-worker.<you>.workers.dev" });
```

## Observe

```bash
npx wrangler tail --format pretty
```

Each interaction logs `sessionId`, turn, escalation state, matched keywords,
and `canaryEchoed`. Add an R2 binding (`TRAP_ARCHIVE`) if you want raw
archival.

## Upgrade to level 2

Swap `apiEndpoint` to your FastAPI URL. See [python-backend.md](python-backend.md).
