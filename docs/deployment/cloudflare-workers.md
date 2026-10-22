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
**For production, treat KV as required**, not optional: without it, sessions
live in an in-isolate map, so escalation depth resets on every isolate
recycle and across PoPs. The rate limiter has the same property — it is an
in-process, per-isolate sliding window and is best-effort only. For strict
global limits, front the worker with a Cloudflare WAF rate-limiting rule.
Webhook delivery (`LOG_WEBHOOK`) is fire-and-forget; failures are swallowed
by design.

## Configuration (wrangler.toml `[vars]`)

| Var | Default | Meaning |
| --- | --- | --- |
| `PERSONA` | Internal AI Assistant | displayed persona |
| `TRAP_STRENGTH` | aggressive | moderate / aggressive / maximum |
| `RATE_LIMIT` | 30 | POST /api/chat per minute per IP |
| `EXTRA_KEYWORDS` | - | comma-separated extra triggers |
| `CANARY_TOKENS` | - | comma-separated tokens embedded in payloads |
| `LOG_WEBHOOK` | - | receives one JSON line per interaction |
| `PHP2SHELL` | `0` | `1` enables the PHP2Shell HTTP decoy on non-chat paths |
| `PHP2SHELL_PROFILE` | `generic` | generic / wordpress / drupal / joomla |
| `PHP2SHELL_MODE` | `tripwire` | tripwire / scanner |
| `PHP2SHELL_STRENGTH` | `aggressive` | tarpit preset for the decoy |
| `PHP2SHELL_CANARY_TOKENS` | - | comma-separated decoy canaries |
| `PHP2SHELL_SCAN_BYTES` | `2097152` | body inspection cap |
| `PHP2SHELL_PRESSURE_BYTES` | `1048576` | oversized-multipart threshold |
| `PHP2SHELL_WEBHOOK` | - | receives one JSON event per decoy request |

## PHP2Shell decoy

Set `PHP2SHELL=1` to turn every non-chat path into the PHP2Shell HTTP decoy. The
health routes and `/api/chat` keep their existing behavior. Use a **dedicated
Worker hostname**; the catch-all is not meant for a production site's main
hostname. `PHP2SHELL_MODE=scanner` adds the opt-in fake-shell/rabbit-hole
strategy. It is synthetic and never executes PHP. Full guide:
[`../php2shell.md`](../php2shell.md).

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
