# Architecture

TokenTrap is one trap engine with three runtimes. The engine is small,
deterministic and dependency-free; everything else is delivery.

```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend Layer                           │
│  tokentrap-ai (npm + CDN + single-file HTML)           │
│  - Chat UI or headless                                       │
│  - Trap engine (client-side fallback)                        │
│  - Config-driven backend target                              │
└──────────────────────┬──────────────────────────────────────┘
                       │  apiEndpoint?
          ┌────────────┼────────────┐
          ▼            ▼            ▼
   Pure Client    Cloudflare     Full Backend
   (static)       Workers        (Python FastAPI)
```

## Packages

| Package | Runtime | Role |
| --- | --- | --- |
| `packages/widget` | Browser / Node | `tokentrap`: UI orchestrator **and** the pure engine (`tokentrap-ai/engine`) used by every JS runtime |
| `packages/widget` | Web / Node | `tokentrap-ai/php2shell` HTTP decoy core, `tokentrap-ai/php2shell/node` adapters, `tokentrap-php2shell` CLI |
| `packages/worker` | Cloudflare Workers | Level-1 backend: KV sessions, rate limiting, canary echo detection, structured logs, optional webhook/R2 archival |
| `packages/backend-python` | CPython 3.10+ | Level-2 backend: `tokentrap` PyPI package, FastAPI app factory, OpenAI-compatible bait endpoint, CLI |

## PHP2Shell decoy layer

The PHP2Shell module is an optional fourth surface, not a change to the chat engine:

- `packages/widget/src/php2shell/` holds the dependency-free detector, phase state
  machine, response templates, canary generator, and Web `Request → Response` handler.
- Node/Express/Next adapters live behind `tokentrap-ai/php2shell/node`; the CLI is
  `tokentrap-php2shell`.
- The Worker imports the same core and enables it with `PHP2SHELL=1`.
- Python mirrors the detection/state/response contract in
  `token_trap/php2shell/` and exposes `create_php2shell_router` / `create_php2shell_app`.

The shared fixtures in `tests/fixtures/php2shell/cases.json` are the cross-language
contract. The chat engine's payload parity tests are untouched. See
[`php2shell.md`](php2shell.md).

## Data flow (widget protocol)

```jsonc
// POST {apiEndpoint}/api/chat
{ "sessionId": "…", "message": "attacker text" }
// → 200
{
  "sessionId": "…",
  "reply": "…compliance payload…",
  "turn": 2,
  "meta": {
    "turn": 2, "strength": "aggressive",
    "repeats": 10, "minWords": 15000,
    "injectionDetected": false, "matchedKeywords": [],
    "escalated": true, "ref": "TR-042871"
  }
}
```

The client never trusts `reply`; it renders or stores it. `meta` exists for
operators and for tests.

## Parity model

Escalation behavior is specified once (`docs/how-the-trap-works.md`) and
implemented twice:

- TypeScript: `packages/widget/src/trapEngine.ts`
- Python: `packages/backend-python/token_trap/traps.py`

Both implementations share identical constants (preset tables, policy ids,
keyword lists), identical FNV-1a-based reference hashing, and byte-identical
payload templates. `tests/e2e/test_parity.py` replays a scripted conversation
through both engines and asserts equality of every response and metadata
field. If you change either engine, both parity suites must pass unchanged.

## Session models per level

| Level | Where sessions live | Failure mode without them |
| --- | --- | --- |
| 0 static | Browser memory only | none - single page session |
| 1 worker | KV namespace (`TRAP_SESSIONS`) or in-isolate map | escalation restarts per isolate; still functional |
| 2 python | In-memory TTL store; Redis adapter possible via `SessionStore` interface | escalation resets on process restart |

Stateless clients (raw OpenAI callers) need no session at all: the Python
`/v1/chat/completions` route derives the turn index from the replayed
transcript length, which is exactly how agent loops behave.

## Trust boundaries

- The widget treats backend responses as opaque text.
- The backends treat inbound messages as hostile input: previews are capped,
  logs are JSON-encoded, nothing is ever executed or echoed into templates.
- Canary tokens flow outbound inside payloads; any reappearance inbound is
  logged as `canaryEchoed` and surfaced via the `x-tokentrap-canary-echo`
  header.
