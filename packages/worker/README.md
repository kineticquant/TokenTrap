# Worker template notes

- The worker imports the shared engine from `tokentrap-ai/engine`
  (workspace package). Run `npm run build -w tokentrap-ai` before
  typechecking/testing/deploying this package.
- `src/index.ts` is a standard Workers `fetch` handler; tests drive it with
  real `Request`/`Response` objects and an in-memory KV stand-in, so no
  emulator is required for CI.
- Sessions: KV binding `TRAP_SESSIONS` (24h TTL) when present, otherwise an
  in-isolate map.
- Every response carries `x-tokentrap-canary-echo`; logs are JSON lines on
  stdout (`wrangler tail`) and optionally POSTed to `LOG_WEBHOOK`.

## Production notes (read before relying on level 1)

- **Bind KV for production.** Without `TRAP_SESSIONS`, sessions live in a
  per-isolate in-memory map: escalation depth resets on every isolate
  recycle and across PoPs. The trap still fires, but multi-turn escalation
  weakens considerably.
- **Rate limiting is per-isolate and best-effort.** The in-process sliding
  window does not coordinate across isolates. For strict global limits, add
  a Cloudflare WAF rate-limiting rule in front of the worker or move
  counters into KV / Durable Objects.
- **Webhook delivery is fire-and-forget.** A dead `LOG_WEBHOOK` endpoint
  never breaks serving — failures are swallowed by design. Watch
  `wrangler tail` if you depend on delivery.

Full deployment guide: `docs/deployment/cloudflare-workers.md`.
