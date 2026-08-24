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
