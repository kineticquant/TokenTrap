# Unit tests

Engine, detection, session and UI-orchestrator unit tests live beside their
implementations:

- TypeScript widget: `packages/widget/test` (vitest)
- Cloudflare Worker handler: `packages/worker/test` (vitest, mocked KV/env)
- Python backend: `packages/backend-python/tests` (pytest)

This directory intentionally holds no test files; it exists so the harness
layout (`tests/unit|integration|e2e`) stays predictable.
